#![forbid(unsafe_code)]

//! A slow (but simple, safe and strict) HTTP/1.1 parser for Rust
//!
//! See [RFC 7230](https://tools.ietf.org/html/rfc7230).
//!
//! # Simple example
//!
//! ```
//! extern crate http;
//! extern crate safehttp;
//! use std::io;
//!
//! let mut source = io::Cursor::new(
//!     b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()
//! );
//! let config = &safehttp::Config::DEFAULT;
//! let request = safehttp::parse_request(&mut source, config).unwrap();
//!
//! assert_eq!(request.method(), http::Method::GET);
//! assert_eq!(request.uri(), "/index.html");
//! assert_eq!(request.headers().get("host").unwrap(), "example.com");
//! ```
//!
//! # Expansive example
//!
//! ```
//!
//!
//! ```
//!

extern crate http;

use std::io;
use http::{
    Method,
    Version,
    Uri,
    HeaderMap,
    Request,
    Response,
    header::{
        HeaderName,
        HeaderValue,
    },
};

mod character_types;
use character_types::{
    is_whitespace_byte,
    is_token_byte,
    is_header_value_byte,
    is_status_reason_byte,
};

mod error;
use error::Error;

mod parse_headers;

mod single_byte_buffered_reader;
use single_byte_buffered_reader::{
    SingleByteBufferedReader as Reader,
    SingleByteBufferedReaderImpl as ReaderImpl,
};

mod types;
use types::{
    TransferEncoding
};

mod unparse;
pub use unparse::{
    unparse_request,
    unparse_request_sync,
    unparse_request_head_parts,
    unparse_request_head,
    unparse_response,
    unparse_response_sync,
    unparse_response_head_parts,
    unparse_response_head,
};


enum ChunkHeaderError {
    SizeTooLarge,
    ExtTooLong,
    InvalidSize,
    Syntax,
    IO(io::Error),
}


/// Parser configuration.
///
/// Mostly used for limiting lengths (and prevents DoS attacks).
/// You should always use `DEFAULT` unless you really know what
/// you are doing.
#[derive(Copy, Clone)]
pub struct Config {

    /// Used for header names and other things (see the definition of `token` in the spec)
    pub max_token_length: usize,

    /// How many headers are allowed
    pub max_header_count: usize,

    /// Maximum length of a header value
    pub max_header_value_length: usize,

    /// The “request target” is the thing between the method name and the HTTP version
    /// in the first line. Usually it’s an URI (but not always).
    pub max_request_target_length: usize,

    /// For `Transfer-Encoding: chunked`
    pub max_chunk_length: usize,

    /// For `Transfer-Encoding: chunked`
    pub max_chunk_ext_length: usize,
}

impl Config {
    /// Should be sane defaults, suitable for most users.
    pub const DEFAULT: Config = Config {
        max_token_length: 32,
        max_header_count: 32,
        max_header_value_length: 8 * 1024,
        max_request_target_length: 4 * 1024,
        max_chunk_length: 64 * 1024,
        max_chunk_ext_length: 8 * 1024,
    };
}


/// Abstraction for parsing streamed payloads.
///
/// A `BodyReader` is a readable stream that transparently handles
/// “identity” and chunked transfer encodings.
pub enum BodyReader<S: io::Read> {
    /// A `Content-Length` limits the body length. After that,
    /// the underlying transport (TCP) stream may contain other
    /// HTTP messages.
    Limited(io::Take<S>),

    /// There’s no `Content-Length` and no `Transfer-Encoding`,
    /// the payload should be read until the underlying transport stream
    /// is closed. This usually happens with responses in HTTP/1.1.
    Unlimited(S),

    /// Like `Unlimited` but for `Transfer-Encoding: chunked`
    Chunked(ChunkReader<S>),
}

impl<S: io::Read> BodyReader<S> {
    /// Destroys this body reader and returns the underlying
    /// transport stream.
    ///
    /// You should call this function after having read the entire
    /// payload in order to be able to reuse the transport for other
    /// HTTP messages. This function panics otherwise.
    ///
    /// This function must not be called after an I/O error has
    /// occured.
    pub fn into_inner(self) -> S {
        match self {
            BodyReader::Limited(take) => {
                assert_eq!(take.limit(), 0, "`into_inner` cannot be called if the message body is not entirely consumed");
                take.into_inner()
            },

            BodyReader::Chunked(cr) =>
                cr.into_inner(), // does the right checks itself

            BodyReader::Unlimited(mut stream) => {
                let mut dummy_buffer = [0u8];
                assert_eq!(
                    stream.read(&mut dummy_buffer).unwrap(),
                    0,
                    "`into_inner` cannot be called if the message body is not entirely consumed"
                );
                stream
            }
        }
    }
}

impl<S: io::Read> io::Read for BodyReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            BodyReader::Limited(take) => take.read(buf),
            BodyReader::Unlimited(stream) => stream.read(buf),
            BodyReader::Chunked(cr) => cr.read(buf),
        }
    }
}


/// Either an HTTP body or nothing.
///
/// This is pretty much like `Option` except both variants wrap
/// the underlying transport stream. You can recover it (and continue
/// to parse other HTTP messages) after having read the whole payload
/// with `into_inner`.
///
/// This enum implements `std::io::Read`. The `read` function for the
/// `Body::None` variant always return `Ok(0)`, i.e. EOF.
pub enum Body<S: io::Read> {
    Some(BodyReader<S>),
    None(S),
}

impl<S: io::Read> Body<S> {
    /// Destroys this body and returns the underlying transport stream.
    ///
    /// Panics if the body (if any) has not be entirely consumed.
    pub fn into_inner(self) -> S {
        match self {
            Body::Some(br) => br.into_inner(),
            Body::None(stream) => stream
        }
    }
}

impl<S: io::Read> io::Read for Body<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::Some(br) => br.read(buf),
            Body::None(_stream) => Ok(0),
        }
    }
}


fn read_bytes(reader: &mut Reader, buffer: &mut [u8]) -> Result<(), Error> {
    reader.read_bytes(buffer).map_err(Error::from_io)
}

fn read_byte(reader: &mut Reader) -> Result<u8, Error> {
    reader.read_byte().map_err(Error::from_io)
}

fn expect(reader: &mut Reader, expected: &'static [u8]) -> Result<(), Error> {
    assert!(expected.len() > 0);

    let mut bytes = vec![0u8; expected.len()];
    read_bytes(reader, &mut bytes)?;
    if &bytes[..] == expected {
        Ok(())
    } else {
        Err(Error::Syntax)
    }
}

fn skip_optional_whitespace(reader: &mut Reader, max_length: usize) -> Result<(), Error> {
    let mut i = 0;
    loop {
        if i >= max_length {
            return Err(Error::Syntax)
        }

        let byte = read_byte(reader)?;
        if !is_whitespace_byte(byte) {
            reader.unread_byte(byte);
            return Ok(())
        }

        i += 1;
    }
}

fn parse_token(reader: &mut Reader, config: &Config) -> Result<Vec<u8>, Error> {
    let mut token = vec![0u8; 0];
    loop {
        if token.len() > config.max_token_length {
            return Err(Error::Syntax)
        }

        let byte = read_byte(reader)?;
        if !is_token_byte(byte) {
            reader.unread_byte(byte);
            if token.len() == 0 {
                return Err(Error::Syntax)
            }
            return Ok(token)
        }
        token.push(byte)
    }
}

fn parse_chunk_size(reader: &mut Reader, config: &Config) -> Result<usize, ChunkHeaderError> {
    let mut digits = vec![0u8; 0];
    loop {
        if digits.len() > 8 {
            return Err(ChunkHeaderError::SizeTooLarge)
        }

        let byte = reader.read_byte()
            .map_err(|ioe| ChunkHeaderError::IO(ioe))?;
        if !byte.is_ascii_hexdigit() {
            reader.unread_byte(byte);
            break
        }
        digits.push(byte)
    }

    let digits_str = std::str::from_utf8(&digits[..])
        .map_err(|_| ChunkHeaderError::InvalidSize)?;
    let size: u32 = u32::from_str_radix(digits_str, 16)
        .map_err(|_| ChunkHeaderError::InvalidSize)?;

    if (size as usize) > config.max_chunk_length {
        Err(ChunkHeaderError::SizeTooLarge)
    } else {
        Ok(size as usize)
    }
}

fn skip_chunk_ext(reader: &mut Reader, config: &Config) -> Result<(), ChunkHeaderError> {
    let mut ext_length = 0;
    loop {
        if ext_length > config.max_chunk_ext_length {
            return Err(ChunkHeaderError::ExtTooLong)
        }
        let byte = reader.read_byte()
            .map_err(|ioe| ChunkHeaderError::IO(ioe))?;
        if byte == b'\r' {
            reader.unread_byte(byte);
            break
        }
        ext_length += 1
    }
    Ok(())
}

fn parse_chunk_header(reader: &mut Reader, config: &Config) -> Result<usize, ChunkHeaderError> {
    let size = parse_chunk_size(reader, config)?;
    skip_chunk_ext(reader, config)?;
    expect(reader, b"\r\n").map_err(|_| ChunkHeaderError::Syntax)?;
    Ok(size)
}

/// Decoder for chunked transfer encoding.
pub struct ChunkReader<S: io::Read> {
    config: Config,
    remaining_chunk_size: usize,
    begin: bool,
    reached_eof: bool,
    reader: ReaderImpl<S>,
}

impl<S> ChunkReader<S> where S: io::Read {
    /// Destroys this `ChunkReader` and returns the underlying
    /// transport stream.
    ///
    /// Panics if the chunk stream isn’t entirely consumed.
    pub fn into_inner(self) -> S {
        assert!(
            self.reached_eof,
            "`into_inner` called but the chunk stream was not entirely consumed"
        );
        self.reader.into_inner()
    }
}

fn skip_chunked_trailer_part(reader: &mut Reader, config: &Config) -> Result<(), Error> {
    // It’s important to keep in mind that trailing headers can contain
    // a ton of nasty things (like Content-Length, Host, Transfer-encoding…).
    // The spec says these invalid headers should be filtered out. Currently,
    // we ignore these headers without giving them to the user so not doing
    // any check should be safe.
    parse_headers(reader, config)?;

    Ok(())
}

impl<S> io::Read for ChunkReader<S> where S: io::Read {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use io::ErrorKind::InvalidData;

        if self.remaining_chunk_size == 0 {
            if !self.begin {
                expect(&mut self.reader, b"\r\n")
                    .map_err(|_| io::Error::new(InvalidData, "expected CRLF between HTTP chunks"))?;
            }

            self.remaining_chunk_size =
                parse_chunk_header(&mut self.reader, &self.config)
                    .map_err(|e|
                        match e {
                            ChunkHeaderError::SizeTooLarge => io::Error::new(InvalidData, "invalid HTTP chunk header"),
                            ChunkHeaderError::ExtTooLong => io::Error::new(InvalidData, "HTTP chunk extension too long"),
                            ChunkHeaderError::InvalidSize => io::Error::new(InvalidData, "invalid HTTP chunk size"),
                            ChunkHeaderError::Syntax => io::Error::new(InvalidData, "HTTP chunk syntax error"),
                            ChunkHeaderError::IO(ioe) => ioe,
                        }
                    )?;

            if self.remaining_chunk_size == 0 {
                skip_chunked_trailer_part(&mut self.reader, &self.config)
                    .map_err(|e| match e {
                        Error::IO(ioe) => ioe,
                        _ => io::Error::new(InvalidData, "invalid trailing headers after HTTP chunks"),
                    })?;

                self.reached_eof = true;
                return Ok(0);
            }

            self.begin = false
        }

        let chunk_buf =
            if buf.len() > self.remaining_chunk_size {
                &mut buf[..self.remaining_chunk_size]
            } else {
                &mut buf[..]
            };

        let len = self.reader.read_bytes_partial(chunk_buf)?;
        self.remaining_chunk_size -= len;
        Ok(len)
    }
}


fn parse_method(reader: &mut Reader, config: &Config) -> Result<Method, Error> {
    let token = parse_token(reader, config)?;
    Method::from_bytes(&token).map_err(|_| Error::Syntax)
}

fn parse_request_target_raw(reader: &mut Reader, config: &Config) -> Result<Vec<u8>, Error> {
    // The spec says it’s okay to parse until the next whitespace here
    // (see section 3.1.1 of RFC7230)
    let mut req_target = vec![0u8; 0];
    while req_target.len() < config.max_request_target_length {
        let byte = read_byte(reader)?;
        if byte == b' ' {
            reader.unread_byte(byte);
            if req_target.len() == 0 {
                return Err(Error::Syntax)
            }
            return Ok(req_target)
        }
        req_target.push(byte)
    }
    Err(Error::RequestTargetTooLong)
}

fn parse_request_target(reader: &mut Reader, config: &Config) -> Result<Uri, Error> {
    let raw = parse_request_target_raw(reader, config)?;
    let s = String::from_utf8(raw).map_err(|_| Error::InvalidRequestTarget)?;
    s.parse().map_err(|_| Error::InvalidRequestTarget)
}

fn parse_version(reader: &mut Reader) -> Result<Version, Error> {
    expect(reader, b"HTTP/")?;
    let maj = read_byte(reader)?;
    expect(reader, b".")?;
    let min = read_byte(reader)?;
    if !(maj.is_ascii_digit() && min.is_ascii_digit()) {
       return Err(Error::Syntax)
    }

    match (maj, min) {
        (b'1', b'0') => Ok(Version::HTTP_10),
        (b'1', b'1') => Ok(Version::HTTP_11),
        (_, _) => Err(Error::UnsupportedVersion),
    }
}

fn parse_status_code(reader: &mut Reader) -> Result<http::StatusCode, Error> {
    let bytes: Vec<u8> =
        (0..3)
        .try_fold(
            Vec::with_capacity(3),
            |mut acc, _| -> Result<Vec<u8>, Error> {
                let b = read_byte(reader)?;
                if !b.is_ascii_digit() {
                    return Err(Error::Syntax)
                }
                acc.push(b);
                Ok(acc)
            }
        )?;

    let status_code = http::StatusCode::from_bytes(&bytes).map_err(|_| Error::Syntax)?;

    Ok(status_code)
}

fn skip_optional_status_reason(reader: &mut Reader) -> Result<(), Error> {
    let max_length = 64;
    let mut i = 0;
    loop {
        if i >= max_length {
            return Err(Error::Syntax)
        }

        let byte = read_byte(reader)?;
        if byte == b'\r' {
            reader.unread_byte(byte);
            return Ok(())
        }
        if !is_status_reason_byte(byte) {
            return Err(Error::Syntax)
        }

        i += 1;
    }
}

fn parse_header_value(reader: &mut Reader, config: &Config) -> Result<HeaderValue, Error> {
    let mut content = vec![0u8; 0];
    loop {
        if content.len() > config.max_header_value_length {
            return Err(Error::Syntax)
        }

        let byte = read_byte(reader)?;
        if !is_header_value_byte(byte) {
            reader.unread_byte(byte);
            let hv = HeaderValue::from_bytes(&content)
                .map_err(|_| Error::Syntax)?;
            return Ok(hv)
        }
        content.push(byte)
    }
}

fn parse_header_field(reader: &mut Reader, config: &Config) -> Result<(HeaderName, HeaderValue), Error> {
    let name = HeaderName::from_bytes(&parse_token(reader, config)?)
        .map_err(|_| Error::Syntax)?;
    expect(reader, b":")?;
    skip_optional_whitespace(reader, config.max_token_length)?;
    let value = parse_header_value(reader, config)?;
    Ok((name, value))
}

fn check_host_header(host_source: &HeaderValue, uri: &Uri) -> Result<(), Error> {
    if host_source.as_bytes().len() == 0 {
        return Ok(())
    }

    if host_source.as_bytes().contains(&b',') {
        return Err(Error::InvalidHost);
    }

    let host_str = host_source.to_str().map_err(|_| Error::InvalidHost)?;
    let host_uri: Uri = host_str.parse().map_err(|_| Error::InvalidHost)?;
    let host_authority = host_uri.authority_part().ok_or(Error::InvalidHost)?;
    if let Some(target_authority) = uri.authority_part() {
        if target_authority.host() != host_authority.host() ||
            target_authority.port_part() != host_authority.port_part() {
            return Err(Error::InvalidHost)
        }
    }

    Ok(())
}

/// It’s a response if `uri` is `None`.
///
/// See https://tools.ietf.org/html/rfc7230#section-3.3.3
fn check_headers(
    headers: &HeaderMap,
    maybe_uri: Option<&Uri>,
    version: Version
) -> Result<(), Error> {
    if headers.get_all("Content-Length").iter().count() > 1 {
        return Err(Error::MultipleContentLengths)
    }
    if headers.contains_key("Content-Length") && headers.contains_key("Transfer-Encoding") {
        return Err(Error::ContentLengthAndTransferEncoding)
    }

    if headers.get_all("Host").iter().count() > 1 {
        return Err(Error::MultipleHosts)
    }

    if let Some(uri) = maybe_uri {
        match headers.get("Host") {
            None =>
                if version != Version::HTTP_10 {
                    return Err(Error::MissingHost)
                },

            Some(host_source) =>
                check_host_header(host_source, uri)?,
        }
    }

    Ok(())
}

fn parse_headers(
        reader: &mut Reader,
        config: &Config,
    ) -> Result<HeaderMap, Error> {

    let mut headers = HeaderMap::new();

    let mut count: usize = 0;
    loop {
        match read_byte(reader)? {
            b'\r' => {
                expect(reader, b"\n")?;
                break
            },
            b => {
                reader.unread_byte(b);
            }
        }

        if count > config.max_header_count {
            return Err(Error::TooManyHeaders)
        }

        let (name, value) = parse_header_field(reader, config)?;
        headers.append(name, value);
        count += 1;

        expect(reader, b"\r\n")?;
    }

    Ok(headers)
}

fn parse_body<S: io::Read>(
        reader: ReaderImpl<S>,
        config: &Config,
        headers: &HeaderMap,
        version: Version,
        is_request: bool,
    ) -> Result<Body<S>, Error> {

    // see https://tools.ietf.org/html/rfc7230#section-3.3.3

    let body = match parse_headers::parse_transfer_encoding(headers, version)? {
        TransferEncoding::None => {
            match parse_headers::parse_content_length(headers)? {
                None =>
                    if is_request {
                        Body::None(reader.into_inner()) // (6)
                    } else {
                        Body::Some(BodyReader::Unlimited(reader.into_inner())) // (7)
                    },
                Some(len) => {
                    let take = reader.into_inner().take(len); // (5)
                    Body::Some(BodyReader::Limited(take))
                },
            }
        },

        TransferEncoding::Chunked => {
            let mut cr: ChunkReader<S> = ChunkReader { // (3)
                config: config.clone(),
                reader,
                begin: true,
                remaining_chunk_size: 0,
                reached_eof: false,
            };
            Body::Some(BodyReader::Chunked(cr))
        },
    };

    Ok(body)
}

fn parse_request_head_impl(reader: &mut Reader, config: &Config) -> Result<Request<()>, Error> {
    let method = parse_method(reader, config)?;
    expect(reader, b" ")?;
    let uri = parse_request_target(reader, config)?;
    expect(reader, b" ")?;
    let version = parse_version(reader)?;
    expect(reader, b"\r\n")?;

    let headers = parse_headers(reader, config)?;
    check_headers(&headers, Some(&uri), version)?;

    let mut req = Request::new(());
    *req.headers_mut() = headers;
    *req.version_mut() = version;
    *req.method_mut() = method;
    *req.uri_mut() = uri;
    Ok(req)
}

/// Parses the request line and the headers of an HTTP request.
pub fn parse_request_head<S: io::Read>(stream: S, config: &Config) -> Result<Request<S>, Error> {
    let mut reader = ReaderImpl::new(stream);
    Ok(parse_request_head_impl(&mut reader, config)?.map(|_| reader.into_inner()))
}

fn parse_request_impl<S: io::Read>(mut reader: ReaderImpl<S>, config: &Config) ->
        Result<Request<Body<S>>, Error> {
    let request = parse_request_head_impl(&mut reader, config)?;
    let body = parse_body(reader, config, request.headers(), request.version(), true)?;
    Ok(request.map(|_| body))
}

fn parse_response_impl<S: io::Read>(mut reader: ReaderImpl<S>, config: &Config) ->
        Result<Response<Body<S>>, Error> {
    let version = parse_version(&mut reader)?;
    expect(&mut reader, b" ")?;
    let status_code = parse_status_code(&mut reader)?;
    expect(&mut reader, b" ")?;
    skip_optional_status_reason(&mut reader)?;
    expect(&mut reader, b"\r\n")?;

    let headers = parse_headers(&mut reader, config)?;
    check_headers(&headers, None, version)?;

    let body = parse_body(reader, config, &headers, version, false)?;

    let mut res = Response::new(body);
    *res.headers_mut() = headers;
    *res.version_mut() = version;
    *res.status_mut() = status_code;
    Ok(res)
}


/// Parses an HTTP request.
///
/// This function takes ownership of the given transport stream,
/// but you can recover it by calling `into_inner` on the returned
/// `Body`.
pub fn parse_request<S: io::Read>(stream: S, config: &Config) ->
        Result<Request<Body<S>>, Error> {
    let reader = ReaderImpl::new(stream);
    parse_request_impl(reader, config)
}

/// Parses an HTTP response.
///
/// This function takes ownership of the given transport stream,
/// but you can recover it by calling `into_inner` on the returned
/// `Body`.
pub fn parse_response<S: io::Read>(stream: S, config: &Config) ->
        Result<Response<Body<S>>, Error> {
    let reader = ReaderImpl::new(stream);
    parse_response_impl(reader, config)
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    type TestStream = io::Cursor<Vec<u8>>;

    const C: &Config = &Config::DEFAULT;

    fn with_reader_impl<T>(
        bytes: &[u8],
        fun: &Fn(ReaderImpl<TestStream>) -> T
    ) -> T {
        let vec = bytes.to_vec();
        let cursor = io::Cursor::new(vec);
        let reader = ReaderImpl::new(cursor);
        fun(reader)
    }

    fn with_reader<T>(bytes: &[u8], fun: &Fn(&mut Reader) -> T) -> T {
        with_reader_impl(bytes, &|mut ri| fun(&mut ri))
    }

    fn read_to_end(stream: &mut io::Read) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn read_body_stream(mut body: Body<TestStream>) -> Result<(Vec<u8>, TestStream), Error> {
        let payload = read_to_end(&mut body).map_err(Error::from_io)?;
        Ok((payload, body.into_inner()))
    }

    fn parse_test_request(source: &[u8]) -> Result<(http::request::Parts, Vec<u8>, TestStream), Error> {
        let req = with_reader_impl(source, &|r| parse_request_impl(r, C))?;
        let (parts, body) = req.into_parts();
        let (payload, next_stream) = read_body_stream(body)?;
        Ok((parts, payload, next_stream))
    }

    fn parse_test_response(source: &[u8]) -> Result<(http::response::Parts, Vec<u8>, TestStream), Error> {
        let res = with_reader_impl(source, &|r| parse_response_impl(r, C))?;
        let (parts, body) = res.into_parts();
        let (payload, next_stream) = read_body_stream(body)?;
        Ok((parts, payload, next_stream))
    }

    fn concat(bytes_list: Vec<&[u8]>) -> Vec<u8> {
        bytes_list
            .iter()
            .flat_map(|b| b.to_vec())
            .collect()
    }

    fn concat_lines(bytes_list: Vec<&[u8]>) -> Vec<u8> {
        bytes_list
            .iter()
            .flat_map(|b| concat(vec![b, b"\r\n"]))
            .collect()
    }


    #[test]
    fn version() {
        let res = with_reader(b"", &parse_version);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::Syntax);

        let res = with_reader(b"HTTP/1.3", &parse_version);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::UnsupportedVersion);

        let (v_res, d_res) = with_reader(
            b"HTTP/1.0$",
            &|r| (parse_version(r), expect(r, b"$"))
        );
        assert_eq!(v_res.unwrap(), Version::HTTP_10);
        assert!(d_res.is_ok());

        let res = with_reader(
            b"HTTP/1.1",
            &parse_version
        );
        assert_eq!(res.unwrap(), Version::HTTP_11);
    }

    #[test]
    fn typical_get_request() {
        let source = concat_lines(vec![
            b"GET /index.html HTTP/1.1",
            b"Host: www.example.com",
            b"Accept: text/html, application/json",
            b"Accept: image/webp",
            b"",
        ]);

        let req = with_reader_impl(&source, &|r| parse_request_impl(r, C)).unwrap();
        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri(), &Uri::from_static("/index.html"));
        assert_eq!(req.headers().len(), 3);
        assert_eq!(req.headers().get("Host").unwrap(), "www.example.com");
        let mut accept = req.headers().get_all("accept").iter();
        assert_eq!(accept.next().unwrap(), "text/html, application/json");
        assert_eq!(accept.next().unwrap(), "image/webp");
        assert!(accept.next().is_none());
    }

    #[test]
    fn typical_post_request() {
        let source = concat_lines(vec![
            b"POST /index.html HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 4",
            b"",
            b"1234"
        ]);

        let req = with_reader_impl(&source, &|r| parse_request_impl(r, C)).unwrap();
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.uri(), &Uri::from_static("/index.html"));
        assert_eq!(req.headers().len(), 2);
        assert_eq!(req.headers().get("Content-Length").unwrap(), "4");
    }

    #[test]
    fn transfer_encoding_did_not_exist_before_http_1_1() {
        let source = concat_lines(vec![
            b"POST /foo HTTP/1.0",
            b"Transfer-Encoding: chunked",
            b"",
            b"1",
            b"a",
            b"0",
            b"",
        ]);

        let (_parts, body, _next) = parse_test_request(&source).unwrap();
        assert_eq!(body.len(), 0);
    }

    #[test]
    fn unsupported_transfer_encodings_are_rejected() {
        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: ",
            b"",
            b"0",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidTransferEncoding);

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"Transfer-Encoding: gzip",
            b"",
            b"0",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidTransferEncoding);

        let tes: Vec<&[u8]> = vec![
            b"gzip, chunked",
            b"chunked, gzip",
            b"gzip",
            b"compress",
            b"deflate",
            b"foo"
        ];
        for te in tes {
            let source = concat_lines(vec![
                b"POST /foo HTTP/1.1",
                b"Host: example.com",
                &concat(vec![b"Transfer-Encoding: ", te]),
                b"",
                b"0",
                b"",
            ]);

            let err = parse_test_request(&source).unwrap_err();
            assert_eq!(err, Error::InvalidTransferEncoding);
        }
    }

    #[test]
    fn transfer_encoding_chunked() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"000", // The spec says “one or more zeroes”
            b"",
            b"ignored",
        ]);

        let (_parts, body, mut next) = parse_test_request(&source).unwrap();
        assert_eq!(body.len(), 0);

        assert_eq!(
            b"ignored\r\n".to_vec(),
            read_to_end(&mut next).unwrap()
        );

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"3",
            b"hel",
            b"2",
            b"lo",
            b"0",
            b"",
        ]);

        let (_parts, body, _next) = parse_test_request(&source).unwrap();
        assert_eq!(&body, b"hello");

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"wrong",
            b"",
        ]);

        match parse_test_request(&source).unwrap_err() {
            Error::IO(ioe) => {
                assert_eq!(ioe.kind(), io::ErrorKind::InvalidData);
                assert_eq!(ioe.to_string(), "invalid HTTP chunk size");
            },
            _ => panic!(),
        }

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"2",
            b"hello",
            b"",
        ]);

        match parse_test_request(&source).unwrap_err() {
            Error::IO(ioe) => {
                assert_eq!(ioe.kind(), io::ErrorKind::InvalidData);
                assert_eq!(ioe.to_string(), "expected CRLF between HTTP chunks");
            },
            _ => panic!(),
        }

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"0",
            b"wrong",
        ]);

        match parse_test_request(&source).unwrap_err() {
            Error::IO(ioe) => {
                assert_eq!(ioe.kind(), io::ErrorKind::InvalidData);
                assert_eq!(ioe.to_string(), "invalid trailing headers after HTTP chunks");
            },
            _ => panic!(),
        }

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"+0",
            b"",
        ]);

        match parse_test_request(&source).unwrap_err() {
            Error::IO(ioe) => {
                assert_eq!(ioe.kind(), io::ErrorKind::InvalidData);
                assert_eq!(ioe.to_string(), "invalid HTTP chunk size");
            },
            _ => panic!(),
        }

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"aA",
            "x".repeat(0xaa).as_bytes(),
            b"0",
            b"",
        ]);

        let (_parts, body, _next_stream) = parse_test_request(&source).unwrap();
        assert_eq!(body.len(), 0xaa);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"fffff",
            b"ignored",
        ]);

        match parse_test_request(&source).unwrap_err() {
            Error::IO(ioe) => {
                assert_eq!(ioe.kind(), io::ErrorKind::InvalidData);
                assert_eq!(ioe.to_string(), "invalid HTTP chunk header");
            },
            _ => panic!(),
        }
    }

    #[test]
    fn ignores_chunk_extensions() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"3;ignored-chunk-ext=ignored-value",
            b"foo",
            b"0;another-ignored-ext;foo=\"bar\"",
            b"",
        ]);

        let (_parts, body, _next_stream) = parse_test_request(&source).unwrap();
        assert_eq!(&body, b"foo");
    }

    #[test]
    fn ignores_chunk_trailer() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"",
            b"3",
            b"foo",
            b"0",
            b"This-Field: should-be-ignored",
            b"",
        ]);

        let (parts, body, mut next_stream) = parse_test_request(&source).unwrap();
        assert_eq!(&body, b"foo");
        assert!(!parts.headers.contains_key("This-Field"));
        assert!(!parts.headers.contains_key("this-field"));
        assert_eq!(read_to_end(&mut next_stream).unwrap().len(), 0);
    }

    #[test]
    fn content_length_overflow() {
        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 99999999999999999999",
            b"",
            b"hello",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidContentLength);
    }

    #[test]
    fn message_body_length_security() {
        // https://tools.ietf.org/html/rfc7230#section-3.3.3

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 8",
            b"Transfer-Encoding: chunked",
            b"",
            b"5",
            b"hello",
            b"6",
            b" world",
            b"0",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::ContentLengthAndTransferEncoding);

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 2",
            b"Content-Length: 3",
            b"",
            b"hello",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::MultipleContentLengths);

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 2, 3",
            b"",
            b"hello",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidContentLength);

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: +2",
            b"",
            b"hello",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidContentLength);

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"",
            b"hello",
            b"",
        ]);

        let (_parts, body, mut next) = parse_test_request(&source).unwrap();
        assert_eq!(body.len(), 0);
        assert_eq!(
            b"hello\r\n\r\n".to_vec(),
            read_to_end(&mut next).unwrap()
        );

        let source = concat_lines(vec![
            b"POST /foo HTTP/1.1",
            b"Host: example.com",
            b"Transfer-Encoding: chunked",
            b"Transfer-Encoding: chunked",
            b"",
            b"5",
            b"hello",
            b"0",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidTransferEncoding);
    }

    #[test]
    fn rejects_invalid_line_terminators() {
        let source = b"GET /foo HTTP/1.0\n\n";
        let err = parse_test_request(source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = b"GET /foo HTTP/1.0\r\nHost: bar\rAccept: text/html\r\n\r\n";
        let err = parse_test_request(source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = b"GET /foo HTTP/1.0\r\nHost: bar\nAccept: text/html\r\n\r\n";
        let err = parse_test_request(source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = b"GET /foo HTTP/1.0\r\nHost: bar\n\rAccept: text/html\r\n\r\n";
        let err = parse_test_request(source).unwrap_err();
        assert_eq!(err, Error::Syntax);
    }

    #[test]
    fn http_09_and_http_20_are_not_supported() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/0.9",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion);

        let source = concat_lines(vec![
            b"GET /foo HTTP/2.0",
            b"",
        ]);

        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::UnsupportedVersion);
    }

    #[test]
    fn multiple_header_values() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"X-Bar: foo",
            b"X-Bar: bar",
            b"",
        ]);

        let (parts, _body, _next_stream) = parse_test_request(&source).unwrap();
        let mut iter = parts.headers.get_all("x-bar").iter();
        assert_eq!(&"foo", iter.next().unwrap());
        assert_eq!(&"bar", iter.next().unwrap());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_unparse_requests() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"host: bar.example.com",
            b"x-bar: foo",
            b"",
        ]);

        let (parts, body, _next_stream) = parse_test_request(&source).unwrap();
        assert_eq!(body.len(), 0);
        let req = Request::from_parts(parts, body);
        let empty: Vec<u8> = vec![];
        let unparsed = unparse_request_sync(&req.map(|_| empty)).unwrap();
        assert_eq!(unparsed, source);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"host: bar.example.com",
            b"transfer-encoding: chunked",
            b"",
            b"5",
            b"hello",
            b"0",
            b"",
        ]);

        let (parts, body, mut next_stream) = parse_test_request(&source).unwrap();
        let req = Request::from_parts(parts, body);
        let unparsed = unparse_request_sync(&req).unwrap();

        assert_eq!(unparsed, source);
        assert_eq!(read_to_end(&mut next_stream).unwrap().len(), 0);
    }

    #[test]
    fn test_unparse_responses() {
        let source = concat_lines(vec![
            b"HTTP/1.1 200 OK",
            b"x-bar: foo",
            b"",
            b"foo",
            b"",
            b"bar",
            b"",
        ]);

        let (parts, body, mut next_stream) = parse_test_response(&source).unwrap();
        assert_eq!(read_to_end(&mut next_stream).unwrap(), b"");
        let res = Response::from_parts(parts, body);
        let unparsed = unparse_response_sync(&res).unwrap();
        assert_eq!(unparsed, source);
    }

    #[test]
    fn requires_host_header_in_http_11() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b""
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::MissingHost);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.0",
            b""
        ]);
        let _ = parse_test_request(&source).unwrap();
    }

    #[test]
    fn rejects_multiple_host_headers() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.0",
            b"Host: foo.example.com",
            b"Host: foo.example.com",
            b""
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::MultipleHosts);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.0",
            b"Host: foo.example.com, foo.example.com",
            b""
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidHost);
    }

    #[test]
    fn host_header_authority_must_match_target_uri() {
        let source = concat_lines(vec![
            b"GET http://a.example.com/foo HTTP/1.1",
            b"Host: b.example.com",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidHost);

        let source = concat_lines(vec![
            b"GET http://example.com:1234/foo HTTP/1.1",
            b"Host: example.com:4321",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidHost);

        let source = concat_lines(vec![
            b"GET http://example.com:1234/foo HTTP/1.1",
            b"Host: example.com",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidHost);

        let source = concat_lines(vec![
            b"GET http://example.com/foo HTTP/1.1",
            b"Host: example.com:1234",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidHost);


        let source = concat_lines(vec![
            b"GET http://antoine@example.com/foo HTTP/1.1",
            b"Host: example.com",
            b"",
        ]);
        parse_test_request(&source).unwrap();
    }

    #[test]
    fn allows_empty_host_headers() {
        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host:          ",
            b"",
        ]);
        let (parts, _body, _next_stream) = parse_test_request(&source).unwrap();
        assert_eq!(parts.headers.get("host").unwrap().as_bytes(), b"");
    }

    #[test]
    fn method_names_are_case_sensitive() {
        let source = concat_lines(vec![
            b"get /foo HTTP/1.0",
            b"Host: example.com",
            b"",
        ]);

        let (parts, _body, _next_stream) = parse_test_request(&source).unwrap();
        assert_ne!(parts.method, Method::GET);
    }

    #[test]
    fn rejects_non_ascii_characters() {
        let source = concat_lines(vec![
            "GET /café HTTP/1.1".as_bytes(),
            b"Host: example.com",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::InvalidRequestTarget);

        let source = concat_lines(vec![
            "MÉTHODE /coffe HTTP/1.1".as_bytes(),
            b"Host: example.com",
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = concat_lines(vec![
            b"GET /coffe HTTP/1.1",
            b"Host: example.com",
            "X-En-Tête: value".as_bytes(),
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = concat_lines(vec![
            b"GET /coffe HTTP/1.1",
            b"Host: example.com",
            "X-Custom-Header: entrée".as_bytes(),
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            "Host: déjàvu.example.com".as_bytes(),
            b"",
        ]);
        let err = parse_test_request(&source).unwrap_err();
        assert_eq!(err, Error::Syntax);

        let source = concat_lines(vec![
            b"GET /foo HTTP/1.1",
            b"Host: example.com",
            b"Content-Length: 8",
            b"",
            "déjàvu".as_bytes(),
        ]);
        parse_test_request(&source).unwrap();
    }

    #[test]
    fn response_splitting() {
        // TODO
    }
}

