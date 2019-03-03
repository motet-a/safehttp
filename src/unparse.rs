
use character_types;
use http;
use http::{
    header::{
        HeaderValue,
        HeaderName
    }
};
use io;
use parse_headers;
use types::{TransferEncoding};


/// Encoder for chunked transfer encoding.
pub struct ChunkWriter<S: io::Write> {
    writer: S
}

impl<S> ChunkWriter<S> where S: io::Write {
    /// Writes the last special chunk (with a chunk size of 0)
    pub fn write_end_marker(mut self) -> io::Result<S> {
        self.writer.write_all(b"0\r\n\r\n")?;
        Ok(self.writer)
    }

    fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        let hex_size = format!("{:x}", data.len()).into_bytes();
        self.writer.write_all(&hex_size)?;
        self.writer.write_all(b"\r\n")?;
        self.writer.write_all(data)?;
        self.writer.write_all(b"\r\n")?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}




/// Abstraction for serializing payloads.
///
/// `BodyWriter::Raw` does nothing special: It transfers writes
/// to the underlying `io::Write` without any transformation.
///
/// `BodyWriter::Chunked` translates writes into HTTP chunks.
/// Each call to `write` will create a separate chunk. Because
/// a chunk with a size of 0 marks the end of the tranfer,
/// `write` will panic if the given buffer is empty.
/// `into_inner` must be called in order to write the special
/// zero-sized trailing chunk.
pub enum BodyWriter<S: io::Write> {
    Raw(S),
    Chunked(ChunkWriter<S>)
}

impl<S: io::Write> BodyWriter<S> {
    /// Sends the end chunk marker if `Chunked`
    pub fn into_inner(self) -> io::Result<S> {
        match self {
            BodyWriter::Raw(w) => Ok(w),
            BodyWriter::Chunked(cw) => cw.write_end_marker(),
        }
    }
}

impl<S: io::Write> io::Write for BodyWriter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            BodyWriter::Raw(r) => r.write(buf),
            BodyWriter::Chunked(cw) => {
                assert!(buf.len() > 0, "an HTTP chunk cannot be empty");
                cw.write_chunk(buf)?;
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            BodyWriter::Raw(r) => r.flush(),
            BodyWriter::Chunked(cw) => cw.flush(),
        }
    }
}


fn unparse_token(token: &[u8]) -> Vec<u8> {
    assert!(token.len() > 0);
    assert!(token.iter().all(|b| character_types::is_token_byte(*b)));
    token.to_vec()
}

fn unparse_method(m: &http::Method) -> Vec<u8> {
    let s = m.as_str();
    assert!(s.to_ascii_uppercase() == s);
    s.as_bytes().to_vec()
}

fn unparse_request_target(uri: &http::Uri) -> Vec<u8> {
    uri.to_string().as_bytes().to_vec()
}

fn unparse_version(version: http::Version) -> Vec<u8> {
    use http::Version;

    let mut bytes = b"HTTP/".to_vec();
    bytes.extend(
        match version {
            Version::HTTP_09 => b"0.9",
            Version::HTTP_10 => b"1.0",
            Version::HTTP_11 => b"1.1",
            Version::HTTP_2 => b"2.0",
        }
    );
    bytes
}

fn unparse_header_value(value: &[u8]) -> Vec<u8> {
    assert!(value.len() > 0);
    assert!(value.iter().all(|b| character_types::is_header_value_byte(*b)));
    value.to_vec()
}

// Doesn’t unparse the trailing CRLF
fn unparse_header_field(name: &HeaderName, value: &HeaderValue) -> Vec<u8> {
    let mut v = unparse_token(name.as_str().as_bytes());
    v.extend(b": ");
    v.extend(unparse_header_value(value.as_bytes()));
    v
}

fn unparse_headers(headers: &http::HeaderMap) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for (name, value) in headers.iter() {
        v.extend(unparse_header_field(name, value));
        v.extend(b"\r\n")
    }
    v
}

/// Serializes a request line and headers.
///
/// Same as `unparse_request_head` but works with a `Parts`.
pub fn unparse_request_head_parts(parts: &http::request::Parts) -> Vec<u8> {
    let mut v = unparse_method(&parts.method);
    v.extend(b" ");
    v.extend(unparse_request_target(&parts.uri));
    v.extend(b" ");
    v.extend(unparse_version(parts.version));
    v.extend(b"\r\n");
    v.extend(unparse_headers(&parts.headers));
    v.extend(b"\r\n");
    v
}

/// Serializes a status line and headers.
///
/// Same as `unparse_response_head` but works with a `Parts`.
pub fn unparse_response_head_parts(parts: &http::response::Parts) -> Vec<u8> {
    let mut v = unparse_version(parts.version);
    v.extend(b" ");
    v.extend(parts.status.as_str().as_bytes());
    if let Some(reason) = parts.status.canonical_reason() {
        v.extend(b" ");
        v.extend(reason.as_bytes());
    }
    v.extend(b"\r\n");
    v.extend(unparse_headers(&parts.headers));
    v.extend(b"\r\n");
    v
}


/// Serializes a request line and headers.
///
/// Same as `unparse_request_head_parts` but works with a `Request`.
pub fn unparse_request_head<B>(request: &http::Request<B>) -> Vec<u8> {
    let mut v = unparse_method(request.method());
    v.extend(b" ");
    v.extend(unparse_request_target(request.uri()));
    v.extend(b" ");
    v.extend(unparse_version(request.version()));
    v.extend(b"\r\n");
    v.extend(unparse_headers(request.headers()));
    v.extend(b"\r\n");
    v
}

/// Serializes a status line and headers.
///
/// Same as `unparse_response_head_parts` but works with a `Request`.
pub fn unparse_response_head<B>(response: &http::Response<B>) -> Vec<u8> {
    let mut v = unparse_version(response.version());
    v.extend(b" ");
    v.extend(response.status().as_str().as_bytes());
    if let Some(reason) = response.status().canonical_reason() {
        v.extend(b" ");
        v.extend(reason.as_bytes());
    }
    v.extend(b"\r\n");
    v.extend(unparse_headers(&response.headers()));
    v.extend(b"\r\n");
    v
}


/// Serializes an HTTP request into a stream.
///
/// The request is written to the given output stream. The request body
/// must be written by the caller into the returned `BodyWriter`.
/// The body of the `request` parameter is ignored and unused.
pub fn unparse_request<B, O: io::Write>(
        request: &http::Request<B>,
        mut output: O
    ) -> io::Result<BodyWriter<O>> {
    let te = parse_headers::parse_transfer_encoding(request.headers(), request.version()).unwrap();
    output.write_all(&unparse_request_head(request))?;
    let body_writer =
        match te {
            TransferEncoding::None =>
                BodyWriter::Raw(output),
            TransferEncoding::Chunked =>
                BodyWriter::Chunked(ChunkWriter { writer: output })
        };

    Ok(body_writer)
}

/// Serializes an HTTP response into a stream.
///
/// The response is written to the given output stream. The response body
/// must be written by the caller into the returned `BodyWriter`.
/// The body of the `response` parameter is ignored and unused.
pub fn unparse_response<B, O: io::Write>(
        response: &http::Response<B>,
        mut output: O
    ) -> io::Result<BodyWriter<O>> {
    let te = parse_headers::parse_transfer_encoding(response.headers(), response.version()).unwrap();
    output.write_all(&unparse_response_head(response))?;
    let body_writer =
        match te {
            TransferEncoding::None =>
                BodyWriter::Raw(output),
            TransferEncoding::Chunked =>
                BodyWriter::Chunked(ChunkWriter { writer: output })
        };

    Ok(body_writer)
}


/// Serializes an HTTP request into a byte array.
///
/// Use this function for small payloads only. Prefer `unparse_request`.
pub fn unparse_request_sync(request: &http::Request<Vec<u8>>) -> io::Result<Vec<u8>> {
    use std::io::Write;

    let mut body_writer = unparse_request(request, io::Cursor::new(Vec::new()))?;
    body_writer.write_all(request.body())?;
    body_writer.flush()?;
    Ok(body_writer.into_inner()?.into_inner())
}

/// Serializes an HTTP response into a byte array.
///
/// Use this function for small payloads only. Prefer `unparse_response`.
pub fn unparse_response_sync(response: &http::Response<Vec<u8>>) -> io::Result<Vec<u8>> {
    use std::io::Write;

    let mut body_writer = unparse_response(response, io::Cursor::new(Vec::new()))?;
    body_writer.write_all(response.body())?;
    body_writer.flush()?;
    Ok(body_writer.into_inner()?.into_inner())
}

