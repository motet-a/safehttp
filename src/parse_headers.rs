use error::Error;
use http;
use types::TransferEncoding;

pub fn parse_transfer_encoding(
    headers: &http::HeaderMap,
    version: http::Version,
) -> Result<TransferEncoding, Error> {
    if version != http::Version::HTTP_11 {
        return Ok(TransferEncoding::None);
    }

    if headers.get_all("Transfer-Encoding").iter().count() > 1 {
        return Err(Error::InvalidTransferEncoding);
    }

    match headers.get("Transfer-Encoding").map(|v| v.as_bytes()) {
        None => Ok(TransferEncoding::None),
        Some(b"chunked") => Ok(TransferEncoding::Chunked),
        Some(_) => Err(Error::InvalidTransferEncoding),
    }
}

pub fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>, Error> {
    match headers.get("Content-Length").map(|hv| hv.to_str()) {
        Some(Ok(len_str)) => {
            // Necessary because things like `+123` successfully parse below
            // and are forbidden by the spec
            if !len_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidContentLength);
            }

            let len = len_str
                .parse::<u64>()
                .map_err(|_| Error::InvalidContentLength)?;

            Ok(Some(len))
        }
        None => Ok(None),
        _ => Err(Error::InvalidContentLength),
    }
}
