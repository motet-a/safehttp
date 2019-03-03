
use io;

/// Errors that can be raised during HTTP parsing.
#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Syntax,
    UnsupportedVersion,
    TooManyHeaders,
    HeaderTooLong,
    RequestTargetTooLong,
    InvalidRequestTarget,
    InvalidContentLength,
    InvalidTransferEncoding,
    MultipleContentLengths,
    ContentLengthAndTransferEncoding,
    MultipleHosts,
    MissingHost,
    InvalidHost
}

impl Error {
    pub fn from_io(io_error: io::Error) -> Error {
        if io_error.kind() == io::ErrorKind::UnexpectedEof {
            // let’s consider EOFs as syntax errors for the sake of
            // simplicity
            Error::Syntax
        } else {
            Error::IO(io_error)
        }
    }
}

impl PartialEq<Error> for Error {
    fn eq(&self, other: &Error) -> bool {
        macro_rules! d {
            ($n:ident) => {(Error::$n, Error::$n)};
        }

        match (self, other) {
            (Error::IO(io_e0), Error::IO(io_e1)) => io_e0.kind() == io_e1.kind(),

            d!(Syntax) => true,
            d!(UnsupportedVersion) => true,
            d!(TooManyHeaders) => true,
            d!(HeaderTooLong) => true,
            d!(RequestTargetTooLong) => true,
            d!(InvalidRequestTarget) => true,
            d!(InvalidContentLength) => true,
            d!(InvalidTransferEncoding) => true,
            d!(MultipleContentLengths) => true,
            d!(ContentLengthAndTransferEncoding) => true,
            d!(MultipleHosts) => true,
            d!(MissingHost) => true,
            d!(InvalidHost) => true,

            (_, _) => false,
        }
    }
}


