use std::io;

/// Used to poison bytes that should not be read
#[cfg(debug_assertions)]
fn poison(buffer: &mut [u8]) {
    buffer.iter_mut().for_each(|c| *c = 0);
}

#[cfg(not(debug_assertions))]
#[inline]
fn poison(_buffer: &mut [u8]) {
}


/// TODO: Write more documentation
///
/// The buffer is filled with zeroes if an error is returned.
///
/// If an “end of file” is encountered after reading `n` bytes,
/// then `Ok(n)` is returned and only the `n` first bytes of the
/// buffer are valid.
fn reliable_read_partial(stream: &mut io::Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    loop {
        match stream.read(&mut buffer[total..]) {
            Ok(size) => {
                total += size;
                if total == buffer.len() {
                    // `size` may be zero here if we encounter an EOF
                    return Ok(total)
                }
                if size == 0 {
                    // EOF
                    return Ok(total)
                }
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::Interrupted {
                    poison(buffer);
                    return Err(err)
                }
            }
        }
    }
}


pub trait SingleByteBufferedReader {
    /// The buffer is filled with zeroes if an error is returned.
    ///
    /// If an “end of file” is encountered after reading `n` bytes,
    /// then `Ok(n)` is returned and only the `n` first bytes of the
    /// buffer are valid.
    fn read_bytes_partial(&mut self, out_buffer: &mut [u8]) -> io::Result<usize>;

    fn unread_byte(&mut self, byte: u8);

    fn read_bytes(&mut self, out_buffer: &mut [u8]) -> io::Result<()> {
        let read_count = self.read_bytes_partial(out_buffer)?;
        if read_count == out_buffer.len() {
            return Ok(())
        }
        poison(out_buffer);
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "expected one byte"))
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        let mut bytes = [0u8];
        self.read_bytes(&mut bytes)?;
        Ok(bytes[0])
    }
}

pub struct SingleByteBufferedReaderImpl<S: io::Read> {
    stream: S,
    pushed_back_byte: Option<u8>
}

impl<S> SingleByteBufferedReaderImpl<S> where S: io::Read {
    pub fn new(stream: S) -> Self {
        Self { stream, pushed_back_byte: None }
    }

    /// Panics if there is a pushed back byte
    pub fn into_inner(self) -> S {
        assert!(
            self.pushed_back_byte.is_none(),
            "cannot recover the underlying stream if there is a buffered byte"
        );
        self.stream
    }
}

impl<S> SingleByteBufferedReader for SingleByteBufferedReaderImpl<S> where S: io::Read {
    fn read_bytes_partial(&mut self, out_buffer: &mut [u8]) -> io::Result<usize> {
        poison(out_buffer);

        if out_buffer.len() == 0 {
            return Ok(0)
        }

        let mut total = 0;
        if let Some(byte) = self.pushed_back_byte {
            out_buffer[0] = byte;
            self.pushed_back_byte = None;
            total += 1;
            if out_buffer.len() == 1 {
                return Ok(1)
            }
        }

        match reliable_read_partial(&mut self.stream, &mut out_buffer[total..]) {
            Ok(size) => {
                Ok(total + size)
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    fn unread_byte(&mut self, byte: u8) {
        assert!(self.pushed_back_byte == None);
        self.pushed_back_byte = Some(byte)
    }
}



#[cfg(test)]
mod tests {
    use std::io;
    use super::*;

    struct BrokenReader {}

    impl io::Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "oops"))
        }
    }


    #[test]
    fn test_reliable_read_partial() {
        let mut cursor = io::Cursor::new(b"");
        let mut buf = [0u8; 0];
        assert_eq!(buf.len(), 0);
        assert_eq!(reliable_read_partial(&mut cursor, &mut buf).unwrap(), 0);

        let mut cursor = io::Cursor::new(b"");
        let mut buf = [0u8; 7];
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[4] = 4;
        buf[6] = 5;
        assert_eq!(reliable_read_partial(&mut cursor, &mut buf).unwrap(), 0);
        assert_eq!(buf, [1, 2, 3, 0, 4, 0, 5]);

        let mut cursor = io::Cursor::new(b"a");
        let mut buf = [0u8; 7];
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[4] = 4;
        buf[6] = 5;
        assert_eq!(reliable_read_partial(&mut cursor, &mut buf).unwrap(), 1);
        assert_eq!(buf, [b'a', 2, 3, 0, 4, 0, 5]);

        let mut cursor = io::Cursor::new(b"elixir");
        let mut buf = [0u8; 7];
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;
        buf[4] = 4;
        buf[6] = 5;
        assert_eq!(reliable_read_partial(&mut cursor, &mut buf).unwrap(), 6);
        assert_eq!(buf, [b'e', b'l', b'i', b'x', b'i', b'r', 5]);

        let mut reader = BrokenReader {};
        let mut buf = *b"hello";
        let res = reliable_read_partial(&mut reader, &mut buf);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(buf, [0u8, 0u8, 0u8, 0u8, 0u8]);
    }


    #[test]
    fn test_single_byte_buffered_reader() {
        let mut cursor = io::Cursor::new("abc");
        let mut reader = SingleByteBufferedReaderImpl::new(&mut cursor);
        let mut buf = [0u8; 2];
        reader.read_bytes(&mut buf).unwrap();
        assert_eq!(buf, [b'a', b'b']);
        reader.unread_byte(b'z');
        reader.read_bytes(&mut buf).unwrap();
        assert_eq!(buf, [b'z', b'c']);

        let mut buf = [0u8; 0];
        assert!(reader.read_bytes(&mut buf).is_ok());

        assert_eq!(reader.read_byte().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}

