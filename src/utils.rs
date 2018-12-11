use crc32fast;
use std::fmt;
use std::io::{self, Write};
use std::ops::Deref;

/// A blob of raw bytes.
///
/// This has a convenient `Debug` impl that won't output all data if the blob is
/// large. It also uses hexadecimal output.
#[derive(Copy, Clone)]
pub struct Blob<T>(pub T)
where
    T: AsRef<[u8]>;

impl<T> Blob<T>
where
    T: AsRef<[u8]>,
{
    const MAX_DEBUG_LEN: usize = 32;
}

impl<T> Deref for Blob<T>
where
    T: AsRef<[u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> AsRef<[u8]> for Blob<T>
where
    T: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> fmt::Debug for Blob<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut data = self.0.as_ref();
        let len = data.len();
        let mut abbr = false;
        if len > Self::MAX_DEBUG_LEN {
            data = &data[..Self::MAX_DEBUG_LEN];
            abbr = true;
        }

        write!(fmt, "({} bytes) [", len)?;
        for (i, byte) in data.iter().enumerate() {
            if i != 0 {
                fmt.write_str(", ")?;
            }
            write!(fmt, "{:02X}", byte)?;
        }

        if abbr {
            fmt.write_str(", ...")?;
        }

        fmt.write_str("]")
    }
}

impl<T> From<T> for Blob<T>
where
    T: AsRef<[u8]>,
{
    fn from(t: T) -> Self {
        Blob(t)
    }
}

/// Wraps an `io::Write` implementor and calculates the CRC32 of the written
/// data on the fly.
pub struct Crc32Writer<W: Write> {
    pub digest: crc32fast::Hasher,
    pub inner: W,
}

impl<W: Write> Crc32Writer<W> {
    /// Creates a new `Crc32Writer` forwarding data to `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            digest: crc32fast::Hasher::new(),
            inner: writer,
        }
    }
}

impl<W: Write> Write for Crc32Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.inner.write(buf)?;
        let written = &buf[..bytes];
        self.digest.update(written);
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
