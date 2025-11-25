// Licensed under the Apache-2.0 license

//! IO abstraction for sync and async operations

use crate::error::{OsalError, OsalResult};

/// Synchronous reader trait
pub trait Reader {
    fn read(&mut self, buf: &mut [u8]) -> OsalResult<usize>;

    fn read_exact(&mut self, mut buf: &mut [u8]) -> OsalResult<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => return Err(OsalError::Io(crate::error::IoErrorKind::UnexpectedEof)),
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Synchronous writer trait
pub trait Writer {
    fn write(&mut self, buf: &[u8]) -> OsalResult<usize>;

    fn write_all(&mut self, mut buf: &[u8]) -> OsalResult<()> {
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => return Err(OsalError::Io(crate::error::IoErrorKind::WriteZero)),
                Ok(n) => buf = &buf[n..],
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> OsalResult<()> {
        Ok(())
    }
}

/// Asynchronous reader trait (for future async support)
pub trait AsyncReader {
    type ReadFuture<'a>: core::future::Future<Output = OsalResult<usize>> + 'a
    where
        Self: 'a;

    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Self::ReadFuture<'a>;
}

/// Asynchronous writer trait (for future async support)
pub trait AsyncWriter {
    type WriteFuture<'a>: core::future::Future<Output = OsalResult<usize>> + 'a
    where
        Self: 'a;

    type FlushFuture<'a>: core::future::Future<Output = OsalResult<()>> + 'a
    where
        Self: 'a;

    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteFuture<'a>;
    fn flush(&mut self) -> Self::FlushFuture<'_>;
}

/// Buffer-based reader/writer
pub struct BufferIo {
    buffer: crate::memory::Buffer,
    read_pos: usize,
    write_pos: usize,
}

impl BufferIo {
    pub fn new(capacity: usize) -> OsalResult<Self> {
        Ok(Self {
            buffer: crate::memory::Buffer::new(capacity)?,
            read_pos: 0,
            write_pos: 0,
        })
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.read_pos = 0;
        self.write_pos = 0;
    }

    pub fn available(&self) -> usize {
        self.write_pos - self.read_pos
    }

    pub fn space_available(&self) -> usize {
        self.buffer.capacity() - self.write_pos
    }
}

impl Reader for BufferIo {
    fn read(&mut self, buf: &mut [u8]) -> OsalResult<usize> {
        let available = self.available();
        if available == 0 {
            return Ok(0);
        }

        let to_read = core::cmp::min(buf.len(), available);
        let buffer_slice = self.buffer.as_slice();

        buf[..to_read].copy_from_slice(&buffer_slice[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;

        Ok(to_read)
    }
}

impl Writer for BufferIo {
    fn write(&mut self, buf: &[u8]) -> OsalResult<usize> {
        let space = self.space_available();
        if space == 0 {
            return Err(OsalError::Io(crate::error::IoErrorKind::WriteZero));
        }

        let to_write = core::cmp::min(buf.len(), space);

        // Extend buffer if needed
        if self.write_pos + to_write > self.buffer.len() {
            self.buffer.set_len(self.write_pos + to_write)?;
        }

        let buffer_slice = self.buffer.as_mut_slice();
        buffer_slice[self.write_pos..self.write_pos + to_write].copy_from_slice(&buf[..to_write]);
        self.write_pos += to_write;

        Ok(to_write)
    }
}

#[cfg(feature = "std")]
impl<T: std::io::Read> Reader for T {
    fn read(&mut self, buf: &mut [u8]) -> OsalResult<usize> {
        std::io::Read::read(self, buf).map_err(OsalError::from)
    }
}

#[cfg(feature = "std")]
impl<T: std::io::Write> Writer for T {
    fn write(&mut self, buf: &[u8]) -> OsalResult<usize> {
        std::io::Write::write(self, buf).map_err(OsalError::from)
    }

    fn flush(&mut self) -> OsalResult<()> {
        std::io::Write::flush(self).map_err(OsalError::from)
    }
}
