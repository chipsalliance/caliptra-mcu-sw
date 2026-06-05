// Licensed under the Apache-2.0 license

//! Cursor-style sync wire I/O over zerocopy types.
//!
//! Every wire field in spdm-lite is modelled as a `#[repr(C)]`
//! [`zerocopy::Unaligned`] struct, so the only cursor operations a
//! handler needs are:
//!
//! - "write this whole struct at the current position"
//! - "read a reference to a struct of this type at the current
//!   position"
//! - "advance / retrieve raw bytes" for opaque blobs (cert chain,
//!   nonce, …).
//!
//! Errors are a single ZST so `Result<T, WireError>` shares the same
//! niche as `McuResult<T>` after enum-niche optimisation.

use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WireError;

/// Borrow-only writer over a caller-owned `&mut [u8]`.
pub struct WireWriter<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> WireWriter<'b> {
    #[inline]
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Reserve `n` bytes for in-place population (length-prefixed
    /// payloads or crypto output buffers).
    #[inline]
    pub fn reserve(&mut self, n: usize) -> Result<&mut [u8], WireError> {
        let start = self.pos;
        let end = start.checked_add(n).ok_or(WireError)?;
        let slice = self.buf.get_mut(start..end).ok_or(WireError)?;
        self.pos = end;
        Ok(slice)
    }

    /// Write a whole zerocopy value at the current position.
    #[inline]
    pub fn write<T: IntoBytes + Immutable + ?Sized>(&mut self, v: &T) -> Result<(), WireError> {
        let bytes = v.as_bytes();
        let dst = self.reserve(bytes.len())?;
        for (d, s) in dst.iter_mut().zip(bytes) {
            *d = *s;
        }
        Ok(())
    }

    /// Write raw bytes (transcript material, opaque blobs, etc.).
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), WireError> {
        self.write(b)
    }

    /// Pad with `n` zero bytes (spec Reserved fields).
    pub fn pad_zero(&mut self, n: usize) -> Result<(), WireError> {
        let dst = self.reserve(n)?;
        dst.fill(0);
        Ok(())
    }

    /// Truncate the cursor back to a known length.
    #[inline]
    pub fn truncate(&mut self, len: usize) {
        debug_assert!(len <= self.pos);
        self.pos = len;
    }

    /// Consume the writer and return the populated prefix.
    #[inline]
    pub fn into_bytes(self) -> &'b [u8] {
        &self.buf[..self.pos]
    }

    /// Consume the writer and return the populated prefix mutably.
    #[inline]
    pub fn into_bytes_mut(self) -> &'b mut [u8] {
        &mut self.buf[..self.pos]
    }
}

/// Borrow-only reader over a caller-owned `&[u8]`.
pub struct WireReader<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> WireReader<'b> {
    #[inline]
    pub fn new(buf: &'b [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrow a `T` at the current position and advance the cursor by
    /// `size_of::<T>()`.
    pub fn read<T>(&mut self) -> Result<&'b T, WireError>
    where
        T: FromBytes + KnownLayout + Unaligned + Immutable,
    {
        let n = size_of::<T>();
        let bytes = self.take(n)?;
        T::ref_from_bytes(bytes).map_err(|_| WireError)
    }

    /// Take `n` raw bytes (opaque blobs, signatures, transcript
    /// material).
    pub fn take(&mut self, n: usize) -> Result<&'b [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError);
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..self.pos])
    }

    /// Skip `n` bytes; bounds-checked.
    pub fn skip(&mut self, n: usize) -> Result<(), WireError> {
        let _ = self.take(n)?;
        Ok(())
    }

    /// Returns the unread tail of the buffer without consuming it.
    #[inline]
    pub fn rest(&self) -> &'b [u8] {
        &self.buf[self.pos..]
    }
}
