// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, PartialEq)]
pub enum CodecError {
    BufferTooShort,
    Unsupported,
}

/// A trait for encoding and decoding MCU mailbox messages.
///
/// This trait provides methods for encoding a MCU mailbox message into a byte buffer
/// and decoding a MCU mailbox message from a byte buffer. Implementers of this trait
/// must also implement the `Debug` trait and be `Sized`.
pub trait Codec: core::fmt::Debug + Sized {
    /// Encodes the MCU mailbox message into the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a byte slice where the encoded message will be stored.
    ///
    /// # Returns
    ///
    /// A `Result` containing the size of the encoded message on success, or a `CodecError` on failure.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, CodecError>;

    /// Decodes a MCU mailbox message from the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A reference to a byte slice containing the encoded message.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded message on success, or a `CodecError` on failure.
    fn decode(buffer: &[u8]) -> Result<Self, CodecError>;
}

// Default implementation of Codec for types that can leverage zerocopy.
impl<T> Codec for T
where
    T: core::fmt::Debug + Sized + FromBytes + IntoBytes + Immutable,
{
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, CodecError> {
        self.write_to_prefix(buffer)
            .map_err(|_| CodecError::BufferTooShort)
            .map(|_| core::mem::size_of::<T>())
    }

    fn decode(buffer: &[u8]) -> Result<Self, CodecError> {
        Ok(Self::read_from_prefix(buffer)
            .map_err(|_| CodecError::BufferTooShort)?
            .0)
    }
}
