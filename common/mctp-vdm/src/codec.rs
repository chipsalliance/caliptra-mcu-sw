// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Errors that can occur during VDM codec operations.
#[derive(Debug, PartialEq)]
pub enum VdmCodecError {
    /// The provided buffer is too short for the operation.
    BufferTooShort,
    /// The operation is not supported.
    Unsupported,
}

/// A trait for encoding and decoding MCTP VDM (Vendor Defined Message) messages.
///
/// This trait provides methods for encoding a VDM message into a byte buffer
/// and decoding a VDM message from a byte buffer. Implementers of this trait
/// must also implement the `Debug` trait and be `Sized`.
pub trait VdmCodec: core::fmt::Debug + Sized {
    /// Encodes the VDM message into the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a byte slice where the encoded message will be stored.
    ///
    /// # Returns
    ///
    /// A `Result` containing the size of the encoded message on success, or a `VdmCodecError` on failure.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError>;

    /// Decodes a VDM message from the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A reference to a byte slice containing the encoded message.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded message on success, or a `VdmCodecError` on failure.
    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError>;
}

/// Default implementation of VdmCodec for types that can leverage zerocopy.
impl<T> VdmCodec for T
where
    T: core::fmt::Debug + Sized + FromBytes + IntoBytes + Immutable,
{
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, VdmCodecError> {
        self.write_to_prefix(buffer)
            .map_err(|_| VdmCodecError::BufferTooShort)
            .map(|_| core::mem::size_of::<T>())
    }

    fn decode(buffer: &[u8]) -> Result<Self, VdmCodecError> {
        Ok(Self::read_from_prefix(buffer)
            .map_err(|_| VdmCodecError::BufferTooShort)?
            .0)
    }
}
