// Licensed under the Apache-2.0 license

#[derive(Debug)]
pub enum PldmCodecError {
    BufferTooShort,
    Unsupported,
}

/// A trait for encoding and decoding PLDM (Platform Level Data Model) messages.
///
/// This trait provides methods for encoding a PLDM message into a byte buffer
/// and decoding a PLDM message from a byte buffer. Implementers of this trait
/// must also implement the `Debug` trait and be `Sized`.
pub trait PldmCodec: core::fmt::Debug + Sized {
    /// Encodes the PLDM message into the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a byte slice where the encoded message will be stored.
    ///
    /// # Returns
    ///
    /// A `Result` containing the size of the encoded message on success, or a `PldmCodecError` on failure.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, PldmCodecError>;

    /// Decodes a PLDM message from the provided byte buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A reference to a byte slice containing the encoded message.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decoded message on success, or a `PldmCodecError` on failure.
    fn decode(buffer: &[u8]) -> Result<Self, PldmCodecError>;
}
