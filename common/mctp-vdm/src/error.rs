// Licensed under the Apache-2.0 license

/// Errors that can occur during VDM message processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdmError {
    /// The provided buffer is too short for the operation.
    BufferTooShort,
    /// The message type is not supported.
    UnsupportedMessageType,
    /// The command is not supported.
    UnsupportedCommand,
    /// Invalid message header.
    InvalidHeader,
    /// Invalid vendor ID.
    InvalidVendorId,
    /// Invalid data in the message.
    InvalidData,
    /// Invalid completion code.
    InvalidCompletionCode,
}

/// Errors from utility functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtilError {
    /// Invalid MCTP payload length.
    InvalidMctpPayloadLength,
    /// Invalid MCTP message type.
    InvalidMctpMsgType,
}
