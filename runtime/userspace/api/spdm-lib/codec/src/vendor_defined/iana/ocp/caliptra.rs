// Licensed under the Apache-2.0 license

//! Caliptra VDM protocol definitions: vendor id, command codes, completion
//! codes, and the dispatch result type.
//!
//! This is the protocol layer — pure wire definitions with no platform
//! dependencies — kept in the lib and shared by every command handler.

/// IANA-assigned vendor id for the OCP / Caliptra Working Group (0xA67F).
pub const CALIPTRA_VENDOR_ID: u32 = 42623;

/// Caliptra VDM command version — the first byte of every Caliptra VDM message.
pub const CALIPTRA_VDM_COMMAND_VERSION: u8 = 0x01;

/// Caliptra VDM command codes, as defined in the OCP command registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraVdmCommand {
    GetDebugLog = 0x05,
    ClearDebugLog = 0x06,
    GetAttestationLog = 0x07,
    ClearAttestationLog = 0x08,
    GetAttestation = 0x09,
    RequestDebugUnlock = 0x0A,
    AuthorizeDebugUnlockToken = 0x0B,
    SetSlot0Cert = 0x0D,
    GetSlot0State = 0x0E,
    ExportAttestedCsr = 0x0F,
    DeviceOwnershipTransfer = 0x11,
    /// Single entry point for authorization-related sub-commands.
    AuthorizedCommand = 0x12,
}

impl TryFrom<u8> for CaliptraVdmCommand {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x05 => Self::GetDebugLog,
            0x06 => Self::ClearDebugLog,
            0x07 => Self::GetAttestationLog,
            0x08 => Self::ClearAttestationLog,
            0x09 => Self::GetAttestation,
            0x0A => Self::RequestDebugUnlock,
            0x0B => Self::AuthorizeDebugUnlockToken,
            0x0D => Self::SetSlot0Cert,
            0x0E => Self::GetSlot0State,
            0x0F => Self::ExportAttestedCsr,
            0x11 => Self::DeviceOwnershipTransfer,
            0x12 => Self::AuthorizedCommand,
            _ => return Err(()),
        })
    }
}

impl CaliptraVdmCommand {
    /// The Caliptra VDM response command code equals the request command code.
    pub fn response_code(self) -> u8 {
        self as u8
    }
}

/// Caliptra VDM command completion codes (OCP command registry).
///
/// Standard codes (0x00–0x0F) follow the OCP registry; codes 0xC0–0xFF are
/// reserved for Caliptra project-specific errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraCompletionCode {
    Success = 0x00,
    GeneralError = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidIdentifier = 0x04,
    OperationFailed = 0x05,
    InsufficientResources = 0x06,
    UnsupportedOperation = 0x07,
    DeviceNotReady = 0x08,
    InvalidCommandVersion = 0x09,
    InvalidPayloadSize = 0x0A,
    Timeout = 0x0B,
    AccessDenied = 0x0C,
    ResourceUnavailable = 0x0D,
    PolicyViolation = 0x0E,
    InvalidState = 0x0F,

    // Caliptra project-specific codes (0xC0–0xFF).
    CaliptraMailboxBusy = 0xC0,
    CaliptraBufferTooSmall = 0xC1,
}

/// Device-operation result: bytes written on success, or a completion code on failure.
pub type CaliptraVdmResult<T> = Result<T, CaliptraCompletionCode>;

/// Outcome of dispatching a single Caliptra VDM command.
pub enum CaliptraVdmCmdResult {
    /// Wrote `usize` payload bytes (completion code + command data) after the
    /// 2-byte VDM header, in the inline buffer.
    Response(usize),
    /// Wrote `usize` bytes of the complete VDM payload (header + completion +
    /// data) into the large staging buffer; sent as a chunked large response.
    Large(usize),
    /// The command failed; frame this completion code with no command data.
    Error(CaliptraCompletionCode),
}
