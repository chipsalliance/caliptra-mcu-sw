// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_mbox_common::messages::CommandId;
use zerocopy::{Immutable, IntoBytes};

pub use caliptra_api::mailbox::MAX_ATTESTED_CSR_RESP_DATA_SIZE as MAX_ATTESTED_CSR_DATA_LEN;
pub const MAX_FW_VERSION_LEN: usize = 32;
pub const MAX_UID_LEN: usize = 32;

/// Size of the unique device identifier in bytes.
pub const DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE: usize = 32;
/// Size of the debug unlock challenge in bytes.
pub const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;

/// Caliptra command completion codes.
/// Standard codes (0x00-0x0F) follow the OCP command registry:
/// https://github.com/opencomputeproject/ocp-registry/blob/main/command-registry.md
/// Codes 0xC0-0xFF: Reserved for Caliptra project-specific error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaliptraCompletionCode {
    // OCP standard codes (0x00-0x0F)
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

    // Caliptra project-specific codes (0xC0-0xFF)
    CaliptraMailboxBusy = 0xC0,
    CaliptraBufferTooSmall = 0xC1,
}

/// Result type for Caliptra command handlers.
pub type CaliptraCmdResult<T> = Result<T, CaliptraCompletionCode>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCsrData {
    pub len: usize,
    pub data: [u8; MAX_ATTESTED_CSR_DATA_LEN],
}

impl Default for AttestedCsrData {
    fn default() -> Self {
        Self {
            len: 0,
            data: [0u8; MAX_ATTESTED_CSR_DATA_LEN],
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub len: usize,
    pub ver_str: [u8; MAX_FW_VERSION_LEN],
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Uid {
    pub len: usize,
    pub unique_chip_id: [u8; MAX_UID_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceInfo {
    Uid(Uid),
}

/// Log type identifiers used by `get_log` / `clear_log`.
///
/// These values are wire-stable (carried in the MCU mailbox `log_type` field
/// and implied by Caliptra/MCTP VDM command codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LogType {
    /// MCU debug log (Tock logging-flash capsule).
    Debug = 0,
    /// Caliptra attestation log (sourced from Caliptra core).
    Attestation = 1,
}

impl TryFrom<u32> for LogType {
    type Error = CaliptraCompletionCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LogType::Debug),
            1 => Ok(LogType::Attestation),
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }
}

/// Result of a single `get_log` invocation.
///
/// Read-side cursor is owned by the implementor. Callers drain the log by
/// repeating `get_log` until `more_data == false`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GetLogResult {
    /// Number of valid bytes written into the caller-supplied buffer.
    pub bytes_written: usize,
    /// `true` if at least one further entry remains that did not fit in the
    /// caller's buffer; `false` if the log was fully drained by this call.
    pub more_data: bool,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, Immutable, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub caliptra_rt: [u8; 8],  // Bytes [0:7]
    pub caliptra_fmc: [u8; 4], // Bytes [8:11]
    pub caliptra_rom: [u8; 4], // Bytes [12:15]
    pub mcu_rt: [u8; 8],       // Bytes [16:23]
    pub mcu_rom: [u8; 4],      // Bytes [24:27]
    pub reserved: [u8; 4],     // Bytes [28:31]
}

/// Debug unlock challenge response returned by `request_debug_unlock`.
#[derive(Debug, Clone)]
pub struct DebugUnlockChallenge {
    pub unique_device_identifier: [u8; DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
}

impl Default for DebugUnlockChallenge {
    fn default() -> Self {
        Self {
            unique_device_identifier: [0u8; DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_SIZE],
        }
    }
}

/// Asynchronous trait for handling Caliptra common commands across all transport protocols.
///
/// Each function represents a transport-agnostic command handler. Implementors should provide
/// the specific logic for each command as required by their application.
#[async_trait]
pub trait CaliptraCmdHandler: Send + Sync {
    /// Retrieves the firmware version for the given index.
    ///
    /// # Arguments
    /// * `index` - The firmware index to query.
    /// * `version` - Mutable reference to store the firmware version.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()>;

    /// Retrieves the device ID.
    ///
    /// # Arguments
    /// * `device_id` - Mutable reference to store the device ID.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_device_id(&self, device_id: &mut DeviceId) -> CaliptraCmdResult<()>;

    /// Retrieves device information for the given index.
    ///
    /// # Arguments
    /// * `index` - The device info index to query.
    /// * `info` - Mutable reference to store the device info.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> CaliptraCmdResult<()>;

    /// Retrieves the device capabilities.
    ///
    /// # Arguments
    /// * `capabilities` - Mutable reference to store the device capabilities.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()>;

    /// Exports an attested CSR for the specified device key.
    ///
    /// # Arguments
    /// * `device_key_id` - The device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias).
    /// * `algorithm` - The asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87).
    /// * `nonce` - A 32-byte nonce provided by the requester for freshness.
    /// * `csr_buf` - Mutable buffer to write the CSR DER data into directly.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<usize>` - Number of bytes written on success, or an error.
    async fn export_attested_csr(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize>;

    /// Exports an IDevID CSR (manufacturing mode only).
    ///
    /// # Arguments
    /// * `algorithm` - The asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87).
    /// * `csr_buf` - Mutable buffer to write the CSR DER data into directly.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<usize>` - Number of bytes written on success, or an error.
    async fn export_idevid_csr(
        &self,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize>;

    /// Requests a production debug unlock challenge.
    ///
    /// # Arguments
    /// * `unlock_level` - The debug unlock level requested (1-8).
    /// * `challenge` - Mutable reference to store the challenge response.
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn request_debug_unlock(
        &self,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()>;

    /// Submits a signed debug unlock token.
    ///
    /// The token payload is streamed in chunks via the chunked mailbox API
    /// because it can be very large (~7.5KB due to MLDSA keys/signatures).
    ///
    /// # Arguments
    /// * `token_data` - The complete token payload bytes (excluding checksum header).
    ///
    /// # Returns
    /// * `CaliptraCmdResult<()>` - Ok on success, or an error.
    async fn authorize_debug_unlock_token(&self, token_data: &[u8]) -> CaliptraCmdResult<()>;

    /// Drain log entries of `log_type` into `data`.
    ///
    /// Reads as many complete log entries as fit into `data`. Entries are not
    /// split: if the next entry does not fit in the remaining buffer, it is
    /// left in place for the caller's next invocation and the returned
    /// `more_data` flag is set to `true`.
    ///
    /// Implementors own the read-side cursor; `clear_log` resets it.
    ///
    /// # Arguments
    /// * `log_type` - Log identifier; see [`LogType`].
    /// * `data` - Destination buffer for serialized log entries.
    ///
    /// # Returns
    /// * `Ok(GetLogResult)` on success.
    /// * `Err(CaliptraCompletionCode::InvalidParameter)` for unknown `log_type`.
    /// * `Err(CaliptraCompletionCode::UnsupportedOperation)` if the implementor
    ///   does not provide this log on the current platform.
    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
        let _ = (log_type, data);
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Clear (erase) the log of `log_type` and reset the read cursor.
    ///
    /// # Arguments
    /// * `log_type` - Log identifier; see [`LogType`].
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CaliptraCompletionCode::InvalidParameter)` for unknown `log_type`.
    /// * `Err(CaliptraCompletionCode::UnsupportedOperation)` if the implementor
    ///   does not provide this log on the current platform.
    async fn clear_log(&self, log_type: u32) -> CaliptraCmdResult<()> {
        let _ = log_type;
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }
}

pub struct AuthorizationError;

pub type AuthorizationResult<T> = Result<T, AuthorizationError>;

#[async_trait(?Send)]
pub trait CommandAuthorizer {
    /// Validates if a message is authorized.
    ///
    /// The request can contain authorization data (e.g. a HMAC).
    /// This method is responsible for unpacking the contained
    /// request message and returning it as a slice.
    ///
    /// # Arguments
    /// * `cmd_id` - Command identifier
    /// * `req` - Message to be authorized
    ///
    /// # Returns
    /// * `Result<&[u8], CommandError>` - Unpacked command or Error
    async fn is_authorized<'a>(
        &mut self,
        cmd_id: CommandId,
        req: &'a [u8],
    ) -> Result<&'a [u8], AuthorizationError>;

    /// Get the challenge from the last call to `MC_GET_AUTH_CMD_CHALLENGE`.
    ///
    /// This consumes the challenge so it can only be used once.
    fn take_challenge(&mut self) -> Option<[u8; 32]>;

    /// Set the challenge nonce to be used on the next authorized command.
    fn set_challenge(&mut self, challenge: [u8; 32]);
}
