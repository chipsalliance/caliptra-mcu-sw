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
