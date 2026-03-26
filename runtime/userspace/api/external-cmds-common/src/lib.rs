// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use zerocopy::{Immutable, IntoBytes};

pub const MAX_FW_VERSION_LEN: usize = 32;
pub const MAX_UID_LEN: usize = 32;
// TODO: Replace with imported constant from Caliptra core crate when available.
pub const MAX_ATTESTED_CSR_DATA_LEN: usize = 12800;

// Request Debug Unlock / Authorize Debug Unlock Token (external_mctp_vdm_cmds.md)
pub const DEBUG_UNLOCK_LEVEL_MIN: u8 = 1;
pub const DEBUG_UNLOCK_LEVEL_MAX: u8 = 8;
pub const UNIQUE_DEVICE_ID_LEN: usize = 32;
pub const DEBUG_UNLOCK_CHALLENGE_LEN: usize = 48;
pub const DEBUG_UNLOCK_ECC_PUBLIC_KEY_DWORDS: usize = 24;
pub const DEBUG_UNLOCK_MLDSA_PUBLIC_KEY_DWORDS: usize = 648;
pub const DEBUG_UNLOCK_ECC_SIGNATURE_DWORDS: usize = 24;
pub const DEBUG_UNLOCK_MLDSA_SIGNATURE_DWORDS: usize = 1157;

/// Common error type for unified commands.
#[derive(Debug)]
pub enum CommandError {
    InvalidParams,
    RespLengthTooLarge,
    InternalError,
    NotSupported,
    Busy,
}

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

/// Request payload for Request Debug Unlock (command 0x0A).
/// Byte layout: length (u32), unlock_level (u8), reserved (u8[3]).
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RequestDebugUnlockReq {
    pub length_dwords: u32,
    pub unlock_level: u8,
    pub reserved: [u8; 3],
}

/// Response payload for Request Debug Unlock (command 0x0A).
/// Byte layout: completion_code (u32), length (u32), unique_device_identifier (u8[32]), challenge (u8[48]).
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestDebugUnlockResp {
    pub completion_code: u32,
    pub length_dwords: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_LEN],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_LEN],
}

impl Default for RequestDebugUnlockResp {
    fn default() -> Self {
        Self {
            completion_code: 0,
            length_dwords: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_LEN],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_LEN],
        }
    }
}

/// Request payload for Authorize Debug Unlock Token (command 0x0B).
/// Layout per external_mctp_vdm_cmds.md: length, unique_device_identifier, unlock_level, reserved,
/// challenge, ecc_public_key, mldsa_public_key, ecc_signature, mldsa_signature.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeDebugUnlockTokenReq {
    pub length_dwords: u32,
    pub unique_device_identifier: [u8; UNIQUE_DEVICE_ID_LEN],
    pub unlock_level: u8,
    pub reserved: [u8; 3],
    pub challenge: [u8; DEBUG_UNLOCK_CHALLENGE_LEN],
    pub ecc_public_key: [u32; DEBUG_UNLOCK_ECC_PUBLIC_KEY_DWORDS],
    pub mldsa_public_key: [u32; DEBUG_UNLOCK_MLDSA_PUBLIC_KEY_DWORDS],
    pub ecc_signature: [u32; DEBUG_UNLOCK_ECC_SIGNATURE_DWORDS],
    pub mldsa_signature: [u32; DEBUG_UNLOCK_MLDSA_SIGNATURE_DWORDS],
}

impl Default for AuthorizeDebugUnlockTokenReq {
    fn default() -> Self {
        Self {
            length_dwords: 0,
            unique_device_identifier: [0u8; UNIQUE_DEVICE_ID_LEN],
            unlock_level: 0,
            reserved: [0; 3],
            challenge: [0u8; DEBUG_UNLOCK_CHALLENGE_LEN],
            ecc_public_key: [0u32; DEBUG_UNLOCK_ECC_PUBLIC_KEY_DWORDS],
            mldsa_public_key: [0u32; DEBUG_UNLOCK_MLDSA_PUBLIC_KEY_DWORDS],
            ecc_signature: [0u32; DEBUG_UNLOCK_ECC_SIGNATURE_DWORDS],
            mldsa_signature: [0u32; DEBUG_UNLOCK_MLDSA_SIGNATURE_DWORDS],
        }
    }
}

/// Response payload for Authorize Debug Unlock Token (command 0x0B).
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuthorizeDebugUnlockTokenResp {
    pub completion_code: u32,
}

/// Asynchronous trait for handling commands common to both external MCU mailbox and MCTP VDM protocols.
///
/// Each function represents a protocol-agnostic command handler. Implementors should provide
/// the specific logic for each command as required by their application.
#[async_trait]
pub trait UnifiedCommandHandler {
    /// Retrieves the firmware version for the given index.
    ///
    /// # Arguments
    /// * `index` - The firmware index to query.
    /// * `version` - Mutable reference to store the firmware version.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> Result<(), CommandError>;

    /// Retrieves the device ID.
    ///
    /// # Arguments
    /// * `device_id` - Mutable reference to store the device ID.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_id(&self, device_id: &mut DeviceId) -> Result<(), CommandError>;

    /// Retrieves device information for the given index.
    ///
    /// # Arguments
    /// * `index` - The device info index to query.
    /// * `info` - Mutable reference to store the device info.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> Result<(), CommandError>;

    /// Retrieves the device capabilities.
    ///
    /// # Arguments
    /// * `capabilities` - Mutable reference to store the device capabilities.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> Result<(), CommandError>;

    /// Exports an attested CSR for the specified device key.
    ///
    /// # Arguments
    /// * `device_key_id` - The device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias).
    /// * `algorithm` - The asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87).
    /// * `csr_data` - Mutable reference to store the attested CSR data.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn export_attested_csr(
        &self,
        device_key_id: u32,
        algorithm: u32,
        csr_data: &mut AttestedCsrData,
    ) -> Result<(), CommandError>;

    /// Request debug unlock in production (command 0x0A).
    /// Returns challenge and device identifier for the host to sign.
    ///
    /// # Arguments
    /// * `req` - Request payload (length in DWORDs, unlock_level 1–8).
    /// * `resp` - Mutable reference to fill with completion_code, length, unique_device_identifier, challenge.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn request_debug_unlock(
        &self,
        req: &RequestDebugUnlockReq,
        resp: &mut RequestDebugUnlockResp,
    ) -> Result<(), CommandError>;

    /// Authorize debug unlock token (command 0x0B).
    /// Sends the signed token (ECC + MLDSA) for the device to verify.
    ///
    /// # Arguments
    /// * `req` - Request payload (identifier, level, challenge, keys, signatures).
    /// * `resp` - Mutable reference to fill with completion_code.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn authorize_debug_unlock_token(
        &self,
        req: &AuthorizeDebugUnlockTokenReq,
        resp: &mut AuthorizeDebugUnlockTokenResp,
    ) -> Result<(), CommandError>;
}
