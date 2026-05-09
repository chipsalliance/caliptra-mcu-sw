// Licensed under the Apache-2.0 license

//! AES commands for mailbox transport
//!
//! This module provides command definitions and implementations for AES
//! encrypt/decrypt commands using the mailbox transport protocol.
//!
//! External mailbox command codes:
//! - MC_AES_ENCRYPT_INIT     = 0x4D43_4349 ("MCCI")
//! - MC_AES_ENCRYPT_UPDATE   = 0x4D43_4355 ("MCCU")
//! - MC_AES_DECRYPT_INIT     = 0x4D43_414A ("MCAJ")
//! - MC_AES_DECRYPT_UPDATE   = 0x4D43_4155 ("MCAU")
//! - MC_AES_GCM_ENCRYPT_INIT = 0x4D43_4749 ("MCGI")
//! - MC_AES_GCM_ENCRYPT_UPDATE = 0x4D43_4755 ("MCGU")
//! - MC_AES_GCM_ENCRYPT_FINAL  = 0x4D43_4746 ("MCGF")
//! - MC_AES_GCM_DECRYPT_INIT = 0x4D43_4449 ("MCDI")
//! - MC_AES_GCM_DECRYPT_UPDATE = 0x4D43_4455 ("MCDU")
//! - MC_AES_GCM_DECRYPT_FINAL  = 0x4D43_4446 ("MCDF")

extern crate alloc;

use alloc::vec::Vec;

use super::checksum::calc_checksum;
use super::command_traits::*;
use caliptra_util_host_command_types::crypto_aes::{
    AesDecryptInitRequest, AesDecryptInitResponse, AesDecryptUpdateRequest,
    AesDecryptUpdateResponse, AesEncryptInitRequest, AesEncryptInitResponse,
    AesEncryptUpdateRequest, AesEncryptUpdateResponse, AesGcmDecryptFinalRequest,
    AesGcmDecryptFinalResponse, AesGcmDecryptInitRequest, AesGcmDecryptInitResponse,
    AesGcmDecryptUpdateRequest, AesGcmDecryptUpdateResponse, AesGcmEncryptFinalRequest,
    AesGcmEncryptFinalResponse, AesGcmEncryptInitRequest, AesGcmEncryptInitResponse,
    AesGcmEncryptUpdateRequest, AesGcmEncryptUpdateResponse, AES_CONTEXT_SIZE,
    AES_GCM_CONTEXT_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_IV_SIZE, MAX_AES_DATA_SIZE,
    MAX_AES_GCM_OUTPUT_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::CMK_SIZE;
use caliptra_util_host_command_types::CommonResponse;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesEncryptInitRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
    pub mode: u32,
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesEncryptInitRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
            mode: 1, // CBC
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesEncryptInitResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub iv: [u8; AES_IV_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesEncryptInitResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            iv: [0u8; AES_IV_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesEncryptInitRequest> for ExtCmdAesEncryptInitRequest {
    fn from_internal(internal: &AesEncryptInitRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.mode.to_le_bytes());
        payload.extend_from_slice(&internal.plaintext_size.to_le_bytes());
        let len = core::cmp::min(internal.plaintext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.plaintext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
            mode: internal.mode,
            plaintext_size: internal.plaintext_size,
            plaintext: internal.plaintext,
        }
    }
}

impl ToInternalResponse<AesEncryptInitResponse> for ExtCmdAesEncryptInitResponse {
    fn to_internal(&self) -> AesEncryptInitResponse {
        AesEncryptInitResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            iv: self.iv,
            ciphertext_size: self.ciphertext_size,
            ciphertext: self.ciphertext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesEncryptInitRequest {}

impl VariableSizeBytes for ExtCmdAesEncryptInitResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(156) + iv(16) + ciphertext_size(4) = 184 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_CONTEXT_SIZE + AES_IV_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_CONTEXT_SIZE]);

        let iv_offset = 8 + AES_CONTEXT_SIZE;
        let mut iv = [0u8; AES_IV_SIZE];
        iv.copy_from_slice(&bytes[iv_offset..iv_offset + AES_IV_SIZE]);

        let size_offset = iv_offset + AES_IV_SIZE;
        let ciphertext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let ct_len = core::cmp::min(ciphertext_size as usize, MAX_AES_DATA_SIZE);
        let ct_offset = size_offset + 4;
        if bytes.len() < ct_offset + ct_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut ciphertext = [0u8; MAX_AES_DATA_SIZE];
        ciphertext[..ct_len].copy_from_slice(&bytes[ct_offset..ct_offset + ct_len]);

        Ok(ExtCmdAesEncryptInitResponse {
            chksum,
            fips_status,
            context,
            iv,
            ciphertext_size,
            ciphertext,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesEncryptUpdateRequest {
    pub chksum: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesEncryptUpdateRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesEncryptUpdateResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesEncryptUpdateResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesEncryptUpdateRequest> for ExtCmdAesEncryptUpdateRequest {
    fn from_internal(internal: &AesEncryptUpdateRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.plaintext_size.to_le_bytes());
        let len = core::cmp::min(internal.plaintext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.plaintext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            plaintext_size: internal.plaintext_size,
            plaintext: internal.plaintext,
        }
    }
}

impl ToInternalResponse<AesEncryptUpdateResponse> for ExtCmdAesEncryptUpdateResponse {
    fn to_internal(&self) -> AesEncryptUpdateResponse {
        AesEncryptUpdateResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            ciphertext_size: self.ciphertext_size,
            ciphertext: self.ciphertext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesEncryptUpdateRequest {}

impl VariableSizeBytes for ExtCmdAesEncryptUpdateResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(156) + ciphertext_size(4) = 168 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_CONTEXT_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_CONTEXT_SIZE]);

        let size_offset = 8 + AES_CONTEXT_SIZE;
        let ciphertext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let ct_len = core::cmp::min(ciphertext_size as usize, MAX_AES_DATA_SIZE);
        let ct_offset = size_offset + 4;
        if bytes.len() < ct_offset + ct_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut ciphertext = [0u8; MAX_AES_DATA_SIZE];
        ciphertext[..ct_len].copy_from_slice(&bytes[ct_offset..ct_offset + ct_len]);

        Ok(ExtCmdAesEncryptUpdateResponse {
            chksum,
            fips_status,
            context,
            ciphertext_size,
            ciphertext,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesDecryptInitRequest {
    pub chksum: u32,
    pub cmk: [u8; CMK_SIZE],
    pub mode: u32,
    pub iv: [u8; AES_IV_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesDecryptInitRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            cmk: [0u8; CMK_SIZE],
            mode: 1, // CBC
            iv: [0u8; AES_IV_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesDecryptInitResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesDecryptInitResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesDecryptInitRequest> for ExtCmdAesDecryptInitRequest {
    fn from_internal(internal: &AesDecryptInitRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.mode.to_le_bytes());
        payload.extend_from_slice(&internal.iv);
        payload.extend_from_slice(&internal.ciphertext_size.to_le_bytes());
        let len = core::cmp::min(internal.ciphertext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.ciphertext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            cmk: internal.cmk.0,
            mode: internal.mode,
            iv: internal.iv,
            ciphertext_size: internal.ciphertext_size,
            ciphertext: internal.ciphertext,
        }
    }
}

impl ToInternalResponse<AesDecryptInitResponse> for ExtCmdAesDecryptInitResponse {
    fn to_internal(&self) -> AesDecryptInitResponse {
        AesDecryptInitResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            plaintext_size: self.plaintext_size,
            plaintext: self.plaintext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesDecryptInitRequest {}

impl VariableSizeBytes for ExtCmdAesDecryptInitResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(156) + plaintext_size(4) = 168 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_CONTEXT_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_CONTEXT_SIZE]);

        let size_offset = 8 + AES_CONTEXT_SIZE;
        let plaintext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let pt_len = core::cmp::min(plaintext_size as usize, MAX_AES_DATA_SIZE);
        let pt_offset = size_offset + 4;
        if bytes.len() < pt_offset + pt_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut plaintext = [0u8; MAX_AES_DATA_SIZE];
        plaintext[..pt_len].copy_from_slice(&bytes[pt_offset..pt_offset + pt_len]);

        Ok(ExtCmdAesDecryptInitResponse {
            chksum,
            fips_status,
            context,
            plaintext_size,
            plaintext,
        })
    }
}

// ============================================================================
// AES Decrypt Update Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesDecryptUpdateRequest {
    pub chksum: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesDecryptUpdateRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesDecryptUpdateResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesDecryptUpdateResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesDecryptUpdateRequest> for ExtCmdAesDecryptUpdateRequest {
    fn from_internal(internal: &AesDecryptUpdateRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.ciphertext_size.to_le_bytes());
        let len = core::cmp::min(internal.ciphertext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.ciphertext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            ciphertext_size: internal.ciphertext_size,
            ciphertext: internal.ciphertext,
        }
    }
}

impl ToInternalResponse<AesDecryptUpdateResponse> for ExtCmdAesDecryptUpdateResponse {
    fn to_internal(&self) -> AesDecryptUpdateResponse {
        AesDecryptUpdateResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            plaintext_size: self.plaintext_size,
            plaintext: self.plaintext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesDecryptUpdateRequest {}

impl VariableSizeBytes for ExtCmdAesDecryptUpdateResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(156) + plaintext_size(4) = 168 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_CONTEXT_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_CONTEXT_SIZE]);

        let size_offset = 8 + AES_CONTEXT_SIZE;
        let plaintext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let pt_len = core::cmp::min(plaintext_size as usize, MAX_AES_DATA_SIZE);
        let pt_offset = size_offset + 4;
        if bytes.len() < pt_offset + pt_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut plaintext = [0u8; MAX_AES_DATA_SIZE];
        plaintext[..pt_len].copy_from_slice(&bytes[pt_offset..pt_offset + pt_len]);

        Ok(ExtCmdAesDecryptUpdateResponse {
            chksum,
            fips_status,
            context,
            plaintext_size,
            plaintext,
        })
    }
}

// ============================================================================
// AES-GCM Encrypt Init Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptInitRequest {
    pub chksum: u32,
    pub flags: u32,
    pub cmk: [u8; CMK_SIZE],
    pub aad_size: u32,
    pub aad: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmEncryptInitRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            flags: 0,
            cmk: [0u8; CMK_SIZE],
            aad_size: 0,
            aad: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptInitResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
}

impl Default for ExtCmdAesGcmEncryptInitResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            iv: [0u8; AES_GCM_IV_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmEncryptInitRequest> for ExtCmdAesGcmEncryptInitRequest {
    fn from_internal(internal: &AesGcmEncryptInitRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.flags.to_le_bytes());
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.aad_size.to_le_bytes());
        let len = internal.aad_size as usize;
        payload.extend_from_slice(&internal.aad[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            flags: internal.flags,
            cmk: internal.cmk.0,
            aad_size: internal.aad_size,
            aad: internal.aad,
        }
    }
}

impl ToInternalResponse<AesGcmEncryptInitResponse> for ExtCmdAesGcmEncryptInitResponse {
    fn to_internal(&self) -> AesGcmEncryptInitResponse {
        AesGcmEncryptInitResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            iv: self.iv,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmEncryptInitRequest {}

impl VariableSizeBytes for ExtCmdAesGcmEncryptInitResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Fixed size: chksum(4) + fips_status(4) + context(128) + iv(12) = 148 bytes
        const EXPECTED_SIZE: usize = 4 + 4 + AES_GCM_CONTEXT_SIZE + AES_GCM_IV_SIZE;
        if bytes.len() < EXPECTED_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_GCM_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_GCM_CONTEXT_SIZE]);

        let iv_offset = 8 + AES_GCM_CONTEXT_SIZE;
        let mut iv = [0u8; AES_GCM_IV_SIZE];
        iv.copy_from_slice(&bytes[iv_offset..iv_offset + AES_GCM_IV_SIZE]);

        Ok(ExtCmdAesGcmEncryptInitResponse {
            chksum,
            fips_status,
            context,
            iv,
        })
    }
}

// ============================================================================
// AES-GCM Encrypt Update Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptUpdateRequest {
    pub chksum: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmEncryptUpdateRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptUpdateResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmEncryptUpdateResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmEncryptUpdateRequest> for ExtCmdAesGcmEncryptUpdateRequest {
    fn from_internal(internal: &AesGcmEncryptUpdateRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.plaintext_size.to_le_bytes());
        let len = core::cmp::min(internal.plaintext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.plaintext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            plaintext_size: internal.plaintext_size,
            plaintext: internal.plaintext,
        }
    }
}

impl ToInternalResponse<AesGcmEncryptUpdateResponse> for ExtCmdAesGcmEncryptUpdateResponse {
    fn to_internal(&self) -> AesGcmEncryptUpdateResponse {
        AesGcmEncryptUpdateResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            ciphertext_size: self.ciphertext_size,
            ciphertext: self.ciphertext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmEncryptUpdateRequest {}

impl VariableSizeBytes for ExtCmdAesGcmEncryptUpdateResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(128) + ciphertext_size(4) = 140 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_GCM_CONTEXT_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_GCM_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_GCM_CONTEXT_SIZE]);

        let size_offset = 8 + AES_GCM_CONTEXT_SIZE;
        let ciphertext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let ct_len = core::cmp::min(ciphertext_size as usize, MAX_AES_DATA_SIZE);
        let ct_offset = size_offset + 4;
        if bytes.len() < ct_offset + ct_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut ciphertext = [0u8; MAX_AES_DATA_SIZE];
        ciphertext[..ct_len].copy_from_slice(&bytes[ct_offset..ct_offset + ct_len]);

        Ok(ExtCmdAesGcmEncryptUpdateResponse {
            chksum,
            fips_status,
            context,
            ciphertext_size,
            ciphertext,
        })
    }
}

// ============================================================================
// AES-GCM Encrypt Final Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptFinalRequest {
    pub chksum: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmEncryptFinalRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmEncryptFinalResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_GCM_OUTPUT_SIZE],
}

impl Default for ExtCmdAesGcmEncryptFinalResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            tag: [0u8; AES_GCM_TAG_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmEncryptFinalRequest> for ExtCmdAesGcmEncryptFinalRequest {
    fn from_internal(internal: &AesGcmEncryptFinalRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.plaintext_size.to_le_bytes());
        let len = core::cmp::min(internal.plaintext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.plaintext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            plaintext_size: internal.plaintext_size,
            plaintext: internal.plaintext,
        }
    }
}

impl ToInternalResponse<AesGcmEncryptFinalResponse> for ExtCmdAesGcmEncryptFinalResponse {
    fn to_internal(&self) -> AesGcmEncryptFinalResponse {
        AesGcmEncryptFinalResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            tag: self.tag,
            ciphertext_size: self.ciphertext_size,
            ciphertext: self.ciphertext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmEncryptFinalRequest {}

impl VariableSizeBytes for ExtCmdAesGcmEncryptFinalResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + tag(16) + ciphertext_size(4) = 28 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_GCM_TAG_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        tag.copy_from_slice(&bytes[8..8 + AES_GCM_TAG_SIZE]);

        let size_offset = 8 + AES_GCM_TAG_SIZE;
        let ciphertext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let ct_len = core::cmp::min(ciphertext_size as usize, MAX_AES_GCM_OUTPUT_SIZE);
        let ct_offset = size_offset + 4;
        if bytes.len() < ct_offset + ct_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut ciphertext = [0u8; MAX_AES_GCM_OUTPUT_SIZE];
        ciphertext[..ct_len].copy_from_slice(&bytes[ct_offset..ct_offset + ct_len]);

        Ok(ExtCmdAesGcmEncryptFinalResponse {
            chksum,
            fips_status,
            tag,
            ciphertext_size,
            ciphertext,
        })
    }
}

// ============================================================================
// AES-GCM Decrypt Init Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptInitRequest {
    pub chksum: u32,
    pub flags: u32,
    pub cmk: [u8; CMK_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub aad_size: u32,
    pub aad: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmDecryptInitRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            flags: 0,
            cmk: [0u8; CMK_SIZE],
            iv: [0u8; AES_GCM_IV_SIZE],
            aad_size: 0,
            aad: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptInitResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
}

impl Default for ExtCmdAesGcmDecryptInitResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmDecryptInitRequest> for ExtCmdAesGcmDecryptInitRequest {
    fn from_internal(internal: &AesGcmDecryptInitRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.flags.to_le_bytes());
        payload.extend_from_slice(&internal.cmk.0);
        payload.extend_from_slice(&internal.iv);
        payload.extend_from_slice(&internal.aad_size.to_le_bytes());
        let len = internal.aad_size as usize;
        payload.extend_from_slice(&internal.aad[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            flags: internal.flags,
            cmk: internal.cmk.0,
            iv: internal.iv,
            aad_size: internal.aad_size,
            aad: internal.aad,
        }
    }
}

impl ToInternalResponse<AesGcmDecryptInitResponse> for ExtCmdAesGcmDecryptInitResponse {
    fn to_internal(&self) -> AesGcmDecryptInitResponse {
        AesGcmDecryptInitResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmDecryptInitRequest {}

impl VariableSizeBytes for ExtCmdAesGcmDecryptInitResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Fixed size: chksum(4) + fips_status(4) + context(128) = 136 bytes
        const EXPECTED_SIZE: usize = 4 + 4 + AES_GCM_CONTEXT_SIZE;
        if bytes.len() < EXPECTED_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_GCM_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_GCM_CONTEXT_SIZE]);

        Ok(ExtCmdAesGcmDecryptInitResponse {
            chksum,
            fips_status,
            context,
        })
    }
}

// ============================================================================
// AES-GCM Decrypt Update Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptUpdateRequest {
    pub chksum: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmDecryptUpdateRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptUpdateResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmDecryptUpdateResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmDecryptUpdateRequest> for ExtCmdAesGcmDecryptUpdateRequest {
    fn from_internal(internal: &AesGcmDecryptUpdateRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.ciphertext_size.to_le_bytes());
        let len = core::cmp::min(internal.ciphertext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.ciphertext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            ciphertext_size: internal.ciphertext_size,
            ciphertext: internal.ciphertext,
        }
    }
}

impl ToInternalResponse<AesGcmDecryptUpdateResponse> for ExtCmdAesGcmDecryptUpdateResponse {
    fn to_internal(&self) -> AesGcmDecryptUpdateResponse {
        AesGcmDecryptUpdateResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            context: self.context,
            plaintext_size: self.plaintext_size,
            plaintext: self.plaintext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmDecryptUpdateRequest {}

impl VariableSizeBytes for ExtCmdAesGcmDecryptUpdateResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + context(128) + plaintext_size(4) = 140 bytes
        const HEADER_SIZE: usize = 4 + 4 + AES_GCM_CONTEXT_SIZE + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut context = [0u8; AES_GCM_CONTEXT_SIZE];
        context.copy_from_slice(&bytes[8..8 + AES_GCM_CONTEXT_SIZE]);

        let size_offset = 8 + AES_GCM_CONTEXT_SIZE;
        let plaintext_size = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);

        let pt_len = core::cmp::min(plaintext_size as usize, MAX_AES_DATA_SIZE);
        let pt_offset = size_offset + 4;
        if bytes.len() < pt_offset + pt_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut plaintext = [0u8; MAX_AES_DATA_SIZE];
        plaintext[..pt_len].copy_from_slice(&bytes[pt_offset..pt_offset + pt_len]);

        Ok(ExtCmdAesGcmDecryptUpdateResponse {
            chksum,
            fips_status,
            context,
            plaintext_size,
            plaintext,
        })
    }
}

// ============================================================================
// AES-GCM Decrypt Final Command
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptFinalRequest {
    pub chksum: u32,
    pub context: [u8; AES_GCM_CONTEXT_SIZE],
    pub tag_len: u32,
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_AES_DATA_SIZE],
}

impl Default for ExtCmdAesGcmDecryptFinalRequest {
    fn default() -> Self {
        Self {
            chksum: 0,
            context: [0u8; AES_GCM_CONTEXT_SIZE],
            tag_len: AES_GCM_TAG_SIZE as u32,
            tag: [0u8; AES_GCM_TAG_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_AES_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct ExtCmdAesGcmDecryptFinalResponse {
    pub chksum: u32,
    pub fips_status: u32,
    pub tag_verified: u32,
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_AES_GCM_OUTPUT_SIZE],
}

impl Default for ExtCmdAesGcmDecryptFinalResponse {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: 0,
            tag_verified: 0,
            plaintext_size: 0,
            plaintext: [0u8; MAX_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl FromInternalRequest<AesGcmDecryptFinalRequest> for ExtCmdAesGcmDecryptFinalRequest {
    fn from_internal(internal: &AesGcmDecryptFinalRequest, command_code: u32) -> Self {
        let mut payload = Vec::new();
        payload.extend_from_slice(&internal.context);
        payload.extend_from_slice(&internal.tag_len.to_le_bytes());
        payload.extend_from_slice(&internal.tag);
        payload.extend_from_slice(&internal.ciphertext_size.to_le_bytes());
        let len = core::cmp::min(internal.ciphertext_size as usize, MAX_AES_DATA_SIZE);
        payload.extend_from_slice(&internal.ciphertext[..len]);

        let chksum = calc_checksum(command_code, &payload);

        Self {
            chksum,
            context: internal.context,
            tag_len: internal.tag_len,
            tag: internal.tag,
            ciphertext_size: internal.ciphertext_size,
            ciphertext: internal.ciphertext,
        }
    }
}

impl ToInternalResponse<AesGcmDecryptFinalResponse> for ExtCmdAesGcmDecryptFinalResponse {
    fn to_internal(&self) -> AesGcmDecryptFinalResponse {
        AesGcmDecryptFinalResponse {
            common: CommonResponse {
                fips_status: self.fips_status,
            },
            tag_verified: self.tag_verified,
            plaintext_size: self.plaintext_size,
            plaintext: self.plaintext,
        }
    }
}

impl VariableSizeBytes for ExtCmdAesGcmDecryptFinalRequest {}

impl VariableSizeBytes for ExtCmdAesGcmDecryptFinalResponse {
    fn from_bytes_variable(bytes: &[u8]) -> Result<Self, crate::TransportError> {
        // Header: chksum(4) + fips_status(4) + tag_verified(4) + plaintext_size(4) = 16 bytes
        const HEADER_SIZE: usize = 4 + 4 + 4 + 4;
        if bytes.len() < HEADER_SIZE {
            return Err(crate::TransportError::InvalidMessage);
        }

        let chksum = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fips_status = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let tag_verified = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let plaintext_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        let pt_len = core::cmp::min(plaintext_size as usize, MAX_AES_GCM_OUTPUT_SIZE);
        let pt_offset = 16;
        if bytes.len() < pt_offset + pt_len {
            return Err(crate::TransportError::InvalidMessage);
        }

        let mut plaintext = [0u8; MAX_AES_GCM_OUTPUT_SIZE];
        plaintext[..pt_len].copy_from_slice(&bytes[pt_offset..pt_offset + pt_len]);

        Ok(ExtCmdAesGcmDecryptFinalResponse {
            chksum,
            fips_status,
            tag_verified,
            plaintext_size,
            plaintext,
        })
    }
}

// ============================================================================
// Command Metadata Definitions
// ============================================================================

use crate::define_command;

define_command!(
    AesEncryptInitCmd,
    0x4D43_4349, // MC_AES_ENCRYPT_INIT
    AesEncryptInitRequest,
    AesEncryptInitResponse,
    ExtCmdAesEncryptInitRequest,
    ExtCmdAesEncryptInitResponse
);

define_command!(
    AesEncryptUpdateCmd,
    0x4D43_4355, // MC_AES_ENCRYPT_UPDATE
    AesEncryptUpdateRequest,
    AesEncryptUpdateResponse,
    ExtCmdAesEncryptUpdateRequest,
    ExtCmdAesEncryptUpdateResponse
);

define_command!(
    AesDecryptInitCmd,
    0x4D43_414A, // MC_AES_DECRYPT_INIT
    AesDecryptInitRequest,
    AesDecryptInitResponse,
    ExtCmdAesDecryptInitRequest,
    ExtCmdAesDecryptInitResponse
);

define_command!(
    AesDecryptUpdateCmd,
    0x4D43_4155, // MC_AES_DECRYPT_UPDATE
    AesDecryptUpdateRequest,
    AesDecryptUpdateResponse,
    ExtCmdAesDecryptUpdateRequest,
    ExtCmdAesDecryptUpdateResponse
);

define_command!(
    AesGcmEncryptInitCmd,
    0x4D43_4749, // MC_AES_GCM_ENCRYPT_INIT
    AesGcmEncryptInitRequest,
    AesGcmEncryptInitResponse,
    ExtCmdAesGcmEncryptInitRequest,
    ExtCmdAesGcmEncryptInitResponse
);

define_command!(
    AesGcmEncryptUpdateCmd,
    0x4D43_4755, // MC_AES_GCM_ENCRYPT_UPDATE
    AesGcmEncryptUpdateRequest,
    AesGcmEncryptUpdateResponse,
    ExtCmdAesGcmEncryptUpdateRequest,
    ExtCmdAesGcmEncryptUpdateResponse
);

define_command!(
    AesGcmEncryptFinalCmd,
    0x4D43_4746, // MC_AES_GCM_ENCRYPT_FINAL
    AesGcmEncryptFinalRequest,
    AesGcmEncryptFinalResponse,
    ExtCmdAesGcmEncryptFinalRequest,
    ExtCmdAesGcmEncryptFinalResponse
);

define_command!(
    AesGcmDecryptInitCmd,
    0x4D43_4449, // MC_AES_GCM_DECRYPT_INIT
    AesGcmDecryptInitRequest,
    AesGcmDecryptInitResponse,
    ExtCmdAesGcmDecryptInitRequest,
    ExtCmdAesGcmDecryptInitResponse
);

define_command!(
    AesGcmDecryptUpdateCmd,
    0x4D43_4455, // MC_AES_GCM_DECRYPT_UPDATE
    AesGcmDecryptUpdateRequest,
    AesGcmDecryptUpdateResponse,
    ExtCmdAesGcmDecryptUpdateRequest,
    ExtCmdAesGcmDecryptUpdateResponse
);

define_command!(
    AesGcmDecryptFinalCmd,
    0x4D43_4446, // MC_AES_GCM_DECRYPT_FINAL
    AesGcmDecryptFinalRequest,
    AesGcmDecryptFinalResponse,
    ExtCmdAesGcmDecryptFinalRequest,
    ExtCmdAesGcmDecryptFinalResponse
);
