// Licensed under the Apache-2.0 license

//! Cryptographic AES API functions
//!
//! High-level functions for AES encrypt/decrypt operations.
//!
//! Basic AES (CBC/CTR):
//! - `caliptra_cmd_aes_encrypt_init` - Start AES encryption
//! - `caliptra_cmd_aes_encrypt_update` - Continue encryption with more data
//! - `caliptra_cmd_aes_decrypt_init` - Start AES decryption
//! - `caliptra_cmd_aes_decrypt_update` - Continue decryption with more data
//!
//! AES-GCM (Authenticated):
//! - `caliptra_cmd_aes_gcm_encrypt_init` - Start AES-GCM encryption
//! - `caliptra_cmd_aes_gcm_encrypt_update` - Encrypt intermediate data
//! - `caliptra_cmd_aes_gcm_encrypt_final` - Finalize encryption and get tag
//! - `caliptra_cmd_aes_gcm_decrypt_init` - Start AES-GCM decryption
//! - `caliptra_cmd_aes_gcm_decrypt_update` - Decrypt intermediate data
//! - `caliptra_cmd_aes_gcm_decrypt_final` - Verify tag and finalize decryption
//!
//! High-level convenience functions:
//! - `caliptra_aes_encrypt` - One-shot encrypt
//! - `caliptra_aes_decrypt` - One-shot decrypt
//! - `caliptra_aes_gcm_encrypt` - One-shot authenticated encrypt
//! - `caliptra_aes_gcm_decrypt` - One-shot authenticated decrypt

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_aes::{
    AesDecryptInitRequest, AesDecryptInitResponse, AesDecryptUpdateRequest,
    AesDecryptUpdateResponse, AesEncryptInitRequest, AesEncryptInitResponse,
    AesEncryptUpdateRequest, AesEncryptUpdateResponse, AesGcmDecryptFinalRequest,
    AesGcmDecryptFinalResponse, AesGcmDecryptInitRequest, AesGcmDecryptInitResponse,
    AesGcmDecryptUpdateRequest, AesGcmDecryptUpdateResponse, AesGcmEncryptFinalRequest,
    AesGcmEncryptFinalResponse, AesGcmEncryptInitRequest, AesGcmEncryptInitResponse,
    AesGcmEncryptUpdateRequest, AesGcmEncryptUpdateResponse, AesMode, AES_CONTEXT_SIZE,
    AES_GCM_CONTEXT_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE, AES_IV_SIZE, MAX_AES_DATA_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::Cmk;
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

extern crate alloc;
use alloc::vec::Vec;

// ============================================================================
// Low-Level AES Command Functions
// ============================================================================

/// Start AES encryption
///
/// Initializes an AES encryption operation with the first block of data.
/// Returns a context that must be passed to subsequent Update calls if needed.
pub fn caliptra_cmd_aes_encrypt_init(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    mode: AesMode,
    plaintext: &[u8],
) -> CaliptraResult<AesEncryptInitResponse> {
    let len = core::cmp::min(plaintext.len(), MAX_AES_DATA_SIZE);
    let mut plaintext_buf = [0u8; MAX_AES_DATA_SIZE];
    plaintext_buf[..len].copy_from_slice(&plaintext[..len]);

    let request = AesEncryptInitRequest {
        cmk: cmk.clone(),
        mode: mode as u32,
        plaintext_size: len as u32,
        plaintext: plaintext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesEncryptInit, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES encrypt init failed"))
}

/// Continue AES encryption with more data
pub fn caliptra_cmd_aes_encrypt_update(
    session: &mut CaliptraSession,
    context: &[u8; AES_CONTEXT_SIZE],
    plaintext: &[u8],
) -> CaliptraResult<AesEncryptUpdateResponse> {
    let len = core::cmp::min(plaintext.len(), MAX_AES_DATA_SIZE);
    let mut plaintext_buf = [0u8; MAX_AES_DATA_SIZE];
    plaintext_buf[..len].copy_from_slice(&plaintext[..len]);

    let request = AesEncryptUpdateRequest {
        context: *context,
        plaintext_size: len as u32,
        plaintext: plaintext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesEncryptUpdate, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES encrypt update failed"))
}

/// Start AES decryption
///
/// Initializes an AES decryption operation with the first block of ciphertext.
/// Requires the IV that was generated during encryption.
pub fn caliptra_cmd_aes_decrypt_init(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    mode: AesMode,
    iv: &[u8; AES_IV_SIZE],
    ciphertext: &[u8],
) -> CaliptraResult<AesDecryptInitResponse> {
    let len = core::cmp::min(ciphertext.len(), MAX_AES_DATA_SIZE);
    let mut ciphertext_buf = [0u8; MAX_AES_DATA_SIZE];
    ciphertext_buf[..len].copy_from_slice(&ciphertext[..len]);

    let request = AesDecryptInitRequest {
        cmk: cmk.clone(),
        mode: mode as u32,
        iv: *iv,
        ciphertext_size: len as u32,
        ciphertext: ciphertext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesDecryptInit, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES decrypt init failed"))
}

/// Continue AES decryption with more data
pub fn caliptra_cmd_aes_decrypt_update(
    session: &mut CaliptraSession,
    context: &[u8; AES_CONTEXT_SIZE],
    ciphertext: &[u8],
) -> CaliptraResult<AesDecryptUpdateResponse> {
    let len = core::cmp::min(ciphertext.len(), MAX_AES_DATA_SIZE);
    let mut ciphertext_buf = [0u8; MAX_AES_DATA_SIZE];
    ciphertext_buf[..len].copy_from_slice(&ciphertext[..len]);

    let request = AesDecryptUpdateRequest {
        context: *context,
        ciphertext_size: len as u32,
        ciphertext: ciphertext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesDecryptUpdate, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES decrypt update failed"))
}

// ============================================================================
// Low-Level AES-GCM Command Functions
// ============================================================================

/// Start AES-GCM encryption
///
/// Initializes an AES-GCM encryption operation with AAD (Additional Authenticated Data).
/// Returns a context and IV for subsequent operations.
pub fn caliptra_cmd_aes_gcm_encrypt_init(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    aad: &[u8],
) -> CaliptraResult<AesGcmEncryptInitResponse> {
    let len = core::cmp::min(aad.len(), MAX_AES_DATA_SIZE);
    let mut aad_buf = [0u8; MAX_AES_DATA_SIZE];
    aad_buf[..len].copy_from_slice(&aad[..len]);

    let request = AesGcmEncryptInitRequest {
        flags: 0,
        cmk: cmk.clone(),
        aad_size: len as u32,
        aad: aad_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmEncryptInit, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM encrypt init failed"))
}

/// Encrypt intermediate data in AES-GCM
pub fn caliptra_cmd_aes_gcm_encrypt_update(
    session: &mut CaliptraSession,
    context: &[u8; AES_GCM_CONTEXT_SIZE],
    plaintext: &[u8],
) -> CaliptraResult<AesGcmEncryptUpdateResponse> {
    let len = core::cmp::min(plaintext.len(), MAX_AES_DATA_SIZE);
    let mut plaintext_buf = [0u8; MAX_AES_DATA_SIZE];
    plaintext_buf[..len].copy_from_slice(&plaintext[..len]);

    let request = AesGcmEncryptUpdateRequest {
        context: *context,
        plaintext_size: len as u32,
        plaintext: plaintext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmEncryptUpdate, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM encrypt update failed"))
}

/// Finalize AES-GCM encryption and get authentication tag
pub fn caliptra_cmd_aes_gcm_encrypt_final(
    session: &mut CaliptraSession,
    context: &[u8; AES_GCM_CONTEXT_SIZE],
    plaintext: &[u8],
) -> CaliptraResult<AesGcmEncryptFinalResponse> {
    let len = core::cmp::min(plaintext.len(), MAX_AES_DATA_SIZE);
    let mut plaintext_buf = [0u8; MAX_AES_DATA_SIZE];
    plaintext_buf[..len].copy_from_slice(&plaintext[..len]);

    let request = AesGcmEncryptFinalRequest {
        context: *context,
        plaintext_size: len as u32,
        plaintext: plaintext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmEncryptFinal, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM encrypt final failed"))
}

/// Start AES-GCM decryption
///
/// Initializes an AES-GCM decryption operation with IV and AAD.
pub fn caliptra_cmd_aes_gcm_decrypt_init(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    iv: &[u8; AES_GCM_IV_SIZE],
    aad: &[u8],
) -> CaliptraResult<AesGcmDecryptInitResponse> {
    let len = core::cmp::min(aad.len(), MAX_AES_DATA_SIZE);
    let mut aad_buf = [0u8; MAX_AES_DATA_SIZE];
    aad_buf[..len].copy_from_slice(&aad[..len]);

    let request = AesGcmDecryptInitRequest {
        flags: 0,
        cmk: cmk.clone(),
        iv: *iv,
        aad_size: len as u32,
        aad: aad_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmDecryptInit, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM decrypt init failed"))
}

/// Decrypt intermediate data in AES-GCM
pub fn caliptra_cmd_aes_gcm_decrypt_update(
    session: &mut CaliptraSession,
    context: &[u8; AES_GCM_CONTEXT_SIZE],
    ciphertext: &[u8],
) -> CaliptraResult<AesGcmDecryptUpdateResponse> {
    let len = core::cmp::min(ciphertext.len(), MAX_AES_DATA_SIZE);
    let mut ciphertext_buf = [0u8; MAX_AES_DATA_SIZE];
    ciphertext_buf[..len].copy_from_slice(&ciphertext[..len]);

    let request = AesGcmDecryptUpdateRequest {
        context: *context,
        ciphertext_size: len as u32,
        ciphertext: ciphertext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmDecryptUpdate, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM decrypt update failed"))
}

/// Finalize AES-GCM decryption and verify authentication tag
pub fn caliptra_cmd_aes_gcm_decrypt_final(
    session: &mut CaliptraSession,
    context: &[u8; AES_GCM_CONTEXT_SIZE],
    tag: &[u8; AES_GCM_TAG_SIZE],
    ciphertext: &[u8],
) -> CaliptraResult<AesGcmDecryptFinalResponse> {
    let len = core::cmp::min(ciphertext.len(), MAX_AES_DATA_SIZE);
    let mut ciphertext_buf = [0u8; MAX_AES_DATA_SIZE];
    ciphertext_buf[..len].copy_from_slice(&ciphertext[..len]);

    let request = AesGcmDecryptFinalRequest {
        context: *context,
        tag_len: AES_GCM_TAG_SIZE as u32,
        tag: *tag,
        ciphertext_size: len as u32,
        ciphertext: ciphertext_buf,
    };

    session
        .execute_command_with_id(CaliptraCommandId::AesGcmDecryptFinal, &request)
        .map_err(|_| CaliptraApiError::SessionError("AES-GCM decrypt final failed"))
}

// ============================================================================
// High-Level Convenience Functions
// ============================================================================

/// AES encryption result
pub struct AesEncryptResult {
    pub iv: [u8; AES_IV_SIZE],
    pub ciphertext: Vec<u8>,
}

/// One-shot AES encryption
///
/// Encrypts plaintext using AES-CBC or AES-CTR mode.
/// Handles chunking for data larger than MAX_AES_DATA_SIZE.
///
/// # Parameters
/// - `session`: Session for command execution
/// - `cmk`: Encrypted AES key (imported with CmKeyUsage::Aes)
/// - `mode`: AES mode (CBC or CTR)
/// - `plaintext`: Data to encrypt
///
/// # Returns
/// - IV and ciphertext on success
pub fn caliptra_aes_encrypt(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    mode: AesMode,
    plaintext: &[u8],
) -> CaliptraResult<AesEncryptResult> {
    // Use half the buffer for streaming to ensure we have room for context
    let chunk_size = MAX_AES_DATA_SIZE / 2;

    if plaintext.len() <= chunk_size {
        // Small data: single Init call
        let resp = caliptra_cmd_aes_encrypt_init(session, cmk, mode, plaintext)?;
        let ct_len = resp.ciphertext_size as usize;
        Ok(AesEncryptResult {
            iv: resp.iv,
            ciphertext: resp.ciphertext[..ct_len].to_vec(),
        })
    } else {
        // Large data: Init + Update calls
        let first_chunk = &plaintext[..chunk_size];
        let mut remaining = &plaintext[chunk_size..];

        let init_resp = caliptra_cmd_aes_encrypt_init(session, cmk, mode, first_chunk)?;
        let iv = init_resp.iv;
        let mut context = init_resp.context;
        let mut ciphertext = Vec::new();
        let ct_len = init_resp.ciphertext_size as usize;
        ciphertext.extend_from_slice(&init_resp.ciphertext[..ct_len]);

        while !remaining.is_empty() {
            let chunk_len = core::cmp::min(remaining.len(), chunk_size);
            let chunk = &remaining[..chunk_len];

            let update_resp = caliptra_cmd_aes_encrypt_update(session, &context, chunk)?;
            context = update_resp.context;
            let ct_len = update_resp.ciphertext_size as usize;
            ciphertext.extend_from_slice(&update_resp.ciphertext[..ct_len]);

            remaining = &remaining[chunk_len..];
        }

        Ok(AesEncryptResult { iv, ciphertext })
    }
}

/// One-shot AES decryption
///
/// Decrypts ciphertext using AES-CBC or AES-CTR mode.
/// Handles chunking for data larger than MAX_AES_DATA_SIZE.
///
/// # Parameters
/// - `session`: Session for command execution
/// - `cmk`: Encrypted AES key
/// - `mode`: AES mode (must match encryption mode)
/// - `iv`: IV from encryption
/// - `ciphertext`: Data to decrypt
///
/// # Returns
/// - Decrypted plaintext on success
pub fn caliptra_aes_decrypt(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    mode: AesMode,
    iv: &[u8; AES_IV_SIZE],
    ciphertext: &[u8],
) -> CaliptraResult<Vec<u8>> {
    let chunk_size = MAX_AES_DATA_SIZE / 2;

    if ciphertext.len() <= chunk_size {
        // Small data: single Init call
        let resp = caliptra_cmd_aes_decrypt_init(session, cmk, mode, iv, ciphertext)?;
        let pt_len = resp.plaintext_size as usize;
        Ok(resp.plaintext[..pt_len].to_vec())
    } else {
        // Large data: Init + Update calls
        let first_chunk = &ciphertext[..chunk_size];
        let mut remaining = &ciphertext[chunk_size..];

        let init_resp = caliptra_cmd_aes_decrypt_init(session, cmk, mode, iv, first_chunk)?;
        let mut context = init_resp.context;
        let mut plaintext = Vec::new();
        let pt_len = init_resp.plaintext_size as usize;
        plaintext.extend_from_slice(&init_resp.plaintext[..pt_len]);

        while !remaining.is_empty() {
            let chunk_len = core::cmp::min(remaining.len(), chunk_size);
            let chunk = &remaining[..chunk_len];

            let update_resp = caliptra_cmd_aes_decrypt_update(session, &context, chunk)?;
            context = update_resp.context;
            let pt_len = update_resp.plaintext_size as usize;
            plaintext.extend_from_slice(&update_resp.plaintext[..pt_len]);

            remaining = &remaining[chunk_len..];
        }

        Ok(plaintext)
    }
}

/// AES-GCM encryption result
pub struct AesGcmEncryptResult {
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub ciphertext: Vec<u8>,
}

/// One-shot AES-GCM authenticated encryption
///
/// Encrypts plaintext and authenticates both the plaintext and AAD.
///
/// # Parameters
/// - `session`: Session for command execution
/// - `cmk`: Encrypted AES key (imported with CmKeyUsage::Aes)
/// - `aad`: Additional Authenticated Data (not encrypted, but authenticated)
/// - `plaintext`: Data to encrypt
///
/// # Returns
/// - IV, authentication tag, and ciphertext on success
pub fn caliptra_aes_gcm_encrypt(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    aad: &[u8],
    plaintext: &[u8],
) -> CaliptraResult<AesGcmEncryptResult> {
    let chunk_size = MAX_AES_DATA_SIZE / 2;

    // Init with AAD
    let init_resp = caliptra_cmd_aes_gcm_encrypt_init(session, cmk, aad)?;
    let iv = init_resp.iv;
    let mut context = init_resp.context;
    let mut ciphertext = Vec::new();

    if plaintext.len() <= chunk_size {
        // Small data: single Final call
        let final_resp = caliptra_cmd_aes_gcm_encrypt_final(session, &context, plaintext)?;
        let ct_len = final_resp.ciphertext_size as usize;
        ciphertext.extend_from_slice(&final_resp.ciphertext[..ct_len]);

        Ok(AesGcmEncryptResult {
            iv,
            tag: final_resp.tag,
            ciphertext,
        })
    } else {
        // Large data: Update calls + Final
        let mut remaining = plaintext;

        while remaining.len() > chunk_size {
            let chunk = &remaining[..chunk_size];
            let update_resp = caliptra_cmd_aes_gcm_encrypt_update(session, &context, chunk)?;
            context = update_resp.context;
            let ct_len = update_resp.ciphertext_size as usize;
            ciphertext.extend_from_slice(&update_resp.ciphertext[..ct_len]);
            remaining = &remaining[chunk_size..];
        }

        // Final call with remaining data
        let final_resp = caliptra_cmd_aes_gcm_encrypt_final(session, &context, remaining)?;
        let ct_len = final_resp.ciphertext_size as usize;
        ciphertext.extend_from_slice(&final_resp.ciphertext[..ct_len]);

        Ok(AesGcmEncryptResult {
            iv,
            tag: final_resp.tag,
            ciphertext,
        })
    }
}

/// AES-GCM decryption result
pub struct AesGcmDecryptResult {
    pub tag_verified: bool,
    pub plaintext: Vec<u8>,
}

/// One-shot AES-GCM authenticated decryption
///
/// Decrypts ciphertext and verifies the authentication tag.
///
/// # Parameters
/// - `session`: Session for command execution
/// - `cmk`: Encrypted AES key
/// - `iv`: IV from encryption
/// - `aad`: Additional Authenticated Data (must match encryption)
/// - `ciphertext`: Data to decrypt
/// - `tag`: Authentication tag from encryption
///
/// # Returns
/// - Tag verification status and plaintext on success
pub fn caliptra_aes_gcm_decrypt(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    iv: &[u8; AES_GCM_IV_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; AES_GCM_TAG_SIZE],
) -> CaliptraResult<AesGcmDecryptResult> {
    let chunk_size = MAX_AES_DATA_SIZE / 2;

    // Init with IV and AAD
    let init_resp = caliptra_cmd_aes_gcm_decrypt_init(session, cmk, iv, aad)?;
    let mut context = init_resp.context;
    let mut plaintext = Vec::new();

    if ciphertext.len() <= chunk_size {
        // Small data: single Final call
        let final_resp = caliptra_cmd_aes_gcm_decrypt_final(session, &context, tag, ciphertext)?;
        let pt_len = final_resp.plaintext_size as usize;
        plaintext.extend_from_slice(&final_resp.plaintext[..pt_len]);

        Ok(AesGcmDecryptResult {
            tag_verified: final_resp.tag_verified != 0,
            plaintext,
        })
    } else {
        // Large data: Update calls + Final
        let mut remaining = ciphertext;

        while remaining.len() > chunk_size {
            let chunk = &remaining[..chunk_size];
            let update_resp = caliptra_cmd_aes_gcm_decrypt_update(session, &context, chunk)?;
            context = update_resp.context;
            let pt_len = update_resp.plaintext_size as usize;
            plaintext.extend_from_slice(&update_resp.plaintext[..pt_len]);
            remaining = &remaining[chunk_size..];
        }

        // Final call with remaining data and tag verification
        let final_resp = caliptra_cmd_aes_gcm_decrypt_final(session, &context, tag, remaining)?;
        let pt_len = final_resp.plaintext_size as usize;
        plaintext.extend_from_slice(&final_resp.plaintext[..pt_len]);

        Ok(AesGcmDecryptResult {
            tag_verified: final_resp.tag_verified != 0,
            plaintext,
        })
    }
}
