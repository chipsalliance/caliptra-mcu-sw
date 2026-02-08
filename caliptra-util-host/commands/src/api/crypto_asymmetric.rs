// Licensed under the Apache-2.0 license

//! Cryptographic Asymmetric API functions
//!
//! High-level functions for ECDSA and ECDH operations.
//!
//! ECDSA operations:
//! - `caliptra_cmd_ecdsa_public_key` - Get public key from an ECDSA CMK
//! - `caliptra_cmd_ecdsa_sign` - Sign a message with an ECDSA CMK
//! - `caliptra_cmd_ecdsa_verify` - Verify a signature with an ECDSA CMK
//!
//! ECDH operations:
//! - `caliptra_cmd_ecdh_generate` - Generate an ephemeral ECDH keypair
//! - `caliptra_cmd_ecdh_finish` - Complete ECDH key exchange and derive shared secret

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::crypto_asymmetric::{
    EcdhFinishRequest, EcdhFinishResponse, EcdhGenerateRequest, EcdhGenerateResponse,
    EcdsaPublicKeyRequest, EcdsaPublicKeyResponse, EcdsaSignRequest, EcdsaSignResponse,
    EcdsaVerifyRequest, EcdsaVerifyResponse, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE,
    CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, ECC384_SCALAR_BYTE_SIZE,
};
use caliptra_util_host_command_types::crypto_hmac::{CmKeyUsage, Cmk};
use caliptra_util_host_command_types::CaliptraCommandId;
use caliptra_util_host_session::CaliptraSession;

/// Get the public key from an ECDSA CMK
///
/// Extracts the public key (X, Y coordinates) from an encrypted ECDSA CMK.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `cmk`: Cryptographic mailbox key (encrypted ECDSA private key)
///
/// # Returns
///
/// - `Ok(EcdsaPublicKeyResponse)` containing the public key coordinates
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let resp = caliptra_cmd_ecdsa_public_key(&mut session, &ecdsa_cmk)?;
/// println!("Public key X: {:02x?}", &resp.pub_key_x[..16]);
/// println!("Public key Y: {:02x?}", &resp.pub_key_y[..16]);
/// ```
pub fn caliptra_cmd_ecdsa_public_key(
    session: &mut CaliptraSession,
    cmk: &Cmk,
) -> CaliptraResult<EcdsaPublicKeyResponse> {
    let request = EcdsaPublicKeyRequest::new(cmk);
    session
        .execute_command_with_id(CaliptraCommandId::EcdsaPublicKey, &request)
        .map_err(|_| CaliptraApiError::SessionError("ECDSA public key command execution failed"))
}

/// Sign a message with an ECDSA CMK
///
/// Signs the provided message using ECDSA-P384 with the specified CMK.
/// The message should be a hash (e.g., SHA-384) of the data to sign.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `cmk`: Cryptographic mailbox key (encrypted ECDSA private key)
/// - `message`: Message to sign (typically a hash, up to 4096 bytes)
///
/// # Returns
///
/// - `Ok(EcdsaSignResponse)` containing the signature (r, s components)
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let resp = caliptra_cmd_ecdsa_sign(&mut session, &ecdsa_cmk, &message_hash)?;
/// println!("Signature R: {:02x?}", &resp.signature_r[..16]);
/// println!("Signature S: {:02x?}", &resp.signature_s[..16]);
/// ```
pub fn caliptra_cmd_ecdsa_sign(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    message: &[u8],
) -> CaliptraResult<EcdsaSignResponse> {
    let request = EcdsaSignRequest::new(cmk, message);
    session
        .execute_command_with_id(CaliptraCommandId::EcdsaSign, &request)
        .map_err(|_| CaliptraApiError::SessionError("ECDSA sign command execution failed"))
}

/// Verify an ECDSA signature
///
/// Verifies a signature over a message using the public key derived from the CMK.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `cmk`: Cryptographic mailbox key (encrypted ECDSA private key - used to get public key)
/// - `message`: Message that was signed (typically a hash)
/// - `signature_r`: Signature R component (48 bytes for P-384)
/// - `signature_s`: Signature S component (48 bytes for P-384)
///
/// # Returns
///
/// - `Ok(EcdsaVerifyResponse)` if verification succeeds
/// - `Err(CaliptraApiError)` if verification fails or on error
///
/// # Example
///
/// ```ignore
/// match caliptra_cmd_ecdsa_verify(&mut session, &cmk, &msg, &sig_r, &sig_s) {
///     Ok(_) => println!("Signature verified!"),
///     Err(_) => println!("Signature verification failed!"),
/// }
/// ```
pub fn caliptra_cmd_ecdsa_verify(
    session: &mut CaliptraSession,
    cmk: &Cmk,
    message: &[u8],
    signature_r: &[u8; ECC384_SCALAR_BYTE_SIZE],
    signature_s: &[u8; ECC384_SCALAR_BYTE_SIZE],
) -> CaliptraResult<EcdsaVerifyResponse> {
    let request = EcdsaVerifyRequest::new(cmk, message, signature_r, signature_s);
    session
        .execute_command_with_id(CaliptraCommandId::EcdsaVerify, &request)
        .map_err(|_| CaliptraApiError::SessionError("ECDSA verify command execution failed"))
}

/// Generate an ephemeral ECDH keypair
///
/// Generates a new ephemeral ECDH keypair for key exchange. The private key
/// is returned encrypted in the `context` field, and the public key is
/// returned in the `exchange_data` field.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
///
/// # Returns
///
/// - `Ok(EcdhGenerateResponse)` containing the context and exchange data
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let generate_resp = caliptra_cmd_ecdh_generate(&mut session)?;
/// // Send generate_resp.exchange_data to peer
/// // Receive peer's exchange data
/// let derived_key = caliptra_cmd_ecdh_finish(
///     &mut session,
///     &generate_resp.context,
///     CmKeyUsage::Aes,
///     &peer_exchange_data,
/// )?;
/// ```
pub fn caliptra_cmd_ecdh_generate(
    session: &mut CaliptraSession,
) -> CaliptraResult<EcdhGenerateResponse> {
    let request = EcdhGenerateRequest::new();
    session
        .execute_command_with_id(CaliptraCommandId::EcdhGenerate, &request)
        .map_err(|_| CaliptraApiError::SessionError("ECDH generate command execution failed"))
}

/// Complete ECDH key exchange and derive shared secret
///
/// Completes the ECDH key exchange using the context from `ecdh_generate`
/// and the peer's public key. Returns the derived shared secret as a CMK.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `context`: Encrypted context from EcdhGenerateResponse
/// - `key_usage`: Intended usage for the derived key (e.g., AES, HMAC)
/// - `incoming_exchange_data`: Peer's public key (X || Y coordinates, 96 bytes)
///
/// # Returns
///
/// - `Ok(EcdhFinishResponse)` containing the derived key as CMK
/// - `Err(CaliptraApiError)` on failure
///
/// # Example
///
/// ```ignore
/// let finish_resp = caliptra_cmd_ecdh_finish(
///     &mut session,
///     &generate_resp.context,
///     CmKeyUsage::Aes,
///     &peer_exchange_data,
/// )?;
/// let shared_key = finish_resp.output;
/// ```
pub fn caliptra_cmd_ecdh_finish(
    session: &mut CaliptraSession,
    context: &[u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    key_usage: CmKeyUsage,
    incoming_exchange_data: &[u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
) -> CaliptraResult<EcdhFinishResponse> {
    let request = EcdhFinishRequest::new(context, key_usage, incoming_exchange_data);
    session
        .execute_command_with_id(CaliptraCommandId::EcdhFinish, &request)
        .map_err(|_| CaliptraApiError::SessionError("ECDH finish command execution failed"))
}
