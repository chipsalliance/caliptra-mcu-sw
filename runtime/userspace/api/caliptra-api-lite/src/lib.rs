// Licensed under the Apache-2.0 license

//! `mcu-caliptra-api-lite` — minimal Caliptra mailbox API surface.
//!
//! Self-contained crate exposing the Caliptra-mailbox primitives
//! consumers (today: SPDM-Lite, tomorrow: DPE clients, custom
//! attestation flows) actually need, without dragging in the heavy
//! `caliptra-api` crate.
//!
//! Two abstractions:
//!
//! * [`ApiAlloc`] — per-call scratch-allocator the caller
//!   implements. All mailbox request / response buffers come from
//!   here so no large `[u8; N]` array ever sits on the stack across
//!   an `.await`.
//! * Free functions [`sha_init`] / [`sha_update`] / [`sha_finish`]
//!   driving Caliptra's `CM_SHA_*` mailbox commands.
//!
//! Future modules (`cert`, `dpe`, `ecdsa`) will follow the same
//! pattern: free `async` functions taking `&impl ApiAlloc`.

#![no_std]
#![allow(async_fn_in_trait)]

mod aes_gcm;
mod alloc;
mod cert;
mod debug_unlock;
mod device_state;
mod dpe;
pub mod eat;
mod ecdh;
mod fe_prog;
mod fw_info;
mod hmac;
mod import;
pub mod raw;
mod rng;
mod sha;
pub mod signed_eat;
mod types;
mod wire;

pub use aes_gcm::{
    spdm_aes_gcm_decrypt, spdm_aes_gcm_decrypt_final, spdm_aes_gcm_decrypt_init,
    spdm_aes_gcm_decrypt_update, spdm_aes_gcm_encrypt, spdm_aes_gcm_encrypt_final,
    spdm_aes_gcm_encrypt_init, spdm_aes_gcm_encrypt_update, Aes256GcmTag, AesGcmCtx,
};
pub use alloc::ApiAlloc;
pub use cert::{get_attested_csr_ecc384, get_attested_csr_mldsa87, populate_idev_ecc384_cert};
pub use debug_unlock::{
    request_debug_unlock_challenge, DEBUG_UNLOCK_CHALLENGE_LEN,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};
pub use device_state::{get_pcr_value, pcr_quote_ecc384, PCR_QUOTE_ECC384_LEN};
pub use dpe::{
    dpe_certify_key, dpe_certify_key_cert_size, dpe_certify_key_cert_slice, dpe_certify_key_pubkey,
    dpe_get_cert_chain_chunk, dpe_rotate_context_default, dpe_sign_ecc_p384, dpe_tag_tci,
    walk_dpe_chain, DpeChainSink, DpeContextHandle, DPE_CONTEXT_HANDLE_SIZE, DPE_LABEL_LEN,
    DPE_MAX_CHUNK_SIZE, DPE_MAX_LEAF_CERT_SIZE, DPE_P384_SIGNATURE_SIZE,
};
pub use ecdh::{
    ecdh_finish, ecdh_generate, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE,
};
pub use fe_prog::fe_prog;
pub use fw_info::{fw_info, FwInfo};
pub use hmac::{cm_hmac, hkdf_expand, hkdf_extract, HkdfSalt, CMB_HMAC_MAX_SIZE};
pub use import::{cm_delete, cm_import};
pub use rng::rng_generate;
pub use sha::{
    sha_finish, sha_init, sha_update, HashAlgo, HashState, SHA_CHUNK_SIZE, SHA_CONTEXT_SIZE,
};
pub use types::{CmKeyUsage, Cmk, CMK_SIZE};

pub use mcu_error::{McuErrorCode, McuResult};
