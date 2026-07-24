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
//!   implements. Large mailbox request / response buffers come from
//!   here so large `[u8; N]` arrays do not sit on the stack across an
//!   `.await`.
//! * Free functions [`sha_init`] / [`sha_update`] / [`sha_finish`]
//!   driving Caliptra's `CM_SHA_*` mailbox commands.
//!
//! Future modules (`cert`, `dpe`, `ecdsa`) will follow the same
//! pattern: free `async` functions taking `&impl ApiAlloc`.

#![no_std]
#![allow(async_fn_in_trait)]

#[cfg(feature = "mailbox-io")]
mod aes_gcm;
#[cfg(feature = "mailbox-io")]
mod alloc;
#[cfg(feature = "mailbox-io")]
mod auth_stash;
#[cfg(feature = "mailbox-io")]
mod cert;
#[cfg(feature = "mailbox-io")]
mod debug_unlock;
#[cfg(feature = "mailbox-io")]
mod device_state;
#[cfg(feature = "mailbox-io")]
mod dpe;
pub mod eat;
#[cfg(feature = "mailbox-io")]
mod ecdh;
#[cfg(feature = "mailbox-io")]
mod fe_prog;
#[cfg(feature = "mailbox-io")]
mod fw_info;
#[cfg(feature = "mailbox-io")]
mod hmac;
#[cfg(feature = "mailbox-io")]
mod import;
pub mod mailbox;
#[cfg(feature = "mailbox-io")]
mod pcr;
#[cfg(feature = "mailbox-io")]
pub mod raw;
#[cfg(feature = "mailbox-io")]
mod rng;
#[cfg(feature = "mailbox-io")]
mod sha;
#[cfg(feature = "mailbox-io")]
pub mod signed_eat;
#[cfg(feature = "mailbox-io")]
mod slice;
mod types;
#[cfg(feature = "mailbox-io")]
mod wire;

#[cfg(feature = "mailbox-io")]
pub use aes_gcm::{
    spdm_aes_gcm_decrypt, spdm_aes_gcm_decrypt_final, spdm_aes_gcm_decrypt_init,
    spdm_aes_gcm_decrypt_update, spdm_aes_gcm_encrypt, spdm_aes_gcm_encrypt_final,
    spdm_aes_gcm_encrypt_init, spdm_aes_gcm_encrypt_update, Aes256GcmTag, AesGcmCtx,
};
#[cfg(feature = "mailbox-io")]
pub use alloc::ApiAlloc;
#[cfg(feature = "mailbox-io")]
pub use auth_stash::{
    authorize_and_stash, AuthorizeAndStashFlags, AuthorizeAndStashParams, ImageHashSource,
    AUTHORIZE_AND_STASH_CONTEXT_SIZE, AUTHORIZE_AND_STASH_MEASUREMENT_SIZE,
};
#[cfg(feature = "mailbox-io")]
pub use cert::{
    get_attested_csr_ecc384, get_attested_csr_mldsa87, get_idev_csr_ecc384,
    populate_idev_ecc384_cert,
};
#[cfg(feature = "mailbox-io")]
pub use debug_unlock::{
    request_debug_unlock_challenge, DEBUG_UNLOCK_CHALLENGE_LEN,
    PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_CMD, PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN_RSP_LEN,
};
#[cfg(feature = "mailbox-io")]
pub use device_state::{get_pcr_value, pcr_quote_ecc384, PCR_QUOTE_ECC384_LEN};
#[cfg(feature = "mailbox-io")]
pub use dpe::{
    dpe_certify_key, dpe_certify_key_cert_size, dpe_certify_key_cert_slice, dpe_certify_key_pubkey,
    dpe_derive_context, dpe_get_cert_chain_chunk, dpe_rotate_context_default, dpe_sign_ecc_p384,
    dpe_tag_tci, dpe_update_context_measurement, walk_dpe_chain, DpeChainSink, DpeContextHandle,
    DpeDeriveContextFlags, DpeDeriveContextParams, DpeDeriveContextResult,
    DpeUpdateContextMeasurementParams, DpeUpdateContextMeasurementResult, DPE_CONTEXT_HANDLE_SIZE,
    DPE_LABEL_LEN, DPE_MAX_CHUNK_SIZE, DPE_MAX_LEAF_CERT_SIZE, DPE_P384_SIGNATURE_SIZE,
    DPE_TCI_MEASUREMENT_SIZE,
};
#[cfg(feature = "mailbox-io")]
pub use ecdh::{
    ecdh_finish, ecdh_generate, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE,
};
#[cfg(feature = "mailbox-io")]
pub use fe_prog::fe_prog;
#[cfg(feature = "mailbox-io")]
pub use fw_info::{fw_info, FwInfo};
#[cfg(feature = "mailbox-io")]
pub use hmac::{cm_hmac, hkdf_expand, hkdf_extract, HkdfSalt, CMB_HMAC_MAX_SIZE};
#[cfg(feature = "mailbox-io")]
pub use import::{cm_delete, cm_import};
#[cfg(feature = "mailbox-io")]
pub use pcr::{extend_pcr31, PCR31_INDEX, PCR31_MEASUREMENT_SIZE};
#[cfg(feature = "mailbox-io")]
pub use rng::rng_generate;
#[cfg(feature = "mailbox-io")]
pub use sha::{
    sha_finish, sha_init, sha_update, HashAlgo, HashState, SHA_CHUNK_SIZE, SHA_CONTEXT_SIZE,
};
pub use types::{CmKeyUsage, Cmk, CMK_SIZE};

#[cfg(feature = "mailbox-io")]
pub use mcu_error::{McuErrorCode, McuResult};
