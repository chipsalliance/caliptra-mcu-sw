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

mod alloc;
mod cert;
mod device_state;
mod dpe;
pub mod eat;
mod rng;
mod sha;
pub mod signed_eat;
mod wire;

pub use alloc::ApiAlloc;
pub use cert::populate_idev_ecc384_cert;
pub use device_state::{get_pcr_value, pcr_quote_ecc384, PCR_QUOTE_ECC384_LEN};
pub use dpe::{
    dpe_certify_key, dpe_certify_key_pubkey, dpe_get_cert_chain_chunk, dpe_sign_ecc_p384,
    walk_dpe_chain, DpeChainSink, DPE_LABEL_LEN, DPE_MAX_CHUNK_SIZE, DPE_MAX_LEAF_CERT_SIZE,
    DPE_P384_SIGNATURE_SIZE,
};
pub use rng::rng_generate;
pub use sha::{sha_finish, sha_init, sha_update, HashAlgo, HashState, SHA_CHUNK_SIZE};

pub use mcu_error::{McuErrorCode, McuResult};
