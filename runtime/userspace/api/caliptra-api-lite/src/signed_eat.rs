// Licensed under the Apache-2.0 license

//! Allocator-backed COSE_Sign1 EAT token generation via byte templates.
//!
//! Uses pre-computed CBOR byte layouts for the COSE_Sign1 envelope and
//! Sig_structure, replacing all CborEncoder calls with `copy_from_slice`.

use crate::dpe::{dpe_sign_ecc_p384, DPE_LABEL_LEN, DPE_P384_SIGNATURE_SIZE};
use crate::eat::EAT_PAYLOAD_LEN;
use crate::sha::{sha_finish, sha_init, sha_update, HashAlgo};
use crate::ApiAlloc;
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

const KID_LEN: usize = 48;

/// Total size of the COSE_Sign1 output (16 preamble + 48 kid + 2 + 206 payload + 2 + 96 sig).
pub const COSE_SIGN1_LEN: usize = 370;

/// Minimum scratch buffer size for the Sig_structure (20 header + 206 payload).
pub const SIG_STRUCTURE_LEN: usize = 226;

// --- COSE_Sign1 byte layout ---
//
// d9 d9f7         TAG(55799) self-described CBOR
// d8 3d           TAG(61)    CWT
// d2              TAG(18)    COSE_Sign1
// 84              array(4)
// 44 a1 01 38 22  bstr(4) protected: {1: -35} (ES384)
// a1 04 58 30     unprotected: map(1) {4: bstr(48)} kid
// <48 bytes kid>
// 58 ce           bstr(206) payload
// <206 bytes payload>
// 58 60           bstr(96) signature
// <96 bytes signature>

#[rustfmt::skip]
const COSE_PREAMBLE: [u8; 16] = [
    0xd9, 0xd9, 0xf7,              // TAG(55799)
    0xd8, 0x3d,                     // TAG(61)
    0xd2,                           // TAG(18)
    0x84,                           // array(4)
    0x44, 0xa1, 0x01, 0x38, 0x22,  // bstr(4) {1: -35} ES384
    0xa1, 0x04, 0x58, 0x30,        // map(1) {4: bstr(48)}
];

// --- Sig_structure byte layout ---
//
// 84                          array(4)
// 6a "Signature1"             tstr(10)
// 44 a1 01 38 22              bstr(4) protected: {1: -35}
// 40                          bstr(0) external_aad
// 58 ce                       bstr(206) payload
// <206 bytes payload>

#[rustfmt::skip]
const SIG_HEADER: [u8; 20] = [
    0x84,                                                                // array(4)
    0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // tstr(10) "Signature1"
    0x44, 0xa1, 0x01, 0x38, 0x22,                                       // bstr(4) {1:-35}
    0x40,                                                                // bstr(0) empty
    0x58, 0xce,                                                          // bstr(206)
];

/// Lightweight EAT signer backed by [`ApiAlloc`].
///
/// Unlike the `caliptra-api` `SignedEat`, this version routes all DPE
/// and SHA operations through caliptra-api-lite, which allocates
/// mailbox request/response buffers from a [`BitmapAllocator`] instead
/// of the async stack.
pub struct SignedEatLite<'a> {
    key_label: &'a [u8; DPE_LABEL_LEN],
}

impl<'a> SignedEatLite<'a> {
    pub fn new(key_label: &'a [u8; DPE_LABEL_LEN]) -> Self {
        Self { key_label }
    }

    /// Generate a COSE_Sign1 EAT token with a `kid` unprotected header.
    ///
    /// # Parameters
    /// - `alloc` — allocator for DPE/SHA mailbox buffers
    /// - `payload` — 206-byte EAT claims payload (from `stamp_eat_payload`)
    /// - `kid` — 48-byte key identifier (SHA-384 of public key)
    /// - `eat_buffer` — output buffer (≥ [`COSE_SIGN1_LEN`] bytes)
    /// - `sig_scratch` — scratch for Sig_structure (≥ [`SIG_STRUCTURE_LEN`] bytes)
    pub async fn generate_with_kid<A: ApiAlloc>(
        &self,
        alloc: &A,
        payload: &[u8],
        kid: &[u8],
        eat_buffer: &mut [u8],
        sig_scratch: &mut [u8],
    ) -> McuResult<usize> {
        if payload.len() != EAT_PAYLOAD_LEN || kid.len() != KID_LEN {
            return Err(INVARIANT);
        }
        if eat_buffer.len() < COSE_SIGN1_LEN || sig_scratch.len() < SIG_STRUCTURE_LEN {
            return Err(INVARIANT);
        }

        // 1. Build Sig_structure in scratch: header(20) + payload(206) = 226 bytes
        sig_scratch[..20].copy_from_slice(&SIG_HEADER);
        sig_scratch[20..SIG_STRUCTURE_LEN].copy_from_slice(payload);

        // 2. Hash Sig_structure and sign via DPE (alloc-backed)
        let signature = self
            .sign_context(alloc, &sig_scratch[..SIG_STRUCTURE_LEN])
            .await?;

        // 3. Assemble COSE_Sign1 output
        eat_buffer[0..16].copy_from_slice(&COSE_PREAMBLE);
        eat_buffer[16..64].copy_from_slice(kid);
        eat_buffer[64..66].copy_from_slice(&[0x58, 0xce]); // bstr(206)
        eat_buffer[66..272].copy_from_slice(payload);
        eat_buffer[272..274].copy_from_slice(&[0x58, 0x60]); // bstr(96)
        eat_buffer[274..COSE_SIGN1_LEN].copy_from_slice(&signature);

        Ok(COSE_SIGN1_LEN)
    }

    /// Hash the Sig_structure and sign via DPE — all alloc-backed.
    async fn sign_context<A: ApiAlloc>(
        &self,
        alloc: &A,
        sig_context: &[u8],
    ) -> McuResult<[u8; DPE_P384_SIGNATURE_SIZE]> {
        let mut state = sha_init(alloc, HashAlgo::Sha384, &[]).await?;
        sha_update(alloc, &mut state, sig_context).await?;
        let mut hash = [0u8; 48];
        sha_finish(alloc, &mut state, &mut hash).await?;

        let mut sig = [0u8; DPE_P384_SIGNATURE_SIZE];
        dpe_sign_ecc_p384(alloc, self.key_label, &hash, &mut sig).await?;
        Ok(sig)
    }
}
