// Licensed under the Apache-2.0 license

//! Allocator-backed COSE_Sign1 EAT token generation via byte templates.

use crate::dpe::{dpe_sign_ecc_p384, DPE_LABEL_LEN, DPE_P384_SIGNATURE_SIZE};
use crate::eat::cbor_bstr_len;
use crate::sha::{sha_finish, sha_init, sha_update, HashAlgo, SHA_CONTEXT_SIZE};
use crate::ApiAlloc;
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

const KID_LEN: usize = 48;
const SIGNATURE_BSTR_HEADER: [u8; 2] = [0x58, 0x60];
const ECDSA_P384_SIGNATURE_LEN: usize = DPE_P384_SIGNATURE_SIZE;
const ES384_PROTECTED_HEADER: [u8; 5] = [0x44, 0xa1, 0x01, 0x38, 0x22];

// This signer currently supports only ES384/P-384. Keep algorithm-specific
// bytes isolated here so MLDSA87 can add another protected header/sign path.

// --- COSE_Sign1 byte layout ---
//
// d9 d9f7         TAG(55799) self-described CBOR
// d8 3d           TAG(61)    CWT
// d2              TAG(18)    COSE_Sign1
// 84              array(4)
// 44 a1 01 38 22  bstr(4) protected: {1: -35} (ES384)
// a1 04 58 30     unprotected: map(1) {4: bstr(48)} kid
// <48 bytes kid>
// <COSE payload bstr length prefix>
// <EAT claims payload>
// 58 60           bstr(96) signature
// <96 bytes signature>

#[rustfmt::skip]
const COSE_PREAMBLE: [u8; 16] = [
    0xd9, 0xd9, 0xf7,              // TAG(55799)
    0xd8, 0x3d,                     // TAG(61)
    0xd2,                           // TAG(18)
    0x84,                           // array(4)
    ES384_PROTECTED_HEADER[0], ES384_PROTECTED_HEADER[1], ES384_PROTECTED_HEADER[2],
    ES384_PROTECTED_HEADER[3], ES384_PROTECTED_HEADER[4],
    0xa1, 0x04, 0x58, 0x30,        // map(1) {4: bstr(48)}
];

// --- Sig_structure byte layout ---
//
// 84                          array(4)
// 6a "Signature1"             tstr(10)
// 44 a1 01 38 22              bstr(4) protected: {1: -35}
// 40                          bstr(0) external_aad
// <COSE payload bstr length prefix>
// <EAT claims payload>

#[rustfmt::skip]
const SIG_PREAMBLE: [u8; 18] = [
    0x84,                                                                // array(4)
    0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // tstr(10) "Signature1"
    ES384_PROTECTED_HEADER[0], ES384_PROTECTED_HEADER[1], ES384_PROTECTED_HEADER[2],
    ES384_PROTECTED_HEADER[3], ES384_PROTECTED_HEADER[4],
    0x40,                                                                // bstr(0) empty
];

pub const fn cose_sign1_len(payload_len: usize) -> usize {
    COSE_PREAMBLE.len()
        + KID_LEN
        + cbor_bstr_len(payload_len)
        + SIGNATURE_BSTR_HEADER.len()
        + ECDSA_P384_SIGNATURE_LEN
}

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
    /// - `payload` — encoded EAT claims payload
    /// - `kid` — 48-byte key identifier (SHA-384 of public key)
    /// - `eat_buffer` — output buffer sized for [`cose_sign1_len`]
    pub async fn generate_with_kid<A: ApiAlloc>(
        &self,
        alloc: &A,
        payload: &[u8],
        kid: &[u8],
        eat_buffer: &mut [u8],
    ) -> McuResult<usize> {
        let kid_arr: &[u8; KID_LEN] = kid.try_into().map_err(|_| INVARIANT)?;
        let cose_len = cose_sign1_len(payload.len());
        if eat_buffer.len() < cose_len {
            return Err(INVARIANT);
        }

        // Walk `eat_buffer` with `split_first_chunk_mut` so each
        // fixed-size write becomes a panic-free `*chunk = SRC` array
        // assignment instead of a `copy_from_slice` length-check.
        let rest = eat_buffer;
        let (preamble_slot, rest) = rest
            .split_first_chunk_mut::<{ COSE_PREAMBLE.len() }>()
            .ok_or(INVARIANT)?;
        *preamble_slot = COSE_PREAMBLE;
        let (kid_slot, rest) = rest.split_first_chunk_mut::<KID_LEN>().ok_or(INVARIANT)?;
        *kid_slot = *kid_arr;
        let pl_hdr_len =
            write_cose_payload_bstr_len(rest, payload.len()).ok_or(INVARIANT)?;
        let rest = rest.get_mut(pl_hdr_len..).ok_or(INVARIANT)?;
        let (payload_slot, rest) = rest.split_at_mut_checked(payload.len()).ok_or(INVARIANT)?;
        // Variable-length payload: still requires `copy_from_slice`,
        // but only one panic site for this entire function.
        payload_slot.copy_from_slice(payload);
        let (sig_hdr_slot, rest) = rest
            .split_first_chunk_mut::<{ SIGNATURE_BSTR_HEADER.len() }>()
            .ok_or(INVARIANT)?;
        *sig_hdr_slot = SIGNATURE_BSTR_HEADER;
        let (sig_slot, _) = rest
            .split_first_chunk_mut::<ECDSA_P384_SIGNATURE_LEN>()
            .ok_or(INVARIANT)?;
        self.sign_cose_sig_context(alloc, payload, sig_slot).await?;

        Ok(cose_len)
    }

    /// Hash the COSE Sig_structure and sign via DPE — all alloc-backed.
    /// Writes the signature directly into `sig_out` to avoid an extra
    /// 96-byte buffer in the caller's async frame.
    async fn sign_cose_sig_context<A: ApiAlloc>(
        &self,
        alloc: &A,
        payload: &[u8],
        sig_out: &mut [u8; DPE_P384_SIGNATURE_SIZE],
    ) -> McuResult<()> {
        let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
        let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &SIG_PREAMBLE).await?;
        let mut payload_header = [0u8; 9];
        let payload_header_len =
            write_cose_payload_bstr_len(&mut payload_header, payload.len()).ok_or(INVARIANT)?;
        sha_update(alloc, &mut state, &payload_header[..payload_header_len]).await?;
        sha_update(alloc, &mut state, payload).await?;
        let mut hash = [0u8; 48];
        sha_finish(alloc, &mut state, &mut hash).await?;

        dpe_sign_ecc_p384(alloc, self.key_label, &hash, sig_out).await?;
        Ok(())
    }
}

fn write_cose_payload_bstr_len(out: &mut [u8], len: usize) -> Option<usize> {
    write_type_header(out, 2, len as u64)
}

fn write_type_header(out: &mut [u8], major: u8, value: u64) -> Option<usize> {
    if value <= 23 {
        *out.get_mut(0)? = (major << 5) | value as u8;
        Some(1)
    } else if value <= u8::MAX as u64 {
        *out.get_mut(0)? = (major << 5) | 24;
        *out.get_mut(1)? = value as u8;
        Some(2)
    } else if value <= u16::MAX as u64 {
        *out.get_mut(0)? = (major << 5) | 25;
        out.get_mut(1..3)?
            .copy_from_slice(&(value as u16).to_be_bytes());
        Some(3)
    } else if value <= u32::MAX as u64 {
        *out.get_mut(0)? = (major << 5) | 26;
        out.get_mut(1..5)?
            .copy_from_slice(&(value as u32).to_be_bytes());
        Some(5)
    } else {
        *out.get_mut(0)? = (major << 5) | 27;
        out.get_mut(1..9)?.copy_from_slice(&value.to_be_bytes());
        Some(9)
    }
}
