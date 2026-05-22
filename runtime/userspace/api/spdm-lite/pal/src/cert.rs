// Licensed under the Apache-2.0 license

//! Caliptra-DPE–backed [`SpdmPalCertStore`] for [`McuSpdmPal`].
//!
//! Slot 0 only. The full cert chain presented to SPDM is the
//! concatenation of:
//!
//! 1. Caliptra's DPE-managed chain bytes (IDevID → … → RT alias),
//!    fetched in 1 KB chunks via the `INVOKE_DPE / GetCertificateChain`
//!    mailbox command.
//! 2. The DPE-derived leaf X.509 cert produced by
//!    `INVOKE_DPE / CertifyKey` with a stable per-slot label.
//!
//! No persistent caching of leaf bytes is required because
//! Caliptra's hardware ECDSA uses HMAC-DRBG (RFC-6979–style)
//! `k`-derivation, so every `CertifyKey` call with the same label
//! produces byte-identical output. We only cache the chain *length*
//! (4 B/slot) and the full SPDM cert-chain *digest* (48 B/slot),
//! both lazily populated.

use super::*;
use mcu_caliptra_api_lite::{
    dpe_certify_key, dpe_get_cert_chain_chunk, sha_finish, sha_init, sha_update, walk_dpe_chain,
    ApiAlloc, DpeChainSink, HashAlgo as ApiHashAlgo, DPE_LABEL_LEN, DPE_MAX_CHUNK_SIZE,
    DPE_MAX_LEAF_CERT_SIZE,
};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_spdm_lite_traits::{SpdmPalCertStore, SpdmPalHashAlgo, MAX_SLOTS};

/// Slot 0 only.
const PROVISIONED: u8 = 0b0000_0001;

/// 48-byte label fed to DPE `CertifyKey` for slot 0. Matches the
/// constant spdm-lib uses so the leaf-cert key continuity matches
/// what existing tooling expects.
const SLOT0_LEAF_LABEL: [u8; DPE_LABEL_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

// ---------------------------------------------------------------------------
// Sinks for `walk_dpe_chain`
// ---------------------------------------------------------------------------

/// Counts bytes, discards them. Used to probe DPE chain length.
struct CountSink;
impl DpeChainSink for CountSink {
    async fn on_chunk(&mut self, _: &[u8]) -> McuResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

impl SpdmPalCertStore for McuSpdmPal {
    #[inline]
    fn provisioned_slots(&self) -> u8 {
        PROVISIONED
    }

    async fn cert_chain_len(&self, _io: &Self::Io<'_>, slot: u8) -> McuResult<usize> {
        check_slot(slot)?;
        if let Some(n) = self.get_cached_chain_len(slot) {
            return Ok(n as usize);
        }
        // Probe DPE chain length + measure leaf-cert size.
        let dpe_len = walk_dpe_chain(self, &mut CountSink).await?;
        let leaf_len = probe_leaf_len(self).await?;
        let total = dpe_len.checked_add(leaf_len as u32).ok_or(INVARIANT)? as usize;
        self.set_cached_chain_len(slot, total as u32);
        Ok(total)
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        check_slot(slot)?;
        let api_algo = match algo {
            SpdmPalHashAlgo::Sha384 => ApiHashAlgo::Sha384,
        };

        // Single pool buffer reused across iterations. We fetch the
        // first chunk to learn the IDevID DER length, then drive a
        // unified loop that re-uses the same buffer and hash state
        // for every subsequent chunk — collapsing what would
        // otherwise be two distinct async sub-futures into one.
        let mut buf = ApiAlloc::alloc(self, DPE_MAX_CHUNK_SIZE)?;
        let mut offset: u32 = 0;
        let mut got = dpe_get_cert_chain_chunk(self, offset, &mut buf[..]).await?;
        if got == 0 {
            return Err(INTERNAL_BUG);
        }
        let root_len = der_first_seq_len(&buf[..got]).ok_or(INTERNAL_BUG)?;
        if root_len == 0 {
            return Err(INTERNAL_BUG);
        }

        // Empty-seed init: `sha_init` caps its seed at 512 B but
        // Caliptra's IDevID cert is typically ~600–800 B, so we
        // always stream the bytes through `sha_update`.
        let mut state = sha_init(self, api_algo, &[]).await?;
        let mut remaining = root_len;
        loop {
            let take = got.min(remaining);
            sha_update(self, &mut state, &buf[..take]).await?;
            remaining -= take;
            if remaining == 0 {
                break;
            }
            offset = offset.checked_add(take as u32).ok_or(INVARIANT)?;
            got = dpe_get_cert_chain_chunk(self, offset, &mut buf[..]).await?;
            if got == 0 {
                return Err(INTERNAL_BUG);
            }
        }
        sha_finish(self, &mut state, out).await
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        check_slot(slot)?;
        if dst.is_empty() {
            return Ok(0);
        }
        let total = self.cached_chain_len_or_zero(slot);
        // If unknown, refuse — callers always learn length first.
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        // Splice DPE chain bytes (`[0, dpe_len)`) with leaf cert
        // bytes (`[dpe_len, total)`). We don't cache the dpe vs
        // leaf split — recompute by probing once via CertifyKey
        // (size only) if needed.
        let leaf_len = probe_leaf_len(self).await? as usize;
        if leaf_len > total {
            return Err(INTERNAL_BUG);
        }
        let dpe_len = total - leaf_len;

        let want = (total - offset).min(dst.len());
        let mut written = 0usize;
        // 1. DPE-chain region
        if offset < dpe_len {
            let dpe_take = (dpe_len - offset).min(want);
            let got = dpe_get_cert_chain_chunk(self, offset as u32, &mut dst[..dpe_take]).await?;
            if got != dpe_take {
                return Err(INTERNAL_BUG);
            }
            written += dpe_take;
        }
        // 2. Leaf-cert region
        if written < want {
            // Re-derive the leaf into a transient pool slot, then copy the
            // requested window. Bytes are deterministic across calls.
            let mut leaf = ApiAlloc::alloc(self, leaf_len)?;
            let got = dpe_certify_key(self, &SLOT0_LEAF_LABEL, &mut leaf[..]).await?;
            if got != leaf_len {
                return Err(INTERNAL_BUG);
            }
            let leaf_off = (offset + written).saturating_sub(dpe_len);
            let leaf_take = want - written;
            dst[written..written + leaf_take]
                .copy_from_slice(&leaf[leaf_off..leaf_off + leaf_take]);
            written += leaf_take;
        }
        Ok(written)
    }

    #[inline]
    fn cached_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo) -> Option<[u8; 48]> {
        if slot >= MAX_SLOTS {
            return None;
        }
        // SAFETY: single-task responder invariant.
        unsafe { (*self.cached_chain_digest.get())[slot as usize] }
    }

    #[inline]
    fn cache_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo, digest: &[u8]) {
        if slot >= MAX_SLOTS || digest.len() > 48 {
            return;
        }
        let mut entry = [0u8; 48];
        entry[..digest.len()].copy_from_slice(digest);
        // SAFETY: single-task responder invariant.
        unsafe {
            (*self.cached_chain_digest.get())[slot as usize] = Some(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn check_slot(slot: u8) -> McuResult<()> {
    if slot >= MAX_SLOTS || (PROVISIONED & (1u8 << slot)) == 0 {
        return Err(INVARIANT);
    }
    Ok(())
}

impl McuSpdmPal {
    #[inline]
    fn get_cached_chain_len(&self, slot: u8) -> Option<u32> {
        if slot >= MAX_SLOTS {
            return None;
        }
        // SAFETY: single-task responder invariant.
        unsafe { (*self.cached_chain_len.get())[slot as usize] }
    }

    #[inline]
    fn cached_chain_len_or_zero(&self, slot: u8) -> usize {
        self.get_cached_chain_len(slot).unwrap_or(0) as usize
    }

    #[inline]
    fn set_cached_chain_len(&self, slot: u8, len: u32) {
        if slot >= MAX_SLOTS {
            return;
        }
        // SAFETY: single-task responder invariant.
        unsafe {
            (*self.cached_chain_len.get())[slot as usize] = Some(len);
        }
    }
}

/// Probe the DPE leaf-cert size by calling `CertifyKey` and
/// discarding the cert bytes. Deterministic, so subsequent calls
/// produce identical sizes.
async fn probe_leaf_len(pal: &McuSpdmPal) -> McuResult<usize> {
    let mut buf = ApiAlloc::alloc(pal, DPE_MAX_LEAF_CERT_SIZE)?;
    let n = dpe_certify_key(pal, &SLOT0_LEAF_LABEL, &mut buf[..]).await?;
    Ok(n)
}

/// Parse `len(TLV)` for the leading X.509 `SEQUENCE` in `buf` and
/// return `tag_and_length_bytes + content_bytes` — i.e. the total
/// DER encoding size of the first certificate in the chain. Returns
/// `None` on malformed input.
fn der_first_seq_len(buf: &[u8]) -> Option<usize> {
    // Tag 0x30 = SEQUENCE.
    if buf.len() < 2 || buf[0] != 0x30 {
        return None;
    }
    let len_byte = buf[1];
    if len_byte & 0x80 == 0 {
        // Short form: length fits in 7 bits.
        Some(2 + len_byte as usize)
    } else {
        // Long form: low 7 bits = number of length bytes.
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut content = 0usize;
        for &b in &buf[2..2 + n] {
            content = content.checked_shl(8)?;
            content = content.checked_add(b as usize)?;
        }
        Some(2 + n + content)
    }
}

#[cfg(test)]
mod tests {
    use super::der_first_seq_len;

    #[test]
    fn der_short_form() {
        // SEQUENCE { 0x05 } len-byte = 0x01 → total = 2 + 1 = 3
        assert_eq!(der_first_seq_len(&[0x30, 0x01, 0x05]), Some(3));
    }

    #[test]
    fn der_long_form_two_byte_len() {
        // SEQUENCE, length-of-length = 2, content_len = 0x0102 = 258
        let mut buf = vec![0x30, 0x82, 0x01, 0x02];
        buf.resize(2 + 2 + 258, 0);
        assert_eq!(der_first_seq_len(&buf), Some(2 + 2 + 258));
    }

    #[test]
    fn der_malformed_returns_none() {
        assert_eq!(der_first_seq_len(&[]), None);
        assert_eq!(der_first_seq_len(&[0x31, 0x01]), None); // wrong tag
        assert_eq!(der_first_seq_len(&[0x30]), None); // truncated
    }
}
