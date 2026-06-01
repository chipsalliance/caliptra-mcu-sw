// Licensed under the Apache-2.0 license

//! Certificate store for the spdm-lite PAL.
//!
//! Composes SPDM cert chains from three portions:
//! 1. Endorsement chain (static root CA or flash-backed, per slot)
//! 2. DPE device chain (IDevID → RT alias, from Caliptra Core)
//! 3. DPE leaf certificate (CertifyKey, fetched on demand)
//!
//! The endorsement portion is managed by [`SlotEndorsement`] — an enum
//! that dispatches to `ReadOnlyEndorsement` (slot 0) or
//! `ManagedEndorsement` (slots 1-2) without dynamic dispatch.

pub mod endorsement;
pub mod store;

use super::*;
use super::measurements::MeasurementProvider;
use endorsement::{slot_index, SUPPORTED_SLOT_MASK};
use mcu_caliptra_api_lite::{
    dpe_certify_key, dpe_get_cert_chain_chunk, dpe_sign_ecc_p384, walk_dpe_chain, ApiAlloc,
    DpeChainSink, DPE_LABEL_LEN, DPE_MAX_LEAF_CERT_SIZE,
};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_spdm_lite_traits::{SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};

/// 48-byte label fed to DPE `CertifyKey` for slot 0. Matches the
/// constant spdm-lib uses so the leaf-cert key continuity matches
/// what existing tooling expects.
pub const SLOT0_LEAF_LABEL: [u8; DPE_LABEL_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Default CertificateInfo for all Caliptra slots.
const DEFAULT_CERT_INFO: u8 = 0x01;

/// Default KeyUsageMask for all Caliptra slots.
const DEFAULT_KEY_USAGE_MASK: u16 = 0x0003;

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

impl<M: MeasurementProvider> SpdmPalCertStore for McuSpdmPal<M> {
    fn supported_slots(&self) -> u8 {
        SUPPORTED_SLOT_MASK
    }

    fn provisioned_slots(&self) -> u8 {
        let mut mask = 0u8;
        for (i, slot) in self.cert_store.cert_slots().iter().enumerate() {
            if slot.is_provisioned() {
                mask |= 1 << endorsement::DEFAULT_SLOT_MAP[i];
            }
        }
        mask
    }

    async fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if let Some(n) = self.cert_store.get_cached_chain_len(slot) {
            return Ok(n as usize);
        }
        let cert_slot = &self.cert_store.cert_slots()[idx];
        let endorsement_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .map_err(|_| INVARIANT)?;
        let dpe_len = walk_dpe_chain(self, &mut CountSink).await?;
        let leaf_len = probe_leaf_len(self).await?;
        let total = (endorsement_len as u32)
            .checked_add(dpe_len)
            .and_then(|n| n.checked_add(leaf_len as u32))
            .ok_or(INVARIANT)? as usize;
        self.cert_store.set_cached_chain_len(slot, total as u32);
        Ok(total)
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.cert_slots()[idx]
            .endorsement
            .root_cert_hash(SpdmPalAsymAlgo::EccP384, out)
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if dst.is_empty() {
            return Ok(0);
        }
        let total = self.cert_store.cached_chain_len_or_zero(slot);
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        // Chain layout: [endorsement] [DPE chain] [leaf cert]
        let cert_slot = &self.cert_store.cert_slots()[idx];
        let endorsement_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .map_err(|_| INVARIANT)?;
        let leaf_len = probe_leaf_len(self).await? as usize;
        let dpe_len = total - endorsement_len - leaf_len;

        let want = (total - offset).min(dst.len());
        let mut written = 0usize;
        let mut cur_offset = offset;

        // 1. Endorsement region
        if cur_offset < endorsement_len && written < want {
            let n = cert_slot
                .endorsement
                .read(
                    SpdmPalAsymAlgo::EccP384,
                    cur_offset,
                    &mut dst[written..want],
                )
                .map_err(|_| INVARIANT)?;
            written += n;
            cur_offset = offset + written;
        }

        // 2. DPE-chain region
        let dpe_start = endorsement_len;
        let dpe_end = dpe_start + dpe_len;
        if cur_offset < dpe_end && written < want {
            let dpe_off = cur_offset - dpe_start;
            let dpe_take = (dpe_end - cur_offset).min(want - written);
            let got = dpe_get_cert_chain_chunk(
                self,
                dpe_off as u32,
                &mut dst[written..written + dpe_take],
            )
            .await?;
            if got != dpe_take {
                return Err(INTERNAL_BUG);
            }
            written += dpe_take;
            cur_offset += dpe_take;
        }

        // 3. Leaf-cert region
        if cur_offset >= dpe_end && written < want {
            let mut leaf = ApiAlloc::alloc(self, leaf_len)?;
            let got = dpe_certify_key(self, &SLOT0_LEAF_LABEL, &mut leaf[..]).await?;
            if got != leaf_len {
                return Err(INTERNAL_BUG);
            }
            let leaf_off = cur_offset - dpe_end;
            let leaf_take = want - written;
            dst[written..written + leaf_take]
                .copy_from_slice(&leaf[leaf_off..leaf_off + leaf_take]);
            written += leaf_take;
        }
        Ok(written)
    }

    async fn sign_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        digest: &[u8],
        signature: &mut [u8],
    ) -> McuResult<usize> {
        let _idx = slot_index(slot).ok_or(INVARIANT)?;
        dpe_sign_ecc_p384(self, &SLOT0_LEAF_LABEL, digest, signature).await
    }

    async fn write_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        data: &[u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store
            .cert_slot_mut(idx)
            .endorsement
            .write(algo, data)?;
        self.cert_store.invalidate_cache(slot);
        Ok(())
    }

    async fn erase_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.cert_slot_mut(idx).endorsement.erase(algo)?;
        self.cert_store.invalidate_cache(slot);
        Ok(())
    }

    fn key_pair_id(&self, slot: u8) -> Option<u8> {
        let idx = slot_index(slot)?;
        self.cert_store.cert_slots()[idx].key_pair_id
    }

    fn cert_info(&self, slot: u8) -> Option<u8> {
        let idx = slot_index(slot)?;
        if !self.cert_store.cert_slots()[idx].is_provisioned() {
            return None;
        }
        Some(DEFAULT_CERT_INFO)
    }

    fn key_usage_mask(&self, slot: u8) -> Option<u16> {
        let idx = slot_index(slot)?;
        if !self.cert_store.cert_slots()[idx].is_provisioned() {
            return None;
        }
        Some(DEFAULT_KEY_USAGE_MASK)
    }

    #[inline]
    fn cached_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo) -> Option<[u8; 48]> {
        self.cert_store.cached_chain_digest(slot)
    }

    #[inline]
    fn cache_chain_digest(&self, slot: u8, _algo: SpdmPalHashAlgo, digest: &[u8]) {
        self.cert_store.cache_chain_digest(slot, digest);
    }

    async fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> McuResult<()> {
        mcu_caliptra_api_lite::rng_generate(self, out).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Probe the DPE leaf-cert size by calling `CertifyKey` and
/// discarding the cert bytes. Deterministic, so subsequent calls
/// produce identical sizes.
async fn probe_leaf_len<M: MeasurementProvider>(pal: &McuSpdmPal<M>) -> McuResult<usize> {
    let mut buf = ApiAlloc::alloc(pal, DPE_MAX_LEAF_CERT_SIZE)?;
    let n = dpe_certify_key(pal, &SLOT0_LEAF_LABEL, &mut buf[..]).await?;
    Ok(n)
}

/// Parse `len(TLV)` for the leading X.509 `SEQUENCE` in `buf` and
/// return `tag_and_length_bytes + content_bytes` — i.e. the total
/// DER encoding size of the first certificate in the chain. Returns
/// `None` on malformed input.
#[allow(dead_code)]
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
        // Total DER encoding = tag(1) + len-of-len(1) + len(2) + content(258) = 262
        let mut buf = [0u8; 262];
        buf[0] = 0x30;
        buf[1] = 0x82;
        buf[2] = 0x01;
        buf[3] = 0x02;
        assert_eq!(der_first_seq_len(&buf), Some(262));
    }

    #[test]
    fn der_malformed_returns_none() {
        assert_eq!(der_first_seq_len(&[]), None);
        assert_eq!(der_first_seq_len(&[0x31, 0x01]), None); // wrong tag
        assert_eq!(der_first_seq_len(&[0x30]), None); // truncated
    }
}
