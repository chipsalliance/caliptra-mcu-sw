// Licensed under the Apache-2.0 license

//! Certificate store for the spdm-lib PAL.
//!
//! Slot 0 composes an SPDM cert chain from three portions:
//! 1. static endorsement/root chain
//! 2. DPE device chain (IDevID → RT alias, from Caliptra Core)
//! 3. DPE leaf certificate (CertifyKey, fetched on demand)
//!
//! Managed slots store the endorsement/root portion installed by SET_CERTIFICATE.
//! [`SlotEndorsement`] dispatches to `ReadOnlyEndorsement` (slot 0) or
//! `ManagedEndorsement` (slots 1-2) without dynamic dispatch.

pub mod endorsement;
pub mod store;

use super::measurements::MeasurementProvider;
use super::*;
use caliptra_mcu_spdm_traits::{SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};
use core::sync::atomic::Ordering;
use endorsement::slot_index;
use mcu_caliptra_api_lite::{
    dpe_get_cert_chain_chunk, walk_dpe_chain, DpeChainSink, DPE_LABEL_LEN, DPE_MAX_CHUNK_SIZE,
};
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};

/// 48-byte label fed to DPE `CertifyKey`. Keep this stable so DPE
/// leaf-cert key continuity matches what existing tooling expects.
pub const DPE_LEAF_LABEL: [u8; DPE_LABEL_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// Default KeyUsageMask for all Caliptra slots.
const DEFAULT_KEY_USAGE_MASK: u16 = 0x0003;

/// SPDM CertModel AliasCert.
#[cfg(feature = "set-certificate")]
const CERT_MODEL_ALIAS_CERT: u8 = 2;

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

#[cfg(feature = "set-certificate")]
async fn validate_root_hash<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    root_hash: &[u8; 48],
    cert_chain: &[u8],
) -> McuResult<()> {
    let root_cert_len = der_first_seq_len(cert_chain).ok_or(INVARIANT)?;
    let sha_buf =
        mcu_caliptra_api_lite::ApiAlloc::alloc(pal, mcu_caliptra_api_lite::SHA_CONTEXT_SIZE)?;
    let mut state =
        mcu_caliptra_api_lite::sha_init(pal, sha_buf, mcu_caliptra_api_lite::HashAlgo::Sha384, &[])
            .await?;
    mcu_caliptra_api_lite::sha_update(
        pal,
        &mut state,
        checked_slice(cert_chain, 0, root_cert_len)?,
    )
    .await?;
    let mut digest = [0u8; 48];
    mcu_caliptra_api_lite::sha_finish(pal, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(INVARIANT);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming SET_CERTIFICATE validation helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "set-certificate")]
async fn validate_streamed_root_hash<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    managed: &endorsement::ManagedEndorsement,
    root_hash: &[u8; 48],
    data_len: usize,
) -> McuResult<()> {
    let first_cert_len = streamed_first_der_len(managed, data_len).await?;
    let sha_buf =
        mcu_caliptra_api_lite::ApiAlloc::alloc(pal, mcu_caliptra_api_lite::SHA_CONTEXT_SIZE)?;
    let mut state =
        mcu_caliptra_api_lite::sha_init(pal, sha_buf, mcu_caliptra_api_lite::HashAlgo::Sha384, &[])
            .await?;
    let mut offset = 0usize;
    let mut buf = [0u8; 256];
    while offset < first_cert_len {
        let n = (first_cert_len - offset).min(buf.len());
        let read = managed
            .read_stream_chunk(offset, checked_slice_mut(&mut buf, 0, n)?)
            .await?;
        if read != n {
            return Err(INVARIANT);
        }
        mcu_caliptra_api_lite::sha_update(pal, &mut state, checked_slice(&buf, 0, n)?).await?;
        offset += n;
    }
    let mut digest = [0u8; 48];
    mcu_caliptra_api_lite::sha_finish(pal, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(INVARIANT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn streamed_first_der_len(
    managed: &endorsement::ManagedEndorsement,
    data_len: usize,
) -> McuResult<usize> {
    let mut header = [0u8; 6];
    if data_len < 2
        || managed
            .read_stream_chunk(0, checked_slice_mut(&mut header, 0, 2)?)
            .await?
            != 2
    {
        return Err(INVARIANT);
    }
    if header[0] != 0x30 {
        return Err(INVARIANT);
    }
    let len_byte = header[1];
    let (header_len, content_len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || data_len < 2 + len_len {
            return Err(INVARIANT);
        }
        let len_buf = checked_slice_mut(&mut header, 2, len_len)?;
        if managed.read_stream_chunk(2, len_buf).await? != len_len {
            return Err(INVARIANT);
        }
        let mut content_len = 0usize;
        for &byte in checked_slice(&header, 2, len_len)? {
            content_len = content_len.checked_shl(8).ok_or(INVARIANT)?;
            content_len = content_len.checked_add(byte as usize).ok_or(INVARIANT)?;
        }
        (2 + len_len, content_len)
    };
    if content_len == 0 {
        return Err(INVARIANT);
    }
    let cert_len = header_len.checked_add(content_len).ok_or(INVARIANT)?;
    if cert_len > data_len {
        return Err(INVARIANT);
    }
    Ok(cert_len)
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

impl<M: MeasurementProvider> SpdmPalCertStore for McuSpdmPal<M> {
    fn supported_slots(&self) -> u8 {
        let mut mask = 0u8;
        for (i, slot) in self.cert_store.cert_slots().iter().enumerate() {
            if slot.is_supported() {
                mask |= 1 << endorsement::DEFAULT_SLOT_MAP[i];
            }
        }
        mask
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

    async fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;

        // 1. PRE-CHECK: Ensure Slot is provisioned and not undergoing updates before starting
        if self.cert_store.cert_slots()[idx]
            .write_in_progress
            .load(Ordering::Relaxed)
        {
            return Err(INVARIANT);
        }

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let capacity = cert_slot
            .endorsement
            .capacity(SpdmPalAsymAlgo::EccP384)
            .map_err(|_| INVARIANT)?;

        // 2. POST-CHECK: Verify Slot remained unlocked during the intermediate async .await points
        if self.cert_store.cert_slots()[idx]
            .write_in_progress
            .load(Ordering::Relaxed)
        {
            return Err(INVARIANT);
        }

        Ok(capacity)
    }

    #[inline]
    #[cfg(feature = "set-certificate")]
    fn set_certificate_authorized(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _key_pair_id: u8,
        _cert_model: u8,
        _erase: bool,
    ) -> bool {
        slot_index(slot)
            .and_then(|idx| self.cert_store.cert_slots().get(idx))
            .map(|slot| slot.is_writable())
            .unwrap_or(false)
    }

    #[cfg(feature = "set-certificate")]
    async fn validate_set_certificate_chain(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()> {
        if cert_model != CERT_MODEL_ALIAS_CERT {
            return Err(INVARIANT);
        }
        validate_root_hash(self, root_hash, cert_chain).await?;
        Ok(())
    }

    async fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;

        // 1. PRE-CHECK: Ensure Slot is provisioned and not undergoing updates before starting
        if self.cert_store.cert_slots()[idx]
            .write_in_progress
            .load(Ordering::Relaxed)
        {
            return Err(INVARIANT);
        }

        if let Some(n) = self.cert_store.cached_chain_len(slot) {
            return Ok(n as usize);
        }

        // Cache miss: Invalidate stale leaf and digest caches before starting recomputation
        self.cert_store.invalidate_cert_caches(slot);

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .map_err(|_| INVARIANT)?;
        let dpe_len = walk_dpe_chain(self, &mut CountSink).await?;
        let leaf_len = probe_leaf_len(self).await?;
        self.cert_store.set_cached_leaf_len(slot, leaf_len as u32);
        let total = (slot_chain_len as u32)
            .checked_add(dpe_len)
            .and_then(|n| n.checked_add(leaf_len as u32))
            .ok_or(INVARIANT)? as usize;

        // 2. POST-CHECK: Verify Slot remained unlocked during the intermediate async .await points
        if self.cert_store.cert_slots()[idx]
            .write_in_progress
            .load(Ordering::Relaxed)
        {
            return Err(INVARIANT);
        }

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
        let total = self.cert_store.cached_chain_len(slot).unwrap_or(0) as usize;
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot
            .endorsement
            .size(SpdmPalAsymAlgo::EccP384)
            .map_err(|_| INVARIANT)?;
        let want = (total - offset).min(dst.len());
        // Composed chain layout: [endorsement] [DPE chain] [leaf cert]
        let endorsement_len = slot_chain_len;
        let leaf_len = match self.cert_store.cached_leaf_len(slot) {
            Some(n) => n as usize,
            None => {
                let n = probe_leaf_len(self).await?;
                self.cert_store.set_cached_leaf_len(slot, n as u32);
                n
            }
        };
        let dpe_len = total - endorsement_len - leaf_len;
        let mut written = 0usize;
        let mut cur_offset = offset;

        // 1. Endorsement region
        if cur_offset < endorsement_len && written < want {
            let n = cert_slot
                .endorsement
                .read(
                    SpdmPalAsymAlgo::EccP384,
                    cur_offset,
                    checked_slice_mut(dst, written, want - written)?,
                )
                .await
                .map_err(|_| INVARIANT)?;
            written += n;
            cur_offset = offset + written;
        }

        // 2. DPE-chain region
        let dpe_start = endorsement_len;
        let dpe_end = dpe_start + dpe_len;
        while cur_offset < dpe_end && written < want {
            let dpe_off = cur_offset - dpe_start;
            let dpe_take = (dpe_end - cur_offset)
                .min(want - written)
                .min(DPE_MAX_CHUNK_SIZE);
            let got = dpe_get_cert_chain_chunk(
                self,
                dpe_off as u32,
                checked_slice_mut(dst, written, dpe_take)?,
            )
            .await?;
            if got != dpe_take {
                return Err(INTERNAL_BUG);
            }
            written += got;
            cur_offset += got;
        }

        // 3. Leaf-cert region
        if cur_offset >= dpe_end && written < want {
            let leaf_off = cur_offset - dpe_end;
            let leaf_take = (leaf_len - leaf_off).min(want - written);
            let got = caliptra_mcu_measurement_api::leaf_cert_slice(
                self.allocator,
                &DPE_LEAF_LABEL,
                leaf_off as u32,
                checked_slice_mut(dst, written, leaf_take)?,
            )
            .await
            .map_err(|_| INTERNAL_BUG)?;
            if got != leaf_take {
                return Err(INTERNAL_BUG);
            }
            written += got;
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
        caliptra_mcu_measurement_api::sign(self.allocator, &DPE_LEAF_LABEL, digest, signature)
            .await
            .map_err(|_| INTERNAL_BUG)
    }

    #[cfg(feature = "set-certificate")]
    async fn write_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        // Set write_in_progress to block transient readers during flash updates
        self.cert_store.cert_slots()[idx]
            .write_in_progress
            .store(true, Ordering::Relaxed);
        let result = async {
            let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                endorsement::SlotEndorsement::Managed(e) => *e,
                endorsement::SlotEndorsement::ReadOnly(_) => {
                    return Err(mcu_error::codes::NOT_IMPLEMENTED);
                }
                endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
            };
            let managed = managed
                .write_updated(algo, key_pair_id, cert_info, root_hash, data)
                .await?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
            cert_slot.key_pair_id = Some(key_pair_id);
            cert_slot.cert_info = Some(cert_info);
            Ok(())
        }
        .await;
        self.cert_store.cert_slots()[idx]
            .write_in_progress
            .store(false, Ordering::Relaxed);
        result?;
        self.cert_store.invalidate_cert_caches(slot);
        Ok(())
    }

    async fn begin_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        _key_pair_id: u8,
        cert_info: u8,
        _root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            if cert_info != CERT_MODEL_ALIAS_CERT {
                return Err(INVARIANT);
            }
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            self.cert_store.cert_slots()[idx]
                .write_in_progress
                .store(true, Ordering::Relaxed);
            let result = async {
                let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                    endorsement::SlotEndorsement::Managed(e) => *e,
                    endorsement::SlotEndorsement::ReadOnly(_) => {
                        return Err(mcu_error::codes::NOT_IMPLEMENTED);
                    }
                    endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
                };
                let managed = managed.begin_stream_update(algo, data_len).await?;
                let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
                cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
                cert_slot.clear_metadata();
                Ok(())
            }
            .await;
            if result.is_err() {
                self.cert_store.cert_slots()[idx]
                    .write_in_progress
                    .store(false, Ordering::Relaxed);
            }
            result
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, cert_info, data_len);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn write_cert_chain_stream_chunk(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        data: &[u8],
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                endorsement::SlotEndorsement::Managed(e) => *e,
                endorsement::SlotEndorsement::ReadOnly(_) => {
                    return Err(mcu_error::codes::NOT_IMPLEMENTED);
                }
                endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
            };
            if algo != SpdmPalAsymAlgo::EccP384 {
                return Err(INVARIANT);
            }
            managed.write_stream_chunk(offset, data).await
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, offset, data);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn finish_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            let result = async {
                let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                    endorsement::SlotEndorsement::Managed(e) => *e,
                    endorsement::SlotEndorsement::ReadOnly(_) => {
                        return Err(mcu_error::codes::NOT_IMPLEMENTED);
                    }
                    endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
                };
                validate_streamed_root_hash(self, &managed, root_hash, data_len).await?;
                let managed = managed
                    .finish_stream_update(algo, key_pair_id, cert_info, root_hash, data_len)
                    .await?;
                let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
                cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
                cert_slot.key_pair_id = Some(key_pair_id);
                cert_slot.cert_info = Some(cert_info);
                Ok(())
            }
            .await;
            self.cert_store.cert_slots()[idx]
                .write_in_progress
                .store(false, Ordering::Relaxed);
            result?;
            self.cert_store.invalidate_cert_caches(slot);
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, key_pair_id, cert_info, root_hash, data_len);
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    async fn abort_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            self.cert_store.cert_slots()[idx]
                .write_in_progress
                .store(false, Ordering::Relaxed);
            self.cert_store.invalidate_cert_caches(slot);
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = slot;
            Ok(())
        }
    }

    #[cfg(feature = "set-certificate")]
    async fn erase_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.cert_slots()[idx]
            .write_in_progress
            .store(true, Ordering::Relaxed);
        let result = async {
            let managed = match &self.cert_store.cert_slots()[idx].endorsement {
                endorsement::SlotEndorsement::Managed(e) => *e,
                endorsement::SlotEndorsement::ReadOnly(_) => {
                    return Err(mcu_error::codes::NOT_IMPLEMENTED);
                }
                endorsement::SlotEndorsement::Empty => return Err(INVARIANT),
            };
            let managed = managed.erase_updated(algo).await?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.endorsement = endorsement::SlotEndorsement::Managed(managed);
            cert_slot.clear_metadata();
            Ok(())
        }
        .await;
        self.cert_store.cert_slots()[idx]
            .write_in_progress
            .store(false, Ordering::Relaxed);
        result?;
        self.cert_store.invalidate_cert_caches(slot);
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
        self.cert_store.cert_slots()[idx].cert_info
    }

    fn key_usage_mask(&self, slot: u8) -> Option<u16> {
        let idx = slot_index(slot)?;
        let cert_slot = &self.cert_store.cert_slots()[idx];
        if !cert_slot.is_provisioned() {
            return None;
        }
        #[cfg(feature = "set-certificate")]
        {
            match &cert_slot.endorsement {
                endorsement::SlotEndorsement::Managed(e) => e.key_usage_mask(),
                _ => Some(DEFAULT_KEY_USAGE_MASK),
            }
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            Some(DEFAULT_KEY_USAGE_MASK)
        }
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
/// reading only its fixed response header. Deterministic, so
/// subsequent calls produce identical sizes.
async fn probe_leaf_len<M: MeasurementProvider>(pal: &McuSpdmPal<M>) -> McuResult<usize> {
    caliptra_mcu_measurement_api::leaf_cert_size(pal.allocator, &DPE_LEAF_LABEL)
        .await
        .map_err(|_| INTERNAL_BUG)
}

#[cfg(any(test, feature = "set-certificate"))]
fn checked_slice(src: &[u8], offset: usize, len: usize) -> McuResult<&[u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get(offset..end).ok_or(INVARIANT)
}

fn checked_slice_mut(src: &mut [u8], offset: usize, len: usize) -> McuResult<&mut [u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get_mut(offset..end).ok_or(INVARIANT)
}

/// Return the total encoded length of the first DER SEQUENCE in `buf`.
#[cfg(any(test, feature = "set-certificate"))]
fn der_first_seq_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != 0x30 {
        return None;
    }
    let len_byte = buf[1];
    let total = if len_byte & 0x80 == 0 {
        let content = len_byte as usize;
        if content == 0 {
            return None;
        }
        2usize.checked_add(content)?
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut content = 0usize;
        for &byte in buf.get(2..2 + n)? {
            content = content.checked_shl(8)?;
            content = content.checked_add(byte as usize)?;
        }
        if content == 0 {
            return None;
        }
        2usize.checked_add(n)?.checked_add(content)?
    };
    (total <= buf.len()).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::der_first_seq_len;

    #[test]
    fn der_first_sequence_length() {
        assert_eq!(der_first_seq_len(&[0x30, 0x01, 0x05]), Some(3));

        let mut long = [0u8; 262];
        long[..4].copy_from_slice(&[0x30, 0x82, 0x01, 0x02]);
        assert_eq!(der_first_seq_len(&long), Some(262));

        assert_eq!(der_first_seq_len(&[]), None);
        assert_eq!(der_first_seq_len(&[0x31, 0x01]), None);
        assert_eq!(der_first_seq_len(&[0x30]), None);
    }
}
