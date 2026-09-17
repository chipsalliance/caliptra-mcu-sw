// Licensed under the Apache-2.0 license

//! Certificate store for the spdm-lib PAL.
//!
//! Slot 0 composes an SPDM cert chain from three portions:
//! 1. static endorsement/root chain
//! 2. DPE device chain (IDevID → RT alias, from Caliptra Core)
//! 3. DPE leaf certificate (CertifyKey, fetched on demand)
//!
//! Managed AliasCert slots store the Owner endorsement chain installed by
//! SET_CERTIFICATE and expose it followed by the FMC/RT alias and DPE leaf tail.
//! [`SlotEndorsement`] dispatches to `ReadOnlyEndorsement` (slot 0) or
//! `SingleManagedChain` (slots 1-2) without dynamic dispatch.

pub mod endorsement;
pub mod store;

use super::measurements::MeasurementProvider;
use super::*;
#[cfg(feature = "set-certificate")]
use caliptra_mcu_cert_store::{
    certificate::{certificate_len, validate_endorsement},
    errors as cert_errors,
};
use caliptra_mcu_spdm_traits::{SigningInput, SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHashAlgo};
use core::ops::Range;
use endorsement::slot_index;
use mcu_caliptra_api::{
    dpe_get_cert_chain_chunk, walk_dpe_chain, DpeChainSink, DpeProfile, DPE_LABEL_LEN,
    DPE_MAX_CHUNK_SIZE,
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

/// Snapshot the managed flash region serving `algo` in slot `idx`.
///
/// `NOT_IMPLEMENTED` for a read-only slot so the stack can report
/// UnsupportedRequest; `INVARIANT` when the slot is empty or has no
/// region for that algorithm.
#[cfg(feature = "set-certificate")]
fn managed_endorsement(
    store: &store::TaskCertStore,
    idx: usize,
    algo: SpdmPalAsymAlgo,
) -> McuResult<endorsement::SingleManagedEndorsement> {
    match &store.cert_slots()[idx].endorsement {
        endorsement::SlotEndorsement::Managed(m) => {
            m.get_endorsement(algo).copied().ok_or(INVARIANT)
        }
        endorsement::SlotEndorsement::ReadOnly(_) => Err(mcu_error::codes::NOT_IMPLEMENTED),
        endorsement::SlotEndorsement::Empty => Err(INVARIANT),
    }
}

/// Write an updated region back into its slot.
///
/// Deliberately re-reads the slot rather than writing back a whole
/// snapshot: the write lock is per algorithm, so a write to the other
/// algorithm's region may have landed while we were awaiting flash.
#[cfg(feature = "set-certificate")]
fn commit_managed_endorsement(
    store: &store::TaskCertStore,
    idx: usize,
    chain: endorsement::SingleManagedEndorsement,
) -> McuResult<()> {
    let cert_slot = store.cert_slot_mut(idx).ok_or(INVARIANT)?;
    match &mut cert_slot.endorsement {
        endorsement::SlotEndorsement::Managed(m) => {
            m.set_endorsement(chain);
            Ok(())
        }
        _ => Err(INVARIANT),
    }
}

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

/// Locate the authoritative LDevID certificate without assuming that the
/// optional manufacturing IDevID certificate was prepended to the DPE chain.
struct DpeAnchorScanner<'a> {
    anchor: &'a [u8],
    found: bool,
    matches: bool,
    cert_len: usize,
    cert_bytes_left: usize,
    skip_len: usize,
    header: [u8; 6],
    header_len: usize,
}

impl<'a> DpeAnchorScanner<'a> {
    fn new(anchor: &'a [u8]) -> Self {
        Self {
            anchor,
            found: false,
            matches: true,
            cert_len: 0,
            cert_bytes_left: 0,
            skip_len: 0,
            header: [0; 6],
            header_len: 0,
        }
    }

    fn consume(&mut self, chunk: &[u8]) -> McuResult<()> {
        let mut pos = 0usize;
        while !self.found && pos < chunk.len() {
            if self.cert_bytes_left > 0 {
                let take = self.cert_bytes_left.min(chunk.len() - pos);
                let offset = self.cert_len - self.cert_bytes_left;
                if self.matches {
                    self.matches =
                        self.anchor.get(offset..offset + take) == Some(&chunk[pos..pos + take]);
                }
                self.cert_bytes_left -= take;
                self.skip_len = self.skip_len.checked_add(take).ok_or(INVARIANT)?;
                pos += take;
                if self.cert_bytes_left == 0 {
                    self.found = self.matches;
                    self.matches = true;
                }
                continue;
            }

            if self.header_len == self.header.len() {
                return Err(INVARIANT);
            }
            self.header[self.header_len] = chunk[pos];
            self.matches &= self.anchor.get(self.header_len) == Some(&chunk[pos]);
            self.header_len += 1;
            self.skip_len = self.skip_len.checked_add(1).ok_or(INVARIANT)?;
            pos += 1;

            if let Some(cert_len) = der_first_seq_len(&self.header[..self.header_len]) {
                self.cert_len = cert_len;
                self.matches &= cert_len == self.anchor.len();
                self.cert_bytes_left = cert_len.checked_sub(self.header_len).ok_or(INVARIANT)?;
                self.header_len = 0;
                if self.cert_bytes_left == 0 {
                    self.found = self.matches;
                    self.matches = true;
                }
            }
        }
        Ok(())
    }
}

impl DpeChainSink for DpeAnchorScanner<'_> {
    async fn on_chunk(&mut self, chunk: &[u8]) -> McuResult<()> {
        self.consume(chunk)
    }
}

struct ChainLayout {
    endorsement: Range<usize>,
    dpe: Range<usize>,
    leaf: Range<usize>,
    dpe_source_offset: usize,
}

impl ChainLayout {
    fn new(
        endorsement_len: usize,
        full_dpe_len: usize,
        dpe_source_offset: usize,
        leaf_len: usize,
    ) -> McuResult<Self> {
        let dpe_len = full_dpe_len
            .checked_sub(dpe_source_offset)
            .ok_or(INVARIANT)?;
        let dpe_end = endorsement_len.checked_add(dpe_len).ok_or(INVARIANT)?;
        let leaf_end = dpe_end.checked_add(leaf_len).ok_or(INVARIANT)?;
        Ok(Self {
            endorsement: 0..endorsement_len,
            dpe: endorsement_len..dpe_end,
            leaf: dpe_end..leaf_end,
            dpe_source_offset,
        })
    }

    fn from_total(
        endorsement_len: usize,
        total: usize,
        dpe_source_offset: usize,
        leaf_len: usize,
    ) -> McuResult<Self> {
        let leaf_start = total.checked_sub(leaf_len).ok_or(INVARIANT)?;
        if leaf_start < endorsement_len {
            return Err(INVARIANT);
        }
        Ok(Self {
            endorsement: 0..endorsement_len,
            dpe: endorsement_len..leaf_start,
            leaf: leaf_start..total,
            dpe_source_offset,
        })
    }

    fn total_len(&self) -> usize {
        self.leaf.end
    }
}

#[cfg(feature = "set-certificate")]
async fn validate_root_hash<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    root_hash: &[u8; 48],
    cert_chain: &[u8],
) -> McuResult<()> {
    let root_cert_len = certificate_len(cert_chain)?;
    let root_cert = cert_chain
        .get(..root_cert_len)
        .ok_or(cert_errors::INVALID_ENDORSEMENT)?;
    let sha_buf =
        mcu_caliptra_api::ScratchAlloc::alloc(pal.allocator, mcu_caliptra_api::SHA_CONTEXT_SIZE)?;
    let mut state = mcu_caliptra_api::sha_init(
        pal.allocator,
        sha_buf,
        mcu_caliptra_api::HashAlgo::Sha384,
        &[],
    )
    .await?;
    mcu_caliptra_api::sha_update(pal.allocator, &mut state, root_cert).await?;
    let mut digest = [0u8; 48];
    mcu_caliptra_api::sha_finish(pal.allocator, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming SET_CERTIFICATE validation helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "set-certificate")]
async fn validate_streamed_root_hash<A: mcu_caliptra_api::ScratchAlloc>(
    alloc: &A,
    managed: &endorsement::SingleManagedEndorsement,
    root_hash: &[u8; 48],
    data_len: usize,
) -> McuResult<()> {
    let first_cert_len = streamed_first_der_len(managed, data_len).await?;
    let sha_buf = alloc.alloc(mcu_caliptra_api::SHA_CONTEXT_SIZE)?;
    let mut state =
        mcu_caliptra_api::sha_init(alloc, sha_buf, mcu_caliptra_api::HashAlgo::Sha384, &[]).await?;
    let mut offset = 0usize;
    let mut buf = [0u8; 256];
    while offset < first_cert_len {
        let n = (first_cert_len - offset).min(buf.len());
        let read = managed
            .read_stream_chunk(offset, checked_slice_mut(&mut buf, 0, n)?)
            .await?;
        if read != n {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        mcu_caliptra_api::sha_update(alloc, &mut state, checked_slice(&buf, 0, n)?).await?;
        offset += n;
    }
    let mut digest = [0u8; 48];
    mcu_caliptra_api::sha_finish(alloc, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn streamed_first_der_len(
    managed: &endorsement::SingleManagedEndorsement,
    data_len: usize,
) -> McuResult<usize> {
    let mut header = [0u8; 6];
    let header_len = header.len().min(data_len);
    if managed
        .read_stream_chunk(0, &mut header[..header_len])
        .await?
        != header_len
    {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    let cert_len = certificate_len(&header[..header_len])?;
    if cert_len > data_len {
        return Err(cert_errors::INVALID_ENDORSEMENT);
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

    #[cfg(feature = "set-certificate")]
    fn resolve_set_certificate_key(&self, slot: u8, explicit_key: Option<u8>) -> McuResult<u8> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        let role = endorsement::endorsement_role(idx).ok_or(INVARIANT)?;
        let policy = self.cert_store.shared().policy();
        let configured = policy.key_for_role(role)?;
        let key_pair_id = explicit_key.unwrap_or(configured.key_pair_id());
        policy.validate_key(role, key_pair_id)?;
        Ok(key_pair_id)
    }

    fn provisioned_slots(&self, algo: SpdmPalAsymAlgo) -> u8 {
        let mut mask = 0u8;
        for (i, slot) in self.cert_store.cert_slots().iter().enumerate() {
            if slot.is_provisioned(algo) {
                mask |= 1 << endorsement::DEFAULT_SLOT_MAP[i];
            }
        }
        mask
    }

    async fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;

        if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
            return Err(INVARIANT);
        }

        // SlotSizeRequested describes endorsement storage. The generated DPE
        // and leaf certificates appended to GET_CERTIFICATE are not stored here.
        self.cert_store.cert_slots()[idx]
            .endorsement
            .capacity(algo)
            .map_err(|_| INVARIANT)
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
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.shared().validate_key(idx, key_pair_id)?;
        if cert_model != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        validate_root_hash(self, root_hash, cert_chain).await?;
        Ok(())
    }

    async fn cert_chain_len(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;

        // 1. PRE-CHECK: Ensure Slot is provisioned and not undergoing updates before starting
        if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
            return Err(INVARIANT);
        }

        if let Some(n) = self.cert_store.cached_chain_len(slot, algo) {
            return Ok(n as usize);
        }

        // Cache miss: Invalidate stale leaf and digest caches before starting recomputation
        self.cert_store.invalidate_cert_caches(slot);

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
        let dpe_skip = cert_slot.is_writable();
        let (dpe_len, dpe_skip_len) =
            dpe_chain_len_and_skip_prefix(self, DpeProfile::from(algo), dpe_skip).await?;
        let leaf_len = probe_leaf_len(self, DpeProfile::from(algo)).await?;
        self.cert_store
            .set_cached_leaf_len(slot, algo, leaf_len as u32);
        self.cert_store
            .set_cached_dpe_skip_len(slot, algo, dpe_skip_len as u32);
        let total = ChainLayout::new(slot_chain_len, dpe_len, dpe_skip_len, leaf_len)?.total_len();

        // 2. POST-CHECK: Verify Slot remained unlocked during the intermediate async .await points
        if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
            return Err(INVARIANT);
        }

        self.cert_store
            .set_cached_chain_len(slot, algo, total as u32);
        Ok(total)
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        self.cert_store.cert_slots()[idx]
            .endorsement
            .root_cert_hash(algo, out)
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        let idx = slot_index(slot).ok_or(INVARIANT)?;
        if dst.is_empty() {
            return Ok(0);
        }
        let total = self.cert_store.cached_chain_len(slot, algo).unwrap_or(0) as usize;
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        let cert_slot = &self.cert_store.cert_slots()[idx];
        let slot_chain_len = cert_slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
        let want = (total - offset).min(dst.len());
        // Read-only layout: [endorsement] [DPE chain] [leaf cert].
        // Managed AliasCert layout: [Owner Root + Endorsed LDevID]
        // [DPE chain without Caliptra IDevID/LDevID] [leaf cert].
        let endorsement_len = slot_chain_len;
        let leaf_len = match self.cert_store.cached_leaf_len(slot, algo) {
            Some(n) => n as usize,
            None => {
                let n = probe_leaf_len(self, DpeProfile::from(algo)).await?;
                self.cert_store.set_cached_leaf_len(slot, algo, n as u32);
                n
            }
        };
        let dpe_skip_len = if cert_slot.is_writable() {
            match self.cert_store.cached_dpe_skip_len(slot, algo) {
                Some(n) => n as usize,
                None => {
                    let (_, skip) =
                        dpe_chain_len_and_skip_prefix(self, DpeProfile::from(algo), true).await?;
                    self.cert_store
                        .set_cached_dpe_skip_len(slot, algo, skip as u32);
                    skip
                }
            }
        } else {
            0
        };
        let layout = ChainLayout::from_total(endorsement_len, total, dpe_skip_len, leaf_len)?;
        if total != layout.total_len() {
            return Err(INVARIANT);
        }
        let mut written = 0usize;
        let mut cur_offset = offset;

        // 1. Endorsement region
        if cur_offset < layout.endorsement.end && written < want {
            let n = cert_slot
                .endorsement
                .read(
                    algo,
                    cur_offset,
                    checked_slice_mut(dst, written, want - written)?,
                )
                .await
                .map_err(|_| INVARIANT)?;
            written += n;
            cur_offset = offset + written;
        }

        // 2. DPE-chain region
        while cur_offset < layout.dpe.end && written < want {
            let dpe_off = layout
                .dpe_source_offset
                .checked_add(cur_offset.checked_sub(layout.dpe.start).ok_or(INVARIANT)?)
                .ok_or(INVARIANT)?;
            let dpe_take = (layout.dpe.end - cur_offset)
                .min(want - written)
                .min(DPE_MAX_CHUNK_SIZE);
            let got = dpe_get_cert_chain_chunk(
                self.allocator,
                DpeProfile::from(algo),
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
        if cur_offset >= layout.leaf.start && written < want {
            let leaf_off = cur_offset - layout.leaf.start;
            let leaf_take = (layout.leaf.end - cur_offset).min(want - written);
            let got = caliptra_mcu_measurement_api::leaf_cert_slice(
                self.allocator,
                DpeProfile::from(algo),
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

    async fn sign(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        signing_input: SigningInput<'_>,
        signature: &mut [u8],
    ) -> McuResult<usize> {
        let _idx = slot_index(slot).ok_or(INVARIANT)?;
        if DpeProfile::from(algo) != signing_input.profile() {
            return Err(INVARIANT);
        }
        caliptra_mcu_measurement_api::sign(
            self.allocator,
            &DPE_LEAF_LABEL,
            signing_input,
            signature,
        )
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
        let key = self.cert_store.shared().validate_key(idx, key_pair_id)?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
            return Err(caliptra_mcu_spdm_codec::errors::SPDM_BUSY);
        }
        // Block transient readers of this algorithm's chain during the
        // flash update. The other algorithm's chain stays serveable.
        self.cert_store.cert_slots()[idx].set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = managed_endorsement(&self.cert_store, idx, algo)?;
            validate_endorsement(
                self.allocator,
                data,
                data.len(),
                chain.der_capacity(),
                algo.into(),
                key,
            )
            .await?;
            validate_root_hash(self, root_hash, data).await?;
            let chain = chain
                .write_updated(key_pair_id, cert_info, root_hash, data)
                .await?;
            commit_managed_endorsement(&self.cert_store, idx, chain)?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.set_metadata(algo, Some(cert_info));
            Ok(())
        }
        .await;
        self.cert_store.cert_slots()[idx].set_write_in_progress(algo, false);
        result?;
        self.cert_store.invalidate_cert_caches(slot);
        Ok(())
    }

    async fn begin_write_cert_chain_stream(
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
            self.cert_store.shared().validate_key(idx, key_pair_id)?;
            if cert_info != CERT_MODEL_ALIAS_CERT {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
                return Err(caliptra_mcu_spdm_codec::errors::SPDM_BUSY);
            }
            self.cert_store.cert_slots()[idx].set_write_in_progress(algo, true);
            let result: McuResult<()> = async {
                let chain = managed_endorsement(&self.cert_store, idx, algo)?;
                let chain = chain
                    .begin_stream_update(key_pair_id, cert_info, root_hash, data_len)
                    .await?;
                commit_managed_endorsement(&self.cert_store, idx, chain)?;
                let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
                cert_slot.clear_metadata(algo);
                Ok(())
            }
            .await;
            if result.is_err() {
                self.cert_store.cert_slots()[idx].set_write_in_progress(algo, false);
            }
            result
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo, key_pair_id, cert_info, root_hash, data_len);
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
            if !self.cert_store.cert_slots()[idx].write_in_progress(algo) {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            let chain = managed_endorsement(&self.cert_store, idx, algo)?
                .write_stream_chunk(offset, data)
                .await?;
            commit_managed_endorsement(&self.cert_store, idx, chain)
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
            if !self.cert_store.cert_slots()[idx].write_in_progress(algo) {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            let result: McuResult<()> = async {
                let key = self.cert_store.shared().validate_key(idx, key_pair_id)?;
                let chain = managed_endorsement(&self.cert_store, idx, algo)?;
                chain.validate_stream_metadata(key_pair_id, cert_info, root_hash, data_len)?;
                validate_endorsement(
                    self.allocator,
                    &chain,
                    data_len,
                    chain.der_capacity(),
                    algo.into(),
                    key,
                )
                .await?;
                validate_streamed_root_hash(self.allocator, &chain, root_hash, data_len).await?;
                let chain = chain
                    .finish_stream_update(key_pair_id, cert_info, root_hash, data_len)
                    .await?;
                commit_managed_endorsement(&self.cert_store, idx, chain)?;
                let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
                cert_slot.set_metadata(algo, Some(cert_info));
                Ok(())
            }
            .await;
            if let Err(err) = result {
                self.abort_write_cert_chain_stream(_io, slot, algo).await?;
                return Err(err);
            }
            self.cert_store.cert_slots()[idx].set_write_in_progress(algo, false);
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
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()> {
        #[cfg(feature = "set-certificate")]
        {
            let idx = slot_index(slot).ok_or(INVARIANT)?;
            if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
                let mut chain = managed_endorsement(&self.cert_store, idx, algo)?;
                chain.discard();
                commit_managed_endorsement(&self.cert_store, idx, chain)?;
                self.cert_store
                    .cert_slot_mut(idx)
                    .ok_or(INVARIANT)?
                    .clear_metadata(algo);
            }
            self.cert_store.cert_slots()[idx].set_write_in_progress(algo, false);
            self.cert_store.invalidate_cert_caches(slot);
            Ok(())
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            let _ = (slot, algo);
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
        let role = endorsement::endorsement_role(idx).ok_or(INVARIANT)?;
        self.cert_store.shared().policy().key_for_role(role)?;
        if self.cert_store.cert_slots()[idx].write_in_progress(algo) {
            return Err(caliptra_mcu_spdm_codec::errors::SPDM_BUSY);
        }
        self.cert_store.cert_slots()[idx].set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = managed_endorsement(&self.cert_store, idx, algo)?;
            let chain = chain.erase_updated().await?;
            commit_managed_endorsement(&self.cert_store, idx, chain)?;
            let cert_slot = self.cert_store.cert_slot_mut(idx).ok_or(INVARIANT)?;
            cert_slot.clear_metadata(algo);
            Ok(())
        }
        .await;
        self.cert_store.cert_slots()[idx].set_write_in_progress(algo, false);
        result?;
        self.cert_store.invalidate_cert_caches(slot);
        Ok(())
    }

    fn key_pair_id(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u8> {
        let idx = slot_index(slot)?;
        self.cert_store.cert_slots()[idx].key_pair_id(algo)
    }

    fn cert_info(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u8> {
        let idx = slot_index(slot)?;
        let cert_slot = &self.cert_store.cert_slots()[idx];
        if !cert_slot.is_provisioned(algo) {
            return None;
        }
        cert_slot.cert_info(algo)
    }

    fn key_usage_mask(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u16> {
        let idx = slot_index(slot)?;
        let cert_slot = &self.cert_store.cert_slots()[idx];
        if !cert_slot.is_provisioned(algo) {
            return None;
        }
        #[cfg(feature = "set-certificate")]
        {
            match &cert_slot.endorsement {
                endorsement::SlotEndorsement::Managed(m) => {
                    m.get_endorsement(algo)?.key_usage_mask()
                }
                _ => Some(DEFAULT_KEY_USAGE_MASK),
            }
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            Some(DEFAULT_KEY_USAGE_MASK)
        }
    }

    #[inline]
    fn cached_chain_digest(
        &self,
        slot: u8,
        asym_algo: SpdmPalAsymAlgo,
        _algo: SpdmPalHashAlgo,
    ) -> Option<[u8; 48]> {
        self.cert_store.cached_chain_digest(slot, asym_algo)
    }

    #[inline]
    fn cache_chain_digest(
        &self,
        slot: u8,
        asym_algo: SpdmPalAsymAlgo,
        _algo: SpdmPalHashAlgo,
        digest: &[u8],
    ) {
        self.cert_store.cache_chain_digest(slot, asym_algo, digest);
    }

    async fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> McuResult<()> {
        mcu_caliptra_api::rng_generate(self.allocator, out).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Probe the DPE leaf-cert size by calling `CertifyKey` and
/// reading only its fixed response header. Deterministic, so
/// subsequent calls produce identical sizes.
async fn probe_leaf_len<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    profile: DpeProfile,
) -> McuResult<usize> {
    caliptra_mcu_measurement_api::leaf_cert_size(pal.allocator, profile, &DPE_LEAF_LABEL)
        .await
        .map_err(|_| INTERNAL_BUG)
}

#[allow(dead_code)]
#[cfg(any(test, feature = "set-certificate"))]
fn checked_slice(src: &[u8], offset: usize, len: usize) -> McuResult<&[u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get(offset..end).ok_or(INVARIANT)
}

fn checked_slice_mut(src: &mut [u8], offset: usize, len: usize) -> McuResult<&mut [u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get_mut(offset..end).ok_or(INVARIANT)
}

async fn dpe_chain_len_and_skip_prefix<M: MeasurementProvider>(
    pal: &McuSpdmPal<M>,
    profile: DpeProfile,
    skip_to_ldevid: bool,
) -> McuResult<(usize, usize)> {
    if !skip_to_ldevid {
        return Ok((
            walk_dpe_chain(pal.allocator, profile, &mut CountSink).await? as usize,
            0,
        ));
    }

    let mut anchor = mcu_caliptra_api::ScratchAlloc::alloc(
        pal.allocator,
        mcu_caliptra_api::LDEVID_CERT_RSP_BUF_SIZE,
    )?;
    let anchor_len = mcu_caliptra_api::get_ldevid_cert(profile, &mut anchor).await?;
    let mut sink = DpeAnchorScanner::new(anchor.get(..anchor_len).ok_or(INVARIANT)?);
    let total = walk_dpe_chain(pal.allocator, profile, &mut sink).await? as usize;
    if !sink.found || sink.skip_len > total {
        return Err(INVARIANT);
    }
    Ok((total, sink.skip_len))
}

/// Return the total encoded length of the first DER SEQUENCE in `buf`.
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
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::{der_first_seq_len, ChainLayout, DpeAnchorScanner};

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

    #[test]
    fn dpe_anchor_scanner_handles_split_headers_and_optional_idevid() {
        let anchor = [0x30, 0x02, 4, 5];
        let chain = [0x30, 0x03, 1, 2, 3, 0x30, 0x02, 4, 5, 0x30, 1, 6];
        for (start, skip) in [(0, 9), (5, 4)] {
            for chunk_len in 1..=chain.len() {
                let mut scanner = DpeAnchorScanner::new(&anchor);
                for chunk in chain[start..].chunks(chunk_len) {
                    scanner.consume(chunk).unwrap();
                }
                assert!(scanner.found);
                assert_eq!(scanner.skip_len, skip);
                let layout = ChainLayout::new(20, chain.len() - start, skip, 10).unwrap();
                assert_eq!(layout.dpe.end - layout.dpe.start, 3);
                assert_eq!(layout.total_len(), 33);
            }
        }
    }

    #[test]
    fn dpe_anchor_scanner_does_not_skip_an_unmatched_or_incomplete_certificate() {
        let anchor = [0x30, 2, 4, 5];
        for chain in [&[0x30, 2, 4, 6][..], &[0x30, 2, 4][..]] {
            let mut scanner = DpeAnchorScanner::new(&anchor);
            scanner.consume(chain).unwrap();
            assert!(!scanner.found);
        }
    }

    #[test]
    fn dpe_anchor_scanner_handles_long_certificate_headers() {
        let mut anchor = [7u8; 262];
        anchor[..4].copy_from_slice(&[0x30, 0x82, 0x01, 0x02]);
        for chunk_len in [1, 2, 3, 7, 64, 1024] {
            let mut scanner = DpeAnchorScanner::new(&anchor);
            scanner.consume(&[0x30, 1, 0]).unwrap();
            for chunk in anchor.chunks(chunk_len) {
                scanner.consume(chunk).unwrap();
            }
            scanner.consume(&[0x30, 1, 6]).unwrap();
            assert!(scanner.found);
            assert_eq!(scanner.skip_len, 3 + anchor.len());
        }
    }
}
