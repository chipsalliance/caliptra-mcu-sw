// Licensed under the Apache-2.0 license

//! Shared cert store — a single static instance referenced by all PAL
//! instances (MCTP, DOE, …).
//!
//! Interior mutability is safe because embassy tasks are cooperative
//! on a single-core MCU — only one task runs at a time.

use crate::{
    endorsement::{CertSlot, ReadOnlyEndorsementSlot, SlotEndorsement, NUM_CERT_SLOTS},
    errors as cert_errors, CertificateAlgorithm, CertificateProvisioningPolicy, EndorsementRole,
    DPE_LEAF_LABEL,
};
#[cfg(feature = "set-certificate")]
use crate::{
    endorsement::{ManagedEndorsementSlot, SingleManagedEndorsement, CERT_MODEL_ALIAS_CERT},
    DeviceKey,
};
use core::cell::UnsafeCell;
use core::ops::Range;

use mcu_caliptra_api::{
    dpe_get_cert_chain_chunk, sha_finish, sha_init, sha_update, walk_dpe_chain, DpeChainSink,
    DpeProfile, HashAlgo, ScratchAlloc, DPE_MAX_CHUNK_SIZE, SHA_CONTEXT_SIZE,
};
use mcu_error::{
    codes::{INTERNAL_BUG, INVARIANT},
    McuResult,
};

const DPE_IDEVID_AND_LDEVID_CERT_COUNT: usize = 2;
const CERT_DIGEST_CHUNK_SIZE: usize = 1024;

async fn compute_root_hash<A: ScratchAlloc>(alloc: &A, root_cert: &[u8]) -> McuResult<[u8; 48]> {
    let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
    sha_update(alloc, &mut state, root_cert).await?;
    let mut hash = [0u8; 48];
    sha_finish(alloc, &mut state, &mut hash).await?;
    Ok(hash)
}

/// Static shared cert store.
///
/// Holds per-slot endorsement data common to all transports. Created once at
/// program start and referenced by every `McuSpdmPal` instance via
/// `&'static SharedCertStore`.
pub struct SharedCertStore {
    cert_slots: UnsafeCell<[CertSlot; NUM_CERT_SLOTS]>,
    policy: CertificateProvisioningPolicy,
}

// SAFETY: single-core cooperative scheduling — no concurrent access.
unsafe impl Sync for SharedCertStore {}

impl Default for SharedCertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedCertStore {
    pub const fn new() -> Self {
        Self::with_policy(CertificateProvisioningPolicy::DEFAULT)
    }

    pub const fn with_policy(policy: CertificateProvisioningPolicy) -> Self {
        Self {
            cert_slots: UnsafeCell::new([
                CertSlot::empty(Some(0)),
                CertSlot::empty(match policy.owner_anchor_point {
                    Some(key) => Some(key.key_pair_id()),
                    None => None,
                }),
                CertSlot::empty(match policy.tenant_anchor_point {
                    Some(key) => Some(key.key_pair_id()),
                    None => None,
                }),
            ]),
            policy,
        }
    }

    pub const fn policy(&self) -> CertificateProvisioningPolicy {
        self.policy
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn validate_key(
        &self,
        role: EndorsementRole,
        key_pair_id: u8,
    ) -> McuResult<DeviceKey> {
        self.policy.validate_key(role, key_pair_id)
    }

    // ---------------------------------------------------------------
    // Cert-slot accessors
    // ---------------------------------------------------------------

    pub fn cert_slots(&self) -> &[CertSlot; NUM_CERT_SLOTS] {
        // SAFETY: single-task invariant.
        unsafe { &*self.cert_slots.get() }
    }

    pub fn cert_slot(&self, role: EndorsementRole) -> &CertSlot {
        &self.cert_slots()[role.index()]
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) fn cert_slot_mut(&self, idx: usize) -> Option<&mut CertSlot> {
        // SAFETY: single-task invariant.
        unsafe { (*self.cert_slots.get()).get_mut(idx) }
    }

    // ---------------------------------------------------------------
    // Endorsement setup
    // ---------------------------------------------------------------

    /// Configure a read-only endorsement chain with both ECC and optional ML-DSA roots.
    pub async fn set_endorsement_chains<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        ecc_chain: &'static [&'static [u8]],
        mldsa_chain: Option<&'static [&'static [u8]]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        self.policy.validate()?;
        let idx = role.index();
        if ecc_chain.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if self.cert_slots()[idx].configured_key_pair_id() != Some(key_pair_id) {
            return Err(cert_errors::KEY_MISMATCH);
        }
        let ecc_hash = compute_root_hash(alloc, ecc_chain[0]).await?;
        let mut ro = ReadOnlyEndorsementSlot::new(ecc_chain, ecc_hash);

        if let Some(mldsa) = mldsa_chain {
            if !mldsa.is_empty() {
                let mldsa_hash = compute_root_hash(alloc, mldsa[0]).await?;
                ro = ro.with_mldsa(mldsa, mldsa_hash);
            }
        }

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.endorsement = SlotEndorsement::ReadOnly(ro);
        Ok(())
    }

    /// Configure a DPE-only slot with no static endorsement certs.
    ///
    /// The certificate chain contains only the DPE device chain
    /// (LDevID → FMC → RT) plus a CertifyKey leaf — no Root CA or IDevID
    /// in the endorsement segment.
    ///
    /// The `*_first_dpe_cert` bytes (typically the LDevID cert) are used
    /// **only** to compute the RootHash for each algorithm's
    /// CertificateChain header; they are not stored in the endorsement
    /// segment. Pass `mldsa_first_dpe_cert = None` on platforms that do not
    /// serve an ML-DSA-87 chain for this slot.
    pub async fn set_dpe_only_slot<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        ecc_first_dpe_cert: &[u8],
        mldsa_first_dpe_cert: Option<&[u8]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        self.policy.validate()?;
        let idx = role.index();
        if ecc_first_dpe_cert.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if self.cert_slots()[idx].configured_key_pair_id() != Some(key_pair_id) {
            return Err(cert_errors::KEY_MISMATCH);
        }
        static EMPTY_CHAIN: &[&[u8]] = &[];

        let ecc_hash = compute_root_hash(alloc, ecc_first_dpe_cert).await?;
        let mut ro = ReadOnlyEndorsementSlot::new(EMPTY_CHAIN, ecc_hash);

        if let Some(cert) = mldsa_first_dpe_cert {
            if !cert.is_empty() {
                let mldsa_hash = compute_root_hash(alloc, cert).await?;
                ro = ro.with_mldsa(EMPTY_CHAIN, mldsa_hash);
            }
        }

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.endorsement = SlotEndorsement::ReadOnly(ro);
        Ok(())
    }

    /// Configure a flash-backed managed cert-chain region for `(role, algo)`
    /// and load any existing record from flash. Uninitialized flash leaves
    /// that `(role, algo)` supported but not provisioned.
    ///
    /// Returns `INVARIANT` if the requested region intersects any region
    /// already wired to any slot (including another algorithm in the same
    /// slot), since an update erases a whole region.
    #[cfg(feature = "set-certificate")]
    pub async fn set_managed_endorsement(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        driver_num: u32,
        base: usize,
        capacity: usize,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if capacity == 0 {
            return Err(mcu_error::codes::INVARIANT);
        }
        self.policy.validate_role(role)?;
        let idx = role.index();

        // Updating a chain erases its whole region, so regions must be
        // strictly disjoint — any intersection means installing one
        // chain destroys another. Checking all slots (including `idx`
        // itself) catches both intra-slot and cross-slot collisions.
        let range = base..base
            .checked_add(capacity)
            .ok_or(mcu_error::codes::INVARIANT)?;
        for slot in self.cert_slots() {
            if let SlotEndorsement::Managed(existing) = &slot.endorsement {
                if existing.any_region_overlaps(driver_num, &range) {
                    return Err(mcu_error::codes::INVARIANT);
                }
            }
        }

        match (&self.cert_slots()[idx].endorsement, algo) {
            (SlotEndorsement::Empty, CertificateAlgorithm::EccP384) => {}
            (SlotEndorsement::Managed(m), CertificateAlgorithm::MlDsa87)
                if m.get_endorsement(CertificateAlgorithm::MlDsa87).is_none() => {}
            _ => return Err(mcu_error::codes::INVARIANT),
        }

        let mut region = SingleManagedEndorsement::new(
            role.record_tag(),
            algo,
            driver_num,
            base,
            capacity,
            self.policy.anchor_point(role),
        );
        region.load().await?;
        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        match &mut slot.endorsement {
            SlotEndorsement::Empty => {
                slot.endorsement = SlotEndorsement::Managed(ManagedEndorsementSlot::new(region));
            }
            SlotEndorsement::Managed(m) => {
                m.set_endorsement(region);
            }
            SlotEndorsement::ReadOnly(_) => return Err(mcu_error::codes::INVARIANT),
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Default)]
struct AlgoCache {
    chain_len: Option<u32>,
    leaf_len: Option<u32>,
    chain_digest: Option<[u8; 48]>,
    dpe_skip_len: Option<u32>,
}

#[derive(Copy, Clone, Default)]
struct SlotCache {
    ecc: AlgoCache,
    mldsa: AlgoCache,
}

impl SlotCache {
    fn algo_cache(&self, algo: CertificateAlgorithm) -> &AlgoCache {
        match algo {
            CertificateAlgorithm::EccP384 => &self.ecc,
            CertificateAlgorithm::MlDsa87 => &self.mldsa,
        }
    }

    fn algo_cache_mut(&mut self, algo: CertificateAlgorithm) -> &mut AlgoCache {
        match algo {
            CertificateAlgorithm::EccP384 => &mut self.ecc,
            CertificateAlgorithm::MlDsa87 => &mut self.mldsa,
        }
    }

    fn invalidate(&mut self) {
        self.ecc = AlgoCache::default();
        self.mldsa = AlgoCache::default();
    }
}

/// Per-task cert store wrapper.
///
/// Wraps a reference to the global `'static SharedCertStore` alongside
/// task-local caches (lengths, digests, etc.) to ensure complete task isolation.
pub struct TaskCertStore {
    shared: &'static SharedCertStore,
    caches: UnsafeCell<[SlotCache; NUM_CERT_SLOTS]>,
}

impl TaskCertStore {
    pub const fn new(shared: &'static SharedCertStore) -> Self {
        Self {
            shared,
            caches: UnsafeCell::new(
                [SlotCache {
                    ecc: AlgoCache {
                        chain_len: None,
                        leaf_len: None,
                        chain_digest: None,
                        dpe_skip_len: None,
                    },
                    mldsa: AlgoCache {
                        chain_len: None,
                        leaf_len: None,
                        chain_digest: None,
                        dpe_skip_len: None,
                    },
                }; NUM_CERT_SLOTS],
            ),
        }
    }

    #[inline]
    pub fn shared(&self) -> &'static SharedCertStore {
        self.shared
    }

    #[inline]
    pub fn cert_slots(&self) -> &[CertSlot; NUM_CERT_SLOTS] {
        self.shared.cert_slots()
    }

    #[inline]
    pub fn cert_slot(&self, role: EndorsementRole) -> &CertSlot {
        self.shared.cert_slot(role)
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn cert_slot_mut(&self, idx: usize) -> Option<&mut CertSlot> {
        self.shared.cert_slot_mut(idx)
    }

    pub fn cached_chain_len(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<u32> {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache(algo)
                .chain_len
        }
    }

    pub fn set_cached_chain_len(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        len: u32,
    ) {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache_mut(algo)
                .chain_len = Some(len);
        }
    }

    pub fn cached_leaf_len(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<u32> {
        unsafe { (*self.caches.get())[role.index()].algo_cache(algo).leaf_len }
    }

    pub fn set_cached_leaf_len(&self, role: EndorsementRole, algo: CertificateAlgorithm, len: u32) {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache_mut(algo)
                .leaf_len = Some(len);
        }
    }

    pub fn cached_dpe_skip_len(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<u32> {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache(algo)
                .dpe_skip_len
        }
    }

    pub fn set_cached_dpe_skip_len(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        len: u32,
    ) {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache_mut(algo)
                .dpe_skip_len = Some(len);
        }
    }

    pub fn cached_chain_digest(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<[u8; 48]> {
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache(algo)
                .chain_digest
        }
    }

    pub fn cache_chain_digest(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        digest: &[u8],
    ) {
        if digest.len() > 48 {
            return;
        }
        let mut entry = [0u8; 48];
        for (d, s) in entry.iter_mut().zip(digest) {
            *d = *s;
        }
        unsafe {
            (*self.caches.get())[role.index()]
                .algo_cache_mut(algo)
                .chain_digest = Some(entry);
        }
    }

    pub fn invalidate_cert_caches(&self, role: EndorsementRole) {
        unsafe {
            (*self.caches.get())[role.index()].invalidate();
        }
    }

    // ---------------------------------------------------------------
    // Complete-chain assembly & digest
    // ---------------------------------------------------------------

    pub fn endorsement_capacity(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<usize> {
        let cert_slot = self.cert_slot(role);
        if cert_slot.write_in_progress(algo) {
            return Err(INVARIANT);
        }
        cert_slot.endorsement.capacity(algo).map_err(|_| INVARIANT)
    }

    pub fn root_cert_hash(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        out: &mut [u8],
    ) -> McuResult<()> {
        self.cert_slot(role).endorsement.root_cert_hash(algo, out)
    }

    pub async fn cert_chain_len<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<usize> {
        if self.cert_slot(role).write_in_progress(algo) {
            return Err(INVARIANT);
        }

        if let Some(n) = self.cached_chain_len(role, algo) {
            return Ok(n as usize);
        }

        self.invalidate_cert_caches(role);

        let cert_slot = self.cert_slot(role);
        let slot_chain_len = cert_slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
        let dpe_skip = if cert_slot.is_writable() {
            DPE_IDEVID_AND_LDEVID_CERT_COUNT
        } else {
            0
        };
        let profile = algo.dpe_profile();
        let (dpe_len, dpe_skip_len) =
            dpe_chain_len_and_skip_prefix(alloc, profile, dpe_skip).await?;
        let leaf_len = probe_leaf_len(alloc, profile).await?;
        self.set_cached_leaf_len(role, algo, leaf_len as u32);
        self.set_cached_dpe_skip_len(role, algo, dpe_skip_len as u32);
        let total = ChainLayout::new(slot_chain_len, dpe_len, dpe_skip_len, leaf_len)?.total_len();

        if self.cert_slot(role).write_in_progress(algo) {
            return Err(INVARIANT);
        }

        self.set_cached_chain_len(role, algo, total as u32);
        Ok(total)
    }

    pub async fn read_cert_chain<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        let total = self.cached_chain_len(role, algo).unwrap_or(0) as usize;
        if total == 0 {
            return Err(INVARIANT);
        }
        if offset >= total {
            return Ok(0);
        }

        let cert_slot = self.cert_slot(role);
        let slot_chain_len = cert_slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
        let want = (total - offset).min(dst.len());
        let endorsement_len = slot_chain_len;
        let profile = algo.dpe_profile();
        let leaf_len = match self.cached_leaf_len(role, algo) {
            Some(n) => n as usize,
            None => {
                let n = probe_leaf_len(alloc, profile).await?;
                self.set_cached_leaf_len(role, algo, n as u32);
                n
            }
        };
        let dpe_skip_len = if cert_slot.is_writable() {
            match self.cached_dpe_skip_len(role, algo) {
                Some(n) => n as usize,
                None => {
                    let (_, skip) = dpe_chain_len_and_skip_prefix(
                        alloc,
                        profile,
                        DPE_IDEVID_AND_LDEVID_CERT_COUNT,
                    )
                    .await?;
                    self.set_cached_dpe_skip_len(role, algo, skip as u32);
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
                alloc,
                profile,
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
                alloc,
                profile,
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

    /// Compute the SHA-384 digest over the raw DER certificate chain for `(role, algo)`.
    pub async fn cert_chain_digest<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        out: &mut [u8; 48],
    ) -> McuResult<()> {
        if !self.cert_slot(role).is_provisioned(algo) {
            return Err(INVARIANT);
        }
        let _ = self.cert_chain_len(alloc, role, algo).await?;
        let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
        let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
        let mut offset = 0usize;
        loop {
            let mut chunk = alloc.alloc(CERT_DIGEST_CHUNK_SIZE)?;
            let n = self
                .read_cert_chain(alloc, role, algo, offset, &mut chunk)
                .await?;
            if n == 0 {
                break;
            }
            sha_update(alloc, &mut state, checked_slice(&chunk, 0, n)?).await?;
            offset += n;
            if n < chunk.len() {
                break;
            }
        }
        if !self.cert_slot(role).is_provisioned(algo) {
            return Err(INVARIANT);
        }
        sha_finish(alloc, &mut state, out).await
    }

    // ---------------------------------------------------------------
    // Validated endorsement mutations
    // ---------------------------------------------------------------

    #[cfg(feature = "set-certificate")]
    pub async fn validate_endorsement_chain<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()> {
        self.shared.validate_key(role, key_pair_id)?;
        if cert_model != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        validate_root_hash(alloc, root_hash, cert_chain).await
    }

    #[cfg(feature = "set-certificate")]
    pub async fn write_endorsement_chain(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<()> {
        let idx = role.index();
        let key = self.shared.validate_key(role, key_pair_id)?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if self.cert_slots()[idx].write_in_progress(algo) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        self.cert_slots()[idx].set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = managed_endorsement(self, idx, algo)?;
            let chain = chain
                .write_updated(key.key_pair_id(), cert_info, root_hash, data)
                .await?;
            commit_managed_endorsement(self, idx, chain)?;
            Ok(())
        }
        .await;
        self.cert_slots()[idx].set_write_in_progress(algo, false);
        result?;
        self.invalidate_cert_caches(role);
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    pub async fn begin_write_endorsement_stream(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        key_pair_id: u8,
        cert_info: u8,
        data_len: usize,
    ) -> McuResult<()> {
        let idx = role.index();
        let key = self.shared.validate_key(role, key_pair_id)?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if self.cert_slots()[idx].write_in_progress(algo) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        self.cert_slots()[idx].set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = managed_endorsement(self, idx, algo)?;
            let chain = chain
                .begin_stream_update(key.key_pair_id(), cert_info, data_len)
                .await?;
            commit_managed_endorsement(self, idx, chain)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.cert_slots()[idx].set_write_in_progress(algo, false);
        }
        result
    }

    #[cfg(feature = "set-certificate")]
    pub async fn write_endorsement_stream_chunk(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        offset: usize,
        data: &[u8],
    ) -> McuResult<()> {
        let idx = role.index();
        if !self.cert_slots()[idx].write_in_progress(algo) {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        managed_endorsement(self, idx, algo)?
            .write_stream_chunk(offset, data)
            .await
    }

    #[cfg(feature = "set-certificate")]
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_write_endorsement_stream<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<()> {
        let idx = role.index();
        if !self.cert_slots()[idx].write_in_progress(algo) {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let result: McuResult<()> = async {
            let key = self.shared.validate_key(role, key_pair_id)?;
            if cert_info != CERT_MODEL_ALIAS_CERT {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            let chain = managed_endorsement(self, idx, algo)?;
            validate_streamed_root_hash(alloc, &chain, root_hash, data_len).await?;
            let chain = chain
                .finish_stream_update(key.key_pair_id(), cert_info, root_hash, data_len)
                .await?;
            commit_managed_endorsement(self, idx, chain)?;
            Ok(())
        }
        .await;
        if let Err(err) = result {
            self.abort_write_endorsement_stream(role, algo).await?;
            return Err(err);
        }
        self.cert_slots()[idx].set_write_in_progress(algo, false);
        self.invalidate_cert_caches(role);
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    pub async fn abort_write_endorsement_stream(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<()> {
        let idx = role.index();
        if self.cert_slots()[idx].write_in_progress(algo) {
            let mut chain = managed_endorsement(self, idx, algo)?;
            chain.discard();
            commit_managed_endorsement(self, idx, chain)?;
        }
        self.cert_slots()[idx].set_write_in_progress(algo, false);
        self.invalidate_cert_caches(role);
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    pub async fn erase_endorsement_chain(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<()> {
        let idx = role.index();
        self.shared.policy().validate_role(role)?;
        if self.cert_slots()[idx].write_in_progress(algo) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        self.cert_slots()[idx].set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = managed_endorsement(self, idx, algo)?;
            let chain = chain.erase_updated().await?;
            commit_managed_endorsement(self, idx, chain)?;
            Ok(())
        }
        .await;
        self.cert_slots()[idx].set_write_in_progress(algo, false);
        result?;
        self.invalidate_cert_caches(role);
        Ok(())
    }
}

#[cfg(feature = "set-certificate")]
fn managed_endorsement(
    store: &TaskCertStore,
    idx: usize,
    algo: CertificateAlgorithm,
) -> McuResult<SingleManagedEndorsement> {
    match &store.cert_slots()[idx].endorsement {
        SlotEndorsement::Managed(m) => m.get_endorsement(algo).copied().ok_or(INVARIANT),
        SlotEndorsement::ReadOnly(_) => Err(mcu_error::codes::NOT_IMPLEMENTED),
        SlotEndorsement::Empty => Err(INVARIANT),
    }
}

#[cfg(feature = "set-certificate")]
fn commit_managed_endorsement(
    store: &TaskCertStore,
    idx: usize,
    chain: SingleManagedEndorsement,
) -> McuResult<()> {
    let cert_slot = store.cert_slot_mut(idx).ok_or(INVARIANT)?;
    match &mut cert_slot.endorsement {
        SlotEndorsement::Managed(m) => {
            m.set_endorsement(chain);
            Ok(())
        }
        _ => Err(INVARIANT),
    }
}

struct CountSink;
impl DpeChainSink for CountSink {
    async fn on_chunk(&mut self, _: &[u8]) -> McuResult<()> {
        Ok(())
    }
}

pub(crate) struct DpePrefixScanner {
    pub(crate) certs_left: usize,
    cert_bytes_left: usize,
    pub(crate) skip_len: usize,
    header: [u8; 6],
    header_len: usize,
}

impl DpePrefixScanner {
    pub(crate) fn new(certs: usize) -> Self {
        Self {
            certs_left: certs,
            cert_bytes_left: 0,
            skip_len: 0,
            header: [0; 6],
            header_len: 0,
        }
    }

    pub(crate) fn consume(&mut self, chunk: &[u8]) -> McuResult<()> {
        let mut pos = 0usize;
        while self.certs_left > 0 && pos < chunk.len() {
            if self.cert_bytes_left > 0 {
                let take = self.cert_bytes_left.min(chunk.len() - pos);
                self.cert_bytes_left -= take;
                self.skip_len = self.skip_len.checked_add(take).ok_or(INVARIANT)?;
                pos += take;
                if self.cert_bytes_left == 0 {
                    self.certs_left -= 1;
                }
                continue;
            }

            if self.header_len == self.header.len() {
                return Err(INVARIANT);
            }
            self.header[self.header_len] = chunk[pos];
            self.header_len += 1;
            self.skip_len = self.skip_len.checked_add(1).ok_or(INVARIANT)?;
            pos += 1;

            if let Some(cert_len) = der_first_seq_len(&self.header[..self.header_len]) {
                self.cert_bytes_left = cert_len.checked_sub(self.header_len).ok_or(INVARIANT)?;
                self.header_len = 0;
                if self.cert_bytes_left == 0 {
                    self.certs_left -= 1;
                }
            }
        }
        Ok(())
    }
}

impl DpeChainSink for DpePrefixScanner {
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
async fn validate_root_hash<A: ScratchAlloc>(
    alloc: &A,
    root_hash: &[u8; 48],
    cert_chain: &[u8],
) -> McuResult<()> {
    let root_cert_len = der_first_seq_len(cert_chain).ok_or(cert_errors::INVALID_ENDORSEMENT)?;
    let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
    sha_update(
        alloc,
        &mut state,
        checked_slice(cert_chain, 0, root_cert_len)?,
    )
    .await?;
    let mut digest = [0u8; 48];
    sha_finish(alloc, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn validate_streamed_root_hash<A: ScratchAlloc>(
    alloc: &A,
    managed: &SingleManagedEndorsement,
    root_hash: &[u8; 48],
    data_len: usize,
) -> McuResult<()> {
    let first_cert_len = streamed_first_der_len(managed, data_len).await?;
    let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
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
        sha_update(alloc, &mut state, checked_slice(&buf, 0, n)?).await?;
        offset += n;
    }
    let mut digest = [0u8; 48];
    sha_finish(alloc, &mut state, &mut digest).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn streamed_first_der_len(
    managed: &SingleManagedEndorsement,
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

async fn probe_leaf_len<A: ScratchAlloc>(alloc: &A, profile: DpeProfile) -> McuResult<usize> {
    caliptra_mcu_measurement_api::leaf_cert_size(alloc, profile, &DPE_LEAF_LABEL)
        .await
        .map_err(|_| INTERNAL_BUG)
}

fn checked_slice(src: &[u8], offset: usize, len: usize) -> McuResult<&[u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get(offset..end).ok_or(INVARIANT)
}

fn checked_slice_mut(src: &mut [u8], offset: usize, len: usize) -> McuResult<&mut [u8]> {
    let end = offset.checked_add(len).ok_or(INVARIANT)?;
    src.get_mut(offset..end).ok_or(INVARIANT)
}

async fn dpe_chain_len_and_skip_prefix<A: ScratchAlloc>(
    alloc: &A,
    profile: DpeProfile,
    skip_certs: usize,
) -> McuResult<(usize, usize)> {
    if skip_certs == 0 {
        return Ok((
            walk_dpe_chain(alloc, profile, &mut CountSink).await? as usize,
            0,
        ));
    }

    let mut sink = DpePrefixScanner::new(skip_certs);
    let total = walk_dpe_chain(alloc, profile, &mut sink).await? as usize;
    if sink.certs_left != 0 || sink.skip_len > total {
        return Err(INVARIANT);
    }
    Ok((total, sink.skip_len))
}

pub(crate) fn der_first_seq_len(buf: &[u8]) -> Option<usize> {
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
    use super::*;

    #[test]
    fn dpe_only_endorsement_has_zero_size() {
        let hash = [0xAB_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert_eq!(endorsement.size(CertificateAlgorithm::EccP384).unwrap(), 0);
    }

    #[test]
    fn dpe_only_endorsement_returns_correct_root_hash() {
        let mut hash = [0u8; 48];
        hash[0] = 0xDE;
        hash[47] = 0xAD;
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(CertificateAlgorithm::EccP384, &mut out)
            .unwrap();
        assert_eq!(out, hash);
    }

    #[test]
    fn dpe_only_endorsement_is_supported() {
        let hash = [0x11_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert!(endorsement.is_supported());
        assert!(endorsement.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!endorsement.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn shared_store_slot_defaults_to_empty() {
        let store = SharedCertStore::new();
        let slot = &store.cert_slots()[0];
        assert!(!slot.endorsement.is_supported());
        assert!(slot.key_pair_id(CertificateAlgorithm::EccP384).is_none());
    }

    #[test]
    fn dpe_only_without_mldsa_errors_on_mldsa_algo() {
        let hash = [0x22_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert_eq!(endorsement.size(CertificateAlgorithm::EccP384).unwrap(), 0);
        assert!(endorsement.size(CertificateAlgorithm::MlDsa87).is_err());
    }

    #[test]
    fn dpe_only_with_mldsa_has_zero_size_for_both_algos() {
        let ecc_hash = [0x33_u8; 48];
        let mldsa_hash = [0x44_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(&[], ecc_hash).with_mldsa(&[], mldsa_hash),
        );

        assert_eq!(endorsement.size(CertificateAlgorithm::EccP384).unwrap(), 0);
        assert_eq!(endorsement.size(CertificateAlgorithm::MlDsa87).unwrap(), 0);

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(CertificateAlgorithm::MlDsa87, &mut out)
            .unwrap();
        assert_eq!(out, mldsa_hash);
    }

    #[test]
    fn shared_cert_store_new_has_empty_slots_and_no_metadata() {
        let store = SharedCertStore::new();
        for slot in store.cert_slots() {
            assert!(!slot.is_supported());
            assert!(!slot.is_writable());
            assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), None);
            assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), None);
            assert_eq!(slot.cert_info(CertificateAlgorithm::EccP384), None);
            assert_eq!(slot.cert_info(CertificateAlgorithm::MlDsa87), None);
        }
    }

    #[test]
    fn task_cert_store_caches_and_invalidation() {
        static SHARED: SharedCertStore = SharedCertStore::new();
        let store = TaskCertStore::new(&SHARED);
        assert_eq!(
            store.cached_chain_len(EndorsementRole::Vendor, CertificateAlgorithm::EccP384),
            None
        );
        store.set_cached_chain_len(EndorsementRole::Vendor, CertificateAlgorithm::EccP384, 1024);
        assert_eq!(
            store.cached_chain_len(EndorsementRole::Vendor, CertificateAlgorithm::EccP384),
            Some(1024)
        );

        store.invalidate_cert_caches(EndorsementRole::Vendor);
        assert_eq!(
            store.cached_chain_len(EndorsementRole::Vendor, CertificateAlgorithm::EccP384),
            None
        );
    }

    #[cfg(feature = "set-certificate")]
    #[test]
    fn validate_key_resolves_zero_for_some_policy_and_requires_explicit_for_none() {
        let store = SharedCertStore::new();
        assert_eq!(
            store.validate_key(EndorsementRole::Owner, 0),
            Ok(DeviceKey::LDevId)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Owner, 1),
            Ok(DeviceKey::LDevId)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Owner, 2),
            Err(cert_errors::KEY_MISMATCH)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Tenant, 0),
            Err(cert_errors::KEY_MISMATCH)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Tenant, 1),
            Ok(DeviceKey::LDevId)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Tenant, 2),
            Err(cert_errors::UNSUPPORTED_KEY)
        );
        assert_eq!(
            store.validate_key(EndorsementRole::Vendor, 1),
            Err(cert_errors::PROVISIONING_DISABLED)
        );
    }

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
    fn dpe_prefix_scanner_handles_split_headers_and_bodies() {
        let mut scanner = DpePrefixScanner::new(2);
        scanner.consume(&[0x30]).unwrap();
        scanner.consume(&[0x03, 1]).unwrap();
        scanner.consume(&[2, 3, 0x30, 0x02, 4, 5, 9]).unwrap();

        assert_eq!(scanner.certs_left, 0);
        assert_eq!(scanner.skip_len, 9);
    }
}
