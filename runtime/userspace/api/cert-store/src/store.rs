// Licensed under the Apache-2.0 license

//! Shared certificate store — a single static [`SharedCertStore`] instance
//! referenced by per-task [`TaskCertStore`] views across all transports
//! (SPDM over MCTP/DOE, MCU mailbox, …).
//!
//! Tasks run cooperatively on a single-core Embassy executor and only yield at
//! `.await` points. `SharedCertStore` is `Sync` because borrows of `cert_slots`
//! are strictly synchronous and dropped before `.await`, while state that spans
//! `.await` points (write lock, generation counter, and region reader counts)
//! is tracked with atomics.

#[cfg(feature = "set-certificate")]
use crate::endorsement::{
    managed_endorsement_der_capacity, ManagedEndorsementChain, ManagedEndorsementSlot,
    CERT_MODEL_ALIAS_CERT, MANAGED_REGION_COUNT,
};
use crate::{
    endorsement::{
        CertSlot, EndorsementStorage, NoEndorsementStorage, ReadOnlyEndorsementSlot,
        SlotEndorsement, NUM_ASYM_ALGOS, NUM_CERT_SLOTS,
    },
    errors as cert_errors, CertChainInfo, CertificateAlgorithm, CertificateProvisioningPolicy,
    DeviceKey, EndorsementRole, DPE_LEAF_LABEL,
};
#[cfg(feature = "set-certificate")]
use core::cell::Cell;
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

const CERT_DIGEST_CHUNK_SIZE: usize = 1024;

async fn compute_root_hash<A: ScratchAlloc>(alloc: &A, root_cert: &[u8]) -> McuResult<[u8; 48]> {
    let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
    let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
    sha_update(alloc, &mut state, root_cert).await?;
    let mut hash = [0u8; 48];
    sha_finish(alloc, &mut state, &mut hash).await?;
    Ok(hash)
}

/// Static shared certificate store.
///
/// Holds per-slot endorsement state and provisioning policy common to all
/// transports. Created once at startup and referenced by each transport task's
/// [`TaskCertStore`] via `&'static SharedCertStore<S>`.
pub struct SharedCertStore<S: EndorsementStorage = NoEndorsementStorage> {
    cert_slots: UnsafeCell<[CertSlot<S>; NUM_CERT_SLOTS]>,
    policy: CertificateProvisioningPolicy,
}

// SAFETY: Tasks run on a single-core cooperative Embassy executor and never
// hold borrows into `cert_slots` across `.await` points.
unsafe impl<S: EndorsementStorage> Sync for SharedCertStore<S> {}

impl<S: EndorsementStorage> Default for SharedCertStore<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: EndorsementStorage> SharedCertStore<S> {
    pub const fn new() -> Self {
        Self::with_policy(CertificateProvisioningPolicy::DEFAULT)
    }

    pub const fn with_policy(policy: CertificateProvisioningPolicy) -> Self {
        Self {
            cert_slots: UnsafeCell::new([
                CertSlot::empty(Some(0)),
                CertSlot::empty(match policy.owner_anchor_point {
                    Some(key) => Some(key as u8),
                    None => None,
                }),
                CertSlot::empty(match policy.tenant_anchor_point {
                    Some(key) => Some(key as u8),
                    None => None,
                }),
            ]),
            policy,
        }
    }

    /// Configure a read-only endorsement chain with ECC and optional ML-DSA roots.
    pub async fn init_readonly_endorsement<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        ecc_chain: &'static [&'static [u8]],
        mldsa_chain: Option<&'static [&'static [u8]]>,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if !matches!(self.cert_slot(role).endorsement, SlotEndorsement::Empty) {
            return Err(mcu_error::codes::INVARIANT);
        }
        self.cert_slot(role)
            .configured_key_pair_id()
            .ok_or(cert_errors::KEY_MISMATCH)?;
        let &first_ecc = ecc_chain.first().ok_or(mcu_error::codes::INVARIANT)?;
        if first_ecc.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let ecc_hash = compute_root_hash(alloc, first_ecc).await?;
        let mut ro = ReadOnlyEndorsementSlot::new(ecc_chain, ecc_hash);

        if let Some(mldsa) = mldsa_chain {
            let &first_mldsa = mldsa.first().ok_or(mcu_error::codes::INVARIANT)?;
            if first_mldsa.is_empty() {
                return Err(mcu_error::codes::INVARIANT);
            }
            let mldsa_hash = compute_root_hash(alloc, first_mldsa).await?;
            ro = ro.with_mldsa(mldsa, mldsa_hash);
        }

        let slot = self.cert_slot_mut(role);
        slot.endorsement = SlotEndorsement::ReadOnly(ro);
        slot.bump_generation_counter(CertificateAlgorithm::EccP384);
        if mldsa_chain.is_some() {
            slot.bump_generation_counter(CertificateAlgorithm::MlDsa87);
        }
        Ok(())
    }

    /// Configure a persistent-storage-backed managed cert-chain region for
    /// `(role, algo)` and load any existing record from `storage`.
    /// Uninitialized storage leaves that `(role, algo)` supported but not
    /// provisioned.
    ///
    /// Returns `INVARIANT` if the requested region intersects any region
    /// already wired to any slot (including another algorithm in the same
    /// slot), since an update erases a whole region.
    #[cfg(feature = "set-certificate")]
    pub async fn init_managed_endorsement(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        storage: S,
        base: usize,
        capacity: usize,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if capacity == 0
            || !capacity.is_multiple_of(MANAGED_REGION_COUNT)
            || managed_endorsement_der_capacity(capacity) == 0
        {
            return Err(mcu_error::codes::INVARIANT);
        }
        self.policy.validate_role(role)?;

        // Updating a chain erases its whole region, so regions must be
        // strictly disjoint — any intersection means installing one
        // chain destroys another. Checking all slots (including `role`
        // itself) catches both intra-slot and cross-slot collisions.
        let range = base..base
            .checked_add(capacity)
            .ok_or(mcu_error::codes::INVARIANT)?;
        for existing_role in EndorsementRole::ALL {
            if let SlotEndorsement::Managed(existing) = &self.cert_slot(existing_role).endorsement {
                if existing.any_region_overlaps(storage, &range) {
                    return Err(mcu_error::codes::INVARIANT);
                }
            }
        }

        match (&self.cert_slot(role).endorsement, algo) {
            (SlotEndorsement::Empty, CertificateAlgorithm::EccP384) => {}
            (SlotEndorsement::Managed(m), CertificateAlgorithm::MlDsa87)
                if m.get_endorsement(CertificateAlgorithm::MlDsa87).is_none() => {}
            _ => return Err(mcu_error::codes::INVARIANT),
        }

        let mut region = ManagedEndorsementChain::new(
            role,
            algo,
            storage,
            base,
            capacity,
            self.policy.anchor_point(role),
        );
        region.load().await?;
        let slot = self.cert_slot_mut(role);
        match &mut slot.endorsement {
            SlotEndorsement::Empty => {
                slot.endorsement = SlotEndorsement::Managed(ManagedEndorsementSlot::new(region));
            }
            SlotEndorsement::Managed(m) => {
                m.set_endorsement(region);
            }
            SlotEndorsement::ReadOnly(_) => return Err(mcu_error::codes::INVARIANT),
        }
        slot.bump_generation_counter(algo);
        Ok(())
    }

    pub fn is_provisioned(&self, role: EndorsementRole, algo: CertificateAlgorithm) -> bool {
        self.cert_slot(role).is_provisioned(algo)
    }

    pub(crate) fn cert_slot(&self, role: EndorsementRole) -> &CertSlot<S> {
        // SAFETY: synchronous borrow not held across `.await`.
        unsafe { &(*self.cert_slots.get())[role as usize] }
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn validate_key(
        &self,
        role: EndorsementRole,
        key_pair_id: u8,
    ) -> McuResult<DeviceKey> {
        self.policy.validate_key(role, key_pair_id)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) fn cert_slot_mut(&self, role: EndorsementRole) -> &mut CertSlot<S> {
        // SAFETY: synchronous borrow not held across `.await`.
        unsafe { &mut (*self.cert_slots.get())[role as usize] }
    }
}

#[derive(Copy, Clone, Default)]
struct CertChainCache {
    generation_counter: u32,
    chain_len: Option<u32>,
    leaf_len: Option<u32>,
    chain_digest: Option<[u8; 48]>,
    device_chain_offset: Option<u32>,
}

impl CertChainCache {
    const fn empty() -> Self {
        Self {
            generation_counter: 0,
            chain_len: None,
            leaf_len: None,
            chain_digest: None,
            device_chain_offset: None,
        }
    }
}

struct RegionReadGuard<'a, S: EndorsementStorage = NoEndorsementStorage> {
    shared: &'a SharedCertStore<S>,
    role: EndorsementRole,
    algo: CertificateAlgorithm,
    region: Option<u8>,
}

impl<'a, S: EndorsementStorage> RegionReadGuard<'a, S> {
    fn new(
        shared: &'a SharedCertStore<S>,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        region: Option<u8>,
    ) -> Self {
        if let Some(r) = region {
            shared.cert_slot(role).acquire_region_reader(algo, r);
        }
        Self {
            shared,
            role,
            algo,
            region,
        }
    }
}

impl<S: EndorsementStorage> Drop for RegionReadGuard<'_, S> {
    fn drop(&mut self) {
        if let Some(r) = self.region {
            self.shared
                .cert_slot(self.role)
                .release_region_reader(self.algo, r);
        }
    }
}

#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct RawEndorsementStream {
    role: EndorsementRole,
    algo: CertificateAlgorithm,
    key_pair_id: u8,
    total_size: usize,
}

/// Per-task cert store wrapper.
///
/// Wraps a reference to the global `'static SharedCertStore<S>` alongside
/// task-local caches (lengths, digests, etc.) to ensure complete task isolation.
pub struct TaskCertStore<S: EndorsementStorage = NoEndorsementStorage> {
    shared: &'static SharedCertStore<S>,
    caches: UnsafeCell<[[CertChainCache; NUM_ASYM_ALGOS]; NUM_CERT_SLOTS]>,
    #[cfg(feature = "set-certificate")]
    active_stream: Cell<Option<RawEndorsementStream>>,
}

impl<S: EndorsementStorage> TaskCertStore<S> {
    pub const fn new(shared: &'static SharedCertStore<S>) -> Self {
        Self {
            shared,
            caches: UnsafeCell::new([[CertChainCache::empty(); NUM_ASYM_ALGOS]; NUM_CERT_SLOTS]),
            #[cfg(feature = "set-certificate")]
            active_stream: Cell::new(None),
        }
    }

    #[inline]
    pub fn cert_slot(&self, role: EndorsementRole) -> &CertSlot<S> {
        self.shared.cert_slot(role)
    }

    pub fn cached_chain_digest(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<[u8; 48]> {
        self.valid_chain_cache(role, algo)?.chain_digest
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
        self.update_chain_cache(role, algo, |cache| {
            cache.chain_digest = Some(entry);
        });
    }

    // ---------------------------------------------------------------
    // Complete-chain assembly & digest
    // ---------------------------------------------------------------

    pub async fn cert_chain_len<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<usize> {
        if let Some(n) = self.cached_chain_len(role, algo) {
            return Ok(n as usize);
        }

        let (gen, skip_certs, slot_chain_len) = {
            let slot = self.cert_slot(role);
            let gen = slot.generation_counter(algo);
            let len = slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
            let skip_certs = slot
                .key_pair_id(algo)
                .and_then(|id| DeviceKey::try_from(id).ok())
                .map_or(0, |k| k.device_cert_skip_count());
            (gen, skip_certs, len)
        };
        self.invalidate_algo_cache(role, algo);

        let profile = algo.dpe_profile();
        let (device_chain_len, device_chain_offset) =
            device_chain_len_and_offset(alloc, profile, skip_certs).await?;
        let leaf_len = probe_leaf_len(alloc, profile).await?;
        let total = ChainLayout::new(
            slot_chain_len,
            device_chain_len,
            device_chain_offset,
            leaf_len,
        )?
        .total_len();

        self.ensure_generation_counter(role, algo, gen)?;
        self.set_cached_leaf_len(role, algo, leaf_len as u32);
        self.set_cached_device_chain_offset(role, algo, device_chain_offset as u32);
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
        let total = match self.cached_chain_len(role, algo) {
            Some(n) if n > 0 => n as usize,
            _ if offset == 0 => self.cert_chain_len(alloc, role, algo).await?,
            _ => return Err(INVARIANT),
        };
        if total == 0 || offset > total {
            return Err(INVARIANT);
        }
        if dst.is_empty() || offset == total {
            return Ok(0);
        }

        let (gen, skip_certs, endorsement_len) = {
            let slot = self.cert_slot(role);
            let gen = slot.generation_counter(algo);
            let len = slot.endorsement.size(algo).map_err(|_| INVARIANT)?;
            let skip_certs = slot
                .key_pair_id(algo)
                .and_then(|id| DeviceKey::try_from(id).ok())
                .map_or(0, |k| k.device_cert_skip_count());
            (gen, skip_certs, len)
        };
        let want = (total - offset).min(dst.len());
        let profile = algo.dpe_profile();
        let leaf_len = match self.cached_leaf_len(role, algo) {
            Some(n) => n as usize,
            None => {
                let n = probe_leaf_len(alloc, profile).await?;
                self.ensure_generation_counter(role, algo, gen)?;
                self.set_cached_leaf_len(role, algo, n as u32);
                n
            }
        };
        let device_chain_offset = if skip_certs > 0 {
            match self.cached_device_chain_offset(role, algo) {
                Some(n) => n as usize,
                None => {
                    let (_, skip) = device_chain_len_and_offset(alloc, profile, skip_certs).await?;
                    self.ensure_generation_counter(role, algo, gen)?;
                    self.set_cached_device_chain_offset(role, algo, skip as u32);
                    skip
                }
            }
        } else {
            0
        };
        let layout =
            ChainLayout::from_total(endorsement_len, total, device_chain_offset, leaf_len)?;
        if total != layout.total_len() {
            return Err(INVARIANT);
        }
        let mut written = 0usize;
        let mut cur_offset = offset;

        // 1. Endorsement region: ReadOnly copies synchronously from static RODATA;
        //    Managed captures a 16-byte flash coordinate snapshot and region guard
        //    before awaiting SPI flash.
        if cur_offset < layout.endorsement.end && written < want {
            let out_slice = checked_slice_mut(dst, written, want - written)?;
            let n = match &self.cert_slot(role).endorsement {
                SlotEndorsement::ReadOnly(e) => {
                    e.read(algo, cur_offset, out_slice).map_err(|_| INVARIANT)?
                }
                SlotEndorsement::Managed(m) => {
                    let snapshot = m
                        .get_endorsement(algo)
                        .ok_or(INVARIANT)?
                        .read_snapshot()
                        .map_err(|_| INVARIANT)?;
                    let _guard = RegionReadGuard::new(
                        self.shared,
                        role,
                        algo,
                        Some(snapshot.active_region()),
                    );
                    snapshot
                        .read(cur_offset, out_slice)
                        .await
                        .map_err(|_| INVARIANT)?
                }
                SlotEndorsement::Empty => return Err(INVARIANT),
            };
            self.ensure_generation_counter(role, algo, gen)?;
            written += n;
            cur_offset = offset + written;
        }

        // 2. Device cert-chain region (fetched from Caliptra Core via DPE GetCertificateChain)
        while cur_offset < layout.device_chain.end && written < want {
            let dev_off = layout
                .device_chain_offset
                .checked_add(
                    cur_offset
                        .checked_sub(layout.device_chain.start)
                        .ok_or(INVARIANT)?,
                )
                .ok_or(INVARIANT)?;
            let dev_take = (layout.device_chain.end - cur_offset)
                .min(want - written)
                .min(DPE_MAX_CHUNK_SIZE);
            let got = dpe_get_cert_chain_chunk(
                alloc,
                profile,
                dev_off as u32,
                checked_slice_mut(dst, written, dev_take)?,
            )
            .await?;
            if got != dev_take {
                return Err(INTERNAL_BUG);
            }
            self.ensure_generation_counter(role, algo, gen)?;
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
            self.ensure_generation_counter(role, algo, gen)?;
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
        if let Some(cached) = self.cached_chain_digest(role, algo) {
            *out = cached;
            return Ok(());
        }
        let _ = self.cert_chain_len(alloc, role, algo).await?;
        let (gen, _region_guard) = {
            let slot = self.cert_slot(role);
            let gen = slot.generation_counter(algo);
            let active_region = slot
                .endorsement
                .active_region(algo)
                .map_err(|_| INVARIANT)?;
            (
                gen,
                RegionReadGuard::new(self.shared, role, algo, active_region),
            )
        };
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
        self.ensure_generation_counter(role, algo, gen)?;
        sha_finish(alloc, &mut state, out).await?;
        self.cache_chain_digest(role, algo, out);
        Ok(())
    }

    /// Retrieve metadata, total byte length, and raw DER SHA-384 digest for `(role, algo)`.
    pub async fn cert_chain_info<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        info: &mut CertChainInfo,
    ) -> McuResult<()> {
        let (gen, device_key_id) = {
            let slot = self.cert_slot(role);
            let gen = slot.generation_counter(algo);
            let device_key_id = slot.key_pair_id(algo).ok_or(INVARIANT)? as u32;
            (gen, device_key_id)
        };
        let chain_len = self.cert_chain_len(alloc, role, algo).await? as u32;
        self.cert_chain_digest(alloc, role, algo, &mut info.chain_digest)
            .await?;
        self.ensure_generation_counter(role, algo, gen)?;
        info.device_key_id = device_key_id;
        info.chain_len = chain_len;
        Ok(())
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
        let key = self.shared.validate_key(role, key_pair_id)?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if self.cert_slot(role).write_in_progress(algo) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        let chain = managed_endorsement(self, role, algo)?;
        let target_region = chain.inactive_region();
        if self.cert_slot(role).region_has_readers(algo, target_region) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        self.cert_slot(role).set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = chain
                .write_updated(key as u8, cert_info, root_hash, data)
                .await?;
            commit_managed_endorsement(self, role, chain)?;
            Ok(())
        }
        .await;
        self.cert_slot(role).set_write_in_progress(algo, false);
        result?;
        self.invalidate_algo_cache(role, algo);
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
        let key = self.shared.validate_key(role, key_pair_id)?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if self.cert_slot(role).write_in_progress(algo) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        let chain = managed_endorsement(self, role, algo)?;
        let target_region = chain.inactive_region();
        if self.cert_slot(role).region_has_readers(algo, target_region) {
            return Err(cert_errors::STORAGE_BUSY);
        }
        self.cert_slot(role).set_write_in_progress(algo, true);
        let result: McuResult<()> = async {
            let chain = chain
                .begin_stream_update(key as u8, cert_info, data_len)
                .await?;
            stage_managed_endorsement(self, role, chain)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.cert_slot(role).set_write_in_progress(algo, false);
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
        if !self.cert_slot(role).write_in_progress(algo) {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let mut chain = managed_endorsement(self, role, algo)?;
        chain.write_stream_chunk(offset, data).await?;
        stage_managed_endorsement(self, role, chain)
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
        if !self.cert_slot(role).write_in_progress(algo) {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let result: McuResult<()> = async {
            let key = self.shared.validate_key(role, key_pair_id)?;
            if cert_info != CERT_MODEL_ALIAS_CERT {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            let chain = managed_endorsement(self, role, algo)?;
            validate_streamed_root_hash(alloc, &chain, root_hash, data_len).await?;
            let chain = chain
                .finish_stream_update(key as u8, cert_info, root_hash, data_len)
                .await?;
            commit_managed_endorsement(self, role, chain)?;
            Ok(())
        }
        .await;
        if let Err(err) = result {
            self.abort_write_endorsement_stream(role, algo).await?;
            return Err(err);
        }
        self.cert_slot(role).set_write_in_progress(algo, false);
        self.invalidate_algo_cache(role, algo);
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    pub async fn abort_write_endorsement_stream(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<()> {
        if self.cert_slot(role).write_in_progress(algo) {
            let mut chain = managed_endorsement(self, role, algo)?;
            chain.abort_stream_update()?;
            stage_managed_endorsement(self, role, chain)?;
        }
        self.cert_slot(role).set_write_in_progress(algo, false);
        Ok(())
    }

    #[cfg(feature = "set-certificate")]
    pub async fn erase_endorsement_chain(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> McuResult<()> {
        self.shared.policy.validate_role(role)?;
        if self.cert_slot(role).write_in_progress(algo)
            || self.cert_slot(role).any_region_has_readers(algo)
        {
            return Err(cert_errors::STORAGE_BUSY);
        }
        let chain = managed_endorsement(self, role, algo)?;
        chain.validate_erase()?;
        self.cert_slot(role).set_write_in_progress(algo, true);
        let mut unpublished = chain;
        unpublished.discard();
        commit_managed_endorsement(self, role, unpublished)?;
        self.invalidate_algo_cache(role, algo);
        let result = match chain.erase_updated().await {
            Ok(erased) => stage_managed_endorsement(self, role, erased),
            Err(err) => {
                let mut recovered = chain;
                // Keep the slot unpublished and locked if recovery also fails.
                recovered.recover().await?;
                commit_managed_endorsement(self, role, recovered)?;
                Err(err)
            }
        };
        self.cert_slot(role).set_write_in_progress(algo, false);
        result
    }

    /// Provision, replace, or erase a raw DER endorsement chain for `(role, algo)`.
    ///
    /// - `offset == 0 && total_size == 0 && data.is_empty()` erases the slot.
    /// - `offset == 0 && data.len() == total_size > 0` validates the key and DER root
    ///   certificate, computes the SHA-384 root hash, and writes in a single shot.
    /// - Multi-chunk transfers (`data.len() < total_size`) stream into the inactive
    ///   A/B region and compute the SHA-384 root hash from the first DER SEQUENCE
    ///   before committing the final chunk.
    #[cfg(feature = "set-certificate")]
    #[allow(clippy::too_many_arguments)]
    pub async fn set_raw_endorsement_chain<A: ScratchAlloc>(
        &self,
        alloc: &A,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        key_pair_id: u8,
        offset: usize,
        total_size: usize,
        data: &[u8],
    ) -> McuResult<()> {
        if offset == 0 {
            if let Some(prev) = self.active_stream.take() {
                self.abort_write_endorsement_stream(prev.role, prev.algo)
                    .await?;
            }
            if total_size == 0 {
                if !data.is_empty() {
                    return Err(cert_errors::INVALID_ENDORSEMENT);
                }
                return self.erase_endorsement_chain(role, algo).await;
            }
            if data.is_empty() || data.len() > total_size {
                return Err(cert_errors::INVALID_ENDORSEMENT);
            }
            if data.len() == total_size {
                let key = self.shared.validate_key(role, key_pair_id)?;
                let root_hash = compute_endorsement_root_hash(alloc, data).await?;
                return self
                    .write_endorsement_chain(
                        role,
                        algo,
                        key as u8,
                        CERT_MODEL_ALIAS_CERT,
                        &root_hash,
                        data,
                    )
                    .await;
            }
            self.begin_write_endorsement_stream(
                role,
                algo,
                key_pair_id,
                CERT_MODEL_ALIAS_CERT,
                total_size,
            )
            .await?;
            if let Err(err) = self
                .write_endorsement_stream_chunk(role, algo, 0, data)
                .await
            {
                let _ = self.abort_write_endorsement_stream(role, algo).await;
                return Err(err);
            }
            self.active_stream.set(Some(RawEndorsementStream {
                role,
                algo,
                key_pair_id,
                total_size,
            }));
            return Ok(());
        }

        let Some(stream) = self.active_stream.get() else {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        };
        let end = offset
            .checked_add(data.len())
            .ok_or(cert_errors::INVALID_ENDORSEMENT)?;
        if stream.role != role
            || stream.algo != algo
            || stream.key_pair_id != key_pair_id
            || stream.total_size != total_size
            || data.is_empty()
            || end > total_size
        {
            self.active_stream.set(None);
            let _ = self
                .abort_write_endorsement_stream(stream.role, stream.algo)
                .await;
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        if let Err(err) = self
            .write_endorsement_stream_chunk(role, algo, offset, data)
            .await
        {
            self.active_stream.set(None);
            let _ = self.abort_write_endorsement_stream(role, algo).await;
            return Err(err);
        }
        if end < total_size {
            return Ok(());
        }

        self.active_stream.set(None);
        let result: McuResult<()> = async {
            let key = self.shared.validate_key(role, key_pair_id)?;
            let chain = managed_endorsement(self, role, algo)?;
            let root_hash = compute_streamed_root_hash(alloc, &chain, total_size).await?;
            let chain = chain
                .finish_stream_update(key as u8, CERT_MODEL_ALIAS_CERT, &root_hash, total_size)
                .await?;
            commit_managed_endorsement(self, role, chain)?;
            Ok(())
        }
        .await;
        if let Err(err) = result {
            self.abort_write_endorsement_stream(role, algo).await?;
            return Err(err);
        }
        self.cert_slot(role).set_write_in_progress(algo, false);
        self.invalidate_algo_cache(role, algo);
        Ok(())
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn cert_slot_mut(&self, role: EndorsementRole) -> &mut CertSlot<S> {
        self.shared.cert_slot_mut(role)
    }

    fn cached_chain_len(&self, role: EndorsementRole, algo: CertificateAlgorithm) -> Option<u32> {
        self.valid_chain_cache(role, algo)?.chain_len
    }

    fn set_cached_chain_len(&self, role: EndorsementRole, algo: CertificateAlgorithm, len: u32) {
        self.update_chain_cache(role, algo, |cache| {
            cache.chain_len = Some(len);
        });
    }

    fn cached_leaf_len(&self, role: EndorsementRole, algo: CertificateAlgorithm) -> Option<u32> {
        self.valid_chain_cache(role, algo)?.leaf_len
    }

    fn set_cached_leaf_len(&self, role: EndorsementRole, algo: CertificateAlgorithm, len: u32) {
        self.update_chain_cache(role, algo, |cache| {
            cache.leaf_len = Some(len);
        });
    }

    fn cached_device_chain_offset(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<u32> {
        self.valid_chain_cache(role, algo)?.device_chain_offset
    }

    fn set_cached_device_chain_offset(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        offset: u32,
    ) {
        self.update_chain_cache(role, algo, |cache| {
            cache.device_chain_offset = Some(offset);
        });
    }

    fn invalidate_algo_cache(&self, role: EndorsementRole, algo: CertificateAlgorithm) {
        let gen = self.cert_slot(role).generation_counter(algo);
        *self.chain_cache_mut(role, algo) = CertChainCache {
            generation_counter: gen,
            ..CertChainCache::default()
        };
    }

    #[allow(clippy::mut_from_ref)]
    fn chain_cache_mut(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> &mut CertChainCache {
        unsafe { &mut (*self.caches.get())[role as usize][(algo as usize) - 1] }
    }

    fn valid_chain_cache(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
    ) -> Option<CertChainCache> {
        let gen = self.cert_slot(role).generation_counter(algo);
        let cache = self.chain_cache_mut(role, algo);
        if cache.generation_counter != gen {
            *cache = CertChainCache {
                generation_counter: gen,
                ..CertChainCache::default()
            };
            return None;
        }
        Some(*cache)
    }

    fn update_chain_cache(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        update: impl FnOnce(&mut CertChainCache),
    ) {
        let gen = self.cert_slot(role).generation_counter(algo);
        let cache = self.chain_cache_mut(role, algo);
        if cache.generation_counter != gen {
            *cache = CertChainCache {
                generation_counter: gen,
                ..CertChainCache::default()
            };
        }
        update(cache);
    }

    fn ensure_generation_counter(
        &self,
        role: EndorsementRole,
        algo: CertificateAlgorithm,
        expected_gen: u32,
    ) -> McuResult<()> {
        let slot = self.cert_slot(role);
        if slot.generation_counter(algo) != expected_gen {
            self.invalidate_algo_cache(role, algo);
            return Err(INVARIANT);
        }
        Ok(())
    }
}

#[cfg(feature = "set-certificate")]
fn managed_endorsement<S: EndorsementStorage>(
    store: &TaskCertStore<S>,
    role: EndorsementRole,
    algo: CertificateAlgorithm,
) -> McuResult<ManagedEndorsementChain<S>> {
    match &store.cert_slot(role).endorsement {
        SlotEndorsement::Managed(m) => m.get_endorsement(algo).copied().ok_or(INVARIANT),
        SlotEndorsement::ReadOnly(_) => Err(mcu_error::codes::NOT_IMPLEMENTED),
        SlotEndorsement::Empty => Err(INVARIANT),
    }
}

#[cfg(feature = "set-certificate")]
fn stage_managed_endorsement<S: EndorsementStorage>(
    store: &TaskCertStore<S>,
    role: EndorsementRole,
    chain: ManagedEndorsementChain<S>,
) -> McuResult<()> {
    let cert_slot = store.cert_slot_mut(role);
    match &mut cert_slot.endorsement {
        SlotEndorsement::Managed(m) => {
            m.set_endorsement(chain);
            Ok(())
        }
        _ => Err(INVARIANT),
    }
}

#[cfg(feature = "set-certificate")]
fn commit_managed_endorsement<S: EndorsementStorage>(
    store: &TaskCertStore<S>,
    role: EndorsementRole,
    chain: ManagedEndorsementChain<S>,
) -> McuResult<()> {
    let algo = chain.algo();
    let cert_slot = store.cert_slot_mut(role);
    match &mut cert_slot.endorsement {
        SlotEndorsement::Managed(m) => {
            m.set_endorsement(chain);
            cert_slot.bump_generation_counter(algo);
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

pub(crate) struct DeviceChainPrefixScanner {
    pub(crate) certs_left: usize,
    cert_bytes_left: usize,
    pub(crate) skip_len: usize,
    header: [u8; 6],
    header_len: usize,
}

impl DeviceChainPrefixScanner {
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

impl DpeChainSink for DeviceChainPrefixScanner {
    async fn on_chunk(&mut self, chunk: &[u8]) -> McuResult<()> {
        self.consume(chunk)
    }
}

struct ChainLayout {
    endorsement: Range<usize>,
    device_chain: Range<usize>,
    leaf: Range<usize>,
    device_chain_offset: usize,
}

impl ChainLayout {
    fn new(
        endorsement_len: usize,
        full_device_chain_len: usize,
        device_chain_offset: usize,
        leaf_len: usize,
    ) -> McuResult<Self> {
        let device_chain_len = full_device_chain_len
            .checked_sub(device_chain_offset)
            .ok_or(INVARIANT)?;
        let device_chain_end = endorsement_len
            .checked_add(device_chain_len)
            .ok_or(INVARIANT)?;
        let leaf_end = device_chain_end.checked_add(leaf_len).ok_or(INVARIANT)?;
        Ok(Self {
            endorsement: 0..endorsement_len,
            device_chain: endorsement_len..device_chain_end,
            leaf: device_chain_end..leaf_end,
            device_chain_offset,
        })
    }

    fn from_total(
        endorsement_len: usize,
        total: usize,
        device_chain_offset: usize,
        leaf_len: usize,
    ) -> McuResult<Self> {
        let leaf_start = total.checked_sub(leaf_len).ok_or(INVARIANT)?;
        if leaf_start < endorsement_len {
            return Err(INVARIANT);
        }
        Ok(Self {
            endorsement: 0..endorsement_len,
            device_chain: endorsement_len..leaf_start,
            leaf: leaf_start..total,
            device_chain_offset,
        })
    }

    fn total_len(&self) -> usize {
        self.leaf.end
    }
}

#[cfg(feature = "set-certificate")]
async fn compute_endorsement_root_hash<A: ScratchAlloc>(
    alloc: &A,
    cert_chain: &[u8],
) -> McuResult<[u8; 48]> {
    let root_cert_len = der_first_seq_len(cert_chain).ok_or(cert_errors::INVALID_ENDORSEMENT)?;
    compute_root_hash(alloc, checked_slice(cert_chain, 0, root_cert_len)?).await
}

#[cfg(feature = "set-certificate")]
async fn validate_root_hash<A: ScratchAlloc>(
    alloc: &A,
    root_hash: &[u8; 48],
    cert_chain: &[u8],
) -> McuResult<()> {
    let digest = compute_endorsement_root_hash(alloc, cert_chain).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn compute_streamed_root_hash<A: ScratchAlloc, S: EndorsementStorage>(
    alloc: &A,
    managed: &ManagedEndorsementChain<S>,
    data_len: usize,
) -> McuResult<[u8; 48]> {
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
    Ok(digest)
}

#[cfg(feature = "set-certificate")]
async fn validate_streamed_root_hash<A: ScratchAlloc, S: EndorsementStorage>(
    alloc: &A,
    managed: &ManagedEndorsementChain<S>,
    root_hash: &[u8; 48],
    data_len: usize,
) -> McuResult<()> {
    let digest = compute_streamed_root_hash(alloc, managed, data_len).await?;
    if &digest != root_hash {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    Ok(())
}

#[cfg(feature = "set-certificate")]
async fn streamed_first_der_len<S: EndorsementStorage>(
    managed: &ManagedEndorsementChain<S>,
    data_len: usize,
) -> McuResult<usize> {
    let mut header = [0u8; 6];
    if data_len < 2 {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    if managed
        .read_stream_chunk(0, checked_slice_mut(&mut header, 0, 2)?)
        .await?
        != 2
    {
        return Err(INVARIANT);
    }
    if header[0] != 0x30 {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    let len_byte = header[1];
    let (header_len, content_len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || data_len < 2 + len_len {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let len_buf = checked_slice_mut(&mut header, 2, len_len)?;
        if managed.read_stream_chunk(2, len_buf).await? != len_len {
            return Err(INVARIANT);
        }
        let mut content_len = 0usize;
        for &byte in checked_slice(&header, 2, len_len)? {
            content_len = content_len
                .checked_shl(8)
                .ok_or(cert_errors::INVALID_ENDORSEMENT)?;
            content_len = content_len
                .checked_add(byte as usize)
                .ok_or(cert_errors::INVALID_ENDORSEMENT)?;
        }
        (2 + len_len, content_len)
    };
    if content_len == 0 {
        return Err(cert_errors::INVALID_ENDORSEMENT);
    }
    let cert_len = header_len
        .checked_add(content_len)
        .ok_or(cert_errors::INVALID_ENDORSEMENT)?;
    if cert_len > data_len {
        return Err(cert_errors::INVALID_ENDORSEMENT);
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

async fn device_chain_len_and_offset<A: ScratchAlloc>(
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

    let mut sink = DeviceChainPrefixScanner::new(skip_certs);
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

    static TEST_CERT: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
    static TEST_CHAIN: &[&[u8]] = &[TEST_CERT];

    #[test]
    fn readonly_endorsement_size_matches_chain() {
        let hash = [0xAB_u8; 48];
        let endorsement: SlotEndorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(TEST_CHAIN, hash));

        assert_eq!(
            endorsement.size(CertificateAlgorithm::EccP384).unwrap(),
            TEST_CERT.len()
        );
    }

    #[test]
    fn readonly_endorsement_returns_correct_root_hash() {
        let mut hash = [0u8; 48];
        hash[0] = 0xDE;
        hash[47] = 0xAD;
        let endorsement: SlotEndorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(TEST_CHAIN, hash));

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(CertificateAlgorithm::EccP384, &mut out)
            .unwrap();
        assert_eq!(out, hash);
    }

    #[test]
    fn readonly_endorsement_is_supported_and_provisioned() {
        let hash = [0x11_u8; 48];
        let endorsement: SlotEndorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(TEST_CHAIN, hash));

        assert!(endorsement.is_supported());
        assert!(endorsement.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!endorsement.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn shared_store_slot_defaults_to_empty() {
        let store: SharedCertStore = SharedCertStore::new();
        let slot = store.cert_slot(EndorsementRole::Vendor);
        assert!(!slot.endorsement.is_supported());
        assert!(slot.key_pair_id(CertificateAlgorithm::EccP384).is_none());
    }

    #[test]
    fn readonly_endorsement_without_mldsa_errors_on_mldsa_algo() {
        let hash = [0x22_u8; 48];
        let endorsement: SlotEndorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(TEST_CHAIN, hash));

        assert_eq!(
            endorsement.size(CertificateAlgorithm::EccP384).unwrap(),
            TEST_CERT.len()
        );
        assert!(endorsement.size(CertificateAlgorithm::MlDsa87).is_err());
    }

    #[test]
    fn readonly_endorsement_with_mldsa_supports_both_algos() {
        let ecc_hash = [0x33_u8; 48];
        let mldsa_hash = [0x44_u8; 48];
        let endorsement: SlotEndorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(TEST_CHAIN, ecc_hash).with_mldsa(TEST_CHAIN, mldsa_hash),
        );

        assert_eq!(
            endorsement.size(CertificateAlgorithm::EccP384).unwrap(),
            TEST_CERT.len()
        );
        assert_eq!(
            endorsement.size(CertificateAlgorithm::MlDsa87).unwrap(),
            TEST_CERT.len()
        );

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(CertificateAlgorithm::MlDsa87, &mut out)
            .unwrap();
        assert_eq!(out, mldsa_hash);
    }

    #[test]
    fn shared_cert_store_new_has_empty_slots_and_no_metadata() {
        let store: SharedCertStore = SharedCertStore::new();
        for role in EndorsementRole::ALL {
            let slot = store.cert_slot(role);
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

        store.invalidate_algo_cache(EndorsementRole::Vendor, CertificateAlgorithm::EccP384);
        assert_eq!(
            store.cached_chain_len(EndorsementRole::Vendor, CertificateAlgorithm::EccP384),
            None
        );
    }

    #[test]
    fn cross_task_generation_bump_invalidates_only_modified_algorithm() {
        static SHARED: SharedCertStore = SharedCertStore::new();
        let task_a = TaskCertStore::new(&SHARED);
        let task_b = TaskCertStore::new(&SHARED);

        task_a.set_cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::EccP384, 512);
        task_a.cache_chain_digest(
            EndorsementRole::Owner,
            CertificateAlgorithm::EccP384,
            &[0xAA; 48],
        );
        task_a.set_cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::MlDsa87, 2048);
        task_a.cache_chain_digest(
            EndorsementRole::Owner,
            CertificateAlgorithm::MlDsa87,
            &[0xBB; 48],
        );

        // Task B stages a replacement in the staging_region for (Owner, EccP384).
        // Because the active_region remains untouched until commit, Task A's
        // cached values for the active_region stay valid while staging is in progress.
        let owner_slot = task_b.cert_slot(EndorsementRole::Owner);
        owner_slot.set_write_in_progress(CertificateAlgorithm::EccP384, true);
        assert_eq!(
            task_a.cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::EccP384),
            Some(512)
        );
        assert_eq!(
            task_a.cached_chain_digest(EndorsementRole::Owner, CertificateAlgorithm::EccP384),
            Some([0xAA; 48])
        );
        assert_eq!(
            task_a.cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::MlDsa87),
            Some(2048)
        );

        // When Task B atomically commits the new region, it bumps the generation counter
        // for EccP384, invalidating Task A's EccP384 cache while MlDsa87 stays valid.
        owner_slot.bump_generation_counter(CertificateAlgorithm::EccP384);
        owner_slot.set_write_in_progress(CertificateAlgorithm::EccP384, false);

        assert_eq!(
            task_a.cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::EccP384),
            None
        );
        assert_eq!(
            task_a.cached_chain_digest(EndorsementRole::Owner, CertificateAlgorithm::EccP384),
            None
        );
        assert_eq!(
            task_a.cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::MlDsa87),
            Some(2048)
        );
        assert_eq!(
            task_a.cached_chain_digest(EndorsementRole::Owner, CertificateAlgorithm::MlDsa87),
            Some([0xBB; 48])
        );
    }

    #[test]
    fn active_region_remains_readable_while_write_in_progress() {
        static SHARED: SharedCertStore = SharedCertStore::new();
        let store = TaskCertStore::new(&SHARED);
        let slot = store.cert_slot_mut(EndorsementRole::Vendor);
        slot.endorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(TEST_CHAIN, [0x55; 48]));
        slot.bump_generation_counter(CertificateAlgorithm::EccP384);

        store
            .cert_slot(EndorsementRole::Vendor)
            .set_write_in_progress(CertificateAlgorithm::EccP384, true);

        let mut hash = [0u8; 48];
        store
            .cert_slot(EndorsementRole::Vendor)
            .root_cert_hash(CertificateAlgorithm::EccP384, &mut hash)
            .unwrap();
        assert_eq!(hash, [0x55; 48]);

        store
            .cert_slot(EndorsementRole::Vendor)
            .set_write_in_progress(CertificateAlgorithm::EccP384, false);
    }

    #[test]
    fn region_read_guard_tracks_in_flight_region_readers() {
        static SHARED: SharedCertStore = SharedCertStore::new();
        let slot = SHARED.cert_slot(EndorsementRole::Owner);
        assert!(!slot.region_has_readers(CertificateAlgorithm::EccP384, 0));
        assert!(!slot.any_region_has_readers(CertificateAlgorithm::EccP384));

        {
            let _guard = RegionReadGuard::new(
                &SHARED,
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                Some(0),
            );
            assert!(slot.region_has_readers(CertificateAlgorithm::EccP384, 0));
            assert!(!slot.region_has_readers(CertificateAlgorithm::EccP384, 1));
            assert!(slot.any_region_has_readers(CertificateAlgorithm::EccP384));
            assert!(!slot.any_region_has_readers(CertificateAlgorithm::MlDsa87));
        }

        assert!(!slot.region_has_readers(CertificateAlgorithm::EccP384, 0));
        assert!(!slot.any_region_has_readers(CertificateAlgorithm::EccP384));
    }

    #[cfg(feature = "set-certificate")]
    #[test]
    fn validate_key_resolves_zero_for_some_policy_and_requires_explicit_for_none() {
        let store: SharedCertStore = SharedCertStore::new();
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

    #[cfg(feature = "set-certificate")]
    mod recovery_tests {
        extern crate std;

        use super::*;
        use futures::executor::block_on;
        use std::{
            boxed::Box,
            cell::{Cell, RefCell},
            vec,
            vec::Vec,
        };

        const TEST_DRIVER: u32 = 0x8000_0006;
        const TEST_REGION: usize = 4096;

        struct FaultyFlash {
            bytes: RefCell<Vec<u8>>,
            successful_erases_before_failure: Cell<Option<usize>>,
            fail_reads: Cell<bool>,
            short_header_write: Cell<bool>,
        }

        // Safety: each FaultyStorage instance in unit tests is used on a single thread.
        unsafe impl Sync for FaultyFlash {}

        #[derive(Clone, Copy)]
        struct FaultyStorage {
            id: u32,
            flash: &'static FaultyFlash,
        }

        impl PartialEq for FaultyStorage {
            fn eq(&self, other: &Self) -> bool {
                self.id == other.id
            }
        }

        impl Eq for FaultyStorage {}

        impl FaultyStorage {
            fn new() -> Self {
                let flash = Box::leak(Box::new(FaultyFlash {
                    bytes: RefCell::new(vec![0xFF; TEST_REGION]),
                    successful_erases_before_failure: Cell::new(None),
                    fail_reads: Cell::new(false),
                    short_header_write: Cell::new(false),
                }));
                Self {
                    id: TEST_DRIVER,
                    flash,
                }
            }
        }

        impl EndorsementStorage for FaultyStorage {
            async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<()> {
                if self.flash.fail_reads.get() {
                    return Err(cert_errors::STORAGE_ERROR);
                }
                let bytes = self.flash.bytes.borrow();
                let end = offset
                    .checked_add(buf.len())
                    .ok_or(cert_errors::STORAGE_ERROR)?;
                if end > bytes.len() {
                    return Err(cert_errors::STORAGE_ERROR);
                }
                buf.copy_from_slice(&bytes[offset..end]);
                Ok(())
            }

            async fn write(&self, offset: usize, data: &[u8]) -> McuResult<()> {
                let mut bytes = self.flash.bytes.borrow_mut();
                let len = if offset.is_multiple_of(TEST_REGION / MANAGED_REGION_COUNT)
                    && self.flash.short_header_write.replace(false)
                {
                    data.len() - 8
                } else {
                    data.len()
                };
                let end = offset.checked_add(len).ok_or(cert_errors::STORAGE_ERROR)?;
                if end > bytes.len() {
                    return Err(cert_errors::STORAGE_ERROR);
                }
                bytes[offset..end].copy_from_slice(&data[..len]);
                Ok(())
            }

            async fn erase(&self, offset: usize, len: usize) -> McuResult<()> {
                if let Some(remaining) = self.flash.successful_erases_before_failure.get() {
                    if remaining == 0 {
                        self.flash.successful_erases_before_failure.set(None);
                        return Err(cert_errors::STORAGE_ERROR);
                    }
                    self.flash
                        .successful_erases_before_failure
                        .set(Some(remaining - 1));
                }
                let mut bytes = self.flash.bytes.borrow_mut();
                let end = offset.checked_add(len).ok_or(cert_errors::STORAGE_ERROR)?;
                if end > bytes.len() {
                    return Err(cert_errors::STORAGE_ERROR);
                }
                bytes[offset..end].fill(0xFF);
                Ok(())
            }
        }

        fn provisioned_store(
            shared: &'static SharedCertStore<FaultyStorage>,
            storage: FaultyStorage,
        ) -> TaskCertStore<FaultyStorage> {
            *storage.flash.bytes.borrow_mut() = vec![0xFF; TEST_REGION];
            block_on(shared.init_managed_endorsement(
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                storage,
                0,
                TEST_REGION,
            ))
            .unwrap();
            let store = TaskCertStore::new(shared);
            for byte in [0xAA, 0xBB] {
                block_on(store.write_endorsement_chain(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[byte; 48],
                    &[byte; 16],
                ))
                .unwrap();
            }
            store
        }

        fn recovered_data(storage: FaultyStorage) -> [u8; 16] {
            let mut recovered = ManagedEndorsementChain::new(
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                storage,
                0,
                TEST_REGION,
                Some(DeviceKey::LDevId),
            );
            block_on(recovered.load()).unwrap();
            let mut data = [0; 16];
            block_on(recovered.read_snapshot().unwrap().read(0, &mut data)).unwrap();
            data
        }

        #[test]
        fn erase_failure_recovers_tracking_before_replacement() {
            static SHARED: [SharedCertStore<FaultyStorage>; 2] =
                [const { SharedCertStore::new() }; 2];
            for (successful_erases, shared) in SHARED.iter().enumerate() {
                let storage = FaultyStorage::new();
                let store = provisioned_store(shared, storage);
                let other_task = TaskCertStore::new(shared);
                other_task.set_cached_chain_len(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    512,
                );
                storage
                    .flash
                    .successful_erases_before_failure
                    .set(Some(successful_erases));

                assert_eq!(
                    block_on(store.erase_endorsement_chain(
                        EndorsementRole::Owner,
                        CertificateAlgorithm::EccP384,
                    )),
                    Err(cert_errors::STORAGE_ERROR),
                );
                let slot = store.cert_slot(EndorsementRole::Owner);
                assert!(!slot.write_in_progress(CertificateAlgorithm::EccP384));
                assert!(slot.is_provisioned(CertificateAlgorithm::EccP384));
                assert_eq!(
                    other_task
                        .cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::EccP384),
                    None,
                );

                block_on(store.write_endorsement_chain(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[0xCC; 48],
                    &[0xCC; 16],
                ))
                .unwrap();
                assert_eq!(recovered_data(storage), [0xCC; 16]);
            }
        }

        #[test]
        fn failed_erase_recovery_blocks_updates_and_cannot_be_aborted() {
            static SHARED: SharedCertStore<FaultyStorage> = SharedCertStore::new();
            let storage = FaultyStorage::new();
            let store = provisioned_store(&SHARED, storage);
            storage.flash.successful_erases_before_failure.set(Some(0));
            storage.flash.fail_reads.set(true);

            assert_eq!(
                block_on(store.erase_endorsement_chain(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                )),
                Err(cert_errors::STORAGE_ERROR),
            );
            let slot = store.cert_slot(EndorsementRole::Owner);
            assert!(!slot.is_provisioned(CertificateAlgorithm::EccP384));
            assert!(slot.write_in_progress(CertificateAlgorithm::EccP384));
            assert_eq!(
                block_on(store.abort_write_endorsement_stream(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                )),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            assert_eq!(
                block_on(store.write_endorsement_chain(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[0xCC; 48],
                    &[0xCC; 16],
                )),
                Err(cert_errors::STORAGE_BUSY),
            );
            assert_eq!(
                block_on(store.begin_write_endorsement_stream(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    16,
                )),
                Err(cert_errors::STORAGE_BUSY),
            );

            storage.flash.fail_reads.set(false);
            assert_eq!(recovered_data(storage), [0xBB; 16]);
        }

        #[test]
        fn header_readback_failure_does_not_publish_replacement() {
            static SHARED: SharedCertStore<FaultyStorage> = SharedCertStore::new();
            let storage = FaultyStorage::new();
            let store = provisioned_store(&SHARED, storage);
            storage.flash.short_header_write.set(true);

            assert_eq!(
                block_on(store.write_endorsement_chain(
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[0xCC; 48],
                    &[0xCC; 16],
                )),
                Err(cert_errors::STORAGE_ERROR),
            );
            let slot = store.cert_slot(EndorsementRole::Owner);
            assert!(slot.is_provisioned(CertificateAlgorithm::EccP384));
            assert!(!slot.write_in_progress(CertificateAlgorithm::EccP384));
            assert_eq!(recovered_data(storage), [0xBB; 16]);
        }

        struct DummyAlloc;
        impl ScratchAlloc for DummyAlloc {
            type Buf<'a>
                = Vec<u8>
            where
                Self: 'a;

            fn alloc(&self, _size: usize) -> McuResult<Self::Buf<'_>> {
                Err(INVARIANT)
            }
        }

        #[test]
        fn raw_endorsement_chain_erases_and_handles_stream_aborts() {
            static SHARED: SharedCertStore<FaultyStorage> = SharedCertStore::new();
            let storage = FaultyStorage::new();
            let store = provisioned_store(&SHARED, storage);

            // Non-empty data with total_size == 0 is rejected.
            assert_eq!(
                block_on(store.set_raw_endorsement_chain(
                    &DummyAlloc,
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    0,
                    0,
                    &[0x30],
                )),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );

            // Begin a multi-chunk stream at offset 0.
            block_on(store.set_raw_endorsement_chain(
                &DummyAlloc,
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                1,
                0,
                16,
                &[0x30, 0x0E, 1, 2],
            ))
            .unwrap();
            assert!(store
                .cert_slot(EndorsementRole::Owner)
                .write_in_progress(CertificateAlgorithm::EccP384));

            // Parameter mismatch at offset > 0 aborts the active stream.
            assert_eq!(
                block_on(store.set_raw_endorsement_chain(
                    &DummyAlloc,
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    1,
                    4,
                    32,
                    &[3, 4],
                )),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            assert!(!store
                .cert_slot(EndorsementRole::Owner)
                .write_in_progress(CertificateAlgorithm::EccP384));

            // Begin another stream, then restart at offset == 0 with total_size == 0 (erase).
            block_on(store.set_raw_endorsement_chain(
                &DummyAlloc,
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                1,
                0,
                16,
                &[0x30, 0x0E, 1, 2],
            ))
            .unwrap();
            block_on(store.set_raw_endorsement_chain(
                &DummyAlloc,
                EndorsementRole::Owner,
                CertificateAlgorithm::EccP384,
                0,
                0,
                0,
                &[],
            ))
            .unwrap();
            let slot = store.cert_slot(EndorsementRole::Owner);
            assert!(!slot.is_provisioned(CertificateAlgorithm::EccP384));
            assert!(!slot.write_in_progress(CertificateAlgorithm::EccP384));
        }

        #[test]
        fn read_cert_chain_rejects_uncached_nonzero_offset_and_out_of_bounds_offset() {
            static SHARED: SharedCertStore<FaultyStorage> = SharedCertStore::new();
            let storage = FaultyStorage::new();
            let store = provisioned_store(&SHARED, storage);
            let mut buf = [0u8; 8];

            // Uncached read with offset > 0 fails with INVARIANT.
            assert_eq!(
                block_on(store.read_cert_chain(
                    &DummyAlloc,
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    4,
                    &mut buf,
                )),
                Err(INVARIANT),
            );

            // Cached read with offset == total returns Ok(0), offset > total returns Err(INVARIANT).
            store.set_cached_chain_len(EndorsementRole::Owner, CertificateAlgorithm::EccP384, 64);
            assert_eq!(
                block_on(store.read_cert_chain(
                    &DummyAlloc,
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    64,
                    &mut buf,
                )),
                Ok(0),
            );
            assert_eq!(
                block_on(store.read_cert_chain(
                    &DummyAlloc,
                    EndorsementRole::Owner,
                    CertificateAlgorithm::EccP384,
                    65,
                    &mut buf,
                )),
                Err(INVARIANT),
            );
        }
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
    fn device_chain_prefix_scanner_handles_split_headers_and_bodies() {
        let mut scanner = DeviceChainPrefixScanner::new(2);
        scanner.consume(&[0x30]).unwrap();
        scanner.consume(&[0x03, 1]).unwrap();
        scanner.consume(&[2, 3, 0x30, 0x02, 4, 5, 9]).unwrap();

        assert_eq!(scanner.certs_left, 0);
        assert_eq!(scanner.skip_len, 9);
    }
}
