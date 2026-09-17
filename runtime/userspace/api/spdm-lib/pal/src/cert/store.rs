// Licensed under the Apache-2.0 license

//! Shared cert store — a single static instance referenced by all PAL
//! instances (MCTP, DOE, …).
//!
//! Interior mutability is safe because embassy tasks are cooperative
//! on a single-core MCU — only one task runs at a time.

use caliptra_mcu_cert_store::CertificateProvisioningPolicy;
#[cfg(feature = "set-certificate")]
use caliptra_mcu_cert_store::EndorsementRole;
use caliptra_mcu_spdm_traits::SpdmPalAsymAlgo;
use core::cell::UnsafeCell;

use mcu_caliptra_api::{
    sha_finish, sha_init, sha_update, HashAlgo, ScratchAlloc, SHA_CONTEXT_SIZE,
};
use mcu_error::McuResult;

use super::endorsement::{
    slot_index, CertSlot, ReadOnlyEndorsementSlot, SlotEndorsement, CERT_MODEL_ALIAS_CERT,
    NUM_CERT_SLOTS,
};
#[cfg(feature = "set-certificate")]
use super::endorsement::{ManagedEndorsementSlot, SingleManagedEndorsement};

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
                CertSlot::empty(match policy.owner_key {
                    Some(key) => Some(key.key_pair_id()),
                    None => None,
                }),
                CertSlot::empty(match policy.tenant_key {
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
        idx: usize,
        key_pair_id: u8,
    ) -> McuResult<caliptra_mcu_cert_store::DeviceKey> {
        let role = super::endorsement::endorsement_role(idx).ok_or(mcu_error::codes::INVARIANT)?;
        self.policy.validate_key(role, key_pair_id)
    }

    // ---------------------------------------------------------------
    // Cert-slot accessors
    // ---------------------------------------------------------------

    pub fn cert_slots(&self) -> &[CertSlot; NUM_CERT_SLOTS] {
        // SAFETY: single-task invariant.
        unsafe { &*self.cert_slots.get() }
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
        idx: usize,
        ecc_chain: &'static [&'static [u8]],
        mldsa_chain: Option<&'static [&'static [u8]]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if idx >= NUM_CERT_SLOTS || ecc_chain.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if self.cert_slots()[idx].configured_key_pair_id() != Some(key_pair_id) {
            return Err(caliptra_mcu_cert_store::errors::KEY_MISMATCH);
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
        // Both paths end in a generated DPE leaf, so both use AliasCert.
        slot.set_metadata_all(Some(CERT_MODEL_ALIAS_CERT));
        Ok(())
    }

    /// Configure a DPE-only slot with no static endorsement certs.
    ///
    /// The SPDM certificate chain contains only the DPE device chain
    /// (LDevID → FMC → RT) plus a CertifyKey leaf — no Root CA or IDevID
    /// in the endorsement segment.
    ///
    /// The `*_first_dpe_cert` bytes (typically the LDevID cert) are used
    /// **only** to compute the RootHash for each algorithm's SPDM
    /// CertificateChain header; they are not stored in the endorsement
    /// segment. Pass `mldsa_first_dpe_cert = None` on platforms that do not
    /// serve an ML-DSA-87 chain for this slot.
    pub async fn set_dpe_only_slot<A: ScratchAlloc>(
        &self,
        alloc: &A,
        idx: usize,
        ecc_first_dpe_cert: &[u8],
        mldsa_first_dpe_cert: Option<&[u8]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if idx >= NUM_CERT_SLOTS || ecc_first_dpe_cert.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if self.cert_slots()[idx].configured_key_pair_id() != Some(key_pair_id) {
            return Err(caliptra_mcu_cert_store::errors::KEY_MISMATCH);
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
        slot.set_metadata_all(Some(CERT_MODEL_ALIAS_CERT));
        Ok(())
    }

    /// Configure a flash-backed managed cert-chain region for `(idx, algo)`
    /// and load any existing record from flash. Uninitialized flash leaves
    /// that `(slot, algo)` supported but not provisioned, so SET_CERTIFICATE
    /// can install it later.
    ///
    /// Returns `INVARIANT` if the requested region intersects any region
    /// already wired to any slot (including another algorithm in the same
    /// slot), since an update erases a whole region.
    /// Rejected records leave the region wired but unprovisioned and return
    /// an error for the caller to report. Flash contents are not modified.
    #[cfg(feature = "set-certificate")]
    #[allow(clippy::too_many_arguments)]
    pub async fn set_managed_endorsement<A: ScratchAlloc>(
        &self,
        alloc: &A,
        idx: usize,
        spdm_slot: u8,
        algo: SpdmPalAsymAlgo,
        driver_num: u32,
        base: usize,
        capacity: usize,
    ) -> McuResult<()> {
        self.policy.validate()?;
        if idx >= NUM_CERT_SLOTS || capacity == 0 || slot_index(spdm_slot) != Some(idx) {
            return Err(mcu_error::codes::INVARIANT);
        }
        let role = super::endorsement::endorsement_role(idx).ok_or(mcu_error::codes::INVARIANT)?;
        if role == EndorsementRole::Vendor {
            return Err(caliptra_mcu_cert_store::errors::PROVISIONING_DISABLED);
        }

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
            (SlotEndorsement::Empty, SpdmPalAsymAlgo::EccP384) => {}
            (SlotEndorsement::Managed(m), SpdmPalAsymAlgo::MlDsa87)
                if m.get_endorsement(SpdmPalAsymAlgo::MlDsa87).is_none() => {}
            _ => return Err(mcu_error::codes::INVARIANT),
        }

        let mut region = SingleManagedEndorsement::new(
            spdm_slot,
            algo,
            driver_num,
            base,
            capacity,
            self.policy.configured_key(role),
        );
        let recovery: McuResult<()> = async {
            region.load().await?;
            if region.is_initialized() {
                let key = self.policy.key_for_role(role)?;
                let len = region.size()?;
                caliptra_mcu_cert_store::certificate::validate_endorsement(
                    alloc,
                    &region,
                    len,
                    region.der_capacity(),
                    algo.into(),
                    key,
                )
                .await?;
                let mut root_hash = [0; 48];
                region.root_cert_hash(&mut root_hash)?;
                super::validate_streamed_root_hash(alloc, &region, &root_hash, len).await?;
            }
            Ok(())
        }
        .await;
        if recovery.is_err() {
            region.discard();
        }
        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.set_metadata(algo, region.cert_info());
        match &mut slot.endorsement {
            SlotEndorsement::Empty => {
                slot.endorsement = SlotEndorsement::Managed(ManagedEndorsementSlot::new(region));
            }
            SlotEndorsement::Managed(m) => {
                m.set_endorsement(region);
            }
            SlotEndorsement::ReadOnly(_) => return Err(mcu_error::codes::INVARIANT),
        }
        recovery
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
    fn algo_cache(&self, algo: SpdmPalAsymAlgo) -> &AlgoCache {
        match algo {
            SpdmPalAsymAlgo::EccP384 => &self.ecc,
            SpdmPalAsymAlgo::MlDsa87 => &self.mldsa,
        }
    }

    fn algo_cache_mut(&mut self, algo: SpdmPalAsymAlgo) -> &mut AlgoCache {
        match algo {
            SpdmPalAsymAlgo::EccP384 => &mut self.ecc,
            SpdmPalAsymAlgo::MlDsa87 => &mut self.mldsa,
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
    #[allow(dead_code)]
    pub(crate) fn cert_slot_mut(&self, idx: usize) -> Option<&mut CertSlot> {
        self.shared.cert_slot_mut(idx)
    }

    pub(crate) fn cached_chain_len(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u32> {
        let idx = slot_index(slot)?;
        unsafe { (*self.caches.get())[idx].algo_cache(algo).chain_len }
    }

    pub(crate) fn set_cached_chain_len(&self, slot: u8, algo: SpdmPalAsymAlgo, len: u32) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].algo_cache_mut(algo).chain_len = Some(len);
            }
        }
    }

    pub(crate) fn cached_leaf_len(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u32> {
        let idx = slot_index(slot)?;
        unsafe { (*self.caches.get())[idx].algo_cache(algo).leaf_len }
    }

    pub(crate) fn set_cached_leaf_len(&self, slot: u8, algo: SpdmPalAsymAlgo, len: u32) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].algo_cache_mut(algo).leaf_len = Some(len);
            }
        }
    }

    pub(crate) fn cached_dpe_skip_len(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<u32> {
        let idx = slot_index(slot)?;
        unsafe { (*self.caches.get())[idx].algo_cache(algo).dpe_skip_len }
    }

    pub(crate) fn set_cached_dpe_skip_len(&self, slot: u8, algo: SpdmPalAsymAlgo, len: u32) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].algo_cache_mut(algo).dpe_skip_len = Some(len);
            }
        }
    }

    pub(crate) fn cached_chain_digest(&self, slot: u8, algo: SpdmPalAsymAlgo) -> Option<[u8; 48]> {
        let idx = slot_index(slot)?;
        unsafe { (*self.caches.get())[idx].algo_cache(algo).chain_digest }
    }

    pub(crate) fn cache_chain_digest(&self, slot: u8, algo: SpdmPalAsymAlgo, digest: &[u8]) {
        if let Some(idx) = slot_index(slot) {
            if digest.len() > 48 {
                return;
            }
            let mut entry = [0u8; 48];
            for (d, s) in entry.iter_mut().zip(digest) {
                *d = *s;
            }
            unsafe {
                (*self.caches.get())[idx].algo_cache_mut(algo).chain_digest = Some(entry);
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn invalidate_cert_caches(&self, slot: u8) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].invalidate();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpe_only_endorsement_has_zero_size() {
        let hash = [0xAB_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
    }

    #[test]
    fn dpe_only_endorsement_returns_correct_root_hash() {
        let mut hash = [0u8; 48];
        hash[0] = 0xDE;
        hash[47] = 0xAD;
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(SpdmPalAsymAlgo::EccP384, &mut out)
            .unwrap();
        assert_eq!(out, hash);
    }

    #[test]
    fn dpe_only_endorsement_is_supported() {
        let hash = [0x11_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert!(endorsement.is_supported());
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));
    }

    #[test]
    fn shared_store_slot_defaults_to_empty() {
        let store = SharedCertStore::new();
        let slot = &store.cert_slots()[0];
        assert!(!slot.endorsement.is_supported());
        assert!(slot.key_pair_id(SpdmPalAsymAlgo::EccP384).is_none());
    }

    #[test]
    fn dpe_only_without_mldsa_errors_on_mldsa_algo() {
        let hash = [0x22_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(&[], hash));

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
        assert!(endorsement.size(SpdmPalAsymAlgo::MlDsa87).is_err());
    }

    #[test]
    fn dpe_only_with_mldsa_has_zero_size_for_both_algos() {
        let ecc_hash = [0x33_u8; 48];
        let mldsa_hash = [0x44_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(&[], ecc_hash).with_mldsa(&[], mldsa_hash),
        );

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
        assert_eq!(endorsement.size(SpdmPalAsymAlgo::MlDsa87).unwrap(), 0);

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(SpdmPalAsymAlgo::MlDsa87, &mut out)
            .unwrap();
        assert_eq!(out, mldsa_hash);
    }

    #[test]
    fn shared_cert_store_new_has_empty_slots_and_no_metadata() {
        let store = SharedCertStore::new();
        for slot in store.cert_slots() {
            assert!(!slot.is_supported());
            assert!(!slot.is_writable());
            assert_eq!(slot.key_pair_id(SpdmPalAsymAlgo::EccP384), None);
            assert_eq!(slot.key_pair_id(SpdmPalAsymAlgo::MlDsa87), None);
            assert_eq!(slot.cert_info(SpdmPalAsymAlgo::EccP384), None);
            assert_eq!(slot.cert_info(SpdmPalAsymAlgo::MlDsa87), None);
        }
    }

    #[test]
    fn task_cert_store_caches_and_invalidation() {
        static SHARED: SharedCertStore = SharedCertStore::new();
        let store = TaskCertStore::new(&SHARED);
        assert_eq!(store.cached_chain_len(0, SpdmPalAsymAlgo::EccP384), None);
        store.set_cached_chain_len(0, SpdmPalAsymAlgo::EccP384, 1024);
        assert_eq!(
            store.cached_chain_len(0, SpdmPalAsymAlgo::EccP384),
            Some(1024)
        );

        store.invalidate_cert_caches(0);
        assert_eq!(store.cached_chain_len(0, SpdmPalAsymAlgo::EccP384), None);
    }
}
