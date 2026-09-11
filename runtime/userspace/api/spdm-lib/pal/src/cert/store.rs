// Licensed under the Apache-2.0 license

//! Shared cert store — a single static instance referenced by all PAL
//! instances (MCTP, DOE, …).
//!
//! Interior mutability is safe because embassy tasks are cooperative
//! on a single-core MCU — only one task runs at a time.

use caliptra_mcu_spdm_traits::SpdmPalAsymAlgo;
use core::cell::UnsafeCell;

use mcu_caliptra_api::{sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, SHA_CONTEXT_SIZE};
use mcu_error::McuResult;

use super::endorsement::{
    slot_index, CertSlot, ReadOnlyEndorsement, SlotEndorsement, NUM_CERT_SLOTS,
};
#[cfg(feature = "set-certificate")]
use super::endorsement::{ManagedEndorsement, SingleManagedChain};

const DEFAULT_CERT_INFO: u8 = 0x01;

async fn compute_root_hash<A: ApiAlloc>(alloc: &A, root_cert: &[u8]) -> McuResult<[u8; 48]> {
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
        Self {
            cert_slots: UnsafeCell::new([CertSlot::empty(), CertSlot::empty(), CertSlot::empty()]),
        }
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
    pub async fn set_endorsement_chains<A: ApiAlloc>(
        &self,
        alloc: &A,
        idx: usize,
        ecc_chain: &'static [&'static [u8]],
        mldsa_chain: Option<&'static [&'static [u8]]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        if idx >= NUM_CERT_SLOTS || ecc_chain.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let ecc_hash = compute_root_hash(alloc, ecc_chain[0]).await?;
        let mut ro = ReadOnlyEndorsement::new(ecc_chain, ecc_hash);

        if let Some(mldsa) = mldsa_chain {
            if !mldsa.is_empty() {
                let mldsa_hash = compute_root_hash(alloc, mldsa[0]).await?;
                ro = ro.with_mldsa(mldsa, mldsa_hash);
            }
        }

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.endorsement = SlotEndorsement::ReadOnly(ro);
        // Both chains are provisioned together from the same key
        // material, so they share KeyPairID and CertificateInfo.
        slot.set_metadata_all(Some(key_pair_id), Some(DEFAULT_CERT_INFO));
        Ok(())
    }

    /// Configure a flash-backed managed cert-chain slot and load any existing
    /// records from flash. Uninitialized flash leaves the slot supported but not
    /// provisioned, so SET_CERTIFICATE can install it later.
    ///
    /// `mldsa_base` is the start of a second region holding the slot's
    /// ML-DSA chain. Pass `None` on platforms that have not allocated
    /// one; the slot then serves ECC only.
    ///
    /// Returns `INVARIANT` if the requested regions intersect each
    /// other or any region already wired to another slot, since an
    /// update erases a whole region.
    #[cfg(feature = "set-certificate")]
    pub async fn set_managed_endorsement(
        &self,
        idx: usize,
        spdm_slot: u8,
        driver_num: u32,
        base: usize,
        mldsa_base: Option<usize>,
        capacity: usize,
    ) -> McuResult<()> {
        if idx >= NUM_CERT_SLOTS || capacity == 0 {
            return Err(mcu_error::codes::INVARIANT);
        }

        // Updating a chain erases its whole region, so regions must be
        // strictly disjoint — any intersection means installing one
        // chain destroys another. Check the slot's own two regions
        // against each other, then against every region already wired
        // to a different slot.
        let ecc_end = base
            .checked_add(capacity)
            .ok_or(mcu_error::codes::INVARIANT)?;
        let mldsa_range = match mldsa_base {
            Some(mldsa_base) => {
                let mldsa_end = mldsa_base
                    .checked_add(capacity)
                    .ok_or(mcu_error::codes::INVARIANT)?;
                if base < mldsa_end && mldsa_base < ecc_end {
                    return Err(mcu_error::codes::INVARIANT);
                }
                Some((mldsa_base, mldsa_end))
            }
            None => None,
        };
        for (other_idx, other) in self.cert_slots().iter().enumerate() {
            if other_idx == idx {
                continue;
            }
            let SlotEndorsement::Managed(other) = &other.endorsement else {
                continue;
            };
            if other.any_region_overlaps(driver_num, base, ecc_end) {
                return Err(mcu_error::codes::INVARIANT);
            }
            if let Some((mldsa_base, mldsa_end)) = mldsa_range {
                if other.any_region_overlaps(driver_num, mldsa_base, mldsa_end) {
                    return Err(mcu_error::codes::INVARIANT);
                }
            }
        }

        let mut managed = ManagedEndorsement::new(SingleManagedChain::new(
            spdm_slot,
            SpdmPalAsymAlgo::EccP384,
            driver_num,
            base,
            capacity,
        ));
        if let Some(mldsa_base) = mldsa_base {
            managed = managed.with_mldsa(SingleManagedChain::new(
                spdm_slot,
                SpdmPalAsymAlgo::MlDsa87,
                driver_num,
                mldsa_base,
                capacity,
            ));
        }
        managed.load().await?;

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let (key_pair_id, cert_info) = match managed.get_chain(algo) {
                Ok(region) => (region.key_pair_id(), region.cert_info()),
                Err(_) => (None, None),
            };
            slot.set_metadata(algo, key_pair_id, cert_info);
        }
        slot.endorsement = SlotEndorsement::Managed(managed);
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
