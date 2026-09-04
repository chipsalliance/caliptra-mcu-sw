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

#[cfg(feature = "set-certificate")]
use super::endorsement::ManagedEndorsement;
use super::endorsement::{
    slot_index, CertSlot, ReadOnlyEndorsement, SlotEndorsement, NUM_CERT_SLOTS,
};

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
        slot.key_pair_id = Some(key_pair_id);
        slot.cert_info = Some(DEFAULT_CERT_INFO);
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
    pub async fn set_dpe_only_slot<A: ApiAlloc>(
        &self,
        alloc: &A,
        idx: usize,
        ecc_first_dpe_cert: &[u8],
        mldsa_first_dpe_cert: Option<&[u8]>,
        key_pair_id: u8,
    ) -> McuResult<()> {
        if idx >= NUM_CERT_SLOTS || ecc_first_dpe_cert.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        static EMPTY_CHAIN: &[&[u8]] = &[];

        let ecc_hash = compute_root_hash(alloc, ecc_first_dpe_cert).await?;
        let mut ro = ReadOnlyEndorsement::new(EMPTY_CHAIN, ecc_hash);

        if let Some(cert) = mldsa_first_dpe_cert {
            if !cert.is_empty() {
                let mldsa_hash = compute_root_hash(alloc, cert).await?;
                ro = ro.with_mldsa(EMPTY_CHAIN, mldsa_hash);
            }
        }

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.endorsement = SlotEndorsement::ReadOnly(ro);
        slot.key_pair_id = Some(key_pair_id);
        slot.cert_info = Some(DEFAULT_CERT_INFO);
        Ok(())
    }

    /// Configure a flash-backed managed cert-chain slot and load any existing
    /// record from flash. Uninitialized flash leaves the slot supported but not
    /// provisioned, so SET_CERTIFICATE can install it later.
    #[cfg(feature = "set-certificate")]
    pub async fn set_managed_endorsement(
        &self,
        idx: usize,
        spdm_slot: u8,
        driver_num: u32,
        base: usize,
        capacity: usize,
    ) -> McuResult<()> {
        if idx >= NUM_CERT_SLOTS || capacity == 0 {
            return Err(mcu_error::codes::INVARIANT);
        }
        let mut endorsement = ManagedEndorsement::new(spdm_slot, driver_num, base, capacity);
        endorsement.load().await?;
        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.key_pair_id = endorsement.key_pair_id();
        slot.cert_info = endorsement.cert_info();
        slot.endorsement = SlotEndorsement::Managed(endorsement);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpe_only_endorsement_has_zero_size() {
        let hash = [0xAB_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsement::new(&[], hash));

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
    }

    #[test]
    fn dpe_only_endorsement_returns_correct_root_hash() {
        let mut hash = [0u8; 48];
        hash[0] = 0xDE;
        hash[47] = 0xAD;
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsement::new(&[], hash));

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(SpdmPalAsymAlgo::EccP384, &mut out)
            .unwrap();
        assert_eq!(out, hash);
    }

    #[test]
    fn dpe_only_endorsement_is_supported() {
        let hash = [0x11_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsement::new(&[], hash));

        assert!(endorsement.is_supported());
        assert!(endorsement.is_provisioned());
    }

    #[test]
    fn shared_store_slot_defaults_to_empty() {
        let store = SharedCertStore::new();
        let slot = &store.cert_slots()[0];
        assert!(!slot.endorsement.is_supported());
        assert!(slot.key_pair_id.is_none());
    }

    #[test]
    fn dpe_only_without_mldsa_errors_on_mldsa_algo() {
        let hash = [0x22_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsement::new(&[], hash));

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
        assert!(endorsement.size(SpdmPalAsymAlgo::MlDsa87).is_err());
    }

    #[test]
    fn dpe_only_with_mldsa_has_zero_size_for_both_algos() {
        let ecc_hash = [0x33_u8; 48];
        let mldsa_hash = [0x44_u8; 48];
        let endorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsement::new(&[], ecc_hash).with_mldsa(&[], mldsa_hash),
        );

        assert_eq!(endorsement.size(SpdmPalAsymAlgo::EccP384).unwrap(), 0);
        assert_eq!(endorsement.size(SpdmPalAsymAlgo::MlDsa87).unwrap(), 0);

        let mut out = [0u8; 48];
        endorsement
            .root_cert_hash(SpdmPalAsymAlgo::MlDsa87, &mut out)
            .unwrap();
        assert_eq!(out, mldsa_hash);
    }
}
