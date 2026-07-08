// Licensed under the Apache-2.0 license

//! Shared cert store — a single static instance referenced by all PAL
//! instances (MCTP, DOE, …).
//!
//! Interior mutability is safe because embassy tasks are cooperative
//! on a single-core MCU — only one task runs at a time.

use core::cell::UnsafeCell;

use mcu_caliptra_api_lite::{
    sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, SHA_CONTEXT_SIZE,
};
use mcu_error::McuResult;

#[cfg(feature = "set-certificate")]
use super::endorsement::ManagedEndorsement;
use super::endorsement::{
    slot_index, CertSlot, ReadOnlyEndorsement, SlotEndorsement, NUM_CERT_SLOTS,
};

const DEFAULT_CERT_INFO: u8 = 0x01;

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

    /// Configure a read-only endorsement chain for the given slot.
    ///
    /// Computes the SHA-384 hash of the root cert (first chain entry)
    /// using the provided allocator, then stores the endorsement.
    pub async fn set_endorsement_chain<A: ApiAlloc>(
        &self,
        alloc: &A,
        idx: usize,
        chain: &'static [&'static [u8]],
        key_pair_id: u8,
    ) -> McuResult<()> {
        if idx >= NUM_CERT_SLOTS || chain.is_empty() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let root_cert = chain[0];
        let sha_buf = alloc.alloc(SHA_CONTEXT_SIZE)?;
        let mut state = sha_init(alloc, sha_buf, HashAlgo::Sha384, &[]).await?;
        sha_update(alloc, &mut state, root_cert).await?;
        let mut hash = [0u8; 48];
        sha_finish(alloc, &mut state, &mut hash).await?;

        let slot = self.cert_slot_mut(idx).ok_or(mcu_error::codes::INVARIANT)?;
        slot.endorsement = SlotEndorsement::ReadOnly(ReadOnlyEndorsement::new(chain, hash));
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

#[derive(Copy, Clone)]
struct CacheEntry<T: Copy> {
    provisioning_state_version: u32,
    value: T,
}

#[derive(Copy, Clone, Default)]
struct SlotCache {
    chain_len: Option<CacheEntry<u32>>,
    leaf_len: Option<CacheEntry<u32>>,
    chain_digest: Option<CacheEntry<[u8; 48]>>,
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
                    chain_len: None,
                    leaf_len: None,
                    chain_digest: None,
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

    pub(crate) fn cached_chain_len(
        &self,
        slot: u8,
        provisioning_state_version: u32,
    ) -> Option<u32> {
        let idx = slot_index(slot)?;
        unsafe {
            (*self.caches.get())[idx]
                .chain_len
                .and_then(|cache| {
                    (cache.provisioning_state_version == provisioning_state_version)
                        .then_some(cache.value)
                })
        }
    }

    pub(crate) fn set_cached_chain_len(
        &self,
        slot: u8,
        provisioning_state_version: u32,
        len: u32,
    ) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].chain_len = Some(CacheEntry {
                    provisioning_state_version,
                    value: len,
                });
            }
        }
    }

    pub(crate) fn cached_leaf_len(
        &self,
        slot: u8,
        provisioning_state_version: u32,
    ) -> Option<u32> {
        let idx = slot_index(slot)?;
        unsafe {
            (*self.caches.get())[idx]
                .leaf_len
                .and_then(|cache| {
                    (cache.provisioning_state_version == provisioning_state_version)
                        .then_some(cache.value)
                })
        }
    }

    pub(crate) fn set_cached_leaf_len(
        &self,
        slot: u8,
        provisioning_state_version: u32,
        len: u32,
    ) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].leaf_len = Some(CacheEntry {
                    provisioning_state_version,
                    value: len,
                });
            }
        }
    }

    pub(crate) fn cached_chain_digest(
        &self,
        slot: u8,
        provisioning_state_version: u32,
    ) -> Option<[u8; 48]> {
        let idx = slot_index(slot)?;
        unsafe {
            (*self.caches.get())[idx]
                .chain_digest
                .and_then(|cache| {
                    (cache.provisioning_state_version == provisioning_state_version)
                        .then_some(cache.value)
                })
        }
    }

    pub(crate) fn cache_chain_digest(
        &self,
        slot: u8,
        provisioning_state_version: u32,
        digest: &[u8],
    ) {
        if let Some(idx) = slot_index(slot) {
            if digest.len() > 48 {
                return;
            }
            let mut entry = [0u8; 48];
            for (d, s) in entry.iter_mut().zip(digest) {
                *d = *s;
            }
            unsafe {
                (*self.caches.get())[idx].chain_digest = Some(CacheEntry {
                    provisioning_state_version,
                    value: entry,
                });
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) fn invalidate_cert_caches(&self, slot: u8) {
        if let Some(idx) = slot_index(slot) {
            unsafe {
                (*self.caches.get())[idx].chain_len = None;
                (*self.caches.get())[idx].leaf_len = None;
                (*self.caches.get())[idx].chain_digest = None;
            }
        }
    }
}
