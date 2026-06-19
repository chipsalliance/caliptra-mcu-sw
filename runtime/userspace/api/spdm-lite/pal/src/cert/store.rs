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
use mcu_spdm_lite_traits::MAX_SLOTS;

#[cfg(feature = "set-certificate")]
use super::endorsement::ManagedEndorsement;
use super::endorsement::{CertSlot, ReadOnlyEndorsement, SlotEndorsement, NUM_CERT_SLOTS};

const DEFAULT_CERT_INFO: u8 = 0x01;

/// Static shared cert store.
///
/// Holds per-slot endorsement data and caches that are common to all
/// transports.  Created once at program start and referenced by every
/// `McuSpdmPal` instance via `&'static SharedCertStore`.
pub struct SharedCertStore {
    cert_slots: UnsafeCell<[CertSlot; NUM_CERT_SLOTS]>,
    cached_chain_len: UnsafeCell<[Option<u32>; MAX_SLOTS as usize]>,
    cached_chain_digest: UnsafeCell<[Option<[u8; 48]>; MAX_SLOTS as usize]>,
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
            cached_chain_len: UnsafeCell::new([None; MAX_SLOTS as usize]),
            cached_chain_digest: UnsafeCell::new([None; MAX_SLOTS as usize]),
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
    pub(crate) fn cert_slot_mut(&self, idx: usize) -> &mut CertSlot {
        // SAFETY: single-task invariant.
        unsafe { &mut (*self.cert_slots.get())[idx] }
    }

    // ---------------------------------------------------------------
    // Chain-length cache
    // ---------------------------------------------------------------

    pub fn get_cached_chain_len(&self, slot: u8) -> Option<u32> {
        if slot >= MAX_SLOTS {
            return None;
        }
        unsafe { (*self.cached_chain_len.get())[slot as usize] }
    }

    pub fn cached_chain_len_or_zero(&self, slot: u8) -> usize {
        self.get_cached_chain_len(slot).unwrap_or(0) as usize
    }

    pub fn set_cached_chain_len(&self, slot: u8, len: u32) {
        if slot >= MAX_SLOTS {
            return;
        }
        unsafe {
            (*self.cached_chain_len.get())[slot as usize] = Some(len);
        }
    }

    // ---------------------------------------------------------------
    // Chain-digest cache
    // ---------------------------------------------------------------

    pub fn cached_chain_digest(&self, slot: u8) -> Option<[u8; 48]> {
        if slot >= MAX_SLOTS {
            return None;
        }
        unsafe { (*self.cached_chain_digest.get())[slot as usize] }
    }

    pub fn cache_chain_digest(&self, slot: u8, digest: &[u8]) {
        if slot >= MAX_SLOTS || digest.len() > 48 {
            return;
        }
        let mut entry = [0u8; 48];
        entry[..digest.len()].copy_from_slice(digest);
        unsafe {
            (*self.cached_chain_digest.get())[slot as usize] = Some(entry);
        }
    }

    /// Invalidate all caches for `slot`. Called on SET_CERTIFICATE /
    /// erase so that the next GET_DIGESTS / GET_CERTIFICATE re-probes.
    pub fn invalidate_cache(&self, slot: u8) {
        if slot >= MAX_SLOTS {
            return;
        }
        unsafe {
            (*self.cached_chain_len.get())[slot as usize] = None;
            (*self.cached_chain_digest.get())[slot as usize] = None;
        }
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

        let slot = self.cert_slot_mut(idx);
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
        let slot = self.cert_slot_mut(idx);
        slot.key_pair_id = endorsement.key_pair_id();
        slot.cert_info = endorsement.cert_info();
        slot.endorsement = SlotEndorsement::Managed(endorsement);
        Ok(())
    }
}
