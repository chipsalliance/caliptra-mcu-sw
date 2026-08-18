// Licensed under the Apache-2.0 license

//! SPDM adapter for the shared certificate store.
//!
//! It owns SPDM-specific setup and task-local derived caches. The common
//! certificate-store crate owns the shared slots and their operation locks.

use core::cell::UnsafeCell;
#[cfg(feature = "set-certificate")]
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};

pub use caliptra_mcu_cert_store::SharedCertStore;
use mcu_caliptra_api::{sha_finish, sha_init, sha_update, ApiAlloc, HashAlgo, SHA_CONTEXT_SIZE};
use mcu_error::McuResult;

use super::endorsement::{slot_index, CertSlot, CertificateAttributes, NUM_CERT_SLOTS};

const DEFAULT_CERT_INFO: u8 = 0x01;

/// Configure a read-only endorsement chain for the given slot.
///
/// Computes the SHA-384 hash of the root cert (first chain entry) using the
/// provided allocator, then stores the endorsement.
pub async fn set_endorsement_chain<A: ApiAlloc>(
    store: &SharedCertStore,
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

    store.configure_read_only_slot(
        idx,
        chain,
        hash,
        CertificateAttributes::new(key_pair_id, DEFAULT_CERT_INFO),
    )
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
    #[cfg(feature = "set-certificate")]
    pub(crate) fn update_cert_slot(&self, idx: usize, update: impl FnOnce(&mut CertSlot)) -> bool {
        self.shared.update_cert_slot(idx, update)
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn stream_operation_lock(
        &self,
        idx: usize,
    ) -> Option<&Mutex<CriticalSectionRawMutex, ()>> {
        self.shared.stream_operation_lock(idx)
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
