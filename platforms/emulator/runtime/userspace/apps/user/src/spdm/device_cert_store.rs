// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::spdm::cert_store::cert_chain::device::DeviceCertIndex;
use crate::spdm::cert_store::cert_chain::CertChain;
use crate::spdm::cert_store::DeviceCertStore;
use crate::spdm::endorsement_certs::EndorsementCertChain;
use alloc::boxed::Box;
use async_trait::async_trait;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult, SpdmCertStore};
use spdm_lib::protocol::{
    AsymAlgo, CertificateInfo, KeyUsageMask, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE,
};

/// Static storage just for the endorsement chain (since it needs static lifetime)
static mut SLOT0_ENDORSEMENT: MaybeUninit<EndorsementCertChain> = MaybeUninit::uninit();

/// Atomic flag to track initialization state (thread-safe)
static SLOT0_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Static storage for the shared certificate store
static SHARED_CERT_STORE: Mutex<CriticalSectionRawMutex, Option<DeviceCertStore>> =
    Mutex::new(None);

/// Initialize the endorsement chain for a specific slot
async fn init_endorsement_cert_chain(
    slot_id: u8,
) -> CertStoreResult<&'static mut EndorsementCertChain<'static>> {
    match slot_id {
        0 => {
            // Check if already initialized (fast path)
            if SLOT0_INITIALIZED.load(Ordering::Acquire) {
                // SAFETY: We've confirmed initialization via atomic flag
                unsafe {
                    return Ok(SLOT0_ENDORSEMENT.assume_init_mut());
                }
            }

            // Create the endorsement chain
            let endorsement_chain = EndorsementCertChain::new(0).await?;

            // SAFETY: This unsafe block is safe because:
            // 1. We use atomic operations to ensure single initialization
            // 2. The memory lives for the entire program duration (static)
            // 3. We use proper memory ordering to prevent races
            unsafe {
                // Double-check pattern to handle race conditions
                if SLOT0_INITIALIZED.load(Ordering::Acquire) {
                    // Another thread initialized it, return the existing one
                    return Ok(SLOT0_ENDORSEMENT.assume_init_mut());
                }

                // Write the endorsement chain to static storage
                SLOT0_ENDORSEMENT.write(endorsement_chain);

                // Mark as initialized with release ordering
                // This ensures the write above is visible before the flag is set
                SLOT0_INITIALIZED.store(true, Ordering::Release);

                // Return the mutable reference with static lifetime
                Ok(SLOT0_ENDORSEMENT.assume_init_mut())
            }
        }
        _ => Err(CertStoreError::InvalidSlotId),
    }
}

pub async fn initialize_shared_cert_store(cert_store: DeviceCertStore) -> CertStoreResult<()> {
    let mut shared_store = SHARED_CERT_STORE.lock().await;
    *shared_store = Some(cert_store);
    Ok(())
}

pub async fn initialize_cert_store() -> CertStoreResult<()> {
    // Initialize the endorsement chain for slot 0 and get a static mutable reference
    let slot0_endorsement_ref = init_endorsement_cert_chain(0).await?;

    // Create cert chain with the static reference
    let slot0_cert_chain = CertChain::new(slot0_endorsement_ref, DeviceCertIndex::IdevId);

    // Store everything in DeviceCertStore
    let mut cert_store = DeviceCertStore::new();
    cert_store.set_cert_chain(0, slot0_cert_chain)?;

    initialize_shared_cert_store(cert_store).await?;
    Ok(())
}

/// Wrapper that provides access to the global certificate store
/// This implements SpdmCertStore by forwarding calls to the global mutex-protected store
pub struct SharedCertStore;

impl SharedCertStore {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SpdmCertStore for SharedCertStore {
    fn slot_count(&self) -> u8 {
        // Try to lock the shared certificate store and get the slot count.
        // If the store is not initialized or the lock cannot be acquired, return 0.
        match SHARED_CERT_STORE.try_lock() {
            Ok(store) => store.as_ref().map_or(0, |s| s.slot_count()),
            Err(_) => 0,
        }
    }

    async fn is_provisioned(&self, slot: u8) -> bool {
        let cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_ref() {
            cert_store.is_provisioned(slot)
        } else {
            false
        }
    }

    async fn cert_chain_len(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        let mut cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_mut() {
            cert_store.cert_chain_len(asym_algo, slot_id).await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }

    async fn get_cert_chain<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize> {
        let mut cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_mut() {
            cert_store
                .get_cert_chain(slot_id, asym_algo, offset, cert_portion)
                .await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }

    async fn root_cert_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        let cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_ref() {
            cert_store
                .root_cert_hash(slot_id, asym_algo, cert_hash)
                .await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }

    async fn sign_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_ref() {
            cert_store
                .sign_hash(asym_algo, slot_id, hash, signature)
                .await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }

    async fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        None
    }

    async fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
        None
    }

    async fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}
