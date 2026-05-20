// Licensed under the Apache-2.0 license

extern crate alloc;

pub mod endorsements;
pub mod flash_layout;
pub mod storage;

use crate::spdm::cert_store::cert_chain::{CertChain, DeviceCertIndex};
use crate::spdm::cert_store::{DeviceCertStore, VENDOR_SLOT_ID};
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, SpdmCertStoreReader, SpdmCertStoreSigner,
    SpdmCertStoreWriter,
};
use caliptra_mcu_spdm_lib::protocol::{CertificateInfo, KeyUsageMask};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use storage::EmulatedCertSlotStorage;

pub type PlatformCertStore = DeviceCertStore<EmulatedCertSlotStorage>;

pub static SHARED_CERT_STORE: Mutex<CriticalSectionRawMutex, Option<PlatformCertStore>> =
    Mutex::new(None);

pub async fn initialize_shared_cert_store(cert_store: PlatformCertStore) -> CertStoreResult<()> {
    let mut shared_store = SHARED_CERT_STORE.lock().await;
    *shared_store = Some(cert_store);
    Ok(())
}

pub async fn initialize_cert_store() -> CertStoreResult<()> {
    let mut cert_store = DeviceCertStore::new(EmulatedCertSlotStorage);
    let mut endorsement_readers = endorsements::collect_endorsement_readers().await?;
    let vendor_endorsement = endorsement_readers[VENDOR_SLOT_ID as usize]
        .take()
        .ok_or(CertStoreError::InitFailed)?;

    cert_store.set_cert_chain(
        VENDOR_SLOT_ID,
        CertChain::new(vendor_endorsement, DeviceCertIndex::IdevId, None),
    )?;
    cert_store
        .load_cert_chains(&mut endorsement_readers)
        .await?;

    initialize_shared_cert_store(cert_store).await
}

pub struct SharedCertStore;

impl SharedCertStore {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SpdmCertStoreReader for SharedCertStore {
    fn slot_count(&self) -> u8 {
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
        asym_algo: AsymAlgo,
        slot_id: u8,
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
        asym_algo: AsymAlgo,
        slot_id: u8,
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

    async fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        let cert_store = SHARED_CERT_STORE.lock().await;
        cert_store
            .as_ref()
            .and_then(|store| store.key_pair_id(slot_id))
    }

    async fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        let cert_store = SHARED_CERT_STORE.lock().await;
        cert_store
            .as_ref()
            .and_then(|store| store.cert_info(slot_id))
    }

    async fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        let cert_store = SHARED_CERT_STORE.lock().await;
        cert_store
            .as_ref()
            .and_then(|store| store.key_usage_mask(slot_id))
    }
}

#[async_trait]
impl SpdmCertStoreSigner for SharedCertStore {
    async fn sign_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
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
}

#[async_trait]
impl SpdmCertStoreWriter for SharedCertStore {
    async fn write_cert_chain(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        key_pair_id: u8,
        cert_model: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
    ) -> CertStoreResult<()> {
        let mut cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_mut() {
            let mut endorsement_reader = if !cert_store.is_provisioned(slot_id) {
                Some(endorsements::init_mutable_slot(slot_id)?)
            } else {
                None
            };
            cert_store
                .write_cert_chain(
                    asym_algo,
                    slot_id,
                    key_pair_id,
                    cert_model,
                    root_cert_hash,
                    cert_chain,
                    &mut endorsement_reader,
                )
                .await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }

    async fn erase_cert_chain(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()> {
        let mut cert_store = SHARED_CERT_STORE.lock().await;
        if let Some(cert_store) = cert_store.as_mut() {
            cert_store.erase_cert_chain(asym_algo, slot_id).await
        } else {
            Err(CertStoreError::NotInitialized)
        }
    }
}
