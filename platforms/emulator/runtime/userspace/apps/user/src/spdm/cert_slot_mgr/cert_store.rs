// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::spdm::cert_slot_mgr::device_cert::{DeviceCertIndex, DpeCertChain};
use crate::spdm::cert_slot_mgr::endorsement_cert::EndorsementCertChainTrait;
use crate::spdm::cert_slot_mgr::leaf_cert::DpeLeafCert;
use alloc::boxed::Box;
use async_trait::async_trait;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, SpdmCertStore, MAX_CERT_SLOTS_SUPPORTED,
};
use spdm_lib::protocol::{
    AsymAlgo, CertificateInfo, KeyUsageMask, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE,
};

/// Static storage for the shared certificate store
static SHARED_CERT_STORE: Mutex<CriticalSectionRawMutex, Option<Box<DeviceCertStore>>> =
    Mutex::new(None);

pub async fn initialize_shared_cert_store(cert_store: DeviceCertStore) -> CertStoreResult<()> {
    let mut shared_store = SHARED_CERT_STORE.lock().await;
    *shared_store = Some(Box::new(cert_store));
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

pub struct DeviceCertStore {
    cert_chains: [Option<CertChain>; MAX_CERT_SLOTS_SUPPORTED as usize],
}

impl DeviceCertStore {
    pub fn new() -> Self {
        Self {
            cert_chains: Default::default(),
        }
    }

    pub fn set_cert_chain(&mut self, slot: u8, cert_chain: CertChain) -> CertStoreResult<()> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains[slot as usize] = Some(cert_chain);
        Ok(())
    }

    fn cert_chain(&self, slot: u8) -> CertStoreResult<&CertChain> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains
            .get(slot as usize)
            .and_then(|chain| chain.as_ref())
            .ok_or(CertStoreError::UnprovisionedSlot)
    }

    fn cert_chain_mut(&mut self, slot: u8) -> CertStoreResult<&mut CertChain> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains
            .get_mut(slot as usize)
            .and_then(|chain| chain.as_mut())
            .ok_or(CertStoreError::UnprovisionedSlot)
    }

    fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    fn is_provisioned(&self, slot: u8) -> bool {
        self.cert_chain(slot).is_ok()
    }

    async fn cert_chain_len(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.size(asym_algo).await
    }

    async fn get_cert_chain(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.read(asym_algo, offset, cert_portion).await
    }

    async fn root_cert_hash(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.root_cert_hash(asym_algo, cert_hash).await
    }

    async fn sign_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.sign(asym_algo, hash, signature).await
    }
}

pub struct CertChain {
    endorsement_cert_chain: Box<dyn EndorsementCertChainTrait>,
    dpe_cert_chain: DpeCertChain,
    leaf_cert: DpeLeafCert,
}

impl CertChain {
    pub fn new(
        endorsement_cert_chain: impl EndorsementCertChainTrait + 'static,
        device_cert_id: DeviceCertIndex,
    ) -> Self {
        Self {
            endorsement_cert_chain: Box::new(endorsement_cert_chain),
            dpe_cert_chain: DpeCertChain::new(device_cert_id),
            leaf_cert: DpeLeafCert::new(),
        }
    }

    async fn refresh(&mut self) {
        self.endorsement_cert_chain.refresh().await;
        self.dpe_cert_chain.refresh();
        self.leaf_cert.refresh().await;
    }

    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        self.refresh().await;
        let endorsement_len = self.endorsement_cert_chain.size(asym_algo).await?;
        let dpe_len = self.dpe_cert_chain.size(asym_algo).await?;
        let leaf_len = self.leaf_cert.size(asym_algo).await?;
        let total_len = endorsement_len + dpe_len + leaf_len;

        Ok(total_len)
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        let root_cert_chain_len = self.endorsement_cert_chain.size(asym_algo).await?;
        let dpe_cert_chain_len = self.dpe_cert_chain.size(asym_algo).await?;
        let leaf_cert_len = self.leaf_cert.size(asym_algo).await?;
        let total_cert_chain_len = root_cert_chain_len + dpe_cert_chain_len + leaf_cert_len;

        if offset >= total_cert_chain_len {
            return Err(CertStoreError::InvalidOffset);
        }

        let mut to_read = buf.len().min(total_cert_chain_len - offset);
        let mut cert_chain_offset = offset;
        let mut pos = 0;

        while to_read > 0 {
            if cert_chain_offset < root_cert_chain_len {
                let cert_offset = cert_chain_offset;
                let len = self
                    .endorsement_cert_chain
                    .read(asym_algo, cert_offset, &mut buf[pos..pos + to_read])
                    .await?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            } else if cert_chain_offset < root_cert_chain_len + dpe_cert_chain_len {
                let cert_offset = cert_chain_offset - root_cert_chain_len;
                let len = self
                    .dpe_cert_chain
                    .read(asym_algo, cert_offset, &mut buf[pos..pos + to_read])
                    .await?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            } else {
                let cert_offset = cert_chain_offset - root_cert_chain_len - dpe_cert_chain_len;
                let len = self
                    .leaf_cert
                    .read(asym_algo, cert_offset, &mut buf[pos..pos + to_read])
                    .await?;
                to_read -= len;
                cert_chain_offset += len;
                pos += len;
            }
        }
        Ok(pos)
    }

    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        self.endorsement_cert_chain
            .root_cert_hash(asym_algo, cert_hash)
            .await
    }

    async fn sign<'a>(
        &self,
        asym_algo: AsymAlgo,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        self.leaf_cert.sign(asym_algo, hash, signature).await
    }
}
