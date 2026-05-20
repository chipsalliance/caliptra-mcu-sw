// Licensed under the Apache-2.0 license

extern crate alloc;

pub(crate) mod cert_chain;

use crate::spdm::cert_store::cert_chain::{
    CertChain, DeviceCertIndex, EndorsementCertChainTrait, InstalledMetadata,
};
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, MAX_CERT_SLOTS_SUPPORTED,
};
use caliptra_mcu_spdm_lib::protocol::{CertificateInfo, KeyUsageMask};

#[allow(dead_code)]
pub enum PkiEntity {
    Vendor,
    Owner,
    Tenant,
}

impl PkiEntity {
    pub const fn default_slot_id(&self) -> u8 {
        match self {
            Self::Vendor => 0,
            Self::Owner => 1,
            Self::Tenant => 2,
        }
    }
}

pub const VENDOR_SLOT_ID: u8 = PkiEntity::Vendor.default_slot_id();

#[async_trait]
pub trait CertSlotStorage {
    async fn load(&self, slot_id: u8) -> CertStoreResult<Option<LoadedSlot>>;
    async fn write(&self, slot_id: u8, params: WriteParams<'_>) -> CertStoreResult<()>;
    async fn erase(&self, slot_id: u8) -> CertStoreResult<()>;
}

pub struct LoadedSlot {
    pub key_pair_id: u8,
    pub cert_info: CertificateInfo,
    #[allow(dead_code)]
    pub root_cert_hash: [u8; SHA384_HASH_SIZE],
}

pub struct WriteParams<'a> {
    pub asym_algo: AsymAlgo,
    pub key_pair_id: u8,
    pub cert_info: CertificateInfo,
    pub root_cert_hash: &'a [u8; SHA384_HASH_SIZE],
    pub cert_chain: &'a [u8],
}

pub fn device_cert_index_from_key_pair_id(key_pair_id: u8) -> CertStoreResult<DeviceCertIndex> {
    match key_pair_id {
        1 => Ok(DeviceCertIndex::LDevId),
        2 => Ok(DeviceCertIndex::FmcAlias),
        3 => Ok(DeviceCertIndex::RtAlias),
        _ => Err(CertStoreError::OperationFailed),
    }
}

pub struct DeviceCertStore<S: CertSlotStorage> {
    cert_chains: [Option<CertChain>; MAX_CERT_SLOTS_SUPPORTED as usize],
    storage: S,
}

impl<S: CertSlotStorage> DeviceCertStore<S> {
    pub fn new(storage: S) -> Self {
        Self {
            cert_chains: Default::default(),
            storage,
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

    pub fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    pub fn is_provisioned(&self, slot: u8) -> bool {
        self.cert_chain(slot).is_ok()
    }

    pub fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(|slot| slot.installed().map(|installed| installed.key_pair_id))
    }

    pub fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(|slot| slot.installed().map(|installed| installed.cert_info))
    }

    pub fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(|slot| slot.installed().map(|_| KeyUsageMask::default()))
    }

    pub async fn cert_chain_len(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.size(asym_algo).await
    }

    pub async fn get_cert_chain(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.read(asym_algo, offset, cert_portion).await
    }

    pub async fn root_cert_hash(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.root_cert_hash(asym_algo, cert_hash).await
    }

    pub async fn sign_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.sign(asym_algo, hash, signature).await
    }

    pub async fn load_cert_chains(
        &mut self,
        endorsement_readers: &mut [Option<&'static mut dyn EndorsementCertChainTrait>;
                 MAX_CERT_SLOTS_SUPPORTED as usize],
    ) -> CertStoreResult<()> {
        for slot_id in 1..MAX_CERT_SLOTS_SUPPORTED {
            if let Some(loaded_slot) = self.storage.load(slot_id).await? {
                let endorsement_cert_chain = endorsement_readers[slot_id as usize]
                    .take()
                    .ok_or(CertStoreError::InitFailed)?;
                let device_cert_index =
                    device_cert_index_from_key_pair_id(loaded_slot.key_pair_id)?;
                let installed = InstalledMetadata {
                    key_pair_id: loaded_slot.key_pair_id,
                    cert_info: loaded_slot.cert_info,
                };
                self.set_cert_chain(
                    slot_id,
                    CertChain::new(endorsement_cert_chain, device_cert_index, Some(installed)),
                )?;
            }
        }

        Ok(())
    }

    pub async fn write_cert_chain(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        key_pair_id: u8,
        cert_info: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
        endorsement_cert_chain: &mut Option<&'static mut dyn EndorsementCertChainTrait>,
    ) -> CertStoreResult<()> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }

        let device_cert_index = device_cert_index_from_key_pair_id(key_pair_id)?;
        let installed = InstalledMetadata {
            key_pair_id,
            cert_info,
        };

        self.storage
            .write(
                slot_id,
                WriteParams {
                    asym_algo,
                    key_pair_id,
                    cert_info,
                    root_cert_hash,
                    cert_chain,
                },
            )
            .await?;

        if let Ok(cert_chain_slot) = self.cert_chain_mut(slot_id) {
            cert_chain_slot.update_installed(installed, device_cert_index);
        } else {
            let endorsement_cert_chain = endorsement_cert_chain
                .take()
                .ok_or(CertStoreError::InitFailed)?;
            self.set_cert_chain(
                slot_id,
                CertChain::new(endorsement_cert_chain, device_cert_index, Some(installed)),
            )?;
        }
        Ok(())
    }

    pub async fn erase_cert_chain(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }

        self.storage.erase(slot_id).await?;
        self.cert_chains[slot_id as usize] = None;
        Ok(())
    }
}
