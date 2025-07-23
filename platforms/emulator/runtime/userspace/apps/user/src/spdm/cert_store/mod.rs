// Licensed under the Apache-2.0 license

pub(crate) mod cert_chain;

use crate::spdm::cert_store::cert_chain::CertChain;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult, MAX_CERT_SLOTS_SUPPORTED};
use spdm_lib::protocol::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};

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

    pub fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    pub fn is_provisioned(&self, slot: u8) -> bool {
        self.cert_chain(slot).is_ok()
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
}
