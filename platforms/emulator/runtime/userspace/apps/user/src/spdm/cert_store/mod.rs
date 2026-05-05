// Licensed under the Apache-2.0 license

extern crate alloc;

pub(crate) mod cert_chain;

use crate::spdm::cert_store::cert_chain::CertChain;
use alloc::vec::Vec;
use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, MAX_CERT_SLOTS_SUPPORTED,
};
use caliptra_mcu_spdm_lib::protocol::{CertificateInfo, KeyUsageMask};

const VENDOR_SLOT_ID: u8 = 0;

struct InstalledCertChain {
    asym_algo: AsymAlgo,
    key_pair_id: u8,
    cert_info: CertificateInfo,
    key_usage_mask: KeyUsageMask,
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    cert_chain: Vec<u8>,
}

impl InstalledCertChain {
    fn new(
        asym_algo: AsymAlgo,
        key_pair_id: u8,
        cert_info: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
    ) -> CertStoreResult<Self> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if cert_chain.is_empty() {
            return Err(CertStoreError::CertWriteError);
        }

        // Do not advertise signing usages until the platform can verify the leaf public key and
        // sign with the SPDM KeyPairID associated with this installed certificate.
        let key_usage_mask = KeyUsageMask::default();

        Ok(Self {
            asym_algo,
            key_pair_id,
            cert_info,
            key_usage_mask,
            root_cert_hash: *root_cert_hash,
            cert_chain: cert_chain.to_vec(),
        })
    }

    fn ensure_asym_algo(&self, asym_algo: AsymAlgo) -> CertStoreResult<()> {
        if self.asym_algo != asym_algo {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        Ok(())
    }

    fn size(&self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        self.ensure_asym_algo(asym_algo)?;
        Ok(self.cert_chain.len())
    }

    fn read(&self, asym_algo: AsymAlgo, offset: usize, buf: &mut [u8]) -> CertStoreResult<usize> {
        self.ensure_asym_algo(asym_algo)?;
        if offset > self.cert_chain.len() {
            return Err(CertStoreError::InvalidOffset);
        }
        if offset == self.cert_chain.len() {
            return Ok(0);
        }

        let read_len = buf.len().min(self.cert_chain.len() - offset);
        buf[..read_len].copy_from_slice(&self.cert_chain[offset..offset + read_len]);
        Ok(read_len)
    }

    fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        self.ensure_asym_algo(asym_algo)?;
        cert_hash.copy_from_slice(&self.root_cert_hash);
        Ok(())
    }
}

enum CertSlot {
    BuiltIn(CertChain),
    Installed(InstalledCertChain),
}

impl CertSlot {
    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.size(asym_algo).await,
            CertSlot::Installed(cert_chain) => cert_chain.size(asym_algo),
        }
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.read(asym_algo, offset, buf).await,
            CertSlot::Installed(cert_chain) => cert_chain.read(asym_algo, offset, buf),
        }
    }

    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.root_cert_hash(asym_algo, cert_hash).await,
            CertSlot::Installed(cert_chain) => cert_chain.root_cert_hash(asym_algo, cert_hash),
        }
    }

    async fn sign(
        &self,
        asym_algo: AsymAlgo,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.sign(asym_algo, hash, signature).await,
            // The installed cert chain is persisted with its KeyPairID metadata, but the emulator
            // does not yet have a Caliptra API for signing by SPDM KeyPairID. Keep this explicit
            // instead of silently signing with the wrong key.
            CertSlot::Installed(_) => Err(CertStoreError::OperationFailed),
        }
    }

    fn key_pair_id(&self) -> Option<u8> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.key_pair_id),
        }
    }

    fn cert_info(&self) -> Option<CertificateInfo> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.cert_info),
        }
    }

    fn key_usage_mask(&self) -> Option<KeyUsageMask> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.key_usage_mask),
        }
    }
}

pub struct DeviceCertStore {
    cert_chains: [Option<CertSlot>; MAX_CERT_SLOTS_SUPPORTED as usize],
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

        self.cert_chains[slot as usize] = Some(CertSlot::BuiltIn(cert_chain));
        Ok(())
    }

    fn cert_chain(&self, slot: u8) -> CertStoreResult<&CertSlot> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains
            .get(slot as usize)
            .and_then(|chain| chain.as_ref())
            .ok_or(CertStoreError::UnprovisionedSlot)
    }

    fn cert_chain_mut(&mut self, slot: u8) -> CertStoreResult<&mut CertSlot> {
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

    pub fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(CertSlot::key_pair_id)
    }

    pub fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        self.cert_chain(slot_id).ok().and_then(CertSlot::cert_info)
    }

    pub fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(CertSlot::key_usage_mask)
    }

    pub fn write_cert_chain(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        key_pair_id: u8,
        cert_model: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
    ) -> CertStoreResult<()> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }

        let cert_chain = InstalledCertChain::new(
            asym_algo,
            key_pair_id,
            cert_model,
            root_cert_hash,
            cert_chain,
        )?;
        self.cert_chains[slot_id as usize] = Some(CertSlot::Installed(cert_chain));
        Ok(())
    }

    pub fn erase_cert_chain(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }

        self.cert_chains[slot_id as usize] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed_cert_chain(cert_chain: &[u8]) -> InstalledCertChain {
        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(1);
        InstalledCertChain::new(
            AsymAlgo::EccP384,
            1,
            cert_info,
            &[0x5a; SHA384_HASH_SIZE],
            cert_chain,
        )
        .unwrap()
    }

    #[test]
    fn test_installed_cert_chain_read_allows_exact_eof() {
        let cert_chain = installed_cert_chain(&[1, 2, 3, 4]);
        let mut buf = [0u8; 4];

        assert_eq!(cert_chain.read(AsymAlgo::EccP384, 4, &mut buf), Ok(0));
        assert_eq!(
            cert_chain.read(AsymAlgo::EccP384, 5, &mut buf),
            Err(CertStoreError::InvalidOffset)
        );
    }

    #[test]
    fn test_installed_cert_chain_does_not_advertise_signing_usage() {
        let cert_chain = installed_cert_chain(&[1, 2, 3, 4]);

        assert_eq!(cert_chain.key_usage_mask.key_exch_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.challenge_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.measurement_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.standards_key_usage(), 0);
    }
}
