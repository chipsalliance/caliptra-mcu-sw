// Licensed under the Apache-2.0 license

//! Certificate chain components module
//!
//! Three components make up a certificate chain:
//! - Endorsement component (trait)
//! - Device certificate chain component (standard implementation)
//! - Leaf certificate component (standard implementation and shared between all slots)

// Endorsement certchain portion
pub mod endorsement;
// Device certchain portion
pub(crate) mod device;
// Leaf certchain portion
pub(crate) mod leaf;

// Re-export all the public types from submodules
use crate::spdm::cert_store::cert_chain::device::{DeviceCertIndex, DpeCertChain};
pub use crate::spdm::cert_store::cert_chain::endorsement::EndorsementCertChainTrait;
use crate::spdm::cert_store::cert_chain::leaf::DpeLeafCert;
use libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use spdm_lib::cert_store::CertStoreError;
use spdm_lib::cert_store::CertStoreResult;

/// Generic certificate chain that combines all certificate components
pub struct CertChain {
    endorsement_cert_chain: &'static mut dyn EndorsementCertChainTrait,
    dpe_cert_chain: DpeCertChain,
    leaf_cert: DpeLeafCert,
}

impl CertChain {
    pub fn new(
        endorsement_cert_chain: &'static mut dyn EndorsementCertChainTrait,
        device_cert_id: DeviceCertIndex,
    ) -> Self {
        Self {
            endorsement_cert_chain,
            dpe_cert_chain: DpeCertChain::new(device_cert_id),
            leaf_cert: DpeLeafCert::new(),
        }
    }

    #[allow(dead_code)]
    pub async fn refresh(&mut self) {
        self.endorsement_cert_chain.refresh().await;
        self.dpe_cert_chain.refresh();
        self.leaf_cert.refresh().await;
    }

    pub async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        let endorsement_len = self.endorsement_cert_chain.size(asym_algo).await?;
        let dpe_len = self.dpe_cert_chain.size(asym_algo).await?;
        let leaf_len = self.leaf_cert.size(asym_algo).await?;
        let total_len = endorsement_len + dpe_len + leaf_len;

        Ok(total_len)
    }

    pub async fn read(
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

    pub async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        self.endorsement_cert_chain
            .root_cert_hash(asym_algo, cert_hash)
            .await
    }

    pub async fn sign<'a>(
        &self,
        asym_algo: AsymAlgo,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        self.leaf_cert.sign(asym_algo, hash, signature).await
    }
}
