// Licensed under the Apache-2.0 license

use libapi_caliptra::certificate::CertContext;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult};
use spdm_lib::protocol::AsymAlgo;

const MAX_CERT_PORTION_SIZE: usize = 1024;

pub enum DeviceCertIndex {
    IdevId, // Device Identity Certificate
            // Other device certificate indices can be added here in the future
}

pub(crate) struct DpeCertChain {
    cert_id: DeviceCertIndex,
    cert_chain_len: Option<usize>,
}

impl DpeCertChain {
    pub fn new(cert_id: DeviceCertIndex) -> Self {
        Self {
            cert_id,
            cert_chain_len: None,
        }
    }

    async fn read_device_ecc_cert_chain(
        &self,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        CertContext::new()
            .cert_chain_chunk(offset, cert_portion)
            .await
            .map_err(CertStoreError::CaliptraApi)
    }

    async fn cert_chain_offset(&self) -> usize {
        match self.cert_id {
            DeviceCertIndex::IdevId => 0,
        }
    }

    pub fn refresh(&mut self) {
        self.cert_chain_len = None; // Reset the certificate chain length
    }

    pub async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }

        if let Some(len) = self.cert_chain_len {
            return Ok(len);
        }

        let mut cert_chain_len = 0;
        let mut offset = self.cert_chain_offset().await;
        let mut buf = [0u8; MAX_CERT_PORTION_SIZE];

        loop {
            let size = self.read_device_ecc_cert_chain(offset, &mut buf).await?;
            cert_chain_len += size;
            offset += size;
            if size < MAX_CERT_PORTION_SIZE {
                break;
            }
        }

        self.cert_chain_len = Some(cert_chain_len);
        Ok(cert_chain_len)
    }

    pub async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }

        if self.cert_chain_len.is_none() {
            self.size(asym_algo).await?;
        }

        let cert_chain_len = self.cert_chain_len.ok_or(CertStoreError::CertReadError)?;
        if offset >= cert_chain_len {
            return Err(CertStoreError::InvalidOffset);
        }

        self.read_device_ecc_cert_chain(offset, buf).await
    }
}
