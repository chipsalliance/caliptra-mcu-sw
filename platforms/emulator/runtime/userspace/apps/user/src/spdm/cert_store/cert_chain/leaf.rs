// Licensed under the Apache-2.0 license

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use libapi_caliptra::certificate::CertContext;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult};
use spdm_lib::protocol::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};

const DPE_LEAF_CERT_SIZE: usize = 2048; // Size of the DPE leaf certificate buffer.

pub const DPE_LEAF_CERT_LABEL: [u8; SHA384_HASH_SIZE] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

static SHARED_DPE_LEAF_CERT: Mutex<CriticalSectionRawMutex, DpeLeafCertBuf> =
    Mutex::new(DpeLeafCertBuf::new());

pub(crate) struct DpeLeafCert;

impl DpeLeafCert {
    pub fn new() -> Self {
        Self
    }
}

impl DpeLeafCert {
    pub async fn refresh(&self) {
        let mut dpe_leaf = SHARED_DPE_LEAF_CERT.lock().await;
        dpe_leaf.reset();
    }

    pub async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        let mut dpe_leaf = SHARED_DPE_LEAF_CERT.lock().await;
        if dpe_leaf.size().is_none() {
            dpe_leaf.fetch_cert(asym_algo).await?;
        }
        Ok(dpe_leaf.size().unwrap_or(0))
    }

    pub async fn read(
        &self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        let mut dpe_leaf = SHARED_DPE_LEAF_CERT.lock().await;
        if dpe_leaf.size().is_none() {
            dpe_leaf.fetch_cert(asym_algo).await?;
        }
        dpe_leaf.read(offset, buf)
    }

    pub async fn sign(
        &self,
        asym_algo: AsymAlgo,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let dpe_leaf = SHARED_DPE_LEAF_CERT.lock().await;
        dpe_leaf.sign(asym_algo, hash, signature).await
    }
}

struct DpeLeafCertBuf {
    buffer: [u8; DPE_LEAF_CERT_SIZE],
    size: Option<usize>,
}

impl Default for DpeLeafCertBuf {
    fn default() -> Self {
        Self {
            buffer: [0; DPE_LEAF_CERT_SIZE],
            size: None,
        }
    }
}

impl DpeLeafCertBuf {
    const fn new() -> Self {
        Self {
            buffer: [0; DPE_LEAF_CERT_SIZE],
            size: None,
        }
    }

    fn reset(&mut self) {
        self.buffer.fill(0);
        self.size = None;
    }

    async fn fetch_cert(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }

        self.reset();

        let mut cert_ctx = CertContext::new();

        let size = cert_ctx
            .certify_key(&mut self.buffer, Some(&DPE_LEAF_CERT_LABEL), None, None)
            .await
            .map_err(CertStoreError::CaliptraApi)?;

        if size > DPE_LEAF_CERT_SIZE {
            return Err(CertStoreError::BufferTooSmall);
        }

        self.size = Some(size);

        Ok(())
    }

    fn size(&self) -> Option<usize> {
        self.size
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> CertStoreResult<usize> {
        if offset >= self.size.unwrap_or(0) {
            return Err(CertStoreError::InvalidOffset);
        }
        let size_to_read = (self.size.unwrap_or(0) - offset).min(buf.len());
        buf[..size_to_read].copy_from_slice(&self.buffer[offset..offset + size_to_read]);
        Ok(size_to_read)
    }

    async fn sign(
        &self,
        asym_algo: AsymAlgo,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        let mut cert_ctx = CertContext::new();
        cert_ctx
            .sign(Some(&DPE_LEAF_CERT_LABEL), hash, signature)
            .await
            .map_err(CertStoreError::CaliptraApi)?;
        Ok(())
    }
}
