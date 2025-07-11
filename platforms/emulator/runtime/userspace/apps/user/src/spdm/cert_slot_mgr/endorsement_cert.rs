// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};
use libapi_caliptra::error::CaliptraApiError;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult};
use spdm_lib::protocol::algorithms::AsymAlgo;
use spdm_lib::protocol::SHA384_HASH_SIZE;

#[async_trait]
pub trait EndorsementCertChainTrait: Send + Sync {
    /// Get the root cert hash of the endorsement cert chain.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of endorsement cert
    ///
    /// # Returns
    /// The root cert hash as a byte array.
    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        root_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    /// Refresh the cert chain portion if needed. This can be used to
    /// reset the state of the cert chain or re-fetch the cert buffers.
    async fn refresh(&mut self);

    /// Get the size of the cert chain portion.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of cert chain
    ///
    /// # Returns
    /// The size of the cert chain portion.
    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize>;

    /// Read cert chain portion into the provided buffer.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of cert chain.
    /// * `offset` - The offset to start reading from.
    /// * `buf` - The buffer to read the cert chain portion into.
    ///
    /// # Returns
    /// The number of bytes read.
    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize>;
}

// Example implementation of Endorsement cert chain
pub struct EndorsementCertChain<'b> {
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    root_cert_chain: &'b [&'b [u8]],
    root_cert_chain_len: usize,
}

impl<'b> EndorsementCertChain<'b> {
    pub async fn new(root_cert_chain: &'b [&'b [u8]]) -> CertStoreResult<Self> {
        let mut root_cert_chain_len = 0;
        for cert in root_cert_chain.iter() {
            root_cert_chain_len += cert.len();
        }

        let mut root_hash = [0; SHA384_HASH_SIZE];
        while let Err(e) =
            HashContext::hash_all(HashAlgoType::SHA384, root_cert_chain[0], &mut root_hash).await
        {
            match e {
                CaliptraApiError::MailboxBusy => continue, // Retry if the mailbox is busy
                _ => Err(CertStoreError::CaliptraApi(e))?,
            }
        }
        Ok(Self {
            root_cert_hash: root_hash,
            root_cert_chain,
            root_cert_chain_len,
        })
    }
}

#[async_trait]
impl EndorsementCertChainTrait for EndorsementCertChain<'_> {
    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        root_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        root_hash.copy_from_slice(&self.root_cert_hash);
        Ok(())
    }

    async fn refresh(&mut self) {
        // No-op for endorsement certs, as they are static
    }

    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        Ok(self.root_cert_chain_len)
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }

        let mut cert_offset = offset;
        let mut pos = 0;

        for cert in self.root_cert_chain.iter() {
            if cert_offset < cert.len() {
                let len = (cert.len() - cert_offset).min(buf.len() - pos);
                buf[pos..pos + len].copy_from_slice(&cert[cert_offset..cert_offset + len]);
                pos += len;
                cert_offset = 0; // Reset offset for subsequent certs
                if pos == buf.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        Ok(pos)
    }
}
