// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::asym::AsymAlgo;
use libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use spdm_lib::cert_store::CertStoreResult;

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
