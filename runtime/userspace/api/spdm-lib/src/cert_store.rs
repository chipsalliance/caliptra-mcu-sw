// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::error::{SpdmError, SpdmResult};
use crate::protocol::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext, SHA384_HASH_SIZE};
use libapi_caliptra::error::CaliptraApiError;
use zerocopy::IntoBytes;

pub const MAX_CERT_SLOTS_SUPPORTED: u8 = 2;
pub const SPDM_CERT_CHAIN_METADATA_LEN: u16 =
    size_of::<SpdmCertChainHeader>() as u16 + SHA384_HASH_SIZE as u16;

#[derive(Debug, PartialEq)]
pub enum CertStoreError {
    InitFailed,
    NotInitialized,
    InvalidSlotId,
    UnprovisionedSlot,
    UnsupportedAsymAlgo,
    UnsupportedHashAlgo,
    BufferTooSmall,
    InvalidOffset,
    CertReadError,
    CaliptraApi(CaliptraApiError),
}
pub type CertStoreResult<T> = Result<T, CertStoreError>;

#[async_trait]
pub trait SpdmCertStore {
    /// Get supported certificate slot count
    /// The supported slots are consecutive from 0 to slot_count - 1.
    ///
    /// # Returns
    /// * `u8` - The number of supported certificate slots.
    fn slot_count(&self) -> u8;

    /// Check if the slot is provisioned.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `bool` - True if the slot is provisioned, false otherwise.
    async fn is_provisioned(&self, slot_id: u8) -> bool;

    /// Get the length of the certificate chain in bytes.
    /// The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of certificate chain.
    ///
    /// # Returns
    /// * `usize` - The length of the certificate chain in bytes or error.
    async fn cert_chain_len(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;

    /// Get the certificate chain in portion. The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `offset` - The offset in bytes to start reading from.
    /// * `cert_portion` - The buffer to read the certificate chain into.
    ///
    /// # Returns
    /// * `usize` - The number of bytes read or error.
    /// If the cert portion size is smaller than the buffer size, the remaining bytes in the buffer will be filled with 0,
    /// indicating the end of the cert chain.
    async fn get_cert_chain<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize>;

    /// Get the hash of the root certificate in the certificate chain.
    /// The hash algorithm is always SHA-384. The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `cert_hash` - The buffer to store the hash of the root certificate.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn root_cert_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    /// Sign hash with leaf certificate key
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - Asymmetric algorithm to sign with.
    /// * `hash` - The hash to sign.
    /// * `signature` - The output buffer to store the ECC384 signature.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn sign_hash<'a>(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()>;

    /// Get the KeyPairID associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * u8 - The KeyPairID associated with the certificate chain or None if not supported or not found.
    async fn key_pair_id(&self, slot_id: u8) -> Option<u8>;

    /// Retrieve the `CertificateInfo` associated with the certificate chain for the given slot.
    /// The `CertificateInfo` structure specifies the certificate model (such as DeviceID, Alias, or General),
    /// and includes reserved bits for future extensions.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `CertificateInfo` - The CertificateInfo associated with the certificate chain or None if not supported or not found.
    async fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain if SPDM responder supports
    /// multiple asymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `KeyUsageMask` - The KeyUsageMask associated with the certificate chain or None if not supported or not found.
    async fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;
}

pub(crate) fn validate_cert_store(cert_store: &dyn SpdmCertStore) -> SpdmResult<()> {
    let slot_count = cert_store.slot_count();
    if slot_count > MAX_CERT_SLOTS_SUPPORTED {
        Err(SpdmError::InvalidParam)?;
    }
    Ok(())
}

pub(crate) async fn cert_slot_mask(cert_store: &dyn SpdmCertStore) -> (u8, u8) {
    let slot_count = cert_store.slot_count().min(MAX_CERT_SLOTS_SUPPORTED);
    let supported_slot_mask = (1 << slot_count) - 1;

    let mut provisioned_slot_mask = 0;
    for i in 0..slot_count {
        if cert_store.is_provisioned(i).await {
            provisioned_slot_mask |= 1 << i;
        }
    }

    (supported_slot_mask, provisioned_slot_mask)
}

/// Get the hash of the certificate chain.
/// The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
/// The type of the certificate chain is indicated by the asym_algo parameter.
///
/// # Arguments
/// * `cert_store` - The certificate store to retrieve the certificate chain from.
/// * `slot_id` - The slot ID of the certificate chain.
/// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
/// * `hash` - The output buffer to store the hash of the certificate chain.
///
/// # Returns
/// * `hash` - The hash of the certificate chain.
pub(crate) async fn compute_cert_chain_hash(
    cert_store: &dyn SpdmCertStore,
    slot_id: u8,
    asym_algo: AsymAlgo,
    hash: &mut [u8],
) -> CertStoreResult<()> {
    if hash.len() != SHA384_HASH_SIZE {
        Err(CertStoreError::BufferTooSmall)?;
    }

    let crt_chain_len = cert_store.cert_chain_len(asym_algo, slot_id).await?;
    let cert_chain_format_len = crt_chain_len + SPDM_CERT_CHAIN_METADATA_LEN as usize;

    let header = SpdmCertChainHeader {
        length: cert_chain_format_len as u16,
        reserved: 0,
    };

    // Length and reserved fields
    let header_bytes = header.as_bytes();
    let mut hash_ctx = HashContext::new();
    hash_ctx
        .init(HashAlgoType::SHA384, Some(header_bytes))
        .await
        .map_err(CertStoreError::CaliptraApi)?;

    // Root certificate hash
    let mut root_hash = [0u8; SHA384_HASH_SIZE];

    cert_store
        .root_cert_hash(slot_id, asym_algo, &mut root_hash)
        .await?;
    hash_ctx
        .update(&root_hash)
        .await
        .map_err(CertStoreError::CaliptraApi)?;

    // Hash the certificate chain
    let mut cert_portion = [0u8; SPDM_MAX_CERT_CHAIN_PORTION_LEN as usize];
    let mut offset = 0;

    loop {
        let bytes_read = cert_store
            .get_cert_chain(slot_id, asym_algo, offset, &mut cert_portion)
            .await?;

        hash_ctx
            .update(&cert_portion[..bytes_read])
            .await
            .map_err(CertStoreError::CaliptraApi)?;

        offset += bytes_read;

        // If the bytes read is less than the length of the cert portion, it indicates the end of the chain
        if bytes_read < cert_portion.len() {
            break;
        }
    }
    hash_ctx
        .finalize(hash)
        .await
        .map_err(CertStoreError::CaliptraApi)
}
