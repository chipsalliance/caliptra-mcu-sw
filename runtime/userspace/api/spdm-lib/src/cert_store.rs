// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::error::{SpdmError, SpdmResult};
use crate::protocol::algorithms::{AsymAlgo, SHA384_HASH_SIZE};
use crate::protocol::certs::{CertificateInfo, KeyUsageMask};
use alloc::boxed::Box;
use async_trait::async_trait;
use libapi_caliptra::error::CaliptraApiError;

use core::fmt::Debug;

pub const MAX_CERT_SLOTS_SUPPORTED: u8 = 2;

#[derive(Debug)]
pub enum CertStoreError {
    InitFailed,
    InvalidSlotId,
    UnsupportedHashAlgo,
    BufferTooSmall,
    InvalidOffset,
    CertReadError,
    CaliptraApi(CaliptraApiError),
}
pub type CertStoreResult<T> = Result<T, CertStoreError>;

#[async_trait(?Send)]
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
    fn is_provisioned(&self, slot_id: u8) -> bool;

    /// Get the length of the certificate chain in bytes.
    /// The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    ///
    /// # Returns
    /// * `usize` - The length of the certificate chain in bytes or error.
    async fn cert_chain_len(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;

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
        &mut self,
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
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    // /// Get the leaf certificate key label
    // ///
    // /// # Arguments
    // /// * `slot_id` - The slot ID of the certificate chain.
    // ///
    // /// # Returns
    // /// * `Option<[u8; SHA384_HASH_SIZE]>` - The leaf certificate key label or None if not supported or not found.
    // fn leaf_cert_key_label(&self, slot_id: u8) -> Option<[u8; SHA384_HASH_SIZE]>;

    /// Get the KeyPairID associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * u8 - The KeyPairID associated with the certificate chain or None if not supported or not found.
    fn key_pair_id(&self, slot_id: u8) -> Option<u8>;

    /// Get CertificateInfo associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `CertificateInfo` - The CertificateInfo associated with the certificate chain or None if not supported or not found.
    fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `KeyUsageMask` - The KeyUsageMask associated with the certificate chain or None if not supported or not found.
    fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;
}

pub(crate) fn validate_cert_store(cert_store: &dyn SpdmCertStore) -> SpdmResult<()> {
    let slot_count = cert_store.slot_count();
    if slot_count > MAX_CERT_SLOTS_SUPPORTED {
        Err(SpdmError::InvalidParam)?;
    }
    Ok(())
}

pub(crate) fn cert_slot_mask(cert_store: &dyn SpdmCertStore) -> (u8, u8) {
    let slot_count = cert_store.slot_count().min(MAX_CERT_SLOTS_SUPPORTED);
    let supported_slot_mask = (1 << slot_count) - 1;

    let provisioned_slot_mask = (0..slot_count)
        .filter(|&i| cert_store.is_provisioned(i))
        .fold(0, |mask, i| mask | (1 << i));

    (supported_slot_mask, provisioned_slot_mask)
}

// pub(crate) async fn total_cert_chain_len(
//     cert_store: &mut dyn SpdmCertStore,
//     asym_algo: AsymAlgo,
//     slot_id: u8,
// ) -> CertStoreResult<u16> {
//     cert_store
//         .cert_chain_len(asym_algo, slot_id)
//         .await
//         .map(|len| len as u16 + SPDM_CERT_CHAIN_METADATA_LEN)
// }
