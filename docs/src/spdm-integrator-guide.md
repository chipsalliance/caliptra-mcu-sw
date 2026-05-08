# SPDM Integration Guide

The following sections provide guidance on integrating the SPDM Responder with integrator's specific configurations and implementations.

## Certificate Store

The integrator is responsible for implementing the certificate store. The certificate store provides persistent storage for the certificate chains associated with each certificate slot. To enable this functionality, the integrator shall implement the `SpdmCertStore` trait, which defines the required operations for reading, writing, and managing the SPDM certificate chains.

The certificate store supports both read operations (for `GET_DIGESTS`, `GET_CERTIFICATE`, `CHALLENGE`) and write operations (for `SET_CERTIFICATE`). Write operations receive the complete cert chain data as a slice reference pointing into the reassembled SPDM message buffer — no additional allocation is required.

```rust
pub trait SpdmCertStore {
    /// Get supported certificate slot count.
    fn slot_count(&self) -> u8;

    /// Check if the slot is provisioned.
    async fn is_provisioned(&self, slot_id: u8) -> bool;

    /// Get the length of the certificate chain in bytes (ASN.1 DER-encoded X.509 v3).
    async fn cert_chain_len(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;

    /// Read the certificate chain in portions (ASN.1 DER-encoded X.509 v3).
    async fn get_cert_chain<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8, offset: usize, cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize>;

    /// Get the hash of the root certificate in the certificate chain.
    async fn root_cert_hash<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8, cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    /// Sign hash with leaf certificate key.
    async fn sign_hash<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE], signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()>;

    /// Get the KeyPairID associated with the certificate chain.
    async fn key_pair_id(&self, slot_id: u8) -> Option<u8>;

    /// Get the CertificateInfo for the slot (cert model metadata).
    async fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain.
    async fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;

    /// Write a certificate chain to a slot (SET_CERTIFICATE).
    /// The cert_chain slice is a zero-copy reference into the SPDM message buffer.
    /// The implementation should validate the leaf cert matches the key pair.
    async fn write_cert_chain(
        &self, asym_algo: AsymAlgo, slot_id: u8, key_pair_id: u8,
        cert_model: CertificateInfo, cert_chain: &[u8],
    ) -> CertStoreResult<()>;

    /// Erase a certificate chain from a slot. The key pair is not erased.
    async fn erase_cert_chain(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()>;
}
```
