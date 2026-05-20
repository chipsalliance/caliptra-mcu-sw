# SPDM Integration Guide

The following sections provide guidance on integrating the SPDM Responder with integrator's specific configurations and implementations.

## Certificate Store

The integrator is responsible for implementing the certificate store. The certificate store provides persistent storage for the certificate chains associated with each certificate slot. The cert store interface is split into three traits:

- **`SpdmCertStoreReader`** — Read operations for `GET_DIGESTS`, `GET_CERTIFICATE`, `CHALLENGE`.
- **`SpdmCertStoreSigner`** — Signing operations for `CHALLENGE`, `MEASUREMENTS`, `KEY_EXCHANGE`.
- **`SpdmCertStoreWriter`** — Write operations for `SET_CERTIFICATE` (optional).

`SpdmCertStore` is a composite of `SpdmCertStoreReader + SpdmCertStoreSigner` and is required by `SpdmContext`. The writer is optional — pass it only if `SET_CERTIFICATE` capability is enabled.

Write operations receive the complete cert chain data as a slice reference pointing into the reassembled SPDM message buffer — no additional allocation is required.

```rust
pub trait SpdmCertStoreReader {
    fn slot_count(&self) -> u8;
    async fn is_provisioned(&self, slot_id: u8) -> bool;
    async fn cert_chain_len(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;
    async fn get_cert_chain<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8, offset: usize, cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize>;
    async fn root_cert_hash<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8, cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;
    async fn key_pair_id(&self, slot_id: u8) -> Option<u8>;
    async fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;
    async fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;
}

pub trait SpdmCertStoreSigner {
    async fn sign_hash<'a>(
        &self, asym_algo: AsymAlgo, slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE], signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()>;
}

pub trait SpdmCertStoreWriter {
    async fn write_cert_chain(
        &self, asym_algo: AsymAlgo, slot_id: u8, key_pair_id: u8,
        cert_model: CertificateInfo, root_cert_hash: &[u8; SHA384_HASH_SIZE], cert_chain: &[u8],
    ) -> CertStoreResult<()>;
    async fn erase_cert_chain(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()>;
}

/// Composite trait — required by SpdmContext.
pub trait SpdmCertStore: SpdmCertStoreReader + SpdmCertStoreSigner {}
```
