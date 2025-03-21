// Licensed under the Apache-2.0 license

// Define SPDM certificate chain format

use crate::config;
use crate::error::SpdmError;
use crate::protocol::algorithms::SPDM_MAX_HASH_SIZE;

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SpdmCertChainHeader {
    pub length: u16, // total length of SpdmCertChain struct
    pub reserved: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SpdmCertChain {
    pub header: SpdmCertChainHeader,
    pub root_hash: [u8; SPDM_MAX_HASH_SIZE], // Digest of root cert
    pub data: [u8; config::MAX_CERT_CHAIN_DATA_SIZE], // A complete certificate chain, consisting of one or more ASN.1 DER-encoded X.509 v3 certificates.
}

impl Default for SpdmCertChain {
    fn default() -> Self {
        SpdmCertChain {
            header: SpdmCertChainHeader::default(),
            root_hash: [0u8; SPDM_MAX_HASH_SIZE],
            data: [0u8; config::MAX_CERT_CHAIN_DATA_SIZE],
        }
    }
}

impl SpdmCertChain {
    pub fn new(cert_chain_data: &[u8], root_hash: &[u8]) -> Result<Self, SpdmError> {
        if cert_chain_data.len() > config::MAX_CERT_CHAIN_DATA_SIZE {
            return Err(SpdmError::InvalidParam);
        }
        if root_hash.len() > SPDM_MAX_HASH_SIZE {
            return Err(SpdmError::InvalidParam);
        }
        let mut cert_chain = SpdmCertChain::default();
        cert_chain.header.length = (core::mem::size_of::<SpdmCertChainHeader>()
            + root_hash.len()
            + cert_chain_data.len()) as u16;
        cert_chain.root_hash[..root_hash.len()].copy_from_slice(root_hash);
        cert_chain.data[..cert_chain_data.len()].copy_from_slice(cert_chain_data);
        Ok(cert_chain)
    }
}
