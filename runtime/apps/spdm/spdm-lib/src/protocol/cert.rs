// Licensed under the Apache-2.0 license

// Define SPDM certificate chain format

use crate::config;
use crate::error::SpdmError;
use crate::protocol::algorithms::SPDM_MAX_HASH_SIZE;

pub struct SpdmCertChainData {
    pub data: [u8; config::MAX_CERT_CHAIN_DATA_SIZE],
    pub length: u16,
}

impl Default for SpdmCertChainData {
    fn default() -> Self {
        SpdmCertChainData {
            data: [0u8; config::MAX_CERT_CHAIN_DATA_SIZE],
            length: 0u16,
        }
    }
}

impl SpdmCertChainData {
    pub fn new(data: &[u8]) -> Result<Self, SpdmError> {
        if data.len() > config::MAX_CERT_CHAIN_DATA_SIZE {
            return Err(SpdmError::InvalidParam);
        }
        let mut cert_chain_data = SpdmCertChainData::default();
        cert_chain_data.data[..data.len()].copy_from_slice(data);
        cert_chain_data.length = data.len() as u16;
        Ok(cert_chain_data)
    }

    pub fn add(&mut self, data: &[u8]) -> Result<(), SpdmError> {
        if self.length as usize + data.len() > config::MAX_CERT_CHAIN_DATA_SIZE {
            return Err(SpdmError::InvalidParam);
        }
        self.data[self.length as usize..(self.length as usize + data.len())].copy_from_slice(data);
        self.length += data.len() as u16;
        Ok(())
    }
}

impl AsRef<[u8]> for SpdmCertChainData {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }
}

pub struct SpdmCertChainBaseBuffer {
    pub data: [u8; 4 + SPDM_MAX_HASH_SIZE], // Cert chain format defined in spec
    pub length: u16,
}

impl Default for SpdmCertChainBaseBuffer {
    fn default() -> Self {
        SpdmCertChainBaseBuffer {
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE],
            length: 0u16,
        }
    }
}

impl AsRef<[u8]> for SpdmCertChainBaseBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }
}

impl SpdmCertChainBaseBuffer {
    // SPDM Spec Table 28 — Certificate chain format
    // This function generate the SpdmCertChainBuffer from a x509 certificates chain.
    pub fn new(cert_chain_data_len: usize, root_hash: &[u8]) -> Result<Self, SpdmError> {
        if cert_chain_data_len > config::MAX_CERT_CHAIN_DATA_SIZE
            || root_hash.len() > SPDM_MAX_HASH_SIZE
        {
            return Err(SpdmError::InvalidParam);
        }

        let total_len = (cert_chain_data_len + root_hash.len() + 4) as u16;
        let mut cert_chain_base_buf = SpdmCertChainBaseBuffer::default();
        let mut pos = 0;

        // Length
        let len = 2;
        cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(&total_len.to_le_bytes());
        pos += len;

        // Reserved
        cert_chain_base_buf.data[pos] = 0;
        cert_chain_base_buf.data[pos + 1] = 0;
        pos += 2;

        // RootHash HashLen
        let len = root_hash.len();
        cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
        pos += len;

        cert_chain_base_buf.length = pos as u16;

        Ok(cert_chain_base_buf)
    }
}

/*
#[repr(C, packed)]
#[derive(Default)]
pub struct SpdmCertChainHeader {
    pub length: u16,   // Length of the cert chain including this struct.
    pub reserved: u16, // Reserved
}

pub struct SpdmCertChainCommon {
    pub header: SpdmCertChainHeader,
    pub root_hash: SpdmDigest,
}

impl SpdmCertChainCommon {
    pub fn new(root_hash: &[u8], cert_data_len: usize) -> Result<Self, SpdmError> {
        if root_hash.len() > SPDM_MAX_HASH_SIZE || cert_data_len > config::MAX_CERT_CHAIN_DATA_SIZE {
            return Err(SpdmError::InvalidParam);
        }

        Ok(SpdmCertChainCommon {
            header: SpdmCertChainHeader {
                length: 2 * core::mem::size_of::<u16>() as u16 + root_hash.len() as u16 + cert_data_len as u16,
                reserved: 0,
            },
            root_hash: SpdmDigest::new(root_hash),
        })
    }
}


pub struct SpdmCertChain<'a> {
    pub header: SpdmCertChainHeader,
    pub root_hash: &'a [u8],
    pub cert_chain_data: &'a [u8],
}

impl<'a> SpdmCertChain<'a> {
    pub fn new(root_hash: &'a [u8], cert_chain_data: &'a [u8]) -> Result<Self, SpdmError> {
        if root_hash.len() > SPDM_MAX_HASH_SIZE || cert_chain_data_len > config::MAX_CERT_CHAIN_DATA_SIZE {
            return Err(SpdmError::InvalidParam);
        }

        let length = 2 * core::mem::size_of::<u16>() + root_hash.len() + cert_chain_data_len;
        Ok(SpdmCertChain {
            header: SpdmCertChainHeader {
                length: length as u16,
                reserved: 0,
            },
            root_hash,
            cert_chain_data,
        })
    }
}
*/
