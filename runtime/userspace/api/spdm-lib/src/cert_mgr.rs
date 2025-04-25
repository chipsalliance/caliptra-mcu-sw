// Licensed under the Apache-2.0 license
use crate::config;
use crate::error::SpdmError;
use crate::protocol::BaseHashAlgoType;
use libapi_caliptra::crypto::error::CryptoError;
use libapi_caliptra::crypto::hash::{HashAlgoType, HashContext};

pub const SPDM_MAX_CERT_CHAIN_SLOTS: usize = 8;
pub const SPDM_MAX_HASH_SIZE: usize = 64;
pub const SPDM_CERT_CHAIN_HEADER_SIZE: usize = core::mem::size_of::<SpdmCertChainHeader>();

pub type SupportedSlotMask = u8;
pub type ProvisionedSlotMask = u8;

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

    // Add certificate data to the chain.
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

#[repr(C, packed)]
pub struct SpdmCertChainHeader {
    pub length: u16,
    pub reserved: u16,
}

// Represents the buffer for the SPDM certificate chain base format as defined in SPDM Specification 1.3.2 Table 33.
// This buffer contains the total length of the certificate chain (2 bytes), reserved bytes (2 bytes) and the root certificate hash.
pub struct SpdmCertChainBaseBuffer {
    pub data: [u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE],
    pub length: u16,
}

impl Default for SpdmCertChainBaseBuffer {
    fn default() -> Self {
        SpdmCertChainBaseBuffer {
            data: [0u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE],
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
    pub fn new(cert_chain_data_len: usize, root_hash: &[u8]) -> Result<Self, DeviceCertsMgrError> {
        if cert_chain_data_len > config::MAX_CERT_CHAIN_DATA_SIZE
            || root_hash.len() > SPDM_MAX_HASH_SIZE
        {
            Err(DeviceCertsMgrError::CertDataBufferTooSmall)?;
        }

        let total_len =
            (cert_chain_data_len + root_hash.len() + SPDM_CERT_CHAIN_HEADER_SIZE) as u16;
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

        // Root certificate hash
        let len = root_hash.len();
        cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
        pos += len;

        cert_chain_base_buf.length = pos as u16;

        Ok(cert_chain_base_buf)
    }
}

pub struct SpdmCertChainBuffer {
    pub data:
        [u8; SPDM_CERT_CHAIN_HEADER_SIZE + SPDM_MAX_HASH_SIZE + config::MAX_CERT_CHAIN_DATA_SIZE],
    pub length: u16,
}

impl Default for SpdmCertChainBuffer {
    fn default() -> Self {
        SpdmCertChainBuffer {
            data: [0u8; SPDM_CERT_CHAIN_HEADER_SIZE
                + SPDM_MAX_HASH_SIZE
                + config::MAX_CERT_CHAIN_DATA_SIZE],
            length: 0u16,
        }
    }
}

impl AsRef<[u8]> for SpdmCertChainBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }
}

impl SpdmCertChainBuffer {
    pub fn new(cert_chain_data: &[u8], root_hash: &[u8]) -> Result<Self, DeviceCertsMgrError> {
        if cert_chain_data.len() > config::MAX_CERT_CHAIN_DATA_SIZE
            || root_hash.len() > SPDM_MAX_HASH_SIZE
        {
            Err(DeviceCertsMgrError::CertDataBufferTooSmall)?;
        }

        let total_len =
            (cert_chain_data.len() + root_hash.len() + SPDM_CERT_CHAIN_HEADER_SIZE) as u16;
        let mut cert_chain_buf = SpdmCertChainBuffer::default();
        let mut pos = 0;

        // Length
        let len = 2;
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(&total_len.to_le_bytes());
        pos += len;

        // Reserved
        cert_chain_buf.data[pos] = 0;
        cert_chain_buf.data[pos + 1] = 0;
        pos += 2;

        // Root certificate hash
        let len = root_hash.len();
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
        pos += len;

        // Certificate chain data
        let len = cert_chain_data.len();
        cert_chain_buf.data[pos..(pos + len)].copy_from_slice(cert_chain_data);
        pos += len;

        cert_chain_buf.length = pos as u16;

        Ok(cert_chain_buf)
    }
}

#[derive(Debug)]
pub enum DeviceCertsMgrError {
    UnsupportedSlotId,
    UnprovisionedSlotId,
    CertDataBufferTooSmall,
    CryptoError(CryptoError),
    InvalidParam(&'static str),
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum SpdmCertModel {
    DeviceCertModel = 1,
    AliasCertModel = 2,
    GenericCertModel = 3,
}

#[derive(Debug, Clone)]
pub struct CertChainSlotState {
    // Number of certificates in the chain
    pub certs_count: usize,
    // Sizes of each certificate in the chain
    pub certs_size: [usize; config::MAX_CERT_COUNT_PER_CHAIN],
    // The model of the certificate
    pub cert_model: Option<SpdmCertModel>,
    // The key pair ID associated with the certificate slot.
    pub key_pair_id: Option<u8>,
    // The key usage mask associated with the certificate slot
    pub key_usage_mask: Option<u16>,
}

impl Default for CertChainSlotState {
    fn default() -> Self {
        Self {
            certs_count: 0,
            certs_size: [0; config::MAX_CERT_COUNT_PER_CHAIN],
            cert_model: None,
            key_pair_id: None,
            key_usage_mask: None,
        }
    }
}

pub struct DeviceCertsManager {
    supported_slot_mask: SupportedSlotMask,
    provisioned_slot_mask: ProvisionedSlotMask,
}

impl DeviceCertsManager {
    pub fn new(
        supported_slot_mask: SupportedSlotMask,
        provisioned_slot_mask: ProvisionedSlotMask,
    ) -> Self {
        Self {
            supported_slot_mask,
            provisioned_slot_mask,
        }
    }
}

impl DeviceCertsManager {
    /// Retrieves the supported and provisioned slot masks for certificate chains.
    ///
    /// # Returns
    /// - `Ok((SupportedSlotMask, ProvisionedSlotMask))`: A tuple containing the supported
    ///   and provisioned slot masks.
    /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
    pub fn get_cert_chain_slot_mask(
        &self,
    ) -> Result<(SupportedSlotMask, ProvisionedSlotMask), DeviceCertsMgrError> {
        Ok((self.supported_slot_mask, self.provisioned_slot_mask))
    }

    /// Retrieves the state of the certificate chain for a specific slot, including the
    /// number of certificates in the chain, the size of each certificate, and the type model.
    ///
    /// # Parameters
    /// - `slot_id`: The ID of the slot to retrieve the certificate chain state for.
    /// - `cert_chain_slot_state`: A mutable reference to a `CertChainSlotState` structure
    ///   to store the retrieved state.
    ///
    /// # Returns
    /// - `Ok(())`: If the operation is successful.
    /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
    pub fn get_cert_chain_slot_state(
        &self,
        slot_id: u8,
        cert_chain_slot_state: &mut CertChainSlotState,
    ) -> Result<(), DeviceCertsMgrError> {
        let (supported_mask, provisioned_mask) = self.get_cert_chain_slot_mask()?;
        let slot_mask = 1 << slot_id;
        if slot_mask & supported_mask == 0 {
            return Err(DeviceCertsMgrError::UnsupportedSlotId);
        }
        if slot_mask & provisioned_mask == 0 {
            return Err(DeviceCertsMgrError::UnprovisionedSlotId);
        }

        // Fill the cert_chain_slot_state with test cert chain slot information for now.
        match slot_id {
            0 => {
                cert_chain_slot_state.certs_count = 2;
                cert_chain_slot_state.certs_size[0] = config::TEST_DEVID_CERT_DER.len();
                cert_chain_slot_state.certs_size[1] = config::TEST_ALIAS_CERT_DER.len();
                cert_chain_slot_state.cert_model = Some(SpdmCertModel::AliasCertModel);
                cert_chain_slot_state.key_pair_id = None;
                cert_chain_slot_state.key_usage_mask = None;
            }
            _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
        }

        Ok(())
    }

    fn get_cert_der_data(
        &self,
        slot_id: u8,
        cert_index: usize,
        cert_data: &mut [u8],
    ) -> Result<(), DeviceCertsMgrError> {
        let (supported_mask, provisioned_mask) = self.get_cert_chain_slot_mask()?;
        let slot_mask = 1 << slot_id;
        if slot_mask & supported_mask == 0 {
            return Err(DeviceCertsMgrError::UnsupportedSlotId);
        }
        if slot_mask & provisioned_mask == 0 {
            return Err(DeviceCertsMgrError::UnprovisionedSlotId);
        }
        // Populate the cert data with test cert info for now.
        match slot_id {
            0 => match cert_index {
                0 => {
                    if cert_data.len() < config::TEST_DEVID_CERT_DER.len() {
                        return Err(DeviceCertsMgrError::CertDataBufferTooSmall);
                    }
                    cert_data[..config::TEST_DEVID_CERT_DER.len()]
                        .copy_from_slice(&config::TEST_DEVID_CERT_DER);
                }
                1 => {
                    if cert_data.len() < config::TEST_ALIAS_CERT_DER.len() {
                        return Err(DeviceCertsMgrError::CertDataBufferTooSmall);
                    }
                    cert_data[..config::TEST_ALIAS_CERT_DER.len()]
                        .copy_from_slice(&config::TEST_ALIAS_CERT_DER);
                }
                _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
            },
            _ => return Err(DeviceCertsMgrError::UnsupportedSlotId),
        }

        Ok(())
    }
    /// Constructs the certificate chain data for a specific slot.
    ///
    /// This method validates the slot ID, retrieves the slot state, and iterates over
    /// the certificates in the chain to construct the certificate chain data.
    ///
    /// # Parameters
    /// - `slot_id`: The ID of the slot to construct the certificate chain data for.
    /// - `cert_chain_data`: A mutable reference to an `SpdmCertChainData` structure
    ///   to store the constructed certificate chain data.
    ///
    /// # Returns
    /// - `Ok(usize)`: The length of the root certificate if the operation is successful.
    /// - `Err(DeviceCertsMgrError)`: An error if the operation fails.
    pub fn construct_cert_chain_data(
        &self,
        slot_id: u8,
        cert_chain_data: &mut SpdmCertChainData,
    ) -> Result<usize, DeviceCertsMgrError> {
        let (supported_mask, provisioned_mask) = self.get_cert_chain_slot_mask()?;
        let slot_mask = 1 << slot_id;
        if slot_mask & supported_mask == 0 {
            return Err(DeviceCertsMgrError::UnsupportedSlotId);
        }
        if slot_mask & provisioned_mask == 0 {
            return Err(DeviceCertsMgrError::UnprovisionedSlotId);
        }

        let mut cert_chain_slot_state = CertChainSlotState::default();
        // Retrieve slot state
        self.get_cert_chain_slot_state(slot_id, &mut cert_chain_slot_state)?;

        let mut root_cert_len = 0;
        // Iterate over certificates in the chain
        for (i, &cert_len) in cert_chain_slot_state
            .certs_size
            .iter()
            .take(cert_chain_slot_state.certs_count)
            .enumerate()
        {
            let offset = cert_chain_data.length as usize;
            let cert_buf = cert_chain_data
                .data
                .get_mut(offset..offset + cert_len)
                .ok_or(DeviceCertsMgrError::CertDataBufferTooSmall)?;

            self.get_cert_der_data(slot_id, i, cert_buf)?;
            cert_chain_data.length += cert_len as u16;
            if i == 0 {
                root_cert_len = cert_len;
            }
        }

        Ok(root_cert_len)
    }

    pub async fn cert_chain_digest(
        &self,
        slot_id: u8,
        hash_type: BaseHashAlgoType,
        digest: &mut [u8],
    ) -> Result<(), DeviceCertsMgrError> {
        let mut cert_chain_data = SpdmCertChainData::default();
        let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
        let root_cert_len = self.construct_cert_chain_data(slot_id, &mut cert_chain_data)?;

        let hash_algo: HashAlgoType = hash_type
            .try_into()
            .map_err(|_| DeviceCertsMgrError::InvalidParam("Invalid hash type"))?;

        if digest.len() < hash_algo.hash_size() {
            Err(DeviceCertsMgrError::CertDataBufferTooSmall)?;
        }

        // Get the hash of root_cert
        HashContext::hash_all(
            hash_algo,
            &cert_chain_data.as_ref()[..root_cert_len],
            &mut root_hash,
        )
        .await
        .map_err(DeviceCertsMgrError::CryptoError)?;

        // Construct the cert chain base buffer
        let cert_chain_base_buf =
            SpdmCertChainBaseBuffer::new(cert_chain_data.length as usize, root_hash.as_ref())?;

        // Start the hash operation
        let mut hash_ctx = HashContext::new();

        // Hash the cert chain base
        hash_ctx
            .init(hash_algo, Some(cert_chain_base_buf.as_ref()))
            .await
            .map_err(DeviceCertsMgrError::CryptoError)?;

        // Hash the cert chain data
        hash_ctx
            .update(cert_chain_data.as_ref())
            .await
            .map_err(DeviceCertsMgrError::CryptoError)?;

        // Finalize the hash operation
        hash_ctx
            .finalize(digest)
            .await
            .map_err(DeviceCertsMgrError::CryptoError)?;

        Ok(())
    }

    pub async fn construct_cert_chain_buffer(
        &self,
        hash_type: BaseHashAlgoType,
        slot_id: u8,
    ) -> Result<SpdmCertChainBuffer, DeviceCertsMgrError> {
        let mut cert_chain_data = SpdmCertChainData::default();
        let mut root_hash = [0u8; SPDM_MAX_HASH_SIZE];
        let root_cert_len = self.construct_cert_chain_data(slot_id, &mut cert_chain_data)?;

        let hash_algo: HashAlgoType = hash_type
            .try_into()
            .map_err(|_| DeviceCertsMgrError::InvalidParam("Invalid Hash type"))?;

        if root_hash.len() < hash_algo.hash_size() {
            Err(DeviceCertsMgrError::CertDataBufferTooSmall)?;
        }

        // Get the hash of root_cert
        HashContext::hash_all(
            hash_algo,
            &cert_chain_data.as_ref()[..root_cert_len],
            &mut root_hash,
        )
        .await
        .map_err(DeviceCertsMgrError::CryptoError)?;

        // Construct the cert chain buffer
        let cert_chain_buffer =
            SpdmCertChainBuffer::new(cert_chain_data.as_ref(), root_hash.as_ref())?;

        Ok(cert_chain_buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config;

    #[test]
    fn test_get_certificate_chain_data() {
        let mut cert_chain_data = SpdmCertChainData::default();
        let device_certs_mgr = DeviceCertsManager::new(1, 1);
        let slot_id = 0;

        let root_cert_len = device_certs_mgr
            .construct_cert_chain_data(slot_id, &mut cert_chain_data)
            .unwrap();
        assert_eq!(root_cert_len, config::TEST_DEVID_CERT_DER.len());
        assert_eq!(
            cert_chain_data.as_ref().len(),
            config::TEST_DEVID_CERT_DER.len() + config::TEST_ALIAS_CERT_DER.len()
        );
        assert_eq!(
            &cert_chain_data.as_ref()[..root_cert_len],
            &config::TEST_DEVID_CERT_DER[..]
        );
        assert_eq!(
            &cert_chain_data.as_ref()[root_cert_len..],
            &config::TEST_ALIAS_CERT_DER[..]
        );
    }

    #[test]
    fn test_certificate_chain_base_buffer() {
        let device_certs_mgr = DeviceCertsManager::new(1, 1);
        let mut cert_chain_data = SpdmCertChainData::default();
        let slot_id = 0;
        let root_cert_len = device_certs_mgr
            .construct_cert_chain_data(slot_id, &mut cert_chain_data)
            .unwrap();

        let root_hash = [0xAAu8; SPDM_MAX_HASH_SIZE];
        let cert_chain_base_buf =
            SpdmCertChainBaseBuffer::new(root_cert_len, root_hash.as_ref()).unwrap();
        assert_eq!(
            cert_chain_base_buf.length,
            (SPDM_CERT_CHAIN_HEADER_SIZE + root_hash.len()) as u16
        );
        assert_eq!(
            cert_chain_base_buf.as_ref()[..2],
            ((root_cert_len + SPDM_CERT_CHAIN_HEADER_SIZE + root_hash.len()) as u16).to_le_bytes()
        );
        assert_eq!(cert_chain_base_buf.as_ref()[2..4], [0, 0]);
        assert_eq!(&cert_chain_base_buf.as_ref()[4..], &root_hash[..]);
    }
}
