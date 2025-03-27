// Licensed under the Apache-2.0 license

use crate::config;
use crate::error::SpdmError;

pub const SPDM_MAX_CERT_CHAIN_SLOTS: usize = 8;
pub const SPDM_MAX_HASH_SIZE: usize = 64;

// Represents a DER formatted certificate.
pub struct DerCert {
    pub cert: [u8; config::MAX_DER_CERT_LENGTH],
    pub length: usize,
}

impl Default for DerCert {
    fn default() -> Self {
        Self {
            cert: [0; config::MAX_DER_CERT_LENGTH],
            length: 0,
        }
    }
}

impl AsRef<[u8]> for DerCert {
    fn as_ref(&self) -> &[u8] {
        &self.cert[..self.length]
    }
}

impl DerCert {
    pub fn new(cert: &[u8]) -> Result<Self, SpdmError> {
        if cert.len() > config::MAX_DER_CERT_LENGTH {
            return Err(SpdmError::InvalidParam);
        }
        let mut der_cert = DerCert::default();
        der_cert.cert[..cert.len()].copy_from_slice(cert);
        der_cert.length = cert.len();
        Ok(der_cert)
    }
}

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
// Represents the buffer for the SPDM certificate chain base format as defined in SPDM Specification Table 28.
// This buffer contains the total length of the certificate chain (2 bytes), reserved bytes (2 bytes) and the root certificate hash.
pub struct SpdmCertChainBaseBuffer {
    pub data: [u8; 4 + SPDM_MAX_HASH_SIZE],
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

        // Root certificate hash
        let len = root_hash.len();
        cert_chain_base_buf.data[pos..(pos + len)].copy_from_slice(root_hash);
        pos += len;

        cert_chain_base_buf.length = pos as u16;

        Ok(cert_chain_base_buf)
    }
}

// Represents the device keys, which include the device ID and alias certificates.
// This structure can be extended to accommodate additional keys if needed.
#[derive(Default)]
pub struct DeviceKeys {
    pub devid_cert: DerCert,
    pub alias_cert: DerCert,
}

impl DeviceKeys {
    pub fn new(devid_cert: &[u8], alias_cert: &[u8]) -> Result<Self, SpdmError> {
        let devid_cert = DerCert::new(devid_cert)?;
        let alias_cert = DerCert::new(alias_cert)?;
        Ok(Self {
            devid_cert,
            alias_cert,
        })
    }

    pub fn get_devid_cert(&self) -> &[u8] {
        self.devid_cert.as_ref()
    }

    pub fn get_alias_cert(&self) -> &[u8] {
        self.alias_cert.as_ref()
    }
}

#[derive(Debug)]
pub enum DeviceCertsMgrError {
    DeviceKeysError,
    RootCaError,
    InterCaError,
}

// A trait that defines the interface for managing device certificates and keys.
// This trait can be implemented by a device-specific certificate manager and extended to async-trait if needed.
pub trait DeviceCertsManager {
    /// Retrieves the device keys and populates the provided `DeviceKeys` structure.
    ///
    /// # Arguments
    ///
    /// * `device_keys` - A mutable reference to a `DeviceKeys` structure where the device keys will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the device keys are successfully retrieved.
    /// * `Err(DeviceCertsMgrError)` if an error occurs while retrieving the device keys.
    fn get_device_keys(&self, device_keys: &mut DeviceKeys) -> Result<(), DeviceCertsMgrError>;

    /// Checks if the root CA certificate is present.
    ///
    /// # Returns
    ///
    /// * `true` if the root CA certificate is present.
    /// * `false` otherwise.
    fn is_root_ca_present(&self) -> bool;

    /// Checks if the intermediate CA certificate is present.
    ///
    /// # Returns
    ///
    /// * `true` if the intermediate CA certificate is present.
    /// * `false` otherwise.
    fn is_intermediate_ca_present(&self) -> bool;

    /// Retrieves the root CA certificate and populates the provided `DerCert` structure.
    ///
    /// # Arguments
    ///
    /// * `root_ca_cert` - A mutable reference to a `DerCert` structure where the root CA certificate will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the root CA certificate is successfully retrieved.
    /// * `Err(DeviceCertsMgrError)` if an error occurs while retrieving the root CA certificate.
    fn get_root_ca(&self, root_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError>;

    /// Retrieves the intermediate CA certificate and populates the provided `DerCert` structure.
    ///
    /// # Arguments
    ///
    /// * `inter_ca_cert` - A mutable reference to a `DerCert` structure where the intermediate CA certificate will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the intermediate CA certificate is successfully retrieved.
    /// * `Err(DeviceCertsMgrError)` if an error occurs while retrieving the intermediate CA certificate.
    fn get_intermediate_ca(&self, inter_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError>;

    /// Retrieves the certificate chain data and populates the provided `SpdmCertChainData` structure.
    ///
    /// This function retrieves the root CA certificate, intermediate CA certificate, device ID certificate,
    /// and alias certificate, and adds them to the certificate chain data. It also updates the length of the
    /// root certificate in the SPDM certificate chain data.
    ///
    /// # Arguments
    ///
    /// * `cert_chain_data` - A mutable reference to an `SpdmCertChainData` structure where the certificate chain data will be stored.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` containing the length of the root certificate if successful.
    /// * `Err(SpdmError)` if an error occurs while retrieving or adding certificates to the chain.
    fn get_certificate_chain_data(
        &self,
        cert_chain_data: &mut SpdmCertChainData,
    ) -> Result<usize, SpdmError> {
        let mut root_cert_len = 0;
        if self.is_root_ca_present() {
            // Retrieve the root CA cert and store it in the cert chain data.
            let mut root_cert = DerCert::default();
            self.get_root_ca(&mut root_cert)
                .map_err(SpdmError::CertMgr)?;

            cert_chain_data.add(root_cert.as_ref())?;

            // Update the length of the root cert in the spdm cert chain data
            root_cert_len = root_cert.length;
        }

        if self.is_intermediate_ca_present() {
            // Retrieve the intermediate CA cert and store it in the cert chain data.
            let mut intermediate_cert = DerCert::default();
            self.get_intermediate_ca(&mut intermediate_cert)
                .map_err(SpdmError::CertMgr)?;
            cert_chain_data.add(intermediate_cert.as_ref())?;
        }

        let mut device_keys = DeviceKeys::default();
        self.get_device_keys(&mut device_keys)
            .map_err(SpdmError::CertMgr)?;

        // Retrieve the device ID cert and store it in the cert chain data.
        cert_chain_data.add(device_keys.get_devid_cert())?;

        if root_cert_len == 0 {
            // Update the length of the root cert in the spdm cert chain data.
            root_cert_len = device_keys.get_devid_cert().len();
        }

        // Retrieve the alias cert and store it in the cert chain data.
        cert_chain_data.add(device_keys.get_alias_cert())?;

        Ok(root_cert_len)
    }
}

// Placeholder for the device certificate manager implementation.
#[derive(Default)]
pub struct DeviceCertsManagerImpl;

impl DeviceCertsManagerImpl {
    pub fn new() -> Self {
        Self {}
    }
}

// This implementation uses hard-coded certificates for development testing purposes.
// It should be refactored to integrate with the actual mechanism for retrieving certificates when available.
impl DeviceCertsManager for DeviceCertsManagerImpl {
    fn get_device_keys(&self, device_keys: &mut DeviceKeys) -> Result<(), DeviceCertsMgrError> {
        *device_keys =
            DeviceKeys::new(&config::TEST_DEVID_CERT_DER, &config::TEST_ALIAS_CERT_DER).unwrap();
        Ok(())
    }

    fn get_root_ca(&self, root_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        *root_ca_cert = DerCert::new(&[]).unwrap();
        Ok(())
    }

    fn get_intermediate_ca(&self, inter_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        *inter_ca_cert = DerCert::new(&[]).unwrap();
        Ok(())
    }

    fn is_root_ca_present(&self) -> bool {
        false
    }

    fn is_intermediate_ca_present(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config;

    #[test]
    fn test_get_certificate_chain_data() {
        let mut cert_chain_data = SpdmCertChainData::default();
        let device_certs_mgr = DeviceCertsManagerImpl;

        let root_cert_len = device_certs_mgr
            .get_certificate_chain_data(&mut cert_chain_data)
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
        let device_certs_mgr = DeviceCertsManagerImpl;
        let mut cert_chain_data = SpdmCertChainData::default();
        let root_cert_len = device_certs_mgr
            .get_certificate_chain_data(&mut cert_chain_data)
            .unwrap();

        let root_hash = [0xAAu8; SPDM_MAX_HASH_SIZE];
        let cert_chain_base_buf =
            SpdmCertChainBaseBuffer::new(root_cert_len, root_hash.as_ref()).unwrap();
        assert_eq!(cert_chain_base_buf.length, 4 + root_hash.len() as u16);
        assert_eq!(
            cert_chain_base_buf.as_ref()[..2],
            ((root_cert_len + 4 + root_hash.len()) as u16).to_le_bytes()
        );
        assert_eq!(cert_chain_base_buf.as_ref()[2..4], [0, 0]);
        assert_eq!(&cert_chain_base_buf.as_ref()[4..], &root_hash[..]);
    }
}
