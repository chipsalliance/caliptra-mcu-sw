// Licensed under the Apache-2.0 license

use crate::config;
use crate::error::SpdmError;
use crate::protocol::cert::SpdmCertChainData;

pub struct DerCert {
    pub cert: [u8; config::MAX_DER_CERT_LENGTH], // DER formatted certificate
    pub length: usize,                           // Length of the certificate DER
}

impl Default for DerCert {
    fn default() -> Self {
        // Initialize the structure with default values
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
        // Initialize the structure with the provided values
        let mut der_cert = DerCert::default();
        der_cert.cert[..cert.len()].copy_from_slice(cert);
        der_cert.length = cert.len();
        Ok(der_cert)
    }
}

//use async_trait::async_trait;
pub struct DeviceKeys {
    pub devid_cert: DerCert,
    pub alias_cert: DerCert,
}

impl Default for DeviceKeys {
    fn default() -> Self {
        // Initialize the structure with default values
        Self {
            devid_cert: DerCert::default(),
            alias_cert: DerCert::default(),
        }
    }
}

impl DeviceKeys {
    pub fn new(devid_cert: &[u8], alias_cert: &[u8]) -> Result<Self, SpdmError> {
        // Initialize the structure with the provided values
        let devid_cert = DerCert::new(devid_cert)?;
        let alias_cert = DerCert::new(alias_cert)?;
        Ok(Self {
            devid_cert,
            alias_cert,
        })
    }

    pub fn get_devid_cert(&self) -> &[u8] {
        &self.devid_cert.as_ref()
    }

    pub fn get_alias_cert(&self) -> &[u8] {
        &self.alias_cert.as_ref()
    }
}

#[derive(Debug)]
pub enum DeviceCertsMgrError {
    DeviceKeysError,
    RootCaError,
    InterCaError,
}

pub trait DeviceCertsManager {
    fn get_device_keys(&self, device_keys: &mut DeviceKeys) -> Result<(), DeviceCertsMgrError>;

    fn is_root_ca_present(&self) -> bool;

    fn is_intermediate_ca_present(&self) -> bool;

    fn get_root_ca(&self, root_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError>;

    fn get_intermediate_ca(&self, inter_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError>;
}

#[derive(Default)]
pub struct DeviceCertsManagerImpl;

impl DeviceCertsManager for DeviceCertsManagerImpl {
    fn get_device_keys(&self, device_keys: &mut DeviceKeys) -> Result<(), DeviceCertsMgrError> {
        // Get from config:: TEST_DEVID_CERT_DER and TEST_ALIAS_CERT_DER
        *device_keys =
            DeviceKeys::new(&config::TEST_DEVID_CERT_DER, &config::TEST_ALIAS_CERT_DER).unwrap();
        Ok(())
    }

    fn get_root_ca(&self, root_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        *root_ca_cert = DerCert::new(&[]).unwrap();
        Ok(())
    }

    fn get_intermediate_ca(&self, inter_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        // Implementation here
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

// helper function to get certificate list. Return the length of root cert in the spdm cert chain data
pub(crate) fn get_certificate_list<'a>(
    device_certs_mgr: &'a dyn DeviceCertsManager,
    cert_chain_data: &mut SpdmCertChainData,
) -> Result<usize, SpdmError> {
    //let mut cert_count = 0;
    let mut root_cert_len = 0;

    if device_certs_mgr.is_root_ca_present() {
        // Retrieve the root CA certificate and store it in the cert chain data
        let mut root_cert = DerCert::default();
        device_certs_mgr
            .get_root_ca(&mut root_cert)
            .map_err(SpdmError::CertMgr)?;

        // Store the root CA certificate in the cert chain data
        cert_chain_data.add(root_cert.as_ref())?;

        // Update the length of the root cert in the spdm cert chain data
        root_cert_len = root_cert.length;
    }

    if device_certs_mgr.is_intermediate_ca_present() {
        // Retrieve the intermediate CA certificate and store it in the cert chain data
        let mut intermediate_cert = DerCert::default();
        device_certs_mgr
            .get_intermediate_ca(&mut intermediate_cert)
            .map_err(|e| SpdmError::CertMgr(e))?;

        // Store the intermediate CA certificate in the cert chain data
        cert_chain_data.add(intermediate_cert.as_ref())?;
    }

    let mut device_keys = DeviceKeys::default();

    device_certs_mgr
        .get_device_keys(&mut device_keys)
        .map_err(|e| SpdmError::CertMgr(e))?;

    // Retrieve the device ID certificate and store it in the cert chain data
    cert_chain_data.add(device_keys.get_devid_cert())?;

    if root_cert_len == 0 {
        // Update the length of the root cert in the spdm cert chain data
        root_cert_len = device_keys.get_devid_cert().len();
    }

    // Retrieve the alias certificate and store it in the cert chain data
    cert_chain_data.add(device_keys.get_alias_cert())?;

    Ok(root_cert_len)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config;

    #[test]
    fn test_get_certificate_list() {
        let mut cert_chain_data = SpdmCertChainData::default();
        let device_certs_mgr = DeviceCertsManagerImpl;

        let root_cert_len = get_certificate_list(&device_certs_mgr, &mut cert_chain_data).unwrap();
        assert_eq!(root_cert_len, config::TEST_DEVID_CERT_DER.len());
        assert_eq!(
            cert_chain_data.as_ref().len(),
            config::TEST_DEVID_CERT_DER.len() + config::TEST_ALIAS_CERT_DER.len()
        );
        // Check the root cert contents
        assert_eq!(
            &cert_chain_data.as_ref()[..root_cert_len],
            &config::TEST_DEVID_CERT_DER[..]
        );
        // Check the alias cert contents
        assert_eq!(
            &cert_chain_data.as_ref()[root_cert_len..],
            &config::TEST_ALIAS_CERT_DER[..]
        );
    }
}
