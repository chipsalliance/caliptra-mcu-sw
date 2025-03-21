// Licensed under the Apache-2.0 license

use crate::config;
use crate::error::SpdmError;
use async_trait::async_trait;

pub struct DeviceKeys {
    pub devid_cert: [u8; config::MAX_DEVID_CERT_LENGTH], // Adjust the size as needed
    pub devid_cert_length: usize,
    pub alias_cert: [u8; config::MAX_ALIAS_CERT_LENGTH], // Adjust the size as needed
    pub alias_cert_length: usize,
}

impl Default for DeviceKeys {
    fn default() -> Self {
        // Initialize the structure with default values
        Self {
            devid_cert: [0; config::MAX_DEVID_CERT_LENGTH],
            devid_cert_length: 0,
            alias_cert: [0; config::MAX_ALIAS_CERT_LENGTH],
            alias_cert_length: 0,
        }
    }
}

impl DeviceKeys {
    pub fn new(devid_cert: &[u8], alias_cert: &[u8]) -> Result<Self, SpdmError> {
        if devid_cert.len() > config::MAX_DEVID_CERT_LENGTH {
            return Err(SpdmError::InvalidParam);
        }
        if alias_cert.len() > config::MAX_ALIAS_CERT_LENGTH {
            return Err(SpdmError::InvalidParam);
        }
        // Initialize the structure with the provided values
        let mut device_keys = DeviceKeys::default();
        device_keys.devid_cert[..devid_cert.len()].copy_from_slice(devid_cert);
        device_keys.devid_cert_length = devid_cert.len();
        device_keys.alias_cert[..alias_cert.len()].copy_from_slice(alias_cert);
        device_keys.alias_cert_length = alias_cert.len();
        Ok(device_keys)
    }
}

pub struct DerCert {
    cert: [u8; config::MAX_DER_CERT_LENGTH], // DER formatted certificate
    length: usize,                           // Length of the certificate DER
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

#[derive(Debug)]
pub enum DeviceCertsMgrError {
    DeviceKeysError,
    RootCertError,
    IntermediateCertError,
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
        // Implementation here
        Ok(())
    }

    fn get_root_ca(&self, root_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        // Reference implementation
        Ok(())
    }

    fn get_intermediate_ca(&self, inter_ca_cert: &mut DerCert) -> Result<(), DeviceCertsMgrError> {
        // Implementation here
        Ok(())
    }

    fn is_root_ca_present(&self) -> bool {
        // Implementation here
        false
    }

    fn is_intermediate_ca_present(&self) -> bool {
        // Implementation here
        false
    }
}
