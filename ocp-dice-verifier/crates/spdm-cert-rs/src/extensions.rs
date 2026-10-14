// Licensed under the Apache-2.0 license

//! DMTF SPDM X.509 Certificate Extensions decoder.
//!
//! Defined in DMTF DSP0274.

use crate::error::Result;
use crate::oids::*;
use x509_parser::certificate::X509Certificate;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SpdmExtensions {
    /// Indicates whether the certificate contains `id-DMTF-hardware-identity`.
    pub has_hardware_identity: bool,

    /// Raw DER bytes of hardware identity extension if present.
    pub hardware_identity: Option<Vec<u8>>,

    /// Indicates whether `id-DMTF-mutable-certificate` is present.
    pub is_mutable: bool,

    /// Indicates whether `id-DMTF-device-info` is present.
    pub has_device_info: bool,

    /// Indicates whether `id-DMTF-SPDM-extension` wrapper is present.
    pub has_spdm_extension: bool,
}

impl SpdmExtensions {
    /// Extracts SPDM extensions from a parsed `X509Certificate`.
    pub fn from_x509(cert: &X509Certificate) -> Result<Self> {
        let mut spdm = Self::default();

        // SPDM OID DER byte patterns for scanning inside id-DMTF-SPDM-extension
        let hw_id_der = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x02];
        let mutable_der = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x05];
        let dev_info_der = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01];

        for ext in cert.extensions() {
            let oid_str = ext.oid.to_id_string();
            if let Some(oid) = asn1::ObjectIdentifier::from_string(&oid_str) {
                if oid == OID_DMTF_SPDM_HARDWARE_IDENTITY {
                    spdm.has_hardware_identity = true;
                    spdm.hardware_identity = Some(ext.value.to_vec());
                } else if oid == OID_DMTF_SPDM_MUTABLE_CERTIFICATE {
                    spdm.is_mutable = true;
                } else if oid == OID_DMTF_SPDM_DEVICE_INFO {
                    spdm.has_device_info = true;
                } else if oid == OID_DMTF_SPDM_EXTENSION {
                    spdm.has_spdm_extension = true;
                    // Scan inside id-DMTF-SPDM-extension wrapper
                    if ext.value.windows(hw_id_der.len()).any(|w| w == hw_id_der) {
                        spdm.has_hardware_identity = true;
                    }
                    if ext
                        .value
                        .windows(mutable_der.len())
                        .any(|w| w == mutable_der)
                    {
                        spdm.is_mutable = true;
                    }
                    if ext
                        .value
                        .windows(dev_info_der.len())
                        .any(|w| w == dev_info_der)
                    {
                        spdm.has_device_info = true;
                    }
                }
            }
        }

        Ok(spdm)
    }
}
