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
    /// Indicates whether the certificate contains `id-DMTF-hardware-identity` (`1.3.6.1.4.1.412.274.2`).
    pub has_hardware_identity: bool,

    /// Raw DER bytes of hardware identity extension if present.
    pub hardware_identity: Option<Vec<u8>>,

    /// Indicates whether `id-DMTF-mutable-certificate` (`1.3.6.1.4.1.412.274.5`) is present.
    pub is_mutable: bool,

    /// Indicates whether `id-DMTF-device-info` (`1.3.6.1.4.1.412.274.1`) is present
    /// (either via SubjectAltName `otherName` per DSP0274 / `libspdm` or SPDM extension).
    pub has_device_info: bool,

    /// Decoded UTF8String value of `id-DMTF-device-info` from SubjectAltName `otherName`, if present.
    pub device_info: Option<String>,

    /// Indicates whether `id-DMTF-SPDM-extension` (`1.3.6.1.4.1.412.274.6`) wrapper is present.
    pub has_spdm_extension: bool,

    /// Indicates whether ExtendedKeyUsage contains `id-DMTF-eku-responder-auth` (`1.3.6.1.4.1.412.274.3`).
    pub eku_responder_auth: bool,

    /// Indicates whether ExtendedKeyUsage contains `id-DMTF-eku-requester-auth` (`1.3.6.1.4.1.412.274.4`).
    pub eku_requester_auth: bool,
}

impl SpdmExtensions {
    /// Extracts SPDM extensions from a parsed `X509Certificate` following DMTF DSP0274
    /// and `DMTF/libspdm` (`libspdm_crypt_cert.c`).
    pub fn from_x509(cert: &X509Certificate) -> Result<Self> {
        let mut spdm = Self::default();

        for ext in cert.extensions() {
            let oid_str = ext.oid.to_id_string();

            // 1. Check RFC 5280 SubjectAltName (2.5.29.17) for DMTF otherName (1.3.6.1.4.1.412.274.1)
            // Matches `libspdm_get_dmtf_subject_alt_name_from_bytes` in libspdm.
            if oid_str == "2.5.29.17" {
                if let Some(info) = parse_dmtf_san_device_info(ext.value) {
                    spdm.has_device_info = true;
                    if !info.is_empty() {
                        spdm.device_info = Some(info);
                    }
                }
                continue;
            }

            // 2. Check RFC 5280 ExtendedKeyUsage (2.5.29.37) for SPDM EKU OIDs (274.3, 274.4)
            // Matches `libspdm_verify_leaf_cert_spdm_eku` in libspdm.
            if oid_str == "2.5.29.37" {
                parse_spdm_eku(ext.value, &mut spdm);
                continue;
            }

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
                    parse_spdm_extension_oids(ext.value, &mut spdm);
                }
            }
        }

        Ok(spdm)
    }
}

/// Parses `id-DMTF-SPDM-extension` (`1.3.6.1.4.1.412.274.6`) per DSP0274 / `libspdm`:
/// ```asn1
/// id-spdm-cert-oids ::= SEQUENCE SIZE (1..MAX) OF id-spdm-cert-oid
/// id-spdm-cert-oid ::= SEQUENCE {
///     oid OBJECT IDENTIFIER,
///     ...
/// }
/// ```
/// Also accepts bare `OBJECT IDENTIFIER` elements inside the outer `SEQUENCE`.
fn parse_spdm_extension_oids(der: &[u8], spdm: &mut SpdmExtensions) {
    let Ok(tlvs) = asn1::parse_single::<asn1::SequenceOf<asn1::Tlv>>(der) else {
        return;
    };

    for tlv in tlvs {
        if let Ok(oid) = asn1::parse_single::<asn1::ObjectIdentifier>(tlv.full_data()) {
            apply_spdm_oid(&oid, None, spdm);
        } else if let Ok(inner_tlvs) =
            asn1::parse_single::<asn1::SequenceOf<asn1::Tlv>>(tlv.full_data())
        {
            let items: Vec<asn1::Tlv> = inner_tlvs.collect();
            if let Some(first) = items.first() {
                if let Ok(oid) = asn1::parse_single::<asn1::ObjectIdentifier>(first.full_data()) {
                    let rest = items.get(1).map(|v| v.full_data().to_vec());
                    apply_spdm_oid(&oid, rest, spdm);
                }
            }
        }
    }
}

fn apply_spdm_oid(
    oid: &asn1::ObjectIdentifier,
    raw_value: Option<Vec<u8>>,
    spdm: &mut SpdmExtensions,
) {
    if *oid == OID_DMTF_SPDM_HARDWARE_IDENTITY {
        spdm.has_hardware_identity = true;
        if spdm.hardware_identity.is_none() {
            spdm.hardware_identity = raw_value;
        }
    } else if *oid == OID_DMTF_SPDM_MUTABLE_CERTIFICATE {
        spdm.is_mutable = true;
    } else if *oid == OID_DMTF_SPDM_DEVICE_INFO {
        spdm.has_device_info = true;
    }
}

/// Parses `SubjectAltName` (`2.5.29.17`) `GeneralNames` for DMTF `otherName [0]`
/// with `type-id = 1.3.6.1.4.1.412.274.1` (`id-DMTF-device-info`) and `[0] EXPLICIT UTF8String`.
/// Matches `libspdm_get_dmtf_subject_alt_name_from_bytes` in `DMTF/libspdm`.
fn parse_dmtf_san_device_info(der: &[u8]) -> Option<String> {
    let tlvs = asn1::parse_single::<asn1::SequenceOf<asn1::Tlv>>(der).ok()?;
    for tlv in tlvs {
        // otherName is [0] IMPLICIT SEQUENCE (context-specific constructed tag 0 = 0xA0)
        if tlv.tag().as_u8() == Some(0xA0) {
            let res: asn1::ParseResult<Option<String>> = asn1::parse(tlv.data(), |other| {
                let oid = other.read_element::<asn1::ObjectIdentifier>()?;
                let mut found = None;
                if oid == OID_DMTF_SPDM_DEVICE_INFO && !other.is_empty() {
                    let val_tlv = other.read_element::<asn1::Tlv>()?;
                    // [0] EXPLICIT UTF8String (tag 0xA0)
                    if val_tlv.tag().as_u8() == Some(0xA0) {
                        if let Ok(s) = asn1::parse_single::<asn1::Utf8String>(val_tlv.data()) {
                            found = Some(s.as_str().to_string());
                        } else {
                            found = Some(String::new());
                        }
                    }
                }
                while !other.is_empty() {
                    let _ = other.read_element::<asn1::Tlv>()?;
                }
                Ok(found)
            });
            if let Ok(Some(info)) = res {
                return Some(info);
            }
        }
    }
    None
}

/// Parses `ExtendedKeyUsage` (`2.5.29.37`) `SEQUENCE OF OBJECT IDENTIFIER` for SPDM EKU OIDs.
/// Matches `libspdm_verify_leaf_cert_spdm_eku` in `DMTF/libspdm`.
fn parse_spdm_eku(der: &[u8], spdm: &mut SpdmExtensions) {
    if let Ok(oids) = asn1::parse_single::<asn1::SequenceOf<asn1::ObjectIdentifier>>(der) {
        for oid in oids {
            if oid == OID_DMTF_SPDM_EKU_RESPONDER_AUTH {
                spdm.eku_responder_auth = true;
            } else if oid == OID_DMTF_SPDM_EKU_REQUESTER_AUTH {
                spdm.eku_requester_auth = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libspdm_spdm_extension_sequence_of_sequence() {
        // id-spdm-cert-oids ::= SEQUENCE {
        //   SEQUENCE { 1.3.6.1.4.1.412.274.2 },
        //   SEQUENCE { 1.3.6.1.4.1.412.274.5 }
        // }
        let der = [
            0x30, 0x1C, // outer SEQUENCE
            0x30, 0x0C, // id-spdm-cert-oid #1
            0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x02, 0x30,
            0x0C, // id-spdm-cert-oid #2
            0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x05,
        ];
        let mut spdm = SpdmExtensions::default();
        parse_spdm_extension_oids(&der, &mut spdm);
        assert!(spdm.has_hardware_identity);
        assert!(spdm.is_mutable);
    }

    #[test]
    fn test_libspdm_dmtf_san_device_info() {
        // GeneralNames ::= SEQUENCE {
        //   otherName [0] IMPLICIT SEQUENCE {
        //     type-id OBJECT IDENTIFIER (1.3.6.1.4.1.412.274.1),
        //     value [0] EXPLICIT UTF8String ("ChipsAlliance:Caliptra:01")
        //   }
        // }
        let info_str = b"ChipsAlliance:Caliptra:01";
        let mut der = vec![
            0x30,
            (2 + 12 + 2 + 2 + info_str.len()) as u8, // GeneralNames SEQUENCE
            0xA0,
            (12 + 2 + 2 + info_str.len()) as u8, // otherName [0] IMPLICIT
            0x06,
            0x0A,
            0x2B,
            0x06,
            0x01,
            0x04,
            0x01,
            0x83,
            0x1C,
            0x82,
            0x12,
            0x01, // 1.3.6.1.4.1.412.274.1
            0xA0,
            (2 + info_str.len()) as u8, // [0] EXPLICIT
            0x0C,
            info_str.len() as u8, // UTF8String
        ];
        der.extend_from_slice(info_str);

        let parsed = parse_dmtf_san_device_info(&der);
        assert_eq!(parsed.as_deref(), Some("ChipsAlliance:Caliptra:01"));
    }

    #[test]
    fn test_libspdm_spdm_eku() {
        // ExtendedKeyUsage ::= SEQUENCE {
        //   1.3.6.1.4.1.412.274.3 (responder auth),
        //   1.3.6.1.4.1.412.274.4 (requester auth)
        // }
        let der = [
            0x30, 0x18, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x03,
            0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x04,
        ];
        let mut spdm = SpdmExtensions::default();
        parse_spdm_eku(&der, &mut spdm);
        assert!(spdm.eku_responder_auth);
        assert!(spdm.eku_requester_auth);
    }
}
