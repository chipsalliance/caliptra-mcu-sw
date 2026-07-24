// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Context, Result};
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::{ImageEccSignature, ImagePqcSignature};
use p384::ecdsa::Signature;
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

/// Request payload containing signature targets to be signed offline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningRequestJson {
    pub version: u32,
    pub requests: SigningRequests,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningRequests {
    pub vendor_pub_keys_signatures: SignatureRequestEntry,
    pub owner_pub_keys_signatures: SignatureRequestEntry,
    pub vendor_imc_signatures: SignatureRequestEntry,
    pub owner_imc_signatures: SignatureRequestEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureRequestEntry {
    pub ecc_key: String,
    pub pqc_key: String,
    pub digest_sha384: String,
    pub payload_hex: String,
}

/// Signatures payload returned from offline signing workstation / HSM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SignaturesJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_pub_keys_signatures: Option<SignatureEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_pub_keys_signatures: Option<SignatureEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_imc_signatures: Option<SignatureEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_imc_signatures: Option<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SignatureEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pqc_sig: Option<String>,
}

pub trait ImageEccSignatureExt: Sized {
    /// Convert an ECDSA signature string (raw 96-byte hex R||S or ASN.1 DER hex) into `ImageEccSignature`.
    fn try_from_hex(hex_str: &str) -> Result<Self>;
}

impl ImageEccSignatureExt for ImageEccSignature {
    fn try_from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("Failed to decode hex ECDSA signature")?;

        let (r_bytes, s_bytes) = if bytes.len() == 96 {
            // Raw R || S format (48 bytes R, 48 bytes S)
            let mut r = [0u8; 48];
            let mut s = [0u8; 48];
            r.copy_from_slice(&bytes[..48]);
            s.copy_from_slice(&bytes[48..]);
            (r, s)
        } else {
            // Parse ASN.1 DER encoding
            let parsed_sig = Signature::from_der(&bytes)
                .map_err(|e| anyhow!("Failed to parse ASN.1 DER ECDSA signature: {}", e))?;
            let r_raw = parsed_sig.r().to_bytes();
            let s_raw = parsed_sig.s().to_bytes();

            let r: [u8; 48] = r_raw.into();
            let s: [u8; 48] = s_raw.into();
            (r, s)
        };

        Ok(ImageEccSignature {
            r: to_hw_format(&r_bytes),
            s: to_hw_format(&s_bytes),
        })
    }
}

pub trait ImagePqcSignatureExt: Sized {
    /// Convert a PQC signature hex string into `ImagePqcSignature`.
    fn try_from_hex(hex_str: &str) -> Result<Self>;

    /// Perform pre-flight verification of an `ImagePqcSignature` structure.
    fn verify(&self) -> Result<()>;
}

impl ImagePqcSignatureExt for ImagePqcSignature {
    fn try_from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("Failed to decode hex PQC signature")?;
        if bytes.is_empty() {
            return Err(anyhow!("PQC signature hex string cannot be empty"));
        }
        let mut pqc_sig = ImagePqcSignature::default();
        let max_size = pqc_sig.0.as_bytes().len();
        if bytes.len() > max_size {
            return Err(anyhow!(
                "PQC signature length {} exceeds maximum size {}",
                bytes.len(),
                max_size
            ));
        }
        if bytes.len() != 2420 && bytes.len() != 4627 {
            return Err(anyhow!(
                "Invalid PQC signature length {} (expected LMS 2420 bytes or ML-DSA-87 4627 bytes)",
                bytes.len()
            ));
        }
        pqc_sig.0[..bytes.len()].copy_from_slice(&bytes);
        Ok(pqc_sig)
    }

    fn verify(&self) -> Result<()> {
        let bytes = self.0.as_bytes();
        if bytes.iter().all(|&b| b == 0) {
            return Err(anyhow!("PQC signature cannot be zero-filled"));
        }
        let non_zero_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        if non_zero_len != 2420 && non_zero_len != 4627 {
            return Err(anyhow!(
                "Invalid PQC signature payload size {} (expected LMS 2420 bytes or ML-DSA-87 4627 bytes)",
                non_zero_len
            ));
        }
        // TODO(timothytrippel): cryptographically verify the PQ signatures.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_request_json_serde() {
        let json_str = r#"{
            "version": 1,
            "requests": {
                "vendor_pub_keys_signatures": {
                    "ecc_key": "vendor_fw_ecc_key",
                    "pqc_key": "vendor_fw_pqc_key",
                    "digest_sha384": "aabbcc",
                    "payload_hex": "112233"
                },
                "owner_pub_keys_signatures": {
                    "ecc_key": "owner_fw_ecc_key",
                    "pqc_key": "owner_fw_pqc_key",
                    "digest_sha384": "ddeeff",
                    "payload_hex": "445566"
                },
                "vendor_imc_signatures": {
                    "ecc_key": "vendor_man_ecc_key",
                    "pqc_key": "vendor_man_pqc_key",
                    "digest_sha384": "001122",
                    "payload_hex": "778899"
                },
                "owner_imc_signatures": {
                    "ecc_key": "owner_man_ecc_key",
                    "pqc_key": "owner_man_pqc_key",
                    "digest_sha384": "334455",
                    "payload_hex": "aabbcc"
                }
            }
        }"#;

        let req: SigningRequestJson = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.version, 1);
        assert_eq!(
            req.requests.vendor_pub_keys_signatures.ecc_key,
            "vendor_fw_ecc_key"
        );
        assert_eq!(
            req.requests.vendor_pub_keys_signatures.digest_sha384,
            "aabbcc"
        );

        let serialized = serde_json::to_string(&req).unwrap();
        let req_deser: SigningRequestJson = serde_json::from_str(&serialized).unwrap();
        assert_eq!(req, req_deser);
    }

    #[test]
    fn test_signatures_json_serde() {
        let json_str = r#"{
            "vendor_pub_keys_signatures": {
                "ecc_sig": "aabbcc"
            },
            "owner_pub_keys_signatures": {
                "ecc_sig": "ddeeff",
                "pqc_sig": "123456"
            }
        }"#;

        let sigs: SignaturesJson = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            sigs.vendor_pub_keys_signatures.as_ref().unwrap().ecc_sig,
            Some("aabbcc".to_string())
        );
        assert!(sigs
            .vendor_pub_keys_signatures
            .as_ref()
            .unwrap()
            .pqc_sig
            .is_none());
        assert_eq!(
            sigs.owner_pub_keys_signatures.as_ref().unwrap().pqc_sig,
            Some("123456".to_string())
        );
    }

    #[test]
    fn test_parse_ecc_signature_raw() {
        let raw_hex = "01".repeat(48) + &"02".repeat(48);
        let sig = ImageEccSignature::try_from_hex(&raw_hex).unwrap();
        assert_eq!(sig.r[0], 0x01010101);
        assert_eq!(sig.s[0], 0x02020202);
    }

    #[test]
    fn test_parse_ecc_signature_invalid() {
        assert!(ImageEccSignature::try_from_hex("not_a_hex").is_err());
        assert!(ImageEccSignature::try_from_hex("1234").is_err());
    }

    #[test]
    fn test_parse_ecc_signature_der() {
        let r_bytes = [1u8; 48];
        let s_bytes = [2u8; 48];
        let sig = Signature::from_scalars(r_bytes, s_bytes).unwrap();
        let der = sig.to_der();
        let der_hex = hex::encode(der.as_bytes());
        let parsed_sig = ImageEccSignature::try_from_hex(&der_hex).unwrap();
        assert_eq!(parsed_sig.r[0], 0x01010101);
        assert_eq!(parsed_sig.s[0], 0x02020202);
    }

    #[test]
    fn test_parse_pqc_signature() {
        let lms_sig_hex = "aa".repeat(2420);
        let sig = ImagePqcSignature::try_from_hex(&lms_sig_hex).unwrap();
        assert_eq!(sig.0[0], 0xaa);

        assert!(ImagePqcSignature::try_from_hex("").is_err());
        assert!(ImagePqcSignature::try_from_hex("aabbccdd").is_err());
    }

    #[test]
    fn test_verify_pqc_signature() {
        let lms_sig_hex = "aa".repeat(2420);
        let sig = ImagePqcSignature::try_from_hex(&lms_sig_hex).unwrap();
        assert!(sig.verify().is_ok());

        let empty_sig = ImagePqcSignature::default();
        assert!(empty_sig.verify().is_err());
    }
}
