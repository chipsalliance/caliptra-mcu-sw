// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Context, Result};
use caliptra_auth_man_types::{AuthManifestFlags, AuthManifestPreamble, AuthorizationManifest};
use caliptra_image_crypto::RustCrypto as Crypto;
use caliptra_image_gen::{from_hw_format, to_hw_format, ImageGeneratorCrypto};
use caliptra_image_types::{
    ImageEccPubKey, ImageEccSignature, ImageLmsPublicKey, ImageLmsSignature, ImageMldsaPubKey,
    ImageMldsaSignature, ImagePqcSignature,
};
use openssl::{
    pkey::Public,
    pkey_ctx::PkeyCtx,
    pkey_ml_dsa::{PKeyMlDsaBuilder, Variant},
    signature::Signature as OsslSignature,
};
use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::path::Path;
use zerocopy::{FromBytes, IntoBytes};

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

fn sha384_hex(data: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate a `SigningRequestJson` containing SHA-384 targets and hex payloads from an unsigned `AuthorizationManifest`.
pub fn create_signing_request(
    manifest: &caliptra_auth_man_types::AuthorizationManifest,
) -> Result<SigningRequestJson> {
    let preamble_bytes = manifest.preamble.as_bytes();

    let vendor_range = AuthManifestPreamble::vendor_signed_data_range();
    let vendor_payload = preamble_bytes
        .get(vendor_range.start as usize..vendor_range.end as usize)
        .ok_or_else(|| anyhow!("Invalid vendor signed data range"))?;
    let vendor_digest = sha384_hex(vendor_payload);

    let owner_range = AuthManifestPreamble::owner_pub_keys_range();
    let owner_payload = preamble_bytes
        .get(owner_range.start as usize..owner_range.end as usize)
        .ok_or_else(|| anyhow!("Invalid owner pub keys range"))?;
    let owner_digest = sha384_hex(owner_payload);

    let imc_payload = manifest.image_metadata_col.as_bytes();
    let imc_digest = sha384_hex(imc_payload);

    Ok(SigningRequestJson {
        version: 1,
        requests: SigningRequests {
            vendor_pub_keys_signatures: SignatureRequestEntry {
                ecc_key: "vendor_fw_ecc_key".to_string(),
                pqc_key: "vendor_fw_pqc_key".to_string(),
                digest_sha384: vendor_digest,
                payload_hex: hex::encode(vendor_payload),
            },
            owner_pub_keys_signatures: SignatureRequestEntry {
                ecc_key: "owner_fw_ecc_key".to_string(),
                pqc_key: "owner_fw_pqc_key".to_string(),
                digest_sha384: owner_digest,
                payload_hex: hex::encode(owner_payload),
            },
            vendor_imc_signatures: SignatureRequestEntry {
                ecc_key: "vendor_man_ecc_key".to_string(),
                pqc_key: "vendor_man_pqc_key".to_string(),
                digest_sha384: imc_digest.clone(),
                payload_hex: hex::encode(imc_payload),
            },
            owner_imc_signatures: SignatureRequestEntry {
                ecc_key: "owner_man_ecc_key".to_string(),
                pqc_key: "owner_man_pqc_key".to_string(),
                digest_sha384: imc_digest,
                payload_hex: hex::encode(imc_payload),
            },
        },
    })
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
        // TODO(timothytrippel): Cryptographically verify PQC signatures (LMS / ML-DSA-87).
        Ok(())
    }
}
/// Perform cryptographic verification of an ECDSA P-384 signature over a 48-byte digest against an `ImageEccPubKey`.
pub fn verify_ecdsa384_signature(
    digest: &[u8; 48],
    pub_key: &ImageEccPubKey,
    sig: &ImageEccSignature,
) -> Result<()> {
    let x_bytes: [u8; 48] = from_hw_format(&pub_key.x);
    let y_bytes: [u8; 48] = from_hw_format(&pub_key.y);

    let mut encoded_point = [0u8; 97];
    encoded_point[0] = 0x04;
    encoded_point[1..49].copy_from_slice(&x_bytes);
    encoded_point[49..97].copy_from_slice(&y_bytes);

    let verifying_key = VerifyingKey::from_sec1_bytes(&encoded_point)
        .map_err(|e| anyhow!("Failed to parse public key for verification: {}", e))?;

    let r_bytes: [u8; 48] = from_hw_format(&sig.r);
    let s_bytes: [u8; 48] = from_hw_format(&sig.s);

    let mut sig_bytes = [0u8; 96];
    sig_bytes[..48].copy_from_slice(&r_bytes);
    sig_bytes[48..].copy_from_slice(&s_bytes);

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("Failed to parse signature bytes for verification: {}", e))?;

    verifying_key
        .verify_prehash(digest, &signature)
        .map_err(|e| anyhow!("ECDSA P-384 signature verification failed: {}", e))
}

/// Perform cryptographic verification of an LMS signature over a 48-byte digest against an `ImageLmsPublicKey`.
pub fn verify_lms_signature(
    _digest: &[u8; 48],
    _pub_key: &ImageLmsPublicKey,
    _sig: &ImageLmsSignature,
) -> Result<()> {
    eprintln!("WARNING: LMS signature cryptographic verification is not yet implemented.");
    // TODO(timothytrippel): Cryptographically verify LMS signatures.
    Ok(())
}

/// Perform cryptographic verification of an ML-DSA-87 signature over a message against an `ImageMldsaPubKey`.
pub fn verify_mldsa_signature(
    msg: &[u8],
    pub_key: &ImageMldsaPubKey,
    sig: &ImageMldsaSignature,
) -> Result<()> {
    let builder = PKeyMlDsaBuilder::<Public>::new(Variant::MlDsa87, pub_key.0.as_bytes(), None)?;
    let pkey = builder.build()?;
    let mut algo = OsslSignature::for_ml_dsa(Variant::MlDsa87)?;
    let mut ctx = PkeyCtx::new(&pkey)?;
    ctx.verify_message_init(&mut algo)?;
    match ctx.verify(msg, &sig.0.as_bytes()[..4627]) {
        Ok(true) => Ok(()),
        _ => anyhow::bail!("ML-DSA-87 signature verification failed against ImageMldsaPubKey"),
    }
}

/// Attach signatures from a `SignaturesJson` file to an unsigned authorization manifest binary, verify all signatures, and save the resulting `signed_auth_manifest.bin`.
pub fn attach_auth_manifest_signatures(
    unsigned_manifest_path: &Path,
    signatures_path: &Path,
    vendor_fw_pub_key_path: Option<&Path>,
    owner_fw_pub_key_path: Option<&Path>,
    output_path: &Path,
) -> Result<()> {
    // Load unsigned manifest.
    let manifest_bytes = std::fs::read(unsigned_manifest_path).with_context(|| {
        format!(
            "Failed to read unsigned manifest file {}",
            unsigned_manifest_path.display()
        )
    })?;
    let mut manifest = AuthorizationManifest::read_from_bytes(&manifest_bytes)
        .map_err(|e| anyhow!("Failed to parse unsigned manifest: {:?}", e))?;

    // Load signatures.
    let sig_file_content = std::fs::read_to_string(signatures_path).with_context(|| {
        format!(
            "Failed to read signatures file {}",
            signatures_path.display()
        )
    })?;
    let sigs_json: SignaturesJson = serde_json::from_str(&sig_file_content).with_context(|| {
        format!(
            "Failed to parse signatures JSON file {}",
            signatures_path.display()
        )
    })?;

    let flags = AuthManifestFlags::from(manifest.preamble.flags);
    let vendor_sig_required = flags.contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);

    // Vendor Pub Keys Signatures (signed by Vendor FW Root key over Vendor Manifest Public Keys)
    if let Some(entry) = &sigs_json.vendor_pub_keys_signatures {
        if let Some(ecc_hex) = &entry.ecc_sig {
            manifest.preamble.vendor_pub_keys_signatures.ecc_sig =
                ImageEccSignature::try_from_hex(ecc_hex)?;
        }
        if let Some(pqc_hex) = &entry.pqc_sig {
            let pqc_sig = ImagePqcSignature::try_from_hex(pqc_hex)?;
            pqc_sig
                .verify()
                .context("Vendor public keys PQC signature verification failed")?;
            manifest.preamble.vendor_pub_keys_signatures.pqc_sig = pqc_sig;
        }

        if let Some(vendor_fw_pub_path) = vendor_fw_pub_key_path {
            let vendor_fw_pub = Crypto::ecc_pub_key_from_pem(vendor_fw_pub_path)?;
            let vendor_range = AuthManifestPreamble::vendor_signed_data_range();
            let vendor_data = manifest
                .preamble
                .as_bytes()
                .get(vendor_range.start as usize..vendor_range.end as usize)
                .ok_or_else(|| anyhow!("Invalid vendor signed data range"))?;
            let digest: [u8; 48] = sha2::Sha384::digest(vendor_data).into();
            verify_ecdsa384_signature(
                &digest,
                &vendor_fw_pub,
                &manifest.preamble.vendor_pub_keys_signatures.ecc_sig,
            )
            .context(
                "Vendor public keys signature verification failed against provided vendor FW key",
            )?;
        }
    }

    // Owner Pub Keys Signatures (signed by Owner FW Root key over Owner Manifest Public Keys)
    let owner_pub_sigs = sigs_json
        .owner_pub_keys_signatures
        .as_ref()
        .ok_or_else(|| anyhow!("owner_pub_keys_signatures is required in signatures JSON"))?;
    let ecc_hex = owner_pub_sigs
        .ecc_sig
        .as_ref()
        .ok_or_else(|| anyhow!("ecc_sig is required in owner_pub_keys_signatures"))?;
    let pqc_hex = owner_pub_sigs
        .pqc_sig
        .as_ref()
        .ok_or_else(|| anyhow!("pqc_sig is required in owner_pub_keys_signatures"))?;

    manifest.preamble.owner_pub_keys_signatures.ecc_sig = ImageEccSignature::try_from_hex(ecc_hex)?;
    let pqc_sig = ImagePqcSignature::try_from_hex(pqc_hex)?;
    pqc_sig
        .verify()
        .context("Owner public keys PQC signature verification failed")?;
    manifest.preamble.owner_pub_keys_signatures.pqc_sig = pqc_sig;

    if let Some(owner_fw_pub_path) = owner_fw_pub_key_path {
        let owner_fw_pub = Crypto::ecc_pub_key_from_pem(owner_fw_pub_path)?;
        let owner_data = manifest.preamble.owner_pub_keys.as_bytes();
        let digest: [u8; 48] = sha2::Sha384::digest(owner_data).into();
        verify_ecdsa384_signature(
            &digest,
            &owner_fw_pub,
            &manifest.preamble.owner_pub_keys_signatures.ecc_sig,
        )
        .context("Owner public keys signature verification failed against provided owner FW key")?;
    }

    // IMC Digest for Manifest key verification
    let imc_data = manifest.image_metadata_col.as_bytes();
    let imc_digest: [u8; 48] = sha2::Sha384::digest(imc_data).into();

    // Vendor IMC Signatures (signed by Vendor Manifest key; verified against embedded
    // Vendor Manifest Public Key: `preamble.vendor_pub_keys`)
    if let Some(entry) = &sigs_json.vendor_imc_signatures {
        let ecc_hex = entry
            .ecc_sig
            .as_ref()
            .ok_or_else(|| anyhow!("ecc_sig is required in vendor_imc_signatures"))?;
        let pqc_hex = entry
            .pqc_sig
            .as_ref()
            .ok_or_else(|| anyhow!("pqc_sig is required in vendor_imc_signatures"))?;

        manifest.preamble.vendor_image_metdata_signatures.ecc_sig =
            ImageEccSignature::try_from_hex(ecc_hex)?;
        let pqc_sig = ImagePqcSignature::try_from_hex(pqc_hex)?;
        pqc_sig
            .verify()
            .context("Vendor IMC PQC signature verification failed")?;
        manifest.preamble.vendor_image_metdata_signatures.pqc_sig = pqc_sig;

        verify_ecdsa384_signature(
            &imc_digest,
            &manifest.preamble.vendor_pub_keys.ecc_pub_key,
            &manifest.preamble.vendor_image_metdata_signatures.ecc_sig,
        )
        .context("Vendor IMC signature verification failed against embedded vendor manifest key")?;
    } else if vendor_sig_required {
        anyhow::bail!("vendor_imc_signatures is required in signatures JSON when VENDOR_SIGNATURE_REQUIRED flag is set");
    }

    // Owner IMC Signatures (signed by Owner Manifest key; verified against embedded
    // Owner Manifest Public Key: `preamble.owner_pub_keys`)
    let owner_imc_sigs = sigs_json
        .owner_imc_signatures
        .as_ref()
        .ok_or_else(|| anyhow!("owner_imc_signatures is required in signatures JSON"))?;
    let ecc_hex = owner_imc_sigs
        .ecc_sig
        .as_ref()
        .ok_or_else(|| anyhow!("ecc_sig is required in owner_imc_signatures"))?;
    let pqc_hex = owner_imc_sigs
        .pqc_sig
        .as_ref()
        .ok_or_else(|| anyhow!("pqc_sig is required in owner_imc_signatures"))?;

    manifest.preamble.owner_image_metdata_signatures.ecc_sig =
        ImageEccSignature::try_from_hex(ecc_hex)?;
    let pqc_sig = ImagePqcSignature::try_from_hex(pqc_hex)?;
    pqc_sig
        .verify()
        .context("Owner IMC PQC signature verification failed")?;
    manifest.preamble.owner_image_metdata_signatures.pqc_sig = pqc_sig;

    verify_ecdsa384_signature(
        &imc_digest,
        &manifest.preamble.owner_pub_keys.ecc_pub_key,
        &manifest.preamble.owner_image_metdata_signatures.ecc_sig,
    )
    .context("Owner IMC signature verification failed against embedded owner manifest key")?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, manifest.as_bytes())?;
    Ok(())
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
