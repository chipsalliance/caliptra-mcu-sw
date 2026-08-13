// Licensed under the Apache-2.0 license

use anyhow::{anyhow, Context, Result};
use caliptra_image_crypto::{lms_priv_key_from_pem, OsslCrypto};
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_mcu_builder::offline_signing::{SignatureEntry, SignaturesJson, SigningRequestJson};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zerocopy::IntoBytes;

/// Key manifest entry specifying key file paths or OpenSSL provider key names for a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManifestEntry {
    /// Path or OpenSSL provider key name for ECC P-384 private key.
    pub ecc_priv_key: String,
    /// Path or OpenSSL provider key name for ECC P-384 public key.
    pub ecc_pub_key: String,
    /// Path or OpenSSL provider key name for PQC private key (LMS or ML-DSA).
    pub pqc_priv_key: String,
    /// Optional path or OpenSSL provider key name for PQC public key (required for ML-DSA).
    pub pqc_pub_key: Option<String>,
    /// PQC algorithm type: "LMS" or "MLDSA" (case-insensitive).
    pub pqc_type: String,
}

/// Key manifest JSON file structure containing signing keys for all authorization manifest components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManifest {
    pub vendor_fw: KeyManifestEntry,
    pub owner_fw: KeyManifestEntry,
    pub vendor_man: KeyManifestEntry,
    pub owner_man: KeyManifestEntry,
}

/// Sign a 48-byte hex digest using an ECC P-384 private and public key via `ImageGeneratorCrypto` (`OsslCrypto`).
pub fn sign_ecc(digest_hex: &str, priv_key_path: &Path, pub_key_path: &Path) -> Result<String> {
    let digest_bytes = hex::decode(digest_hex.trim()).context("Invalid digest hex string")?;
    let digest: caliptra_image_types::ImageDigest384 =
        caliptra_image_gen::to_hw_format(&digest_bytes);
    let priv_key = OsslCrypto::ecc_priv_key_from_pem(priv_key_path)?;
    let pub_key = OsslCrypto::ecc_pub_key_from_pem(pub_key_path)?;
    let crypto = OsslCrypto::default();
    let sig = ImageGeneratorCrypto::ecdsa384_sign(&crypto, &digest, &priv_key, &pub_key)?;
    let mut raw = [0u8; 96];
    raw[..48].copy_from_slice(&caliptra_image_gen::from_hw_format(&sig.r));
    raw[48..].copy_from_slice(&caliptra_image_gen::from_hw_format(&sig.s));
    Ok(hex::encode(raw))
}

/// Sign a 48-byte hex digest using an LMS private key PEM file via `ImageGeneratorCrypto` (`OsslCrypto`).
pub fn sign_lms(digest_hex: &str, priv_key_path: &Path) -> Result<String> {
    let digest_bytes = hex::decode(digest_hex.trim()).context("Invalid digest hex string")?;
    let digest: caliptra_image_types::ImageDigest384 =
        caliptra_image_gen::to_hw_format(&digest_bytes);
    let lms_priv_key = lms_priv_key_from_pem(&priv_key_path.to_path_buf())?;
    let crypto = OsslCrypto::default();
    let lms_sig = ImageGeneratorCrypto::lms_sign(&crypto, &digest, &lms_priv_key)?;
    Ok(hex::encode(lms_sig.as_bytes()))
}

/// Sign a hex payload message using an ML-DSA-87 private and public key PEM file via `ImageGeneratorCrypto` (`OsslCrypto`).
pub fn sign_mldsa(msg_hex: &str, priv_key_path: &Path, pub_key_path: &Path) -> Result<String> {
    let msg_bytes = hex::decode(msg_hex.trim()).context("Invalid message hex string")?;
    let priv_key = OsslCrypto::mldsa_priv_key_from_file(priv_key_path)?;
    let pub_key = OsslCrypto::mldsa_pub_key_from_file(pub_key_path)?;
    let crypto = OsslCrypto::default();
    let mldsa_sig = ImageGeneratorCrypto::mldsa_sign(&crypto, &msg_bytes, &priv_key, &pub_key)?;
    Ok(hex::encode(mldsa_sig.as_bytes()))
}

fn sign_entry(
    digest_sha384: &str,
    payload_hex: &str,
    entry: &KeyManifestEntry,
) -> Result<SignatureEntry> {
    let ecc_sig = sign_ecc(
        digest_sha384,
        Path::new(&entry.ecc_priv_key),
        Path::new(&entry.ecc_pub_key),
    )?;

    let pqc_sig = match entry.pqc_type.to_uppercase().as_str() {
        "LMS" => sign_lms(digest_sha384, Path::new(&entry.pqc_priv_key))?,
        "MLDSA" | "ML-DSA" | "MLDSA87" | "ML-DSA-87" => {
            let pub_path = entry
                .pqc_pub_key
                .as_ref()
                .ok_or_else(|| anyhow!("pqc_pub_key required for MLDSA signing"))?;
            sign_mldsa(
                payload_hex,
                Path::new(&entry.pqc_priv_key),
                Path::new(pub_path),
            )?
        }
        other => anyhow::bail!(
            "Unsupported or invalid PQC algorithm type '{}' (expected 'LMS' or 'MLDSA')",
            other
        ),
    };

    Ok(SignatureEntry {
        ecc_sig: Some(ecc_sig),
        pqc_sig: Some(pqc_sig),
    })
}

/// Parse `signing_request.json`, sign each target digest with the keys in `KeyManifest`, and write `signatures.json`.
pub fn generate_offline_signatures(
    signing_request_path: &Path,
    key_manifest: &KeyManifest,
    output_signatures_path: &Path,
) -> Result<SignaturesJson> {
    let req_content = std::fs::read_to_string(signing_request_path).with_context(|| {
        format!(
            "Failed to read signing request {}",
            signing_request_path.display()
        )
    })?;
    let req: SigningRequestJson = serde_json::from_str(&req_content)?;

    let vendor_pub_keys_signatures = Some(sign_entry(
        &req.requests.vendor_pub_keys_signatures.digest_sha384,
        &req.requests.vendor_pub_keys_signatures.payload_hex,
        &key_manifest.vendor_fw,
    )?);

    let owner_pub_keys_signatures = Some(sign_entry(
        &req.requests.owner_pub_keys_signatures.digest_sha384,
        &req.requests.owner_pub_keys_signatures.payload_hex,
        &key_manifest.owner_fw,
    )?);

    let vendor_imc_signatures = Some(sign_entry(
        &req.requests.vendor_imc_signatures.digest_sha384,
        &req.requests.vendor_imc_signatures.payload_hex,
        &key_manifest.vendor_man,
    )?);

    let owner_imc_signatures = Some(sign_entry(
        &req.requests.owner_imc_signatures.digest_sha384,
        &req.requests.owner_imc_signatures.payload_hex,
        &key_manifest.owner_man,
    )?);

    let sigs_json = SignaturesJson {
        vendor_pub_keys_signatures,
        owner_pub_keys_signatures,
        vendor_imc_signatures,
        owner_imc_signatures,
    };

    let formatted_json = serde_json::to_string_pretty(&sigs_json)?;
    if let Some(parent) = output_signatures_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_signatures_path, formatted_json)?;
    Ok(sigs_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_image_fake_keys::{
        VENDOR_LMS_KEY_0_PRIVATE, VENDOR_LMS_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
        VENDOR_MLDSA_KEY_0_PUBLIC,
    };
    use caliptra_image_types::{ImageEccSignature, ImageLmsSignature, ImageMldsaSignature};
    use caliptra_mcu_builder::offline_signing::{
        verify_ecdsa384_signature, verify_lms_signature, verify_mldsa_signature,
        ImageEccSignatureExt,
    };
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use std::path::PathBuf;
    use tempfile::{NamedTempFile, TempDir};
    use zerocopy::FromBytes;

    struct TestKeyFiles {
        _dir: TempDir,
        vendor_ecc_priv: PathBuf,
        vendor_ecc_pub: PathBuf,
        owner_ecc_priv: PathBuf,
        owner_ecc_pub: PathBuf,
        vendor_man_priv: PathBuf,
        vendor_man_pub: PathBuf,
        lms_priv: PathBuf,
        mldsa_priv: PathBuf,
        mldsa_pub: PathBuf,
    }

    impl TestKeyFiles {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (vendor_ecc_priv, vendor_ecc_pub) = write_ecc_key_pair(&dir, "vendor");
            let (owner_ecc_priv, owner_ecc_pub) = write_ecc_key_pair(&dir, "owner");
            let (vendor_man_priv, vendor_man_pub) = write_ecc_key_pair(&dir, "vendor-manifest");

            let lms_priv = dir.path().join("vendor-lms-key.bin");
            std::fs::write(&lms_priv, VENDOR_LMS_KEY_0_PRIVATE.as_bytes()).unwrap();

            let mldsa_priv = dir.path().join("vendor-mldsa-key.bin");
            let mldsa_pub = dir.path().join("vendor-mldsa-pub.bin");
            std::fs::write(&mldsa_priv, VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes()).unwrap();
            std::fs::write(&mldsa_pub, VENDOR_MLDSA_KEY_0_PUBLIC.0.as_bytes()).unwrap();

            Self {
                _dir: dir,
                vendor_ecc_priv,
                vendor_ecc_pub,
                owner_ecc_priv,
                owner_ecc_pub,
                vendor_man_priv,
                vendor_man_pub,
                lms_priv,
                mldsa_priv,
                mldsa_pub,
            }
        }
    }

    fn write_ecc_key_pair(dir: &TempDir, name: &str) -> (PathBuf, PathBuf) {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let private_path = dir.path().join(format!("{name}-key.pem"));
        let public_path = dir.path().join(format!("{name}-pub.pem"));
        std::fs::write(&private_path, key.private_key_to_pem().unwrap()).unwrap();
        std::fs::write(&public_path, key.public_key_to_pem().unwrap()).unwrap();
        (private_path, public_path)
    }

    #[test]
    fn test_sign_and_verify_ecc() {
        let keys = TestKeyFiles::new();

        let dummy_digest = "01".repeat(48);
        let ecc_sig = sign_ecc(&dummy_digest, &keys.vendor_ecc_priv, &keys.vendor_ecc_pub).unwrap();
        assert_eq!(ecc_sig.len(), 192); // 96 bytes * 2 hex chars per byte
        let parsed_ecc = ImageEccSignature::try_from_hex(&ecc_sig).unwrap();

        let digest_bytes = hex::decode(&dummy_digest).unwrap();
        let digest_array: [u8; 48] = digest_bytes.try_into().unwrap();
        let pub_key = OsslCrypto::ecc_pub_key_from_pem(&keys.vendor_ecc_pub).unwrap();
        verify_ecdsa384_signature(&digest_array, &pub_key, &parsed_ecc)
            .expect("Generated ECDSA P-384 signature failed verification against public key");
    }

    #[test]
    fn test_sign_and_verify_lms() {
        let keys = TestKeyFiles::new();

        let dummy_digest = "01".repeat(48);
        let lms_sig_hex = sign_lms(&dummy_digest, &keys.lms_priv).unwrap();
        assert_eq!(lms_sig_hex.len(), 1620 * 2);

        let digest_bytes = hex::decode(&dummy_digest).unwrap();
        let digest_array: [u8; 48] = digest_bytes.try_into().unwrap();
        let sig_bytes = hex::decode(&lms_sig_hex).unwrap();
        let lms_pub_key = VENDOR_LMS_KEY_0_PUBLIC;
        let lms_sig = ImageLmsSignature::ref_from_bytes(&sig_bytes).unwrap();
        verify_lms_signature(&digest_array, &lms_pub_key, lms_sig)
            .expect("LMS signature verification failed");
    }

    #[test]
    fn test_sign_and_verify_mldsa() {
        let keys = TestKeyFiles::new();

        let dummy_msg = "02".repeat(64);
        let mldsa_sig_hex = sign_mldsa(&dummy_msg, &keys.mldsa_priv, &keys.mldsa_pub).unwrap();
        assert_eq!(mldsa_sig_hex.len(), 4628 * 2);

        let msg_bytes = hex::decode(&dummy_msg).unwrap();
        let sig_bytes = hex::decode(&mldsa_sig_hex).unwrap();
        let pub_key = OsslCrypto::mldsa_pub_key_from_file(&keys.mldsa_pub).unwrap();
        let mldsa_sig = ImageMldsaSignature::ref_from_bytes(&sig_bytes).unwrap();
        verify_mldsa_signature(&msg_bytes, &pub_key, mldsa_sig)
            .expect("Generated ML-DSA signature failed verification against public key");
    }

    #[test]
    fn test_generate_offline_signatures_with_manifest() {
        let keys = TestKeyFiles::new();

        let req_json = r#"{
            "version": 1,
            "requests": {
                "vendor_pub_keys_signatures": {
                    "ecc_key": "vendor_fw_ecc_key",
                    "pqc_key": "vendor_fw_pqc_key",
                    "digest_sha384": "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101",
                    "payload_hex": "00"
                },
                "owner_pub_keys_signatures": {
                    "ecc_key": "owner_fw_ecc_key",
                    "pqc_key": "owner_fw_pqc_key",
                    "digest_sha384": "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
                    "payload_hex": "00"
                },
                "vendor_imc_signatures": {
                    "ecc_key": "vendor_man_ecc_key",
                    "pqc_key": "vendor_man_pqc_key",
                    "digest_sha384": "030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303",
                    "payload_hex": "00"
                },
                "owner_imc_signatures": {
                    "ecc_key": "owner_man_ecc_key",
                    "pqc_key": "owner_man_pqc_key",
                    "digest_sha384": "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
                    "payload_hex": "00"
                }
            }
        }"#;

        let req_file = NamedTempFile::new().unwrap();
        std::fs::write(req_file.path(), req_json).unwrap();

        let manifest = KeyManifest {
            vendor_fw: KeyManifestEntry {
                ecc_priv_key: keys.vendor_ecc_priv.to_str().unwrap().to_string(),
                ecc_pub_key: keys.vendor_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: keys.mldsa_priv.to_str().unwrap().to_string(),
                pqc_pub_key: Some(keys.mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            owner_fw: KeyManifestEntry {
                ecc_priv_key: keys.owner_ecc_priv.to_str().unwrap().to_string(),
                ecc_pub_key: keys.owner_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: keys.mldsa_priv.to_str().unwrap().to_string(),
                pqc_pub_key: Some(keys.mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            vendor_man: KeyManifestEntry {
                ecc_priv_key: keys.vendor_man_priv.to_str().unwrap().to_string(),
                ecc_pub_key: keys.vendor_man_pub.to_str().unwrap().to_string(),
                pqc_priv_key: keys.mldsa_priv.to_str().unwrap().to_string(),
                pqc_pub_key: Some(keys.mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            owner_man: KeyManifestEntry {
                ecc_priv_key: keys.owner_ecc_priv.to_str().unwrap().to_string(),
                ecc_pub_key: keys.owner_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: keys.mldsa_priv.to_str().unwrap().to_string(),
                pqc_pub_key: Some(keys.mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
        };

        let sig_file = NamedTempFile::new().unwrap();
        let sigs =
            generate_offline_signatures(req_file.path(), &manifest, sig_file.path()).unwrap();

        let mldsa_pub_key = OsslCrypto::mldsa_pub_key_from_file(&keys.mldsa_pub).unwrap();

        assert!(sigs.vendor_pub_keys_signatures.is_some());
        let v_entry = sigs.vendor_pub_keys_signatures.as_ref().unwrap();
        let vendor_ecc =
            ImageEccSignature::try_from_hex(v_entry.ecc_sig.as_ref().unwrap()).unwrap();
        let vendor_pub = OsslCrypto::ecc_pub_key_from_pem(&keys.vendor_ecc_pub).unwrap();
        let v_digest = hex::decode("010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101").unwrap();
        verify_ecdsa384_signature(&v_digest.try_into().unwrap(), &vendor_pub, &vendor_ecc)
            .expect("vendor_pub_keys_signatures ECC signature verification failed");
        let v_mldsa_bytes = hex::decode(v_entry.pqc_sig.as_ref().unwrap()).unwrap();
        let v_mldsa_sig = ImageMldsaSignature::ref_from_bytes(&v_mldsa_bytes).unwrap();
        verify_mldsa_signature(&[0u8], &mldsa_pub_key, v_mldsa_sig)
            .expect("vendor_pub_keys_signatures MLDSA signature verification failed");

        assert!(sigs.owner_pub_keys_signatures.is_some());
        let o_entry = sigs.owner_pub_keys_signatures.as_ref().unwrap();
        let owner_ecc = ImageEccSignature::try_from_hex(o_entry.ecc_sig.as_ref().unwrap()).unwrap();
        let owner_pub = OsslCrypto::ecc_pub_key_from_pem(&keys.owner_ecc_pub).unwrap();
        let o_digest = hex::decode("020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202").unwrap();
        verify_ecdsa384_signature(&o_digest.try_into().unwrap(), &owner_pub, &owner_ecc)
            .expect("owner_pub_keys_signatures ECC signature verification failed");
        let o_mldsa_bytes = hex::decode(o_entry.pqc_sig.as_ref().unwrap()).unwrap();
        let o_mldsa_sig = ImageMldsaSignature::ref_from_bytes(&o_mldsa_bytes).unwrap();
        verify_mldsa_signature(&[0u8], &mldsa_pub_key, o_mldsa_sig)
            .expect("owner_pub_keys_signatures MLDSA signature verification failed");

        assert!(sigs.vendor_imc_signatures.is_some());
        let vm_entry = sigs.vendor_imc_signatures.as_ref().unwrap();
        let vm_ecc = ImageEccSignature::try_from_hex(vm_entry.ecc_sig.as_ref().unwrap()).unwrap();
        let vm_pub = OsslCrypto::ecc_pub_key_from_pem(&keys.vendor_man_pub).unwrap();
        let vm_digest = hex::decode("030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303").unwrap();
        verify_ecdsa384_signature(&vm_digest.try_into().unwrap(), &vm_pub, &vm_ecc)
            .expect("vendor_imc_signatures ECC signature verification failed");
        let vm_mldsa_bytes = hex::decode(vm_entry.pqc_sig.as_ref().unwrap()).unwrap();
        let vm_mldsa_sig = ImageMldsaSignature::ref_from_bytes(&vm_mldsa_bytes).unwrap();
        verify_mldsa_signature(&[0u8], &mldsa_pub_key, vm_mldsa_sig)
            .expect("vendor_imc_signatures MLDSA signature verification failed");

        assert!(sigs.owner_imc_signatures.is_some());
        let om_entry = sigs.owner_imc_signatures.as_ref().unwrap();
        let om_ecc = ImageEccSignature::try_from_hex(om_entry.ecc_sig.as_ref().unwrap()).unwrap();
        let om_digest = hex::decode("040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404").unwrap();
        verify_ecdsa384_signature(&om_digest.try_into().unwrap(), &owner_pub, &om_ecc)
            .expect("owner_imc_signatures ECC signature verification failed");
        let om_mldsa_bytes = hex::decode(om_entry.pqc_sig.as_ref().unwrap()).unwrap();
        let om_mldsa_sig = ImageMldsaSignature::ref_from_bytes(&om_mldsa_bytes).unwrap();
        verify_mldsa_signature(&[0u8], &mldsa_pub_key, om_mldsa_sig)
            .expect("owner_imc_signatures MLDSA signature verification failed");
    }
}
