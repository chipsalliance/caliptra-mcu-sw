// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use caliptra_auth_man_types::AuthorizationManifest;
    use caliptra_image_crypto::RustCrypto as Crypto;
    use caliptra_image_gen::ImageGeneratorCrypto;
    use caliptra_mcu_builder::offline_signing::{
        attach_auth_manifest_signatures, verify_ecdsa384_signature, ImagePqcSignatureExt,
    };
    use caliptra_mcu_builder::{
        caliptra_sw_workspace_root, AuthManifestPubKeysPaths, CaliptraBuildArgs, CaliptraBuilder,
        ImageCfg,
    };
    use caliptra_mcu_fw_signer::{generate_offline_signatures, KeyManifest, KeyManifestEntry};
    use sha2::Digest;
    use tempfile::tempdir;
    use zerocopy::{FromBytes, IntoBytes};

    #[test]
    fn test_e2e_offline_manifest_signing_flow_mldsa() {
        let temp_dir = tempdir().unwrap();
        let work_dir = temp_dir.path();

        let sw_root = caliptra_sw_workspace_root();
        let keys_dir = sw_root.join("image/fake-keys/keys");

        let vendor_fw_ecc_key = keys_dir.join("vendor_ecc_0_key.pem");
        let vendor_fw_ecc_pub = keys_dir.join("vendor_ecc_0_pub.pem");
        let vendor_fw_mldsa_key = keys_dir.join("vendor_mldsa_0_key.pem");
        let vendor_fw_mldsa_pub = keys_dir.join("vendor_mldsa_0_pub.pem");

        let owner_fw_ecc_key = keys_dir.join("owner_ecc_key.pem");
        let owner_fw_ecc_pub = keys_dir.join("owner_ecc_pub.pem");
        let owner_fw_mldsa_key = keys_dir.join("owner_mldsa_key.pem");
        let owner_fw_mldsa_pub = keys_dir.join("owner_mldsa_pub.pem");

        let vendor_man_ecc_key = keys_dir.join("vendor_ecc_1_key.pem");
        let vendor_man_ecc_pub = keys_dir.join("vendor_ecc_1_pub.pem");
        let vendor_man_mldsa_key = keys_dir.join("vendor_mldsa_1_key.pem");
        let vendor_man_mldsa_pub = keys_dir.join("vendor_mldsa_1_pub.pem");

        let owner_man_ecc_key = keys_dir.join("owner_ecc_key.pem");
        let owner_man_ecc_pub = keys_dir.join("owner_ecc_pub.pem");
        let owner_man_mldsa_key = keys_dir.join("owner_mldsa_key.pem");
        let owner_man_mldsa_pub = keys_dir.join("owner_mldsa_pub.pem");

        // 1. Create dummy MCU and SoC image files
        let mcu_bin = work_dir.join("mcu-runtime.bin");
        std::fs::write(&mcu_bin, vec![0xa5u8; 1024]).unwrap();

        let soc_bin = work_dir.join("soc-fw.bin");
        std::fs::write(&soc_bin, vec![0x5au8; 2048]).unwrap();

        let unsigned_manifest_path = work_dir.join("unsigned_auth_manifest.bin");
        let signing_request_path = work_dir.join("signing_request.json");
        let signatures_path = work_dir.join("signatures.json");
        let signed_manifest_path = work_dir.join("signed_auth_manifest.bin");

        let mcu_image_cfg = ImageCfg {
            path: mcu_bin,
            network_filename: None,
            load_addr: 0xA800_0000,
            staging_addr: 0x6000_0000,
            image_id: 1,
            exec_bit: 2,
            component_id: 0,
            is_tcb: true,
            is_ak_target: false,
            feature: "test".to_string(),
        };

        let soc_image_cfg = ImageCfg {
            path: soc_bin,
            network_filename: None,
            load_addr: 0x8000_0000,
            staging_addr: 0x6000_0000,
            image_id: 2,
            exec_bit: 2,
            component_id: 1,
            is_tcb: false,
            is_ak_target: false,
            feature: "test".to_string(),
        };

        // Step 1: Create unsigned manifest and export signing request
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            mcu_firmware: Some(mcu_image_cfg.path.clone()),
            soc_images: Some(vec![soc_image_cfg]),
            mcu_image_cfg: Some(mcu_image_cfg),
            soc_manifest_svn: Some(1),
            ..Default::default()
        });

        let key_paths = AuthManifestPubKeysPaths {
            vendor_fw_ecc_pub_key: Some(&vendor_fw_ecc_pub),
            vendor_fw_mldsa_pub_key: Some(&vendor_fw_mldsa_pub),
            owner_fw_ecc_pub_key: Some(&owner_fw_ecc_pub),
            owner_fw_mldsa_pub_key: Some(&owner_fw_mldsa_pub),
            vendor_man_ecc_pub_key: Some(&vendor_man_ecc_pub),
            vendor_man_mldsa_pub_key: Some(&vendor_man_mldsa_pub),
            owner_man_ecc_pub_key: Some(&owner_man_ecc_pub),
            owner_man_mldsa_pub_key: Some(&owner_man_mldsa_pub),
            ..Default::default()
        };

        let (path, signing_req) = builder
            .get_unsigned_auth_manifest(
                Some(unsigned_manifest_path.to_str().unwrap()),
                Some(&key_paths),
            )
            .unwrap();

        let req_json_bytes = serde_json::to_string_pretty(&signing_req).unwrap();
        std::fs::write(&signing_request_path, req_json_bytes).unwrap();

        assert!(path.exists());
        assert!(signing_request_path.exists());

        // Step 2: Compute offline signatures for signing request using fw-signer
        let key_manifest = KeyManifest {
            vendor_fw: KeyManifestEntry {
                ecc_priv_key: vendor_fw_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: vendor_fw_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: vendor_fw_mldsa_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(vendor_fw_mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            owner_fw: KeyManifestEntry {
                ecc_priv_key: owner_fw_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: owner_fw_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: owner_fw_mldsa_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(owner_fw_mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            vendor_man: KeyManifestEntry {
                ecc_priv_key: vendor_man_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: vendor_man_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: vendor_man_mldsa_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(vendor_man_mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
            owner_man: KeyManifestEntry {
                ecc_priv_key: owner_man_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: owner_man_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: owner_man_mldsa_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(owner_man_mldsa_pub.to_str().unwrap().to_string()),
                pqc_type: "MLDSA".to_string(),
            },
        };

        generate_offline_signatures(&signing_request_path, &key_manifest, &signatures_path)
            .unwrap();

        assert!(signatures_path.exists());

        // Step 3: Reattach signatures and verify output
        attach_auth_manifest_signatures(
            &unsigned_manifest_path,
            &signatures_path,
            Some(&vendor_fw_ecc_pub),
            Some(&owner_fw_ecc_pub),
            &signed_manifest_path,
        )
        .unwrap();

        assert!(signed_manifest_path.exists());

        // Step 4: Parse final signed manifest and verify cryptographic signatures
        let signed_data = std::fs::read(&signed_manifest_path).unwrap();
        let manifest = AuthorizationManifest::read_from_bytes(&signed_data).unwrap();

        assert_eq!(manifest.preamble.version, 1);
        assert_eq!(manifest.preamble.svn, 1);

        let vendor_fw_pub_key = Crypto::ecc_pub_key_from_pem(&vendor_fw_ecc_pub).unwrap();
        let owner_fw_pub_key = Crypto::ecc_pub_key_from_pem(&owner_fw_ecc_pub).unwrap();

        let vendor_range =
            caliptra_auth_man_types::AuthManifestPreamble::vendor_signed_data_range();
        let vendor_signed_bytes = manifest
            .preamble
            .as_bytes()
            .get(vendor_range.start as usize..vendor_range.end as usize)
            .unwrap();
        let vendor_digest: [u8; 48] = sha2::Sha384::digest(vendor_signed_bytes).into();

        verify_ecdsa384_signature(
            &vendor_digest,
            &vendor_fw_pub_key,
            &manifest.preamble.vendor_pub_keys_signatures.ecc_sig,
        )
        .expect("Vendor pub keys signature verification failed");

        let owner_bytes = manifest.preamble.owner_pub_keys.as_bytes();
        let owner_digest: [u8; 48] = sha2::Sha384::digest(owner_bytes).into();

        verify_ecdsa384_signature(
            &owner_digest,
            &owner_fw_pub_key,
            &manifest.preamble.owner_pub_keys_signatures.ecc_sig,
        )
        .expect("Owner pub keys signature verification failed");

        let imc_bytes = manifest.image_metadata_col.as_bytes();
        let imc_digest: [u8; 48] = sha2::Sha384::digest(imc_bytes).into();

        verify_ecdsa384_signature(
            &imc_digest,
            &manifest.preamble.vendor_pub_keys.ecc_pub_key,
            &manifest.preamble.vendor_image_metdata_signatures.ecc_sig,
        )
        .expect("Vendor IMC signature verification failed");

        verify_ecdsa384_signature(
            &imc_digest,
            &manifest.preamble.owner_pub_keys.ecc_pub_key,
            &manifest.preamble.owner_image_metdata_signatures.ecc_sig,
        )
        .expect("Owner IMC signature verification failed");

        // Verify PQC signatures
        manifest
            .preamble
            .vendor_pub_keys_signatures
            .pqc_sig
            .verify()
            .expect("Vendor pub keys PQC signature verification failed");

        manifest
            .preamble
            .owner_pub_keys_signatures
            .pqc_sig
            .verify()
            .expect("Owner pub keys PQC signature verification failed");

        manifest
            .preamble
            .vendor_image_metdata_signatures
            .pqc_sig
            .verify()
            .expect("Vendor IMC PQC signature verification failed");

        manifest
            .preamble
            .owner_image_metdata_signatures
            .pqc_sig
            .verify()
            .expect("Owner IMC PQC signature verification failed");
    }

    #[test]
    fn test_e2e_offline_manifest_signing_flow_lms() {
        let temp_dir = tempdir().unwrap();
        let work_dir = temp_dir.path();

        let sw_root = caliptra_sw_workspace_root();
        let keys_dir = sw_root.join("image/fake-keys/keys");

        let vendor_fw_ecc_key = keys_dir.join("vendor_ecc_0_key.pem");
        let vendor_fw_ecc_pub = keys_dir.join("vendor_ecc_0_pub.pem");
        let vendor_fw_lms_key = keys_dir.join("vendor_lms_0_key.pem");
        let vendor_fw_lms_pub = keys_dir.join("vendor_lms_0_pub.pem");

        let owner_fw_ecc_key = keys_dir.join("owner_ecc_key.pem");
        let owner_fw_ecc_pub = keys_dir.join("owner_ecc_pub.pem");
        let owner_fw_lms_key = keys_dir.join("owner_lms_key.pem");
        let owner_fw_lms_pub = keys_dir.join("owner_lms_pub.pem");

        let vendor_man_ecc_key = keys_dir.join("vendor_ecc_1_key.pem");
        let vendor_man_ecc_pub = keys_dir.join("vendor_ecc_1_pub.pem");
        let vendor_man_lms_key = keys_dir.join("vendor_lms_1_key.pem");
        let vendor_man_lms_pub = keys_dir.join("vendor_lms_1_pub.pem");

        let owner_man_ecc_key = keys_dir.join("owner_ecc_key.pem");
        let owner_man_ecc_pub = keys_dir.join("owner_ecc_pub.pem");
        let owner_man_lms_key = keys_dir.join("owner_lms_key.pem");
        let owner_man_lms_pub = keys_dir.join("owner_lms_pub.pem");

        // 1. Create dummy MCU and SoC image files
        let mcu_bin = work_dir.join("mcu-runtime.bin");
        std::fs::write(&mcu_bin, vec![0xa5u8; 1024]).unwrap();

        let soc_bin = work_dir.join("soc-fw.bin");
        std::fs::write(&soc_bin, vec![0x5au8; 2048]).unwrap();

        let unsigned_manifest_path = work_dir.join("unsigned_auth_manifest.bin");
        let signing_request_path = work_dir.join("signing_request.json");
        let signatures_path = work_dir.join("signatures.json");
        let signed_manifest_path = work_dir.join("signed_auth_manifest.bin");

        let mcu_image_cfg = ImageCfg {
            path: mcu_bin,
            network_filename: None,
            load_addr: 0xA800_0000,
            staging_addr: 0x6000_0000,
            image_id: 1,
            exec_bit: 2,
            component_id: 0,
            is_tcb: true,
            is_ak_target: false,
            feature: "test".to_string(),
        };

        let soc_image_cfg = ImageCfg {
            path: soc_bin,
            network_filename: None,
            load_addr: 0x8000_0000,
            staging_addr: 0x6000_0000,
            image_id: 2,
            exec_bit: 2,
            component_id: 1,
            is_tcb: false,
            is_ak_target: false,
            feature: "test".to_string(),
        };

        // Step 1: Create unsigned manifest and export signing request
        let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
            mcu_firmware: Some(mcu_image_cfg.path.clone()),
            soc_images: Some(vec![soc_image_cfg]),
            mcu_image_cfg: Some(mcu_image_cfg),
            soc_manifest_svn: Some(1),
            ..Default::default()
        });

        let key_paths = AuthManifestPubKeysPaths {
            vendor_fw_ecc_pub_key: Some(&vendor_fw_ecc_pub),
            vendor_fw_lms_pub_key: Some(&vendor_fw_lms_pub),
            owner_fw_ecc_pub_key: Some(&owner_fw_ecc_pub),
            owner_fw_lms_pub_key: Some(&owner_fw_lms_pub),
            vendor_man_ecc_pub_key: Some(&vendor_man_ecc_pub),
            vendor_man_lms_pub_key: Some(&vendor_man_lms_pub),
            owner_man_ecc_pub_key: Some(&owner_man_ecc_pub),
            owner_man_lms_pub_key: Some(&owner_man_lms_pub),
            ..Default::default()
        };

        let (path, signing_req) = builder
            .get_unsigned_auth_manifest(
                Some(unsigned_manifest_path.to_str().unwrap()),
                Some(&key_paths),
            )
            .unwrap();

        let req_json_bytes = serde_json::to_string_pretty(&signing_req).unwrap();
        std::fs::write(&signing_request_path, req_json_bytes).unwrap();

        assert!(path.exists());
        assert!(signing_request_path.exists());

        // Step 2: Compute offline signatures for signing request using fw-signer
        let key_manifest = KeyManifest {
            vendor_fw: KeyManifestEntry {
                ecc_priv_key: vendor_fw_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: vendor_fw_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: vendor_fw_lms_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(vendor_fw_lms_pub.to_str().unwrap().to_string()),
                pqc_type: "LMS".to_string(),
            },
            owner_fw: KeyManifestEntry {
                ecc_priv_key: owner_fw_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: owner_fw_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: owner_fw_lms_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(owner_fw_lms_pub.to_str().unwrap().to_string()),
                pqc_type: "LMS".to_string(),
            },
            vendor_man: KeyManifestEntry {
                ecc_priv_key: vendor_man_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: vendor_man_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: vendor_man_lms_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(vendor_man_lms_pub.to_str().unwrap().to_string()),
                pqc_type: "LMS".to_string(),
            },
            owner_man: KeyManifestEntry {
                ecc_priv_key: owner_man_ecc_key.to_str().unwrap().to_string(),
                ecc_pub_key: owner_man_ecc_pub.to_str().unwrap().to_string(),
                pqc_priv_key: owner_man_lms_key.to_str().unwrap().to_string(),
                pqc_pub_key: Some(owner_man_lms_pub.to_str().unwrap().to_string()),
                pqc_type: "LMS".to_string(),
            },
        };

        generate_offline_signatures(&signing_request_path, &key_manifest, &signatures_path)
            .unwrap();

        assert!(signatures_path.exists());

        // Step 3: Reattach signatures and verify output
        attach_auth_manifest_signatures(
            &unsigned_manifest_path,
            &signatures_path,
            Some(&vendor_fw_ecc_pub),
            Some(&owner_fw_ecc_pub),
            &signed_manifest_path,
        )
        .unwrap();

        assert!(signed_manifest_path.exists());

        // Step 4: Parse final signed manifest and verify cryptographic signatures
        let signed_data = std::fs::read(&signed_manifest_path).unwrap();
        let manifest = AuthorizationManifest::read_from_bytes(&signed_data).unwrap();

        assert_eq!(manifest.preamble.version, 1);
        assert_eq!(manifest.preamble.svn, 1);

        let vendor_fw_pub_key = Crypto::ecc_pub_key_from_pem(&vendor_fw_ecc_pub).unwrap();
        let owner_fw_pub_key = Crypto::ecc_pub_key_from_pem(&owner_fw_ecc_pub).unwrap();

        let vendor_range =
            caliptra_auth_man_types::AuthManifestPreamble::vendor_signed_data_range();
        let vendor_signed_bytes = manifest
            .preamble
            .as_bytes()
            .get(vendor_range.start as usize..vendor_range.end as usize)
            .unwrap();
        let vendor_digest: [u8; 48] = sha2::Sha384::digest(vendor_signed_bytes).into();

        verify_ecdsa384_signature(
            &vendor_digest,
            &vendor_fw_pub_key,
            &manifest.preamble.vendor_pub_keys_signatures.ecc_sig,
        )
        .expect("Vendor pub keys signature verification failed");

        let owner_bytes = manifest.preamble.owner_pub_keys.as_bytes();
        let owner_digest: [u8; 48] = sha2::Sha384::digest(owner_bytes).into();

        verify_ecdsa384_signature(
            &owner_digest,
            &owner_fw_pub_key,
            &manifest.preamble.owner_pub_keys_signatures.ecc_sig,
        )
        .expect("Owner pub keys signature verification failed");

        let imc_bytes = manifest.image_metadata_col.as_bytes();
        let imc_digest: [u8; 48] = sha2::Sha384::digest(imc_bytes).into();

        verify_ecdsa384_signature(
            &imc_digest,
            &manifest.preamble.vendor_pub_keys.ecc_pub_key,
            &manifest.preamble.vendor_image_metdata_signatures.ecc_sig,
        )
        .expect("Vendor IMC signature verification failed");

        verify_ecdsa384_signature(
            &imc_digest,
            &manifest.preamble.owner_pub_keys.ecc_pub_key,
            &manifest.preamble.owner_image_metdata_signatures.ecc_sig,
        )
        .expect("Owner IMC signature verification failed");

        // Verify PQC signatures
        manifest
            .preamble
            .vendor_pub_keys_signatures
            .pqc_sig
            .verify()
            .expect("Vendor pub keys PQC signature verification failed");

        manifest
            .preamble
            .owner_pub_keys_signatures
            .pqc_sig
            .verify()
            .expect("Owner pub keys PQC signature verification failed");

        manifest
            .preamble
            .vendor_image_metdata_signatures
            .pqc_sig
            .verify()
            .expect("Vendor IMC PQC signature verification failed");

        manifest
            .preamble
            .owner_image_metdata_signatures
            .pqc_sig
            .verify()
            .expect("Owner IMC PQC signature verification failed");
    }
}
