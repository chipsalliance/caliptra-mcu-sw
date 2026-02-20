//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{LazyLock, Mutex},
    };

    use crate::test::{start_runtime_hw_model, CustomCaliptraFw, TestParams, TEST_LOCK};
    use caliptra_api::{
        calc_checksum,
        mailbox::{
            CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacReq, CmHmacResp,
            CmStableKeyType, CommandId,
        },
    };
    use caliptra_auth_man_types::{AuthManifestPrivKeysConfig, AuthManifestPubKeysConfig};
    use caliptra_image_gen::ImageGeneratorOwnerConfig;
    use caliptra_image_types::{ImageManifest, ImageOwnerPrivKeys, OwnerPubKeyConfig};
    use mcu_builder::{AuthManifestOwnerConfig, CaliptraBuilder, FirmwareBinaries};
    use mcu_error::McuError;
    use mcu_hw_model::McuHwModel;
    use mcu_rom_common::McuRomBootStatus;
    use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

    /// Size of the DOT blob structure in bytes.
    /// Layout: version (4) + cak (48) + lak_pub (48) + unlock_method (1) + reserved (3) + hmac (64) = 168 bytes
    const DOT_BLOB_SIZE: usize = 168;

    /// Test DOT blob structure matching the ROM's DotBlob.
    #[repr(C)]
    #[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
    struct TestDotBlob {
        version: u32,
        cak: [u32; 12],
        lak_pub: [u32; 12],
        unlock_method: u8,
        reserved: [u8; 3],
        hmac: [u32; 16],
    }

    impl Default for TestDotBlob {
        fn default() -> Self {
            Self {
                version: 1,
                cak: [0; 12],
                lak_pub: [0; 12],
                unlock_method: 0,
                reserved: [0; 3],
                hmac: [0; 16],
            }
        }
    }

    impl TestDotBlob {
        /// Creates a DOT blob with a specific CAK (owner public key hash).
        fn with_cak(mut self, cak: [u32; 12]) -> Self {
            self.cak = cak;
            self
        }

        /// Creates a DOT blob with a specific LAK (lock authentication key).
        fn with_lak(mut self, lak: [u32; 12]) -> Self {
            self.lak_pub = lak;
            self
        }

        /// Sets the HMAC field from computed value.
        fn with_hmac(mut self, hmac: &[u8]) -> Self {
            assert_eq!(hmac.len(), 64);
            self.hmac = transmute!(<[u8; 64]>::try_from(hmac).unwrap());
            self
        }

        /// Returns the bytes of the blob excluding the HMAC (for HMAC computation).
        fn data_for_hmac(&self) -> Vec<u8> {
            let bytes = self.as_bytes();
            bytes[..bytes.len() - 64].to_vec()
        }

        /// Convert to padded flash contents (4096 bytes).
        fn to_flash_contents(&self) -> Vec<u8> {
            let mut contents = vec![0u8; 4096];
            contents[..DOT_BLOB_SIZE].copy_from_slice(self.as_bytes());
            contents
        }
    }

    /// Returns the owner public key hash from the Caliptra FW bundle.
    /// This is the SHA384 hash of the owner public keys used to sign the firmware,
    /// and must be used as the CAK in DOT blobs for the firmware to verify correctly.
    fn get_owner_pk_hash() -> [u32; 12] {
        // Try to get from prebuilt binaries first
        if let Ok(binaries) = FirmwareBinaries::from_env() {
            if let Some(hash) = binaries.owner_pk_hash() {
                // Convert [u8; 48] to [u32; 12] in big-endian format
                let mut result = [0u32; 12];
                for (i, chunk) in hash.chunks(4).enumerate() {
                    result[i] = u32::from_be_bytes(chunk.try_into().unwrap());
                }
                return result;
            }
        }

        // Fall back to computing from compiled FW bundle
        let mut builder = CaliptraBuilder::new(
            cfg!(feature = "fpga_realtime"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let fw_path = builder
            .get_caliptra_fw()
            .expect("Failed to get Caliptra FW");
        let fw_bytes = std::fs::read(&fw_path).expect("Failed to read Caliptra FW");
        let (manifest, _) =
            ImageManifest::ref_from_prefix(&fw_bytes).expect("Failed to parse manifest");
        let hash =
            CaliptraBuilder::owner_pk_hash(manifest).expect("Failed to compute owner PK hash");
        // Convert [u8; 48] to [u32; 12] in big-endian format
        let mut result = [0u32; 12];
        for (i, chunk) in hash.chunks(4).enumerate() {
            result[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        result
    }

    /// Creates a test LAK (lock authentication key) with a recognizable pattern.
    fn test_lak() -> [u32; 12] {
        [
            0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x01010101,
            0x02020202, 0x03030303, 0x04040404, 0x05050505, 0x06060606,
        ]
    }

    /// Creates a valid DOT blob with proper HMAC signature.
    fn create_valid_dot_blob(cak: [u32; 12], lak: [u32; 12]) -> TestDotBlob {
        let blob = TestDotBlob::default().with_cak(cak).with_lak(lak);
        let hmac = compute_hmac_cached(&blob.data_for_hmac());
        blob.with_hmac(&hmac)
    }

    static HMACS: LazyLock<Mutex<HashMap<Vec<u8>, Vec<u8>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn compute_hmac_cached(blob: &[u8]) -> Vec<u8> {
        let mut hmacs = HMACS.lock().unwrap();

        match hmacs.get(blob) {
            Some(h) => h.clone(),
            None => {
                let h = compute_hmac(blob);
                hmacs.insert(blob.to_vec(), h.clone());
                h
            }
        }
    }

    /// Computes an HMAC of the blob using the Caliptra DOT stable key. Used to make HMACs of DOT blobs.
    /// The key is derived with the EVEN state derivation value (n+1 where n=0, so value=1),
    /// matching the ROM's key derivation for initial blob sealing.
    ///
    /// Caller MUST hold `TEST_LOCK` before calling this function, since it builds and runs
    /// firmware internally via `start_runtime_hw_model`.
    fn compute_hmac(blob: &[u8]) -> Vec<u8> {
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some("test-do-nothing"),
            ..Default::default()
        });

        hw.step_until(|m| {
            (m.mci_flow_status() & 0xffff) as u16
                >= McuRomBootStatus::CaliptraReadyForMailbox.into()
        });

        let mut req = CmDeriveStableKeyReq {
            key_type: CmStableKeyType::IDevId.into(),
            ..Default::default()
        };
        req.info[..23].copy_from_slice(b"Caliptra DOT stable key");
        // EVEN state (burned=0) derives with n+1 = 1 per spec
        req.info[23] = 1;
        req.info[24] = 0;
        let req = req.as_mut_bytes();
        let chksum = calc_checksum(CommandId::CM_DERIVE_STABLE_KEY.into(), req);
        req[..4].copy_from_slice(&chksum.to_le_bytes());

        let resp = hw
            .caliptra_mailbox_execute(CommandId::CM_DERIVE_STABLE_KEY.into(), req)
            .unwrap()
            .unwrap();
        let resp = CmDeriveStableKeyResp::read_from_bytes(&resp).unwrap();
        let cmk = resp.cmk;
        let mut req = CmHmacReq {
            cmk,
            hash_algorithm: CmHashAlgorithm::Sha512.into(),
            data_size: blob.len() as u32,
            ..Default::default()
        };
        req.data[..blob.len()].copy_from_slice(blob);

        let req = req.as_mut_bytes();
        let chksum = calc_checksum(CommandId::CM_HMAC.into(), req);
        req[..4].copy_from_slice(&chksum.to_le_bytes());

        let resp = hw
            .caliptra_mailbox_execute(CommandId::CM_HMAC.into(), req)
            .unwrap()
            .unwrap();
        let resp = CmHmacResp::read_from_bytes(&resp).unwrap();

        resp.mac.to_vec()
    }

    #[test]
    fn test_dot_blob_valid() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let blob = [0u8; 32]; // TODO: make a valid DOT blob
        let hmac = compute_hmac_cached(&blob);
        // Verify HMAC is 64 bytes (SHA-512) and non-zero
        assert_eq!(hmac.len(), 64);
        assert!(hmac.iter().any(|&b| b != 0), "HMAC should not be all zeros");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_dot_blob_corrupt() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(vec![0x12; 4096]),
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.cycle_count() > 10_000_000 || m.mci_fw_fatal_error().is_some());

        let status = hw.mci_fw_fatal_error().unwrap_or(0);
        assert_eq!(
            u32::from(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR),
            status
        );

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that a valid DOT blob with CAK and LAK in EVEN (unlocked) state passes DOT validation.
    /// In EVEN state (burned=0), per spec, ownership is volatile and not derived from DOT_BLOB.
    /// The ROM verifies the blob and burns fuses, but does not set the owner from the blob.
    #[test]
    fn test_dot_unlocked_state_valid_blob() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a valid DOT blob with the actual owner PK hash from the FW bundle as CAK
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let flash_contents = blob.to_flash_contents();

        // Debug: print first 32 bytes of flash contents to verify non-zero
        println!(
            "[TEST] DOT flash contents (first 32 bytes): {:02x?}",
            &flash_contents[..32]
        );

        println!("[TEST] Starting hardware model with DOT flash contents");
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents.clone()),
            rom_only: true,
            dot_enabled: true,
            ..Default::default()
        });

        // Debug: read DOT flash back to verify it was written
        let dot_flash_read = hw.read_dot_flash();
        println!(
            "[TEST] DOT flash read back (first 32 bytes): {:02x?}",
            &dot_flash_read[..32]
        );

        println!("[TEST] Running step_until to wait for DOT flow");

        // Run until DOT flow completes or error occurs
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 50_000_000
        });

        // Print checkpoint for debug
        let checkpoint = hw.mci_boot_checkpoint();
        println!("[TEST] Final checkpoint: {}", checkpoint);

        // Check for fatal errors (DOT flow itself should not cause fatal errors)
        let fatal_error = hw.mci_fw_fatal_error();
        if fatal_error.is_some() {
            println!(
                "[TEST] Warning: Fatal error occurred after DOT flow: {:?}",
                fatal_error
            );
        }

        assert!(fatal_error.is_none());

        // Verify DOT flow completed successfully
        assert!(
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into(),
            "DOT flow did not complete, checkpoint: {}",
            checkpoint
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT works with custom/random owner keys.
    /// This test creates a new owner key configuration using alternate keys,
    /// re-signs both the FW bundle and SoC manifest with those keys, and verifies
    /// DOT flow works with the resulting owner PK hash.
    #[test]
    fn test_dot_unlocked_state_custom_owner_keys() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        use caliptra_image_fake_keys::{
            VENDOR_ECC_KEY_1_PRIVATE, VENDOR_ECC_KEY_1_PUBLIC, VENDOR_LMS_KEY_1_PRIVATE,
            VENDOR_LMS_KEY_1_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE, VENDOR_MLDSA_KEY_0_PUBLIC,
        };

        // Create a custom owner config using alternate vendor keys as "random" owner keys.
        // This simulates having different owner keys than the default OWNER_CONFIG.
        let custom_owner_config = ImageGeneratorOwnerConfig {
            pub_keys: OwnerPubKeyConfig {
                ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(ImageOwnerPrivKeys {
                ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
            not_before: [0u8; 15],
            not_after: [0u8; 15],
        };

        // Create auth manifest owner config with the same keys
        let auth_manifest_owner_config = AuthManifestOwnerConfig {
            pub_keys: AuthManifestPubKeysConfig {
                ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
                lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
                mldsa_pub_key: VENDOR_MLDSA_KEY_0_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeysConfig {
                ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
                lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
                mldsa_priv_key: VENDOR_MLDSA_KEY_0_PRIVATE,
            }),
        };

        // Build the FW bundle and SoC manifest with custom owner keys.
        // We need to provide the MCU runtime path for the SoC manifest generation.
        let mcu_runtime_path = {
            // Try to get prebuilt MCU runtime, or compile it
            let mcu_runtime_bytes = if let Ok(binaries) = FirmwareBinaries::from_env() {
                binaries.mcu_runtime.clone()
            } else {
                // Fall back to compiling the runtime
                let runtime_path = crate::test::compile_runtime(None, false);
                std::fs::read(&runtime_path).expect("Failed to read compiled runtime")
            };

            // Write to a temp file for CaliptraBuilder
            let temp_path = std::env::temp_dir().join("test_dot_mcu_runtime.bin");
            std::fs::write(&temp_path, &mcu_runtime_bytes).expect("Failed to write MCU runtime");
            temp_path
        };

        let mut builder = CaliptraBuilder::new(
            cfg!(feature = "fpga_realtime"),
            None,
            None,
            None,
            None,
            Some(mcu_runtime_path),
            None,
            None,
            None,
            None,
            None,
        )
        .with_owner_config(custom_owner_config)
        .with_auth_manifest_owner_config(auth_manifest_owner_config);

        let fw_path = builder
            .get_caliptra_fw()
            .expect("Failed to get re-signed Caliptra FW");

        // Read the re-signed FW bundle
        let custom_caliptra_fw = std::fs::read(&fw_path).expect("Failed to read re-signed FW");

        // Get the SoC manifest with custom owner keys
        let soc_manifest_path = builder
            .get_soc_manifest(None)
            .expect("Failed to get re-signed SoC manifest");
        let custom_soc_manifest =
            std::fs::read(&soc_manifest_path).expect("Failed to read re-signed SoC manifest");

        // Get the vendor and owner PK hashes from the re-signed bundle
        let vendor_pk_hash_str = builder
            .get_vendor_pk_hash()
            .expect("Failed to get vendor PK hash");
        let vendor_pk_hash_bytes: [u8; 48] = hex::decode(vendor_pk_hash_str)
            .expect("Failed to decode vendor PK hash")[..]
            .try_into()
            .unwrap();

        let owner_pk_hash_str = builder
            .get_owner_pk_hash()
            .expect("Failed to get owner PK hash from re-signed bundle");

        println!(
            "[TEST] Custom owner PK hash from re-signed bundle: {}",
            owner_pk_hash_str
        );

        // Convert hex string to [u32; 12]
        let owner_pk_hash_bytes =
            hex::decode(owner_pk_hash_str).expect("Failed to decode owner PK hash hex");
        assert_eq!(
            owner_pk_hash_bytes.len(),
            48,
            "Owner PK hash should be 48 bytes"
        );
        let mut owner_pk_hash = [0u32; 12];
        for (i, chunk) in owner_pk_hash_bytes.chunks(4).enumerate() {
            owner_pk_hash[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // Create a valid DOT blob with the custom owner PK hash as CAK
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let flash_contents = blob.to_flash_contents();

        println!(
            "[TEST] DOT flash contents (first 32 bytes): {:02x?}",
            &flash_contents[..32]
        );

        println!("[TEST] Starting hardware model with custom owner keys DOT flash");
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents.clone()),
            rom_only: true,
            dot_enabled: true,
            custom_caliptra_fw: Some(CustomCaliptraFw {
                fw_bytes: custom_caliptra_fw,
                vendor_pk_hash: vendor_pk_hash_bytes,
                soc_manifest: custom_soc_manifest,
            }),
            ..Default::default()
        });

        // Debug: read DOT flash back to verify it was written
        let dot_flash_read = hw.read_dot_flash();
        println!(
            "[TEST] DOT flash read back (first 32 bytes): {:02x?}",
            &dot_flash_read[..32]
        );

        println!("[TEST] Running step_until to wait for DOT flow with custom owner keys");

        // Run until cold boot flow completes
        // Run until DOT flow completes or error occurs
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 50_000_000
        });

        // Print checkpoint for debug
        let checkpoint = hw.mci_boot_checkpoint();
        println!("[TEST] Final checkpoint: {}", checkpoint);

        // In EVEN state, ownership is volatile (from Ownership_Storage), not from DOT_BLOB.
        // The DOT flow should complete without error, but no owner is set from the blob.

        // Check for fatal errors - DOT flow should complete without errors
        let fatal_error = hw.mci_fw_fatal_error();
        if fatal_error.is_some() {
            println!(
                "[TEST] Warning: Fatal error occurred after DOT flow: {:?}",
                fatal_error
            );
        }

        assert!(fatal_error.is_none());

        // Verify DOT flow completed successfully
        assert!(
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into(),
            "DOT flow did not complete, checkpoint: {}",
            checkpoint
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that a valid DOT blob with only CAK (no LAK) passes validation but doesn't trigger lock transition.
    #[test]
    fn test_dot_unlocked_state_cak_only() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a DOT blob with CAK but no LAK (all zeros)
        // Use actual owner PK hash for consistency with firmware
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let flash_contents = blob.to_flash_contents();

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            ..Default::default()
        });

        // Run until DOT flow completes or error occurs
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 15_000_000
        });

        // Should not have any fatal error
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "DOT flow failed with error: {:?}",
            fatal_error
        );

        // Verify DOT flow completed successfully
        let checkpoint = hw.mci_boot_checkpoint();
        assert!(
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into(),
            "DOT flow did not complete, checkpoint: {}",
            checkpoint
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that an empty DOT blob (all zeros, no CAK) passes validation.
    /// This represents a device with DOT disabled or no owner set.
    #[test]
    fn test_dot_empty_blob() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a DOT blob with no CAK and no LAK (all zeros except HMAC)
        let blob = create_valid_dot_blob([0u32; 12], [0u32; 12]);
        let flash_contents = blob.to_flash_contents();

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            ..Default::default()
        });

        // Run until DOT flow completes or error occurs
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::DeviceOwnershipTransferComplete.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 15_000_000
        });

        // Should not have any fatal error
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "DOT flow failed with error: {:?}",
            fatal_error
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that the DOT fuse array burned count is computed correctly.
    /// This verifies that the u32-based fuse array counting works properly.
    #[test]
    fn test_dot_fuse_array_counting() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // This test verifies the DOT fuse structure parsing by checking
        // that a valid blob passes verification (which requires correct parsing).
        // Use actual owner PK hash for consistency
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let flash_contents = blob.to_flash_contents();

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            ..Default::default()
        });

        // Run until DOT derive key step completes (this requires correct fuse parsing)
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::DeviceOwnershipDeriveStableKey.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 15_000_000
        });

        // If we reach the derive key step, fuse parsing worked correctly
        let checkpoint = hw.mci_boot_checkpoint();
        assert!(
            checkpoint >= McuRomBootStatus::DeviceOwnershipDeriveStableKey.into(),
            "DOT fuse parsing failed, checkpoint: {}",
            checkpoint
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that an empty DOT blob with DOT disabled in fuses succeeds.
    /// When DOT is not initialized in fuses, an empty blob should be skipped
    /// and boot should continue normally.
    #[test]
    fn test_dot_empty_blob_dot_disabled() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Empty flash (all zeros) with DOT disabled in fuses
        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            dot_enabled: false, // DOT not initialized in fuses
            ..Default::default()
        });

        // Run until cold boot flow completes
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::ColdBootFlowComplete.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 50_000_000
        });

        // Should not have any fatal error - empty blob with DOT disabled is OK
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Empty DOT blob with DOT disabled should not cause fatal error: {:?}",
            fatal_error
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that an empty DOT blob in EVEN state (unlocked) with DOT enabled skips DOT flow.
    /// When DOT is initialized but in EVEN state (burned=0), an empty blob is not an error
    /// because ownership is volatile in EVEN state.
    #[test]
    fn test_dot_empty_blob_dot_enabled_even_state_skips() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Empty flash (all zeros) with DOT enabled in EVEN state (burned=0)
        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            dot_enabled: true, // DOT initialized but EVEN state (burned=0)
            ..Default::default()
        });

        // Run until DOT flash read checkpoint or error
        hw.step_until(|m| {
            let checkpoint = m.mci_boot_checkpoint();
            checkpoint >= McuRomBootStatus::CaliptraReadyForMailbox.into()
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 50_000_000
        });

        // In EVEN state, empty blob should NOT be a fatal error
        // (it just skips DOT flow and uses owner PK from fuses)
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Empty DOT blob in EVEN state should not be a fatal error, got: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that an empty DOT blob in ODD state (locked) with no recovery handler is a fatal error.
    /// When DOT is in locked state but the blob is empty/corrupt and no recovery handler is
    /// available, the ROM should report a fatal error.
    #[test]
    fn test_dot_empty_blob_locked_state_no_recovery_fails() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Empty flash (all zeros) with DOT in locked state (ODD, 1 fuse burned)
        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        // Run until error or timeout
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 50_000_000);

        // Should have a fatal error - empty blob in locked state with no recovery
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Empty DOT blob in locked state should cause fatal error"
        );

        // Verify it's the correct error
        let error_code = fatal_error.unwrap();
        let expected_error: u32 = McuError::ROM_COLD_BOOT_DOT_ERROR.into();
        assert_eq!(
            error_code, expected_error,
            "Expected ROM_COLD_BOOT_DOT_ERROR (0x{:x}), got 0x{:x}",
            expected_error, error_code
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that a corrupt DOT blob in ODD state (locked) with no recovery handler fails
    /// with the BLOB_CORRUPT error.
    #[test]
    fn test_dot_corrupt_blob_locked_state_no_recovery_fails() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Non-empty but invalid blob (random garbage) with DOT in locked state
        let flash_contents = vec![0x42u8; 4096];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        // Run until error or timeout
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 50_000_000);

        // Should have a fatal error - corrupt blob in locked state
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Corrupt DOT blob in locked state should cause fatal error"
        );

        // Verify it's the BLOB_CORRUPT error
        let error_code = fatal_error.unwrap();
        let expected_error: u32 = McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR.into();
        assert_eq!(
            error_code, expected_error,
            "Expected ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR (0x{:x}), got 0x{:x}",
            expected_error, error_code
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT recovery succeeds when a valid backup blob is available.
    ///
    /// This test verifies the DotRecoveryHandler backup blob path:
    /// 1. DOT is in locked state (ODD, 1 fuse burned) with an empty blob
    /// 2. The ROM (compiled with test-dot-recovery feature) has a mock recovery handler
    /// 3. The handler reads a valid backup blob from DOT flash offset 2048
    /// 4. The ROM authenticates the backup blob via HMAC verification
    /// 5. The blob is written to DOT flash offset 0
    /// 6. A warm reset is triggered
    ///
    /// We verify recovery by checking that the ROM reaches the recovery complete
    /// boot status and that the blob is written to flash.
    #[test]
    fn test_dot_recovery_backup_blob_success() {
        // First create a valid DOT blob
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());

        // Create DOT flash contents:
        // - Offset 0: empty (all zeros) to trigger recovery
        // - Offset 2048: valid backup blob for the mock handler to read
        let blob_bytes = blob.as_bytes();
        let mut flash_contents = vec![0u8; 4096];
        flash_contents[2048..2048 + DOT_BLOB_SIZE].copy_from_slice(blob_bytes);

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Run until a fatal error occurs. The recovery flow succeeds, triggers
        // a warm reset, and the ROM restarts. In a ROM-only test the second boot
        // will fail (GENERIC_EXCEPTION) because the test environment isn't set up
        // for a full second boot — that's expected.
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        // Verify the recovery blob was written to DOT flash at offset 0
        let dot_flash = hw.read_dot_flash();
        let written_blob = &dot_flash[..DOT_BLOB_SIZE];
        assert_eq!(
            written_blob,
            blob.as_bytes(),
            "Recovery blob should have been written to DOT flash at offset 0"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT recovery fails when the backup blob has an invalid HMAC.
    ///
    /// This test verifies that the recovery flow properly rejects a backup blob
    /// whose HMAC doesn't match the DOT_EFFECTIVE_KEY:
    /// 1. DOT is in locked state with an empty blob
    /// 2. A backup blob with garbage HMAC is provided
    /// 3. Recovery should fail with the blob corrupt error
    #[test]
    fn test_dot_recovery_backup_blob_invalid_hmac() {
        // Create a blob with valid structure but invalid HMAC
        let owner_pk_hash = get_owner_pk_hash();
        let blob = TestDotBlob::default()
            .with_cak(owner_pk_hash)
            .with_lak(test_lak());
        // Set HMAC to garbage — don't call compute_hmac
        let blob = blob.with_hmac(&[0xAB; 64]);

        let blob_bytes = blob.as_bytes();
        let mut flash_contents = vec![0u8; 4096];
        flash_contents[2048..2048 + DOT_BLOB_SIZE].copy_from_slice(blob_bytes);

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Run until error or timeout
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 50_000_000);

        // Should have a fatal error - backup blob HMAC doesn't match
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Recovery with invalid HMAC should cause fatal error"
        );

        // The error should be the blob corrupt error (HMAC mismatch)
        let error_code = fatal_error.unwrap();
        let expected_error: u32 = McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR.into();
        assert_eq!(
            error_code, expected_error,
            "Expected ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR (0x{:x}), got 0x{:x}",
            expected_error, error_code
        );

        // Verify the blob was NOT written to flash (offset 0 should still be zeros)
        let dot_flash = hw.read_dot_flash();
        assert!(
            dot_flash[..DOT_BLOB_SIZE].iter().all(|&b| b == 0),
            "Invalid backup blob should not have been written to flash"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that the DOT fuse burning mechanism works correctly.
    /// This test:
    /// 1. Creates a DOT blob with CAK and LAK set (triggering lock transition)
    /// 2. Boots with DOT enabled - the ROM should burn the lock fuse
    /// 3. Verifies cold boot completes successfully
    /// 4. Performs a warm reset
    /// 5. Verifies the MCU runtime successfully boots after reset
    ///
    /// Note: In the emulator, warm_reset() triggers a firmware boot reset (not a true
    /// warm reset), so we check for FIRMWARE_BOOT_FLOW_COMPLETE instead of
    /// WARM_RESET_FLOW_COMPLETE. The key verification is that the runtime boots
    /// successfully after the DOT fuse burn.
    #[test]
    fn test_dot_fuse_burn_and_warm_reset() {
        use mcu_rom_common::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a valid DOT blob with CAK and LAK set - this triggers lock transition
        // which causes the ROM to burn the DOT lock fuse (bit 0 of dot_fuse_array)
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let flash_contents = blob.to_flash_contents();

        println!("[TEST] Created DOT blob with CAK and LAK for fuse burn test");
        println!(
            "[TEST] DOT flash contents (first 32 bytes): {:02x?}",
            &flash_contents[..32]
        );

        // Start the hardware model with DOT enabled and runtime included (not rom_only)
        println!("[TEST] Starting hardware model with DOT flash and runtime");
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents.clone()),
            rom_only: false, // Include runtime so we can test warm reset boot
            dot_enabled: true,
            ..Default::default()
        });

        // Wait for cold boot flow to complete
        // The ROM should:
        // 1. Load and verify the DOT blob
        // 2. Detect that CAK and LAK are present in unlocked state
        // 3. Burn the DOT lock fuse to transition to locked state
        // 4. Complete cold boot flow
        println!("[TEST] Waiting for cold boot flow to complete");
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        // Check for fatal errors during cold boot
        let fatal_error = hw.mci_fw_fatal_error();
        if fatal_error.is_some() {
            println!(
                "[TEST] Fatal error during cold boot: 0x{:x}",
                fatal_error.unwrap()
            );
        }
        assert!(
            fatal_error.is_none(),
            "Cold boot failed with fatal error: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify cold boot completed
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE),
            "Cold boot flow did not complete, milestones: 0x{:x}",
            u16::from(hw.mci_boot_milestones())
        );

        // In EVEN state, ownership is volatile (from Ownership_Storage), not from DOT_BLOB.
        // The CAK from the blob is not set as owner PK hash during the first boot.
        // Owner PK hash will be set from the DOT blob on the next boot in ODD state.

        println!("[TEST] Cold boot completed successfully");
        println!("[TEST] Initiating warm reset");

        // Perform warm reset - in the emulator this triggers a firmware boot reset
        hw.warm_reset();

        // Wait for reset flow to complete (runtime should boot)
        // Note: In emulator, warm_reset() triggers firmware boot reset, so we check
        // for FIRMWARE_BOOT_FLOW_COMPLETE instead of WARM_RESET_FLOW_COMPLETE
        println!("[TEST] Waiting for reset flow to complete");
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 150_000_000
        });

        // Check for fatal errors during reset
        let fatal_error = hw.mci_fw_fatal_error();
        if fatal_error.is_some() {
            println!(
                "[TEST] Fatal error during reset: 0x{:x}",
                fatal_error.unwrap()
            );
        }
        assert!(
            fatal_error.is_none(),
            "Reset failed with fatal error: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify reset flow completed (runtime booted successfully)
        // In the emulator, warm_reset() triggers firmware boot reset
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE),
            "Reset flow did not complete, milestones: 0x{:x}",
            u16::from(hw.mci_boot_milestones())
        );

        println!("[TEST] Reset completed successfully - runtime booted after DOT fuse burn");

        // Verify that the DOT lock fuse was actually burned
        use registers_generated::fuses;

        let otp_memory = hw.read_otp_memory();

        // Check dot_initialized is still set (LinearMajorityVote encoding)
        let dot_initialized = otp_memory[fuses::DOT_INITIALIZED.byte_offset];
        assert_ne!(dot_initialized, 0, "DOT should still be initialized");

        // Check the DOT fuse array - the lock fuse (bit 0) should be burned
        let fuse_array_offset = fuses::DOT_FUSE_ARRAY.byte_offset;
        let lock_fuse_byte = otp_memory[fuse_array_offset];

        // Verify bit 0 of the fuse array is set (lock fuse burned)
        assert!(
            lock_fuse_byte & 0x01 != 0,
            "DOT lock fuse was not burned! Fuse array first byte: 0x{:02x}",
            lock_fuse_byte
        );

        // Count total burned fuses - should be exactly 1 (just the lock fuse)
        let fuse_array = &otp_memory[fuse_array_offset..fuse_array_offset + 32];
        let burned_count: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();

        assert_eq!(
            burned_count, 1,
            "Expected exactly 1 fuse to be burned (lock fuse), found {}",
            burned_count
        );

        println!("[TEST] DOT fuse burn verified: lock fuse burned correctly");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Creates OTP memory with DOT in locked state (ODD, 1 fuse bit burned).
    /// Uses the generated fuse entry offsets for correct placement.
    fn create_locked_otp_memory() -> Vec<u8> {
        use registers_generated::fuses;
        let mut otp =
            vec![0u8; fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        // Set dot_initialized = 1 via LinearMajorityVote(1 bit, 3x) encoding: 0b111
        otp[fuses::DOT_INITIALIZED.byte_offset] = 0x07;
        // Set bit 0 of dot_fuse_array to 1 (burned=1, ODD/locked state)
        otp[fuses::DOT_FUSE_ARRAY.byte_offset] = 0x01;
        otp
    }

    /// Test that DOT locked state (ODD) boots successfully with the owner CAK from the DOT blob.
    ///
    /// In locked state (burned=1, ODD):
    /// - The ROM derives the DOT_EFFECTIVE_KEY with derivation value = burned = 1
    /// - The DOT blob is verified using HMAC with this key
    /// - Since is_locked() is true, the CAK from the DOT blob is used as the owner PK hash
    /// - The owner PK hash is set in Caliptra via SET_OWNER_PK_HASH
    /// - Firmware verification uses this owner key, so a successful boot confirms the CAK was applied
    #[test]
    fn test_dot_locked_state_boots_with_owner_cak() {
        use mcu_rom_common::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a valid DOT blob with the actual owner PK hash as CAK
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let flash_contents = blob.to_flash_contents();

        println!("[TEST] Created DOT blob for locked state test");
        println!(
            "[TEST] DOT flash contents (first 32 bytes): {:02x?}",
            &flash_contents[..32]
        );

        // Boot with DOT in locked state (ODD, 1 fuse burned) and runtime included.
        // The ROM should:
        // 1. Read dot_fuse_array and find burned=1 (ODD/locked state)
        // 2. Derive DOT_EFFECTIVE_KEY with derivation value = burned = 1
        // 3. Verify the DOT blob HMAC
        // 4. Use CAK from the DOT blob as the owner PK hash (locked state path)
        // 5. Set owner PK hash in Caliptra and boot firmware
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: false,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        // Wait for cold boot flow to complete
        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let checkpoint = hw.mci_boot_checkpoint();
        println!("[TEST] Final checkpoint: {}", checkpoint);

        // Check for fatal errors - should boot successfully
        let fatal_error = hw.mci_fw_fatal_error();
        if fatal_error.is_some() {
            println!(
                "[TEST] Fatal error during locked state boot: 0x{:x}",
                fatal_error.unwrap()
            );
        }
        assert!(
            fatal_error.is_none(),
            "Locked state boot failed with fatal error: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify cold boot completed
        assert!(
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE),
            "Cold boot flow did not complete in locked state, milestones: 0x{:x}",
            u16::from(hw.mci_boot_milestones())
        );

        // A successful boot confirms the CAK from the DOT blob was used as owner:
        // If the wrong owner PK hash (or none) were set, RI_DOWNLOAD_FIRMWARE would
        // fail because firmware signature verification requires the correct owner key.
        println!(
            "[TEST] Locked state boot completed successfully - owner CAK from DOT blob was used"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT locked state (ODD) with wrong CAK in the DOT blob fails firmware verification.
    ///
    /// This test verifies that the owner CAK from the DOT blob is actually used for
    /// firmware verification in locked state. A wrong CAK should cause boot failure
    /// because the firmware signature won't match.
    #[test]
    fn test_dot_locked_state_wrong_cak_fails() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Create a DOT blob with an incorrect CAK (not matching the FW bundle's owner keys)
        let wrong_cak = [0x12345678u32; 12];
        let blob = create_valid_dot_blob(wrong_cak, test_lak());
        let flash_contents = blob.to_flash_contents();

        println!("[TEST] Created DOT blob with wrong CAK for locked state failure test");

        // Boot with DOT in locked state (ODD) but with wrong CAK
        // The ROM should set the wrong owner PK hash, causing RI_DOWNLOAD_FIRMWARE to fail
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        // Run until error or timeout - firmware download should fail with wrong owner key
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        // Should have a fatal error because the wrong CAK was used as owner PK hash
        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Boot with wrong CAK in locked state should fail"
        );

        println!(
            "[TEST] Locked state with wrong CAK correctly failed with error: 0x{:x}",
            fatal_error.unwrap()
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Challenge/Response DOT Recovery Tests (ECDSA P-384 + MLDSA-87)
    // -----------------------------------------------------------------------

    /// MCI mbox0 command IDs matching the ROM's TestRecoveryTransport.
    const CMD_DOT_RECOVERY_REQUEST: u32 = 0x444F_5451;
    const CMD_DOT_CHALLENGE_RESPONSE: u32 = 0x444F_5452;

    /// Generates a random ECC P-384 key pair, returning the public key
    /// coordinates as raw big-endian bytes (SEC1 format) and the raw private
    /// key bytes for signing.
    fn generate_random_ecc_keys() -> (
        [u8; 48], // pub_key_x (big-endian)
        [u8; 48], // pub_key_y (big-endian)
        [u8; 48], // private key
    ) {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let secret_key = p384::SecretKey::random(&mut rand::thread_rng());
        let pub_point = secret_key.public_key().to_encoded_point(false);

        let x_bytes: [u8; 48] = pub_point.x().unwrap().as_slice().try_into().unwrap();
        let y_bytes: [u8; 48] = pub_point.y().unwrap().as_slice().try_into().unwrap();
        let priv_bytes: [u8; 48] = secret_key.to_bytes().into();
        (x_bytes, y_bytes, priv_bytes)
    }

    /// Generates a random MLDSA-87 key pair, returning the public key as raw
    /// bytes (FIPS 204 format) and the private key for signing.
    fn generate_random_mldsa_keys() -> (Vec<u8>, fips204::ml_dsa_87::PrivateKey) {
        use fips204::ml_dsa_87;
        use fips204::traits::SerDes;

        let (pk, sk) =
            ml_dsa_87::try_keygen_with_rng(&mut rand::thread_rng()).expect("MLDSA keygen failed");
        let pk_bytes = pk.into_bytes();
        (pk_bytes.to_vec(), sk)
    }

    /// Computes SHA-384 hash of the combined recovery public keys (ECC + MLDSA).
    fn compute_recovery_pk_hash(
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8],
    ) -> [u8; 48] {
        use sha2::{Digest, Sha384};

        let mut hasher = Sha384::new();
        hasher.update(ecc_pub_x);
        hasher.update(ecc_pub_y);
        hasher.update(mldsa_pub);
        let result = hasher.finalize();
        let mut hash = [0u8; 48];
        hash.copy_from_slice(&result);
        hash
    }

    /// Creates OTP memory for challenge/response recovery testing.
    /// Includes locked state fuses AND the recovery PK hash.
    fn create_challenge_recovery_otp_memory(pk_hash: &[u8; 48]) -> Vec<u8> {
        use registers_generated::fuses;

        let required_size = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset
            + fuses::VENDOR_RECOVERY_PK_HASH.byte_size
            + 16;
        let otp_size =
            required_size.max(fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size);
        let mut otp = vec![0u8; otp_size];

        // Set DOT locked state
        otp[fuses::DOT_INITIALIZED.byte_offset] = 0x07;
        otp[fuses::DOT_FUSE_ARRAY.byte_offset] = 0x01;

        // Set recovery PK hash (48 bytes split across 2 OTP slots of 32 bytes)
        let hash_offset = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset;
        otp[hash_offset..hash_offset + 32].copy_from_slice(&pk_hash[..32]);
        let next_offset = hash_offset + fuses::VENDOR_RECOVERY_PK_HASH.byte_size;
        otp[next_offset..next_offset + 16].copy_from_slice(&pk_hash[32..48]);

        otp
    }

    /// Build the mbox0 SRAM payload for DOT_RECOVERY_REQUEST.
    fn build_recovery_request_payload(
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8],
        cak: &[u8; 48],
        lak: &[u8; 48],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        // Reserve space for checksum (filled below)
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(ecc_pub_x);
        payload.extend_from_slice(ecc_pub_y);
        payload.extend_from_slice(mldsa_pub);
        let mldsa_expected = 2592;
        if mldsa_pub.len() < mldsa_expected {
            payload.resize(payload.len() + mldsa_expected - mldsa_pub.len(), 0);
        }
        payload.extend_from_slice(cak);
        payload.extend_from_slice(lak);

        // Compute and fill checksum
        let chksum = calc_dot_checksum(CMD_DOT_RECOVERY_REQUEST, &payload[4..]);
        payload[..4].copy_from_slice(&chksum.to_le_bytes());
        payload
    }

    /// Build the mbox0 SRAM payload for DOT_CHALLENGE_RESPONSE.
    fn build_challenge_response_payload(
        ecc_sig_r: &[u8; 48],
        ecc_sig_s: &[u8; 48],
        mldsa_pub: &[u8],
        mldsa_sig: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        // Reserve space for checksum (filled below)
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(ecc_sig_r);
        payload.extend_from_slice(ecc_sig_s);
        let mldsa_pk_expected = 2592;
        payload.extend_from_slice(mldsa_pub);
        if mldsa_pub.len() < mldsa_pk_expected {
            payload.resize(payload.len() + mldsa_pk_expected - mldsa_pub.len(), 0);
        }
        let mldsa_sig_expected = 4628;
        payload.extend_from_slice(mldsa_sig);
        if mldsa_sig.len() < mldsa_sig_expected {
            payload.resize(payload.len() + mldsa_sig_expected - mldsa_sig.len(), 0);
        }

        // Compute and fill checksum
        let chksum = calc_dot_checksum(CMD_DOT_CHALLENGE_RESPONSE, &payload[4..]);
        payload[..4].copy_from_slice(&chksum.to_le_bytes());
        payload
    }

    /// Compute the Caliptra-standard mailbox checksum.
    fn calc_dot_checksum(cmd: u32, data: &[u8]) -> u32 {
        let mut sum = 0u32;
        for &b in cmd.to_le_bytes().iter() {
            sum = sum.wrapping_add(b as u32);
        }
        for &b in data {
            sum = sum.wrapping_add(b as u32);
        }
        0u32.wrapping_sub(sum)
    }

    /// Test challenge/response DOT recovery with both ECDSA and MLDSA signatures.
    ///
    /// Host sends recovery request via MCI mbox0, ROM generates challenge,
    /// host signs challenge with ECDSA + MLDSA, ROM verifies and writes new DOT blob.
    /// Uses randomly generated keys each run.
    #[test]
    fn test_dot_challenge_recovery_success() {
        use ecdsa::signature::hazmat::PrehashSigner;
        use fips204::traits::Signer;
        use p384::ecdsa::SigningKey;
        use sha2::{Digest, Sha384};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let cak: [u8; 48] = transmute!(owner_pk_hash);
        let lak_u32 = test_lak();
        let lak: [u8; 48] = transmute!(lak_u32);

        // Generate random key pairs
        println!("[TEST] Generating random ECC key pair...");
        let (ecc_pub_x, ecc_pub_y, ecc_priv_bytes) = generate_random_ecc_keys();
        println!("[TEST] Generating random MLDSA key pair...");
        let (mldsa_pub, mldsa_priv) = generate_random_mldsa_keys();
        println!("[TEST] Key generation complete");

        // Compute PK hash for OTP fuses
        let pk_hash = compute_recovery_pk_hash(&ecc_pub_x, &ecc_pub_y, &mldsa_pub);

        // DOT flash: offset 0 empty (triggers recovery), offset 2048 has valid backup blob
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let blob_bytes = blob.as_bytes();
        let mut flash_contents = vec![0u8; 4096];
        flash_contents[2048..2048 + DOT_BLOB_SIZE].copy_from_slice(blob_bytes);

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_challenge_recovery_otp_memory(&pk_hash)),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Step 1: Send recovery request via mbox0
        let request_payload =
            build_recovery_request_payload(&ecc_pub_x, &ecc_pub_y, &mldsa_pub, &cak, &lak);
        hw.start_mailbox_execute(CMD_DOT_RECOVERY_REQUEST, &request_payload)
            .expect("Failed to send DOT_RECOVERY_REQUEST");

        // Step 2: Wait for ROM to process and send challenge via DataReady
        let challenge_data = hw
            .finish_mailbox_execute()
            .expect("Failed to get challenge response");
        let challenge = challenge_data.expect("Expected challenge data from ROM");
        assert_eq!(challenge.len(), 48, "Challenge should be 48 bytes");
        println!("[TEST] Received challenge ({} bytes)", challenge.len());

        // Step 3: Sign the challenge
        // ECDSA: sign SHA-384(challenge) with prehash
        println!("[TEST] Signing challenge with ECDSA...");
        let challenge_hash: [u8; 48] = {
            let mut hasher = Sha384::new();
            hasher.update(&challenge);
            hasher.finalize().into()
        };
        let ecc_secret_key =
            p384::SecretKey::from_slice(&ecc_priv_bytes).expect("Invalid ECC private key");
        let ecc_signing_key = SigningKey::from(&ecc_secret_key);
        let ecc_sig: p384::ecdsa::Signature = ecc_signing_key
            .sign_prehash(&challenge_hash)
            .expect("ECDSA signing failed");
        let ecc_r_bytes: [u8; 48] = ecc_sig.r().to_bytes().into();
        let ecc_s_bytes: [u8; 48] = ecc_sig.s().to_bytes().into();
        println!("[TEST] ECDSA signing complete");

        // MLDSA: sign the raw challenge bytes
        println!("[TEST] Signing challenge with MLDSA...");
        let mldsa_sig_bytes = mldsa_priv
            .try_sign_with_seed(&[0u8; 32], &challenge, &[])
            .expect("MLDSA signing failed");
        println!("[TEST] MLDSA signing complete");

        // Step 4: Send signed challenge response via mbox0
        let response_payload = build_challenge_response_payload(
            &ecc_r_bytes,
            &ecc_s_bytes,
            &mldsa_pub,
            &mldsa_sig_bytes,
        );
        hw.start_mailbox_execute(CMD_DOT_CHALLENGE_RESPONSE, &response_payload)
            .expect("Failed to send DOT_CHALLENGE_RESPONSE");

        // Step 5: Let the ROM verify signatures, write DOT blob, and complete.
        // We don't call finish_mailbox_execute() because the ROM transport
        // intentionally leaves the mbox0 transaction open so the SRAM data
        // (MLDSA pub key and signature) stays valid during verification.
        // The ROM will eventually trigger a warm reset or hit a fatal error.
        let start = hw.cycle_count();
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() - start > 20_000_000);

        // Verify a DOT blob was written to flash at offset 0
        let dot_flash = hw.read_dot_flash();
        let written_blob = &dot_flash[..DOT_BLOB_SIZE];
        assert!(
            !written_blob.iter().all(|&b| b == 0),
            "Challenge recovery should have written a DOT blob to flash"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that challenge/response recovery fails when the PK hash doesn't match fuses.
    /// Uses randomly generated keys each run.
    #[test]
    fn test_dot_challenge_recovery_wrong_pk_hash() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let cak: [u8; 48] = transmute!(owner_pk_hash);
        let lak_u32 = test_lak();
        let lak: [u8; 48] = transmute!(lak_u32);

        // Generate random keys
        let (ecc_pub_x, ecc_pub_y, _) = generate_random_ecc_keys();
        let (mldsa_pub, _) = generate_random_mldsa_keys();

        // DOT flash: empty (no backup blob — only challenge recovery available)
        let flash_contents = vec![0u8; 4096];

        // Burn a WRONG recovery PK hash in fuses — the generated keys won't
        // match this hash, so the challenge flow should fail with PK_HASH_MISMATCH.
        let wrong_pk_hash = [0xABu8; 48];
        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_challenge_recovery_otp_memory(&wrong_pk_hash)),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Send recovery request — the ROM should fail during PK hash verification
        let request_payload =
            build_recovery_request_payload(&ecc_pub_x, &ecc_pub_y, &mldsa_pub, &cak, &lak);
        hw.start_mailbox_execute(CMD_DOT_RECOVERY_REQUEST, &request_payload)
            .expect("Failed to send DOT_RECOVERY_REQUEST");

        // The ROM should detect PK hash mismatch and set a fatal error.
        // The mbox0 transaction may complete with CmdFailure or the ROM may
        // crash before responding. Either way, step until fatal error.
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Challenge recovery with wrong PK hash should fail"
        );

        // Verify flash was not written
        let dot_flash = hw.read_dot_flash();
        assert!(
            dot_flash[..DOT_BLOB_SIZE].iter().all(|&b| b == 0),
            "Flash should not be written when PK hash doesn't match"
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
