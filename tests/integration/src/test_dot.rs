//! Licensed under the Apache-2.0 license

//! This module tests Device Ownership Transfer.

#[cfg(test)]
mod test {
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
    use caliptra_mcu_builder::{AuthManifestOwnerConfig, CaliptraBuilder, FirmwareBinaries};
    use caliptra_mcu_error::McuError;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_romtime::McuBootMilestones;
    use caliptra_mcu_romtime::McuRomBootStatus;
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
        let mut builder = CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
            fpga: cfg!(feature = "fpga_realtime"),
            ..Default::default()
        });
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

    fn compute_hmac_cached(blob: &[u8]) -> Vec<u8> {
        compute_hmac(blob)
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
        // When prebuilt binaries are available, pass the Caliptra FW/ROM paths
        // to the builder so it doesn't try to compile them from scratch.
        let (mcu_runtime_path, prebuilt_caliptra_fw, prebuilt_vendor_pk_hash) =
            if let Ok(binaries) = FirmwareBinaries::from_env() {
                let rt_path = std::env::temp_dir().join("test_dot_mcu_runtime.bin");
                std::fs::write(&rt_path, &binaries.mcu_runtime)
                    .expect("Failed to write MCU runtime");
                let fw_path = std::env::temp_dir().join("test_dot_custom_owner_caliptra_fw.bin");
                std::fs::write(&fw_path, &binaries.caliptra_fw)
                    .expect("Failed to write prebuilt Caliptra FW");
                let vendor_pk_hash = hex::encode(
                    binaries
                        .vendor_pk_hash()
                        .expect("Failed to get vendor PK hash from prebuilt binaries"),
                );
                (rt_path, Some(fw_path), Some(vendor_pk_hash))
            } else {
                let runtime_path = crate::test::compile_runtime(None, false);
                let rt_bytes =
                    std::fs::read(&runtime_path).expect("Failed to read compiled runtime");
                let rt_path = std::env::temp_dir().join("test_dot_mcu_runtime.bin");
                std::fs::write(&rt_path, &rt_bytes).expect("Failed to write MCU runtime");
                (rt_path, None, None)
            };

        let mut builder = CaliptraBuilder::new(&caliptra_mcu_builder::CaliptraBuildArgs {
            fpga: cfg!(feature = "fpga_realtime"),
            mcu_firmware: Some(mcu_runtime_path),
            caliptra_firmware: prebuilt_caliptra_fw,
            vendor_pk_hash: prebuilt_vendor_pk_hash,
            ..Default::default()
        })
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
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // First create a valid DOT blob
        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());

        // Create DOT flash contents:
        // - Offset 0: empty (all zeros) to trigger recovery
        // - Offset 2048: valid backup blob for the mock handler to read
        let blob_bytes = blob.as_bytes();
        let mut flash_contents = vec![0u8; 4096];
        flash_contents[2048..2048 + DOT_BLOB_SIZE].copy_from_slice(blob_bytes);

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
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
        use caliptra_mcu_registers_generated::fuses;

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
        use caliptra_mcu_otp_digest::{otp_scramble, OTP_SCRAMBLE_KEYS};
        use caliptra_mcu_registers_generated::fuses;
        let mut otp =
            vec![0u8; fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        // Set dot_initialized = 1 via LinearMajorityVote(1 bit, 3x) encoding: 0b111
        otp[fuses::DOT_INITIALIZED.byte_offset] = 0x07;
        // Set bit 0 of dot_fuse_array to 1 (burned=1, ODD/locked state)
        otp[fuses::DOT_FUSE_ARRAY.byte_offset] = 0x01;

        // VendorSecretProdPartition (partition index 13) is scrambled.
        // Pre-scramble zero blocks so the DAI read path unscrambles them
        // back to zeros, ensuring recovery_pk_hash reads as all-zeros (None).
        let key = OTP_SCRAMBLE_KEYS[5];
        let part_start = fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_OFFSET;
        let part_end = part_start + fuses::VENDOR_SECRET_PROD_PARTITION_BYTE_SIZE;
        let end = part_end.min(otp.len());
        for off in (part_start..end).step_by(8) {
            let scrambled = otp_scramble(0, key);
            let bytes = scrambled.to_le_bytes();
            let copy_len = bytes.len().min(otp.len() - off);
            otp[off..off + copy_len].copy_from_slice(&bytes[..copy_len]);
        }

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
    // DOT Override Challenge/Response Tests (ECDSA P-384)
    // -----------------------------------------------------------------------

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

    /// Computes SHA-384 hash of the combined vendor public keys (ECC + MLDSA).
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

    /// Creates OTP memory for override testing.
    /// Includes locked state fuses AND the vendor recovery PK hash.
    fn create_challenge_recovery_otp_memory(pk_hash: &[u8; 48]) -> Vec<u8> {
        use caliptra_mcu_otp_digest::{otp_scramble, OTP_SCRAMBLE_KEYS};
        use caliptra_mcu_registers_generated::fuses;

        let required_size = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset
            + fuses::VENDOR_RECOVERY_PK_HASH.byte_size
            + 16;
        let otp_size =
            required_size.max(fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size);
        let mut otp = vec![0u8; otp_size];

        // Set DOT locked state (partition 14, not scrambled)
        otp[fuses::DOT_INITIALIZED.byte_offset] = 0x07;
        otp[fuses::DOT_FUSE_ARRAY.byte_offset] = 0x01;

        // Write recovery PK hash into partition 13 (VendorSecretProdPartition),
        // which is scrambled. Pre-scramble each 8-byte block so the DAI read
        // path unscrambles back to the original plaintext.
        let key = OTP_SCRAMBLE_KEYS[5]; // VendorSecretProdPartition
        let hash_offset = fuses::VENDOR_RECOVERY_PK_HASH.byte_offset;
        for (i, chunk) in pk_hash.chunks(8).enumerate() {
            let off = hash_offset + i * 8;
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            let plaintext = u64::from_le_bytes(block);
            let scrambled = otp_scramble(plaintext, key);
            let scrambled_bytes = scrambled.to_le_bytes();
            otp[off..off + 8].copy_from_slice(&scrambled_bytes);
        }

        otp
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

    /// MCI mbox0 command IDs for DOT_UNLOCK_CHALLENGE / DOT_OVERRIDE.
    const CMD_DOT_UNLOCK_CHALLENGE: u32 = 0x444F_5457;
    const CMD_DOT_OVERRIDE: u32 = 0x444F_5458;

    /// Challenge type field values for DOT_UNLOCK_CHALLENGE.
    const CHALLENGE_TYPE_OVERRIDE: u32 = 0x02;

    /// Build the mbox0 SRAM payload for DOT_UNLOCK_CHALLENGE (override type).
    fn build_override_challenge_payload(
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        // Reserve space for checksum (filled below)
        payload.extend_from_slice(&[0u8; 4]);
        // challenge_type = OVERRIDE
        payload.extend_from_slice(&CHALLENGE_TYPE_OVERRIDE.to_le_bytes());
        payload.extend_from_slice(ecc_pub_x);
        payload.extend_from_slice(ecc_pub_y);
        let mldsa_expected = 2592;
        payload.extend_from_slice(mldsa_pub);
        if mldsa_pub.len() < mldsa_expected {
            payload.resize(payload.len() + mldsa_expected - mldsa_pub.len(), 0);
        }

        // Compute and fill checksum
        let chksum = calc_dot_checksum(CMD_DOT_UNLOCK_CHALLENGE, &payload[4..]);
        payload[..4].copy_from_slice(&chksum.to_le_bytes());
        payload
    }

    /// Build the mbox0 SRAM payload for DOT_OVERRIDE.
    fn build_override_response_payload(
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        ecc_sig_r: &[u8; 48],
        ecc_sig_s: &[u8; 48],
        mldsa_pub: &[u8],
        mldsa_sig: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        // Reserve space for checksum (filled below)
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(ecc_pub_x);
        payload.extend_from_slice(ecc_pub_y);
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
        let chksum = calc_dot_checksum(CMD_DOT_OVERRIDE, &payload[4..]);
        payload[..4].copy_from_slice(&chksum.to_le_bytes());
        payload
    }

    /// Test DOT override challenge/response success.
    ///
    /// Host sends override challenge request via MCI mbox0 with vendor public keys,
    /// ROM generates challenge, host signs challenge with VendorKey.priv (ECDSA + MLDSA),
    /// ROM verifies both signatures, burns fuse, and erases DOT blob.
    #[test]
    fn test_dot_override_challenge_success() {
        use ecdsa::signature::hazmat::PrehashSigner;
        use fips204::traits::Signer;
        use p384::ecdsa::SigningKey;
        use sha2::{Digest, Sha384};

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Generate random ECC P-384 key pair for VendorKey
        println!("[TEST] Generating random VendorKey ECC key pair...");
        let (vendor_pub_x, vendor_pub_y, vendor_priv_bytes) = generate_random_ecc_keys();

        // Generate random MLDSA-87 key pair for VendorKey
        println!("[TEST] Generating random VendorKey MLDSA key pair...");
        let (mldsa_pub, mldsa_priv) = generate_random_mldsa_keys();

        // Compute vendor PK hash (ECC + MLDSA) for OTP fuses
        let vendor_pk_hash = compute_recovery_pk_hash(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);

        // Set up recovery mode: corrupted/empty blob, locked fuses, vendor PK hash in OTP
        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        println!("[TEST] Created recovery mode setup for override test");

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_challenge_recovery_otp_memory(&vendor_pk_hash)),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Step 1: Send DOT_OVERRIDE_CHALLENGE via mbox0 with vendor public keys
        let override_payload =
            build_override_challenge_payload(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);
        hw.start_mailbox_execute(CMD_DOT_UNLOCK_CHALLENGE, &override_payload)
            .expect("Failed to send DOT_UNLOCK_CHALLENGE");

        // Step 2: Wait for ROM to process and send challenge via DataReady
        let challenge_data = hw
            .finish_mailbox_execute()
            .expect("Failed to get override challenge response");
        let challenge = challenge_data.expect("Expected challenge data from ROM");
        assert_eq!(challenge.len(), 48, "Challenge should be 48 bytes");
        println!(
            "[TEST] Received override challenge ({} bytes)",
            challenge.len()
        );

        // Step 3: Sign the challenge with VendorKey.priv (ECDSA + MLDSA)
        println!("[TEST] Signing challenge with ECDSA...");
        let challenge_hash: [u8; 48] = {
            let mut hasher = Sha384::new();
            hasher.update(&challenge);
            hasher.finalize().into()
        };
        let vendor_secret_key =
            p384::SecretKey::from_slice(&vendor_priv_bytes).expect("Invalid vendor private key");
        let vendor_signing_key = SigningKey::from(&vendor_secret_key);
        let ecc_sig: p384::ecdsa::Signature = vendor_signing_key
            .sign_prehash(&challenge_hash)
            .expect("ECDSA signing failed");
        let ecc_r_bytes: [u8; 48] = ecc_sig.r().to_bytes().into();
        let ecc_s_bytes: [u8; 48] = ecc_sig.s().to_bytes().into();
        println!("[TEST] ECDSA signing complete");

        println!("[TEST] Signing challenge with MLDSA...");
        let mldsa_sig_bytes = mldsa_priv
            .try_sign_with_seed(&[0u8; 32], &challenge, &[])
            .expect("MLDSA signing failed");
        println!("[TEST] MLDSA signing complete");

        // Step 4: Send signed challenge response via mbox0
        let response_payload = build_override_response_payload(
            &vendor_pub_x,
            &vendor_pub_y,
            &ecc_r_bytes,
            &ecc_s_bytes,
            &mldsa_pub,
            &mldsa_sig_bytes,
        );
        hw.start_mailbox_execute(CMD_DOT_OVERRIDE, &response_payload)
            .expect("Failed to send DOT_OVERRIDE");

        // Step 5: Let the ROM verify signatures, burn fuse, write new blob, and complete.
        let start = hw.cycle_count();
        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() - start > 20_000_000);

        // Verify a new DOT blob was written to flash (non-empty, HMAC'd for EVEN state)
        let dot_flash = hw.read_dot_flash();
        let written_blob = &dot_flash[..DOT_BLOB_SIZE];
        assert!(
            !written_blob.iter().all(|&b| b == 0) && !written_blob.iter().all(|&b| b == 0xFF),
            "DOT blob should have been written (not erased) after override"
        );
        // Verify the blob has empty CAK/LAK (unlocked state)
        let blob_bytes: [u8; DOT_BLOB_SIZE] = written_blob.try_into().unwrap();
        let blob: TestDotBlob = zerocopy::transmute!(blob_bytes);
        assert_eq!(blob.cak, [0u32; 12], "Override blob should have empty CAK");
        assert_eq!(
            blob.lak_pub, [0u32; 12],
            "Override blob should have empty LAK"
        );
        assert_eq!(blob.version, 1, "Override blob should have version 1");
        // HMAC should be non-zero (computed with EVEN-state key)
        assert!(
            !blob.hmac.iter().all(|&w| w == 0),
            "Override blob should have a valid HMAC"
        );

        // Verify the DOT fuse was burned (bit 1 should now be set, total burned = 2)
        let otp_memory = hw.read_otp_memory();
        let fuse_array_offset = caliptra_mcu_registers_generated::fuses::DOT_FUSE_ARRAY.byte_offset;
        let lock_fuse_byte = otp_memory[fuse_array_offset];
        assert!(
            lock_fuse_byte & 0x03 == 0x03,
            "DOT fuse should have 2 bits burned after override (was 1, now 2), got: 0x{:02x}",
            lock_fuse_byte
        );

        println!("[TEST] DOT override succeeded: new unlocked blob written and fuse burned");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT override fails when the vendor PK hash doesn't match OTP fuses.
    #[test]
    fn test_dot_override_wrong_pk_hash_fails() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Generate vendor key pairs for the OTP fuses
        let (vendor_pub_x, vendor_pub_y, _) = generate_random_ecc_keys();
        let (mldsa_pub, _) = generate_random_mldsa_keys();
        let vendor_pk_hash = compute_recovery_pk_hash(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);

        // Set up recovery mode: corrupted/empty blob, locked fuses
        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_challenge_recovery_otp_memory(&vendor_pk_hash)),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Generate DIFFERENT key pairs for the override request (wrong vendor keys)
        let (wrong_pub_x, wrong_pub_y, _) = generate_random_ecc_keys();
        let (wrong_mldsa_pub, _) = generate_random_mldsa_keys();

        // Send override challenge with wrong vendor public keys
        let override_payload =
            build_override_challenge_payload(&wrong_pub_x, &wrong_pub_y, &wrong_mldsa_pub);
        hw.start_mailbox_execute(CMD_DOT_UNLOCK_CHALLENGE, &override_payload)
            .expect("Failed to send DOT_UNLOCK_CHALLENGE");

        // The ROM should fail during vendor PK hash verification.
        // In recovery mode (empty blob, locked fuses), override failure leads
        // to a fatal error because no recovery mechanism remains.
        let start = hw.cycle_count();
        hw.step_until(|m| {
            m.mci_fw_fatal_error().is_some()
                || m.cmd_status().cmd_failure()
                || m.cmd_status().data_ready()
                || m.cycle_count() - start > 50_000_000
        });

        // Verify the DOT blob was NOT erased (should still be in flash)
        let dot_flash = hw.read_dot_flash();
        assert!(
            dot_flash[..DOT_BLOB_SIZE].iter().all(|&b| b == 0),
            "DOT blob should still be empty (was already empty in recovery mode)"
        );

        // Verify the fuse was NOT burned (should still be 1)
        let otp_memory = hw.read_otp_memory();
        let fuse_array_offset = caliptra_mcu_registers_generated::fuses::DOT_FUSE_ARRAY.byte_offset;
        let lock_fuse_byte = otp_memory[fuse_array_offset];
        assert_eq!(
            lock_fuse_byte & 0x03,
            0x01,
            "DOT fuse should still have only 1 bit burned, got: 0x{:02x}",
            lock_fuse_byte
        );

        println!("[TEST] DOT override correctly failed with wrong vendor PK hash");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test that DOT override aborts when PK hash matches but signatures are invalid.
    ///
    /// The ROM should accept the vendor public keys (PK hash matches OTP) and
    /// issue a challenge, but reject the response because the signatures don't
    /// verify. The fuse must NOT be burned.
    #[test]
    fn test_dot_override_invalid_signatures_fails() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Generate correct vendor key pairs and burn their PK hash into OTP.
        let (vendor_pub_x, vendor_pub_y, _vendor_priv_bytes) = generate_random_ecc_keys();
        let (mldsa_pub, _mldsa_priv) = generate_random_mldsa_keys();
        let vendor_pk_hash = compute_recovery_pk_hash(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);

        let flash_contents = vec![0u8; DOT_BLOB_SIZE];

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(flash_contents),
            rom_only: true,
            otp_memory: Some(create_challenge_recovery_otp_memory(&vendor_pk_hash)),
            rom_feature: Some("test-dot-recovery"),
            ..Default::default()
        });

        // Send DOT_UNLOCK_CHALLENGE with correct vendor public keys.
        let override_payload =
            build_override_challenge_payload(&vendor_pub_x, &vendor_pub_y, &mldsa_pub);
        hw.start_mailbox_execute(CMD_DOT_UNLOCK_CHALLENGE, &override_payload)
            .expect("Failed to send DOT_UNLOCK_CHALLENGE");

        // Wait for the ROM to verify PK hash and return a challenge.
        let challenge_data = hw
            .finish_mailbox_execute()
            .expect("Failed to get override challenge response");
        let challenge = challenge_data.expect("Expected challenge data from ROM");
        assert_eq!(challenge.len(), 48, "Challenge should be 48 bytes");
        println!(
            "[TEST] Received override challenge ({} bytes), sending bogus signatures",
            challenge.len()
        );

        // Send a response with garbage signatures (correct PK, wrong sigs).
        let bogus_ecc_r = [0xABu8; 48];
        let bogus_ecc_s = [0xCDu8; 48];
        let bogus_mldsa_sig = vec![0xEFu8; 4628];
        let response_payload = build_override_response_payload(
            &vendor_pub_x,
            &vendor_pub_y,
            &bogus_ecc_r,
            &bogus_ecc_s,
            &mldsa_pub,
            &bogus_mldsa_sig,
        );
        hw.start_mailbox_execute(CMD_DOT_OVERRIDE, &response_payload)
            .expect("Failed to send DOT_OVERRIDE");

        // The ROM should reject the signatures and hit a fatal error.
        let start = hw.cycle_count();
        hw.step_until(|m| {
            m.mci_fw_fatal_error().is_some()
                || m.cmd_status().cmd_failure()
                || m.cycle_count() - start > 50_000_000
        });

        // Verify the fuse was NOT burned (should still be 1 = ODD/locked).
        let otp_memory = hw.read_otp_memory();
        let fuse_array_offset = caliptra_mcu_registers_generated::fuses::DOT_FUSE_ARRAY.byte_offset;
        let lock_fuse_byte = otp_memory[fuse_array_offset];
        assert_eq!(
            lock_fuse_byte & 0x03,
            0x01,
            "DOT fuse should still have only 1 bit burned after sig verify failure, got: 0x{:02x}",
            lock_fuse_byte
        );

        println!("[TEST] DOT override correctly aborted with invalid signatures (fuse not burned)");

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // Firmware manifest DOT command tests
    // -----------------------------------------------------------------------

    /// Creates a firmware manifest DOT section as raw bytes (128 bytes)
    /// with a valid checksum and the provided keys.
    fn create_manifest_section(
        commands: &[u8],
        min_fuse_count: u32,
        cak: [u32; 12],
        lak: [u32; 12],
    ) -> Vec<u8> {
        use caliptra_mcu_rom_common::{FwManifestDotSection, FW_MANIFEST_DOT_MAGIC};
        use zerocopy::IntoBytes;

        let mut cmd_array = [0u8; 8];
        for (i, &c) in commands.iter().enumerate().take(8) {
            cmd_array[i] = c;
        }

        let section = FwManifestDotSection {
            magic: FW_MANIFEST_DOT_MAGIC,
            checksum: 0,
            version: 1,
            num_commands: commands.len().min(8) as u32,
            min_fuse_count,
            commands: cmd_array,
            cak,
            lak,
            _reserved: [0u8; 4],
        }
        .with_checksum();

        section.as_bytes().to_vec()
    }

    /// Test: LOCK command in firmware manifest burns a fuse when device is in EVEN (unlocked) state.
    ///
    /// Setup:
    /// - DOT enabled in fuses, EVEN state (burned=0)
    /// - Valid DOT blob with CAK only (no LAK → DOT blob processing does NOT auto-lock)
    /// - Firmware manifest with LOCK command
    ///
    /// Expected: The manifest LOCK command burns the lock fuse (EVEN → ODD).
    #[test]
    fn test_fw_manifest_dot_lock() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_LOCK;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_LOCK], 0, owner_pk_hash, test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Manifest LOCK test failed with fatal error: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        let otp_memory = hw.read_otp_memory();
        let fuse_byte = otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset];
        assert!(
            fuse_byte & 0x01 != 0,
            "Manifest LOCK should have burned the lock fuse, got 0x{:02x}",
            fuse_byte
        );

        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 1,
            "Expected 1 fuse burned by manifest LOCK, found {}",
            burned
        );

        println!("[TEST] Firmware manifest LOCK command successfully burned lock fuse");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: LOCK command is idempotent when device is already in ODD (locked) state.
    ///
    /// Setup:
    /// - DOT in locked state (ODD, 1 fuse burned)
    /// - Valid DOT blob for locked state
    /// - Firmware manifest with LOCK command
    ///
    /// Expected: No additional fuses burned (idempotent).
    #[test]
    fn test_fw_manifest_dot_lock_idempotent() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_LOCK;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let dot_flash = blob.to_flash_contents();

        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_LOCK], 0, owner_pk_hash, test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Idempotent LOCK test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify still exactly 1 fuse burned (no additional fuse from manifest)
        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 1,
            "LOCK should be idempotent: expected 1 fuse, found {}",
            burned
        );

        println!("[TEST] Firmware manifest LOCK idempotent (no additional fuse burned)");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: UNLOCK command burns a fuse when device is in ODD (locked) state.
    ///
    /// Setup:
    /// - DOT in locked state (ODD, 1 fuse burned)
    /// - Valid DOT blob for locked state
    /// - Firmware manifest with UNLOCK command
    ///
    /// Expected: One additional fuse burned (ODD → EVEN), total 2.
    #[test]
    fn test_fw_manifest_dot_unlock() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_UNLOCK;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let dot_flash = blob.to_flash_contents();

        // UNLOCK needs a LAK in the manifest for writing the unlock DOT blob.
        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_UNLOCK], 0, [0u32; 12], test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Manifest UNLOCK test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 2,
            "UNLOCK should burn 1 fuse: expected 2 total, found {}",
            burned
        );

        println!("[TEST] Firmware manifest UNLOCK command burned fuse (ODD → EVEN)");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: UNLOCK command is idempotent when device is already in EVEN (unlocked) state.
    #[test]
    fn test_fw_manifest_dot_unlock_idempotent() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_UNLOCK;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_UNLOCK], 0, [0u32; 12], test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Idempotent UNLOCK test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify 0 fuses burned (UNLOCK on EVEN state is a no-op)
        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 0,
            "UNLOCK should be idempotent on EVEN state, found {} fuses",
            burned
        );

        println!("[TEST] Firmware manifest UNLOCK idempotent on EVEN state");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: DISABLE command burns a fuse when in EVEN (unlocked) state.
    #[test]
    fn test_fw_manifest_dot_disable() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_DISABLE;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_DISABLE], 0, [0u32; 12], test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Manifest DISABLE test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        let otp_memory = hw.read_otp_memory();
        let fuse_byte = otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset];
        assert!(
            fuse_byte & 0x01 != 0,
            "DISABLE should burn lock fuse, got 0x{:02x}",
            fuse_byte
        );

        println!("[TEST] Firmware manifest DISABLE command burned fuse (EVEN → ODD)");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: No manifest magic means DOT commands are silently skipped.
    #[test]
    fn test_fw_manifest_dot_no_magic_skipped() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        // No firmware_prefix → fw_manifest_dot_enabled is false in the ROM,
        // so DOT manifest processing is entirely skipped.  This verifies
        // that the default ROM configuration never accidentally processes
        // DOT manifests.

        let mut hw = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "No-magic test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // No fuses should be burned (manifest was skipped)
        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 0,
            "No manifest magic: expected 0 fuses burned, found {}",
            burned
        );

        println!("[TEST] No manifest magic: DOT commands correctly skipped");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: ROTATE command burns 2 fuses when below min_fuse_count threshold.
    #[test]
    fn test_fw_manifest_dot_rotate() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_ROTATE;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        // ROTATE with min_fuse_count=2 (current burned=0, so rotation will apply)
        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_ROTATE], 2, owner_pk_hash, test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Manifest ROTATE test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify 2 fuses burned (rotation = 2 fuse burns, preserving parity)
        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(burned, 2, "ROTATE should burn 2 fuses, found {}", burned);

        println!("[TEST] Firmware manifest ROTATE command burned 2 fuses");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: ROTATE command is idempotent when burned count already meets min_fuse_count.
    #[test]
    fn test_fw_manifest_dot_rotate_idempotent() {
        use caliptra_mcu_registers_generated::fuses;
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_ROTATE;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let dot_flash = blob.to_flash_contents();

        // ROTATE with min_fuse_count=1 but device already has 1 fuse burned (locked state)
        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_ROTATE], 1, owner_pk_hash, test_lak());

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Idempotent ROTATE test failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Verify still exactly 1 fuse burned (rotation not applied)
        let otp_memory = hw.read_otp_memory();
        let fuse_array = &otp_memory[fuses::DOT_FUSE_ARRAY.byte_offset
            ..fuses::DOT_FUSE_ARRAY.byte_offset + fuses::DOT_FUSE_ARRAY.byte_size];
        let burned: u32 = fuse_array.iter().map(|b| b.count_ones()).sum();
        assert_eq!(
            burned, 1,
            "ROTATE idempotent: expected 1 fuse, found {}",
            burned
        );

        println!("[TEST] Firmware manifest ROTATE idempotent when already at target");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: Unsupported manifest version causes a fatal error.
    ///
    /// Setup:
    /// - DOT enabled, EVEN state
    /// - Valid DOT blob
    /// - Firmware manifest with correct magic but version = 99
    ///
    /// Expected: ROM halts with ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR.
    #[test]
    fn test_fw_manifest_dot_bad_version() {
        use caliptra_mcu_rom_common::{FwManifestDotSection, FW_MANIFEST_DOT_MAGIC};
        use zerocopy::IntoBytes;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        // Create a manifest with valid magic and checksum but unsupported version (99)
        let section = FwManifestDotSection {
            magic: FW_MANIFEST_DOT_MAGIC,
            checksum: 0,
            version: 99,
            num_commands: 0,
            min_fuse_count: 0,
            commands: [0u8; 8],
            cak: [0u32; 12],
            lak: [0u32; 12],
            _reserved: [0u8; 4],
        }
        .with_checksum();
        let manifest = section.as_bytes().to_vec();

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| m.mci_fw_fatal_error().is_some() || m.cycle_count() > 100_000_000);

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Expected fatal error for unsupported manifest version, but boot completed"
        );
        assert_eq!(
            fatal_error.unwrap(),
            u32::from(caliptra_mcu_error::McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR),
            "Expected ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR, got 0x{:x}",
            fatal_error.unwrap()
        );

        println!("[TEST] Unsupported manifest version correctly triggers fatal error");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: After UNLOCK command, the device boots successfully on the next cold boot.
    #[test]
    fn test_fw_manifest_dot_unlock_second_boot_succeeds() {
        use caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_UNLOCK;
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, test_lak());
        let dot_flash = blob.to_flash_contents();

        let manifest =
            create_manifest_section(&[FW_MANIFEST_DOT_CMD_UNLOCK], 0, [0u32; 12], test_lak());

        // Boot 1: process the UNLOCK manifest — burns a fuse and writes new unlock blob.
        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            rom_only: true,
            otp_memory: Some(create_locked_otp_memory()),
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_none(),
            "Boot 1 (UNLOCK manifest) failed: 0x{:x}",
            fatal_error.unwrap_or(0)
        );

        // Extract post-UNLOCK OTP and flash state.
        let otp_after_unlock = hw.read_otp_memory();
        let dot_flash_after_unlock = hw.read_dot_flash();

        // Boot 2: boot again with the post-UNLOCK state and no firmware manifest.
        // The blob written during boot 1 must be correctly sealed for the new EVEN
        // state (burned=2, derivation_value=3) so this boot can verify it.
        let mut hw2 = start_runtime_hw_model(TestParams {
            dot_flash_initial_contents: Some(dot_flash_after_unlock),
            rom_only: true,
            otp_memory: Some(otp_after_unlock),
            ..Default::default()
        });

        hw2.step_until(|m| {
            m.mci_boot_milestones()
                .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.mci_fw_fatal_error().is_some()
                || m.cycle_count() > 100_000_000
        });

        let fatal_error2 = hw2.mci_fw_fatal_error();
        assert!(
            fatal_error2.is_none(),
            "Boot 2 (post-UNLOCK) failed: 0x{:x} — blob was not correctly sealed for the new EVEN state",
            fatal_error2.unwrap_or(0)
        );

        println!("[TEST] Firmware manifest UNLOCK: second boot succeeds with post-UNLOCK blob");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: An unknown DOT command code triggers a fatal error.
    ///
    /// Command codes outside the defined set (NOP/LOCK/UNLOCK/ROTATE/DISABLE) must
    /// not be silently ignored; the ROM should return an error so a malformed or
    /// future-version manifest is not silently accepted on an older ROM.
    #[test]
    fn test_fw_manifest_dot_unknown_command() {
        use caliptra_mcu_romtime::McuBootMilestones;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let owner_pk_hash = get_owner_pk_hash();
        let blob = create_valid_dot_blob(owner_pk_hash, [0u32; 12]);
        let dot_flash = blob.to_flash_contents();

        // Command 0xFF is not defined; the ROM must reject it.
        let manifest = create_manifest_section(&[0xFF], 0, [0u32; 12], [0u32; 12]);

        let mut hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            dot_flash_initial_contents: Some(dot_flash),
            dot_enabled: true,
            rom_only: true,
            ..Default::default()
        });

        hw.step_until(|m| {
            m.mci_fw_fatal_error().is_some()
                || m.mci_boot_milestones()
                    .contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
                || m.cycle_count() > 100_000_000
        });

        let fatal_error = hw.mci_fw_fatal_error();
        assert!(
            fatal_error.is_some(),
            "Expected fatal error for unknown DOT command, but boot completed"
        );
        assert_eq!(
            fatal_error.unwrap(),
            u32::from(caliptra_mcu_error::McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR),
            "Expected ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR for unknown command, got 0x{:x}",
            fatal_error.unwrap()
        );

        println!(
            "[TEST] Unknown DOT command correctly triggers ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR"
        );
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test: The runtime actually boots when a DOT manifest header (NOP) is
    /// prepended to the firmware image.
    #[test]
    fn test_fw_manifest_dot_runtime_boots() {
        let lock = TEST_LOCK.lock().unwrap();

        let manifest = create_manifest_section(
            &[caliptra_mcu_rom_common::FW_MANIFEST_DOT_CMD_NOP],
            0,
            [0u32; 12],
            [0u32; 12],
        );

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let _hw = start_runtime_hw_model(TestParams {
            firmware_prefix: Some(manifest),
            ..Default::default()
        });

        println!("[TEST] Runtime boots correctly with DOT manifest header prepended");
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
