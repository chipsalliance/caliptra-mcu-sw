// Licensed under the Apache-2.0 license

//! Integration test for the caliptra-util-host MCTP VDM validator.
//!
//! This test starts the emulator with VDM support, then runs the
//! `caliptra-mctp-vdm-client` Validator in-process against it.

#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_api::SocManager;
    use caliptra_mcu_core_mctp_vdm_client::{
        DebugUnlockKeys, DynamicI3cAddress, TestConfig, Validator,
    };
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use zerocopy::IntoBytes;

    /// Run the MCTP VDM validator in-process against the emulated device.
    fn run_validator_in_process(
        i3c_port: u16,
        i3c_address: DynamicI3cAddress,
        debug_unlock_keys: Option<DebugUnlockKeys>,
    ) {
        std::thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }

            println!(
                "Running MCTP VDM validator in-process (port={}, addr=0x{:02X})",
                i3c_port,
                u8::from(i3c_address)
            );

            let config = TestConfig {
                network: caliptra_mcu_core_mctp_vdm_client::NetworkConfig {
                    default_server_address: format!("127.0.0.1:{}", i3c_port),
                    target_i3c_address: i3c_address.into(),
                },
                ..TestConfig::default()
            };
            let mut validator = Validator::new(&config)
                .expect("Failed to create validator")
                .set_verbose(true);

            if let Some(keys) = debug_unlock_keys {
                validator = validator.set_debug_unlock_keys(keys);
            }

            match validator.start() {
                Ok(results) => {
                    let all_passed = results.iter().all(|r| r.passed);
                    if all_passed {
                        println!("✓ Caliptra MCTP VDM validator PASSED");
                        MCU_RUNNING.store(false, Ordering::Relaxed);
                    } else {
                        println!("✗ Caliptra MCTP VDM validator FAILED");
                        for r in &results {
                            if !r.passed {
                                println!("  FAIL: {} — {:?}", r.test_name, r.error_message);
                            }
                        }
                        exit(-1);
                    }
                }
                Err(e) => {
                    println!("✗ Caliptra MCTP VDM validator error: {:#}", e);
                    exit(-1);
                }
            }
        });
    }

    #[ignore]
    #[test]
    fn test_caliptra_util_host_mctp_vdm_validator() {
        use caliptra_image_fake_keys::{
            VENDOR_ECC_KEY_0_PRIVATE, VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PRIVATE,
            VENDOR_MLDSA_KEY_0_PUBLIC,
        };
        use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, ECC384_SCALAR_WORD_SIZE};
        use fips204::traits::SerDes;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-caliptra-util-host-mctp-vdm-validator";
        let i3c_port = PortPicker::new().random(true).pick().unwrap();
        let unlock_level = 1u8;

        // --- Prepare ECC public key in hardware format (big-endian u32 words) ---
        let mut ecc_pub_key_u32 = [0u32; ECC384_SCALAR_WORD_SIZE * 2];
        ecc_pub_key_u32[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecc_pub_key_u32[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
        let ecc_pub_key_bytes: [u8; 96] = ecc_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Prepare MLDSA public key in hardware format (little-endian u32 words) ---
        let mldsa_pub_key_raw = VENDOR_MLDSA_KEY_0_PUBLIC.0.as_bytes();
        let mldsa_pub_key_u32: Vec<u32> = mldsa_pub_key_raw
            .chunks(4)
            .map(|chunk| {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(chunk);
                u32::from_le_bytes(arr)
            })
            .collect();
        let mldsa_pub_key_bytes: [u8; 2592] = mldsa_pub_key_u32.as_bytes().try_into().unwrap();

        // --- Set up keypairs for fuse provisioning ---
        let mut prod_dbg_keypairs: Vec<([u8; 96], [u8; 2592])> = vec![([0u8; 96], [0u8; 2592]); 8];
        prod_dbg_keypairs[(unlock_level - 1) as usize] = (ecc_pub_key_bytes, mldsa_pub_key_bytes);

        // --- Prepare ECC private key bytes for signing ---
        let mut be_ecc_priv_key_bytes = [0u8; ECC384_SCALAR_BYTE_SIZE];
        for (i, word) in VENDOR_ECC_KEY_0_PRIVATE.iter().enumerate() {
            be_ecc_priv_key_bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        // --- Prepare MLDSA private key bytes for signing ---
        let mldsa_priv_key_bytes: Vec<u8> = VENDOR_MLDSA_KEY_0_PRIVATE.0.as_bytes().to_vec();

        // --- Build DebugUnlockKeys to pass to the validator ---
        let debug_unlock_keys = DebugUnlockKeys {
            ecc_private_key_bytes: be_ecc_priv_key_bytes,
            ecc_public_key: ecc_pub_key_u32,
            mldsa_private_key_bytes: mldsa_priv_key_bytes,
            mldsa_public_key: <[u32; 648]>::try_from(mldsa_pub_key_u32.as_slice()).unwrap(),
        };

        // --- Start hw_model with keys provisioned in fuses ---
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            i3c_port: Some(i3c_port),
            debug_intent: true,
            lifecycle_controller_state: Some(caliptra_mcu_hw_model::LifecycleControllerState::Prod),
            prod_dbg_unlock_keypairs: prod_dbg_keypairs,
            ..Default::default()
        });

        hw.start_i3c_controller();

        // Set the prod_dbg_unlock_req bit in the SoC IFC register.
        // This simulates what the SoC would do in a real debug unlock flow.
        hw.caliptra_soc_manager()
            .soc_ifc()
            .ss_dbg_manuf_service_reg_req()
            .write(|w| w.prod_dbg_unlock_req(true));

        let i3c_address = hw.i3c_address().unwrap();
        run_validator_in_process(i3c_port, i3c_address.into(), Some(debug_unlock_keys));

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        MCU_RUNNING.store(false, Ordering::Relaxed);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
