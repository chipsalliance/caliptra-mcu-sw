// Licensed under the Apache-2.0 license

//! Integration test for the caliptra-util-host MCTP VDM validator.
//!
//! This test starts the emulator with VDM support, then runs the
//! `caliptra-mctp-vdm-client` Validator in-process against it.

#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_core_mctp_vdm_client::{DynamicI3cAddress, TestConfig, Validator};
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use random_port::PortPicker;
    use std::process::exit;
    use std::sync::atomic::Ordering;

    /// Run the MCTP VDM validator in-process against the emulated device.
    fn run_validator_in_process(i3c_port: u16, i3c_address: DynamicI3cAddress) {
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
            let validator = Validator::new(&config)
                .expect("Failed to create validator")
                .set_verbose(true);

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
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = "test-caliptra-util-host-mctp-vdm-validator";
        let i3c_port = PortPicker::new().random(true).pick().unwrap();

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            i3c_port: Some(i3c_port),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let i3c_address = hw.i3c_address().unwrap();
        run_validator_in_process(i3c_port, i3c_address.into());

        let test = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, test);

        MCU_RUNNING.store(false, Ordering::Relaxed);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
