//! Licensed under the Apache-2.0 license

//! This module tests the PLDM Firmware Update

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TEST_LOCK};
    use chrono::{TimeZone, Utc};
    use lazy_static::lazy_static;
    use log::{error, LevelFilter};
    use mcu_hw_model::McuHwModel;
    use mcu_testing_common::mctp_transport::{MctpPldmSocket, MctpTransport};
    use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
    use pldm_common::protocol::firmware_update::*;
    use pldm_fw_pkg::{
        manifest::{
            ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
            PackageHeaderInformation, StringType,
        },
        FirmwareManifest,
    };
    use pldm_ua::daemon::Options;
    use pldm_ua::daemon::PldmDaemon;
    use pldm_ua::transport::{EndpointId, PldmSocket, PldmTransport};
    use pldm_ua::{discovery_sm, update_sm};
    use simple_logger::SimpleLogger;
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn test_fw_update_e2e() {
        let feature = "test-pldm-fw-update-e2e";
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let feature = feature.replace("_", "-");
        let mut hw = start_runtime_hw_model(Some(&feature), Some(65534));

        hw.start_i3c_controller();

        let pldm_transport =
            MctpTransport::new(hw.i3c_port().unwrap(), hw.i3c_address().unwrap().into());
        let pldm_socket = pldm_transport
            .create_socket(EndpointId(8), EndpointId(0))
            .unwrap();
        PldmFwUpdateTest::run(pldm_socket);

        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub const DEVICE_UUID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];

    // Define the PLDM Firmware Package that the Update Agent will use
    lazy_static! {
        static ref PLDM_FW_PKG: FirmwareManifest = FirmwareManifest {
            package_header_information: PackageHeaderInformation {
                package_header_identifier: Uuid::parse_str("7B291C996DB64208801B02026E463C78").unwrap(),
                package_header_format_revision: 1,
                package_release_date_time: Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
                package_version_string_type: StringType::Utf8,
                package_version_string: Some("1.2.0-release".to_string()),
                package_header_size: 0, // This will be computed during encoding
            },


            firmware_device_id_records: vec![FirmwareDeviceIdRecord {
                firmware_device_package_data: None,
                device_update_option_flags: 0x0,
                component_image_set_version_string_type: StringType::Utf8,
                component_image_set_version_string: Some("1.2.0".to_string()),
                applicable_components: Some(vec![0]),
                // The descriptor should match the device's ID record found in runtime/apps/pldm/pldm-lib/src/config.rs
                initial_descriptor: Descriptor {
                    descriptor_type: DescriptorType::Uuid,
                    descriptor_data: DEVICE_UUID.to_vec(),
                },
                additional_descriptors: None,
                reference_manifest_data: None,
            }],
            downstream_device_id_records: None,
            component_image_information: vec![ComponentImageInformation {
                // Classification and identifier should match the device's component image information found in runtime/apps/pldm/pldm-lib/src/config.rs
                classification: ComponentClassification::Firmware as u16,
                identifier: 0x0001,

                // Comparison stamp should be greater than the device's comparison stamp
                comparison_stamp: Some(0x12345679),
                options: 0x0,
                requested_activation_method: 0x0002,
                version_string_type: StringType::Utf8,
                version_string: Some("soc-fw-1.2".to_string()),

                // Define the firmware image binary data of size 256 bytes
                // First 128 bytes are 0x55, next 128 bytes are 0xAA
                size: 256,
                image_data: {
                    let mut data = vec![0x55u8; 128];
                    data.extend(vec![0xAAu8; 128]);
                    Some(data)
                },
                ..Default::default()

            }],
        };
    }

    pub struct PldmFwUpdateTest {
        socket: MctpPldmSocket,
        daemon: Option<
            PldmDaemon<MctpPldmSocket, discovery_sm::DefaultActions, update_sm::DefaultActions>,
        >,
    }

    impl PldmFwUpdateTest {
        fn new(socket: MctpPldmSocket) -> Self {
            Self {
                socket,
                daemon: None,
            }
        }
        #[allow(clippy::result_unit_err)]
        pub fn wait_for_state_transition(
            &self,
            expected_state: update_sm::States,
        ) -> Result<(), ()> {
            let timeout = Duration::from_secs(60);
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout {
                if let Some(daemon) = &self.daemon {
                    if daemon.get_update_sm_state() == expected_state {
                        return Ok(());
                    }
                } else {
                    error!("Daemon is not initialized");
                    return Err(());
                }

                std::thread::sleep(Duration::from_millis(100));
            }
            if let Some(daemon) = &self.daemon {
                if daemon.get_update_sm_state() != expected_state {
                    error!("Timed out waiting for state transition");
                    Err(())
                } else {
                    Ok(())
                }
            } else {
                error!("Daemon is not initialized");
                Err(())
            }
        }

        #[allow(clippy::result_unit_err)]
        pub fn test_fw_update(&mut self) -> Result<(), ()> {
            // Initialize log level to info (only once)
            let _ = SimpleLogger::new().with_level(LevelFilter::Debug).init();

            let pldm_fw_pkg = if let Ok(pldm_fw_pkg_path) = std::env::var("PLDM_FW_PKG") {
                FirmwareManifest::decode_firmware_package(&pldm_fw_pkg_path, None).map_err(|e| {
                    error!(
                        "Failed to decode PLDM FW package from {}: {:?}",
                        pldm_fw_pkg_path, e
                    );
                })?
            } else {
                PLDM_FW_PKG.clone()
            };

            // Run the PLDM daemon
            self.daemon = Some(
                PldmDaemon::run(
                    self.socket.clone(),
                    Options {
                        pldm_fw_pkg: Some(pldm_fw_pkg),
                        discovery_sm_actions: discovery_sm::DefaultActions {},
                        update_sm_actions: update_sm::DefaultActions {},
                        fd_tid: 0x01,
                    },
                )
                .map_err(|_| ())?,
            );

            // Modify the expected state to the one that the test will reach.
            // Note that the UA state machine will not progress if it receives an unexpected response from the device.
            let res = self.wait_for_state_transition(update_sm::States::Done);

            self.daemon.as_mut().unwrap().stop();

            res
        }

        pub fn run(socket: MctpPldmSocket) {
            std::thread::spawn(move || {
                wait_for_runtime_start();
                if !MCU_RUNNING.load(Ordering::Relaxed) {
                    exit(-1);
                }
                print!("Emulator: Running PLDM Loopback Test: ",);
                let mut test = PldmFwUpdateTest::new(socket);
                if test.test_fw_update().is_err() {
                    println!("Failed");
                    exit(-1);
                } else {
                    println!("Passed");
                }
                MCU_RUNNING.store(false, Ordering::Relaxed);
            });
        }
    }
}
