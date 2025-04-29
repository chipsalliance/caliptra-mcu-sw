// Licensed under the Apache-2.0 license

/// This module tests the PLDM Firmware Update
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::mctp_transport::MctpPldmSocket;
use pldm_common::protocol::firmware_update::*;
use pldm_ua::transport::PldmSocket;
use pldm_ua::{discovery_sm, update_sm};

use chrono::{TimeZone, Utc};
use lazy_static::lazy_static;
use log::{error, LevelFilter};
use pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use pldm_ua::daemon::Options;
use pldm_ua::daemon::PldmDaemon;
use simple_logger::SimpleLogger;
use uuid::Uuid;

pub const DEVICE_UUID: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
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
            requested_activation_method: 0x0,
            version_string_type: StringType::Utf8,
            version_string: Some("soc-fw-1.2".to_string()),

            // Define the firmware image binary data of size 256 bytes
            // First 128 bytes are 0x55, next 128 bytes are 0xAA
            size: 4096,
            image_data: {

                let image1 = vec![0x55; 128];
                let image2 = vec![0xAA; 128];
                let mut flash_image = vec![

                        // Header: magic, version, image_count
                        0x48, 0x53, 0x4C, 0x46,  // "FLSH"
                        0x01, 0x00,              // version = 0x0001
                        0x02, 0x00,              // image_count = 2

                        // Checksums
                        0x11, 0x11, 0x11, 0x11,  // header_crc32
                        0x22, 0x22, 0x22, 0x22,  // payload_crc32

                        // ImageInfo[0]
                        0x01, 0x00, 0x00, 0x00,  // identifier
                        0x30, 0x00, 0x00, 0x00,  // offset
                        0x80, 0x00, 0x00, 0x00,  // size

                        // ImageInfo[1]
                        0x02, 0x00, 0x00, 0x00,  // identifier
                        0xB0, 0x00, 0x00, 0x00,  // offset
                        0x80, 0x00, 0x00, 0x00,  // size

                ];
                flash_image.extend_from_slice(&image1);
                flash_image.extend_from_slice(&image2);
                Some(flash_image)
            },
            ..Default::default()

        }],
    };
}

pub struct PldmFwUpdateTest {
    socket: MctpPldmSocket,
    daemon:
        Option<PldmDaemon<MctpPldmSocket, discovery_sm::DefaultActions, update_sm::DefaultActions>>,
    running: Arc<AtomicBool>,
}

impl PldmFwUpdateTest {
    fn new(socket: MctpPldmSocket, running: Arc<AtomicBool>) -> Self {
        Self {
            socket,
            running,
            daemon: None,
        }
    }
    pub fn wait_for_state_transition(&self, expected_state: update_sm::States) -> Result<(), ()> {
        let timeout = Duration::from_secs(20);
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

    pub fn test_fw_update(&mut self) -> Result<(), ()> {
        // Initialize log level to info (only once)
        let _ = SimpleLogger::new().with_level(LevelFilter::Info).init();

        // Run the PLDM daemon
        self.daemon = Some(
            PldmDaemon::run(
                self.socket.clone(),
                Options {
                    pldm_fw_pkg: Some(PLDM_FW_PKG.clone()),
                    discovery_sm_actions: discovery_sm::DefaultActions {},
                    update_sm_actions: update_sm::DefaultActions {},
                    fd_tid: 0x01,
                },
            )
            .map_err(|_| ())?,
        );

        // Currently the device supports QueryIdentifiers and GetFirmwareParameters commands
        // The update state machine should settle at RequestUpdate state
        // after receiving the QueryDeviceIdentifiers and GetFirmwareParameters responses from the device.
        // Device will not send the RequestUpdate response so UA will stop at RequestUpdateSent state.
        // Modify this as more commands are supported by the device.
        // Note that the UA state machine will not progress if it receives an unexpected response from the device.
        let res = self.wait_for_state_transition(update_sm::States::Done);

        self.daemon.as_mut().unwrap().stop();

        res
    }

    pub fn run(socket: MctpPldmSocket, running: Arc<AtomicBool>) -> JoinHandle<()>{
        std::thread::spawn(move || {
            print!("Emulator: Running PLDM Loopback Test: ",);
            let mut test = PldmFwUpdateTest::new(socket, running);
            if test.test_fw_update().is_err() {
                println!("Failed");
                exit(-1);
            } else {
                println!("Passed");
            }
            test.running.store(false, Ordering::Relaxed);
        })
    }
}
