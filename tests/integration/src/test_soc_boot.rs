// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{compile_runtime, run_runtime, ROM, TEST_LOCK};
    use chrono::{TimeZone, Utc};
    use mcu_builder::SocImage;
    use mcu_config_emulator::flash::{
        PartitionId, PartitionStatus, PartitionTable, RollbackEnable, StandAloneChecksumCalculator,
        IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    };
    use pldm_fw_pkg::manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    };
    use pldm_fw_pkg::FirmwareManifest;
    use std::path::PathBuf;
    use std::process::ExitStatus;

    const CALIPTRA_EXTERNAL_RAM_BASE: u64 = 0x8000_0000;

    #[derive(Clone)]
    struct TestOptions {
        feature: &'static str,
        runtime: PathBuf,
        i3c_port: u32,
        soc_images: Vec<SocImage>,
        primary_flash_image_path: Option<PathBuf>,
        secondary_flash_image_path: Option<PathBuf>,
        pldm_fw_pkg_path: Option<PathBuf>,
        partition_table: Option<PartitionTable>,
    }

    macro_rules! run_test {
        ($func:ident, $($args:expr),*) => {{
            println!("Running {}...", stringify!($func));
            $func($($args),*);
        }};
    }

    // Helper function to create a flash image from the provided SOC images
    fn create_flash_image(
        partition_table: Option<PartitionTable>,
        flash_offset: usize,
        soc_images: Vec<Vec<u8>>,
    ) -> (Vec<PathBuf>, PathBuf) {
        let soc_images_paths: Vec<PathBuf> = soc_images
            .iter()
            .map(|image| {
                let soc_image_path = tempfile::NamedTempFile::new()
                    .expect("Failed to create temp file")
                    .path()
                    .to_path_buf();
                std::fs::write(soc_image_path.clone(), image).expect("Failed to write temp file");
                soc_image_path
            })
            .collect();

        let flash_image_path = tempfile::NamedTempFile::new()
            .expect("Failed to create flash image file")
            .path()
            .to_path_buf();

        mcu_builder::flash_image::flash_image_create(
            &None,
            &None,
            &None,
            &Some(
                soc_images_paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect(),
            ),
            flash_offset,
            flash_image_path.to_str().unwrap(),
        )
        .expect("Failed to create flash image");

        if let Some(partition_table) = partition_table {
            mcu_builder::flash_image::write_partition_table(
                &partition_table,
                0,
                flash_image_path.to_str().unwrap(),
            )
            .expect("Failed to write partition table");
        }
        println!("Flash image path: {:?}", flash_image_path);
        (soc_images_paths, flash_image_path)
    }

    // Helper function to create a PLDM firmware package from the provided manifest
    fn create_pldm_fw_package(manifest: &FirmwareManifest) -> PathBuf {
        let pldm_fw_pkg_path = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_str()
            .unwrap()
            .to_string();
        manifest
            .generate_firmware_package(&pldm_fw_pkg_path)
            .expect("Failed to generate firmware package");
        println!("PLDM Firmware Package: {:?}", pldm_fw_pkg_path);
        PathBuf::from(pldm_fw_pkg_path)
    }

    // Helper function to retrieve the streaming boot PLDM firmware manifest
    // Identifier and classification should match the device's component image information
    // found in platforms/emulator/runtime/userspace/apps/user/image-loader/config.rs
    fn get_streaming_boot_pldm_fw_manifest(dev_uuid: &[u8], image: &[u8]) -> FirmwareManifest {
        FirmwareManifest {
            package_header_information: PackageHeaderInformation {
                package_header_identifier: uuid::Uuid::parse_str(
                    "7B291C996DB64208801B02026E463C78",
                )
                .unwrap(),
                package_header_format_revision: 1,
                package_release_date_time: Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
                package_version_string_type: StringType::Utf8,
                package_version_string: Some("0.0.0-release".to_string()),
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
                    descriptor_data: dev_uuid.to_vec(),
                },
                additional_descriptors: None,
                reference_manifest_data: None,
            }],
            downstream_device_id_records: None,
            component_image_information: vec![ComponentImageInformation {
                // Classification and identifier should match the device's component image information found in runtime/apps/pldm/pldm-lib/src/config.rs
                classification: 0x000A, // Firmware
                identifier: 0xffff,

                // Comparison stamp should be greater than the device's comparison stamp
                comparison_stamp: Some(0xffffffff),
                options: 0x0,
                requested_activation_method: 0x0002,
                version_string_type: StringType::Utf8,
                version_string: Some("soc-fw-1.2".to_string()),

                size: image.len() as u32,
                image_data: Some(image.to_vec()),
                ..Default::default()
            }],
        }
    }

    // Helper function to retrieve the device UUID
    fn get_device_uuid() -> [u8; 16] {
        // This an arbitrary UUID that should match the one used in the device's ID record
        // found in platforms/emulator/runtime/userspace/apps/user/image-loader/config.rs
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn run_runtime_with_options(opts: TestOptions) -> ExitStatus {
        run_runtime(
            opts.feature,
            ROM.to_path_buf(),
            opts.runtime.clone(),
            opts.i3c_port.to_string(),
            true,
            false,
            Some(opts.soc_images.clone()),
            opts.pldm_fw_pkg_path.clone(),
            opts.primary_flash_image_path.clone(),
            opts.secondary_flash_image_path.clone(),
        )
    }

    /// Test case: happy path
    fn test_successful_boot(opts: TestOptions) {
        let test = run_runtime_with_options(opts);
        assert_eq!(0, test.code().unwrap_or_default());
    }

    // Test case: Image ID in the SOC manifest is different from the one being authorized in the firmware
    fn test_boot_invalid_image_id(opts: TestOptions) {
        let mut new_options = opts.clone();
        new_options.soc_images[0].image_id = 0xDEAD; // Change the image ID to an invalid one

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: The FW to be streamed has been altered making it unauthorized
    fn test_boot_unathorized_image(opts: TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0xDEu8; 512];
        let soc_image_fw_2 = [0xADu8; 256];
        let flash_offset = opts
            .partition_table
            .as_ref()
            .and_then(|pt| pt.get_active_partition().1.as_ref().map(|p| p.offset))
            .unwrap_or(0);
        let (_, flash_image_path) = create_flash_image(
            opts.partition_table,
            flash_offset,
            vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
        );

        // Generate the corresponding PLDM package for the altered flash image
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let device_uuid = get_device_uuid();
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image =
                std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            Some(flash_image_path)
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: The load address in the SOC manifest is not a valid addressable AXI address
    fn test_invalid_load_address(opts: TestOptions) {
        let mut new_options = opts.clone();
        // Change the load address in the SOC manifest to an invalid one
        new_options.soc_images[0].load_addr = 0xffff; // Invalid load address

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: Test booting from secondary flash
    fn test_boot_secondary_flash(opts: TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0x55u8; 512];
        let soc_image_fw_2 = [0xAAu8; 256];
        let mut new_partition_table = PartitionTable {
            active_partition: PartitionId::B as u32,
            partition_a_status: PartitionStatus::Invalid as u16,
            partition_b_status: PartitionStatus::Valid as u16, // Set partition B as valid
            ..Default::default()
        };
        let checksum_calculator = StandAloneChecksumCalculator::new();
        new_partition_table.populate_checksum(&checksum_calculator);
        let secondary_flash_image_path = if opts.secondary_flash_image_path.is_some() {
            let (_, secondary_flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            Some(secondary_flash_image_path)
        } else {
            None
        };
        new_options.secondary_flash_image_path = secondary_flash_image_path.clone();

        // Update the partition table in the primary flash
        let primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            let (_, primary_flash_image_path) =
                create_flash_image(Some(new_partition_table), IMAGE_A_PARTITION.offset, vec![]);
            Some(primary_flash_image_path)
        } else {
            None
        };
        new_options.primary_flash_image_path = primary_flash_image_path.clone();

        let test = run_runtime_with_options(new_options);
        assert_eq!(0, test.code().unwrap_or_default());
    }

    // Test case: Partition table has invalid checksum
    fn test_boot_partition_table_invalid_checksum(opts: TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0x55u8; 512];
        let soc_image_fw_2 = [0xAAu8; 256];
        let new_partition_table = PartitionTable {
            active_partition: PartitionId::B as u32,
            partition_a_status: PartitionStatus::Invalid as u16,
            partition_b_status: PartitionStatus::Valid as u16, // Set partition B as valid
            ..Default::default()
        };
        // Do not populate the checksum
        new_options.secondary_flash_image_path = if opts.secondary_flash_image_path.is_some() {
            let (_, secondary_flash_image_path) = create_flash_image(
                None,
                IMAGE_B_PARTITION.offset,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            Some(secondary_flash_image_path)
        } else {
            None
        };

        // Update the partition table in the primary flash

        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            let (_, primary_flash_image_path) =
                create_flash_image(Some(new_partition_table), IMAGE_A_PARTITION.offset, vec![]);
            Some(primary_flash_image_path)
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: The PLDM descriptor in the PLDM package is different from the device's descriptor
    fn test_incorrect_pldm_descriptor(opts: TestOptions) {
        let mut new_options = opts.clone();

        // Generate another PLDM Package with a different descriptor
        let mut device_uuid = get_device_uuid();
        device_uuid[0] = 0xFF; // Change the first byte of the UUID

        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: The PLDM component ID in the PLDM package is not valid
    fn test_incorrect_pldm_component_id(opts: TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].identifier = 0xDEAD; // Change the component ID to an invalid one
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: Corrupted PLDM FW package
    fn test_corrupted_pldm_fw_package(opts: TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].image_data = Some(vec![0x00]); // Remove the image data to simulate corruption
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Test case: PLDM FW package has lower version than device's active image version
    fn test_lower_version_pldm_fw_package(opts: TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2

        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].options = 0x0001; // Enable comparison stamp option
            pldm_manifest.component_image_information[0].comparison_stamp = Some(0x00000000); // Set a lower version
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(new_options);
        assert_ne!(0, test.code().unwrap_or_default());
    }

    // Common test function for both flash-based and streaming boot
    fn test_soc_boot(is_flash_based_boot: bool) {
        let lock = TEST_LOCK.lock().unwrap();
        let feature = if is_flash_based_boot {
            "test-flash-based-boot"
        } else {
            "test-pldm-streaming-boot"
        };
        let i3c_port = 65500;

        // Compile the runtime once with the appropriate feature
        let test_runtime = compile_runtime(feature, false);

        // Generate a valid flash image file
        let mut partition_table = PartitionTable {
            active_partition: PartitionId::A as u32,
            partition_a_status: PartitionStatus::Valid as u16,
            partition_b_status: PartitionStatus::Invalid as u16,
            rollback_enable: RollbackEnable::Enabled as u32,
            ..Default::default()
        };
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        let flash_offset = partition_table
            .get_active_partition()
            .1
            .map_or(0, |p| p.offset);
        let (soc_images_paths, flash_image_path) = create_flash_image(
            Some(partition_table.clone()),
            flash_offset,
            vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
        );

        // Generate the corresponding PLDM package from the flash image
        let pldm_fw_pkg_path = if is_flash_based_boot {
            None
        } else {
            let device_uuid = get_device_uuid();
            let (_, flash_image_path) = create_flash_image(
                None,
                0,
                vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()],
            );
            let flash_image =
                std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        };

        // For non flash-based boot, the flash image path is not needeed to be passed to the emulator
        // as the firmware will be streamed from the PLDM package
        let flash_image_path = if is_flash_based_boot {
            Some(flash_image_path)
        } else {
            None
        };

        // Create SOC image metadata that will be written to the SoC manifest
        let soc_images = vec![
            SocImage {
                path: soc_images_paths[0].clone(),
                load_addr: CALIPTRA_EXTERNAL_RAM_BASE,
                image_id: 4096,
            },
            SocImage {
                path: soc_images_paths[1].clone(),
                load_addr: CALIPTRA_EXTERNAL_RAM_BASE + soc_image_fw_1.len() as u64,
                image_id: 4097,
            },
        ];

        // These are the options for a successful boot
        // Each test case will override the options to simulate different scenarios
        let pass_options = TestOptions {
            feature,
            runtime: test_runtime.clone(),
            i3c_port,
            soc_images: soc_images.clone(),
            primary_flash_image_path: flash_image_path.clone(),
            secondary_flash_image_path: flash_image_path.clone(),
            pldm_fw_pkg_path: pldm_fw_pkg_path.clone(),
            partition_table: Some(partition_table.clone()),
        };

        run_test!(test_successful_boot, pass_options.clone());
        run_test!(test_boot_invalid_image_id, pass_options.clone());
        run_test!(test_boot_unathorized_image, pass_options.clone());
        run_test!(test_invalid_load_address, pass_options.clone());

        if !is_flash_based_boot {
            // Streaming boot-only tests
            run_test!(test_incorrect_pldm_descriptor, pass_options.clone());
            run_test!(test_incorrect_pldm_component_id, pass_options.clone());
            run_test!(test_corrupted_pldm_fw_package, pass_options.clone());
            run_test!(test_lower_version_pldm_fw_package, pass_options.clone());
        } else {
            // Flash-based boot-only tests
            run_test!(test_boot_secondary_flash, pass_options.clone());
            run_test!(
                test_boot_partition_table_invalid_checksum,
                pass_options.clone()
            );
        }
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot() {
        test_soc_boot(true);
    }

    #[test]
    fn test_streaming_soc_boot() {
        test_soc_boot(false);
    }
}
