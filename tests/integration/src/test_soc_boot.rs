// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{
        compile_runtime, get_rom_with_feature, has_prebuilt_binaries, run_runtime, TEST_LOCK,
    };
    use caliptra_image_types::ImageManifest;
    use chrono::{TimeZone, Utc};
    use hex::ToHex;
    use mcu_builder::{CaliptraBuilder, FirmwareBinaries, ImageCfg};
    use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
    use mcu_config_emulator::flash::{
        PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    };
    use mcu_testing_common::DeviceLifecycle;
    use pldm_fw_pkg::manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    };
    use pldm_fw_pkg::FirmwareManifest;
    use random_port::PortPicker;
    use std::env;
    use std::path::PathBuf;
    use zerocopy::transmute;

    // Set an arbitrary MCI base address
    const MCI_BASE_AXI_ADDRESS: u64 = 0xA800_0000;

    const MCU_MBOX_SRAM1_OFFSET: u64 = 0x80_0000;

    #[derive(Clone)]
    struct TestOptions {
        feature: &'static str,
        rom: PathBuf,
        runtime: PathBuf,
        i3c_port: u32,
        soc_images: Vec<ImageCfg>,
        soc_images_paths: Vec<PathBuf>,
        primary_flash_image_path: Option<PathBuf>,
        secondary_flash_image_path: Option<PathBuf>,
        pldm_fw_pkg_path: Option<PathBuf>,
        partition_table: Option<PartitionTable>,
        builder: Option<CaliptraBuilder>,
        flash_offset: usize,
        fuse_soc_manifest_svn: Option<u8>,
        fuse_soc_manifest_max_svn: Option<u8>,
        device_security_state: Option<DeviceLifecycle>,
    }

    fn create_soc_images(soc_images: Vec<Vec<u8>>) -> Vec<PathBuf> {
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
        soc_images_paths
    }
    // Helper function to create a flash image from the provided SOC images
    fn create_flash_image(
        caliptra_fw_path: Option<PathBuf>,
        soc_manifest_path: Option<PathBuf>,
        mcu_runtime_path: Option<PathBuf>,
        partition_table: Option<PartitionTable>,
        flash_offset: usize,
        soc_images_paths: Vec<PathBuf>,
    ) -> (Vec<PathBuf>, PathBuf) {
        let flash_image_path = tempfile::NamedTempFile::new()
            .expect("Failed to create flash image file")
            .path()
            .to_path_buf();

        let caliptra_fw_path_str = caliptra_fw_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());
        let soc_manifest_path_str = soc_manifest_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());
        let mcu_runtime_path_str = mcu_runtime_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());
        mcu_builder::flash_image::flash_image_create(
            &caliptra_fw_path_str,
            &soc_manifest_path_str,
            &mcu_runtime_path_str,
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

    fn run_runtime_with_options(opts: &TestOptions) -> i32 {
        run_runtime(
            opts.feature,
            opts.rom.clone(),
            opts.runtime.clone(),
            opts.i3c_port.to_string(),
            true,
            opts.device_security_state
                .unwrap_or(DeviceLifecycle::Production),
            Some(opts.soc_images.clone()),
            opts.pldm_fw_pkg_path.clone(),
            opts.primary_flash_image_path.clone(),
            opts.secondary_flash_image_path.clone(),
            opts.builder.clone(),
            Some("2.1.0".to_string()),
            opts.fuse_soc_manifest_svn,
            opts.fuse_soc_manifest_max_svn,
            None,
        )
    }

    /// Test case: happy path
    fn test_successful_boot(opts: &TestOptions) {
        let test = run_runtime_with_options(opts);
        assert_eq!(0, test);
    }

    fn test_soc_manifest_svn_lt_fuse(opts: &TestOptions) {
        let mut new_options = opts.clone();
        new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), Some(10))
            .unwrap();
        new_options.fuse_soc_manifest_svn = Some(12);
        new_options.fuse_soc_manifest_max_svn = Some(13);
        new_options.device_security_state = Some(DeviceLifecycle::Manufacturing);
        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    fn test_soc_manifest_svn_gt_max_svn(opts: &TestOptions) {
        let mut new_options = opts.clone();
        new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), Some(14))
            .unwrap();
        new_options.fuse_soc_manifest_svn = Some(12);
        new_options.fuse_soc_manifest_max_svn = Some(13);
        new_options.device_security_state = Some(DeviceLifecycle::Manufacturing);
        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    fn test_soc_manifest_good_svn(opts: &TestOptions) {
        let mut new_options = opts.clone();
        new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), Some(10))
            .unwrap();
        new_options.fuse_soc_manifest_svn = Some(9);
        new_options.fuse_soc_manifest_max_svn = Some(13);
        new_options.device_security_state = Some(DeviceLifecycle::Manufacturing);

        // Replace the SoC Manifest in the PLDM package
        let flash_offset = opts
            .partition_table
            .as_ref()
            .and_then(|pt| pt.get_active_partition().1.as_ref().map(|p| p.offset))
            .unwrap_or(0);
        let (_, flash_image_path) = create_flash_image(
            new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
            new_options
                .builder
                .as_mut()
                .unwrap()
                .get_soc_manifest(None)
                .ok(),
            Some(opts.runtime.clone()),
            opts.partition_table.clone(),
            flash_offset,
            new_options.soc_images_paths.clone(),
        );
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let device_uuid = get_device_uuid();
            let flash_image =
                std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: Image ID in the SOC manifest is different from the one being authorized in the firmware
    fn test_boot_invalid_image_id(opts: &TestOptions) {
        let mut new_options = opts.clone();
        new_options.soc_images[0].image_id = 0xDEAD; // Change the image ID to an invalid one
        let soc_manifest = new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), None)
            .unwrap();

        // Update the SOC manifest in the flash image
        let (_, flash_image_path) = create_flash_image(
            new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
            Some(soc_manifest),
            Some(new_options.runtime.clone()),
            new_options.partition_table.clone(),
            new_options.flash_offset,
            new_options.soc_images_paths.clone(),
        );

        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            Some(flash_image_path)
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: The FW to be streamed has been altered making it unauthorized
    fn test_boot_unathorized_image(opts: &TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0xDEu8; 512];
        let soc_image_fw_2 = [0xADu8; 256];
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
        let flash_offset = opts
            .partition_table
            .as_ref()
            .and_then(|pt| pt.get_active_partition().1.as_ref().map(|p| p.offset))
            .unwrap_or(0);
        let (_, flash_image_path) = create_flash_image(
            new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
            new_options
                .builder
                .as_mut()
                .unwrap()
                .get_soc_manifest(None)
                .ok(),
            Some(opts.runtime.clone()),
            opts.partition_table.clone(),
            flash_offset,
            soc_images_paths.clone(),
        );

        // Generate the corresponding PLDM package for the altered flash image
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let device_uuid = get_device_uuid();
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
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

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: The load address in the SOC manifest is not a valid addressable AXI address
    fn test_invalid_load_address(opts: &TestOptions) {
        let mut new_options = opts.clone();
        // Change the load address in the SOC manifest to an invalid one
        new_options.soc_images[0].load_addr = 0xffff; // Invalid load address

        let soc_manifest = new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), None)
            .unwrap();

        // Update the SOC manifest in the flash image
        let (_, flash_image_path) = create_flash_image(
            new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
            Some(soc_manifest),
            Some(new_options.runtime.clone()),
            new_options.partition_table.clone(),
            new_options.flash_offset,
            new_options.soc_images_paths.clone(),
        );
        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            Some(flash_image_path)
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: Test booting from secondary flash
    fn test_boot_secondary_flash(opts: TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0x55u8; 512];
        let soc_image_fw_2 = [0xAAu8; 256];
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
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
                new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
                new_options
                    .builder
                    .as_mut()
                    .unwrap()
                    .get_soc_manifest(None)
                    .ok(),
                Some(opts.runtime.clone()),
                None,
                0,
                soc_images_paths.clone(),
            );
            Some(secondary_flash_image_path)
        } else {
            None
        };
        new_options.secondary_flash_image_path = secondary_flash_image_path.clone();

        // Update the partition table in the primary flash
        let primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            let (_, primary_flash_image_path) = create_flash_image(
                None,
                None,
                None,
                Some(new_partition_table),
                IMAGE_A_PARTITION.offset,
                vec![],
            );
            Some(primary_flash_image_path)
        } else {
            None
        };
        new_options.primary_flash_image_path = primary_flash_image_path.clone();

        let test = run_runtime_with_options(&new_options);
        assert_eq!(0, test);
    }

    // Test case: Partition table has invalid checksum
    fn test_boot_partition_table_invalid_checksum(opts: &TestOptions) {
        let mut new_options = opts.clone();

        // Create another flash image with a different content
        let soc_image_fw_1 = [0x55u8; 512];
        let soc_image_fw_2 = [0xAAu8; 256];
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
        let new_partition_table = PartitionTable {
            active_partition: PartitionId::B as u32,
            partition_a_status: PartitionStatus::Invalid as u16,
            partition_b_status: PartitionStatus::Valid as u16, // Set partition B as valid
            ..Default::default()
        };
        // Do not populate the checksum
        new_options.secondary_flash_image_path = if opts.secondary_flash_image_path.is_some() {
            let (_, secondary_flash_image_path) = create_flash_image(
                new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
                new_options
                    .builder
                    .as_mut()
                    .unwrap()
                    .get_soc_manifest(None)
                    .ok(),
                Some(new_options.runtime.clone()),
                None,
                IMAGE_B_PARTITION.offset,
                soc_images_paths.clone(),
            );
            Some(secondary_flash_image_path)
        } else {
            None
        };

        // Update the partition table in the primary flash

        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            let (_, primary_flash_image_path) = create_flash_image(
                None,
                None,
                None,
                Some(new_partition_table),
                IMAGE_A_PARTITION.offset,
                vec![],
            );
            Some(primary_flash_image_path)
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: The PLDM descriptor in the PLDM package is different from the device's descriptor
    fn test_incorrect_pldm_descriptor(opts: &TestOptions) {
        let mut new_options = opts.clone();

        // Generate another PLDM Package with a different descriptor
        let mut device_uuid = get_device_uuid();
        device_uuid[0] = 0xFF; // Change the first byte of the UUID

        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: The PLDM component ID in the PLDM package is not valid
    fn test_incorrect_pldm_component_id(opts: &TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].identifier = 0xDEAD; // Change the component ID to an invalid one
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: Corrupted PLDM FW package
    fn test_corrupted_pldm_fw_package(opts: &TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].image_data = Some(vec![0x00]); // Remove the image data to simulate corruption
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    // Test case: PLDM FW package has lower version than device's active image version
    fn test_lower_version_pldm_fw_package(opts: &TestOptions) {
        let mut new_options = opts.clone();
        let device_uuid = get_device_uuid();
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2
        let soc_images_paths =
            create_soc_images(vec![soc_image_fw_1.to_vec(), soc_image_fw_2.to_vec()]);

        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let mut pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            pldm_manifest.component_image_information[0].options = 0x0001; // Enable comparison stamp option
            pldm_manifest.component_image_information[0].comparison_stamp = Some(0x00000000); // Set a lower version
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_ne!(0, test);
    }

    fn test_one_component_id_for_all(opts: &TestOptions) {
        let mut new_options = opts.clone();

        // First soc_image metadata
        let first_soc_image_metadata = new_options.soc_images[0].clone();
        // Set all soc_images to have the same component ID as the first one
        for soc_image in new_options.soc_images.iter_mut() {
            soc_image.component_id = first_soc_image_metadata.component_id;
            soc_image.path = first_soc_image_metadata.path.clone();
        }

        new_options
            .builder
            .as_mut()
            .unwrap()
            .replace_manifest_config(new_options.soc_images.clone(), None)
            .unwrap();

        // Replace the SoC Manifest in the PLDM package
        let flash_offset = opts
            .partition_table
            .as_ref()
            .and_then(|pt| pt.get_active_partition().1.as_ref().map(|p| p.offset))
            .unwrap_or(0);

        // Same image for all SOCs
        let soc_images_paths =
            vec![new_options.soc_images_paths[0].clone(); new_options.soc_images.len()];

        let new_soc_manifest = new_options
            .builder
            .as_mut()
            .unwrap()
            .get_soc_manifest(None)
            .ok();

        // Create a flash image with the updated SOC manifest
        let (_, flash_image_path) = create_flash_image(
            new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
            new_soc_manifest.clone(),
            Some(opts.runtime.clone()),
            opts.partition_table.clone(),
            flash_offset,
            soc_images_paths.clone(),
        );
        new_options.primary_flash_image_path = if opts.primary_flash_image_path.is_some() {
            Some(flash_image_path)
        } else {
            None
        };
        new_options.pldm_fw_pkg_path = if opts.pldm_fw_pkg_path.is_some() {
            let (_, flash_image_path) = create_flash_image(
                new_options.builder.as_mut().unwrap().get_caliptra_fw().ok(),
                new_soc_manifest.clone(),
                Some(opts.runtime.clone()),
                None,
                0,
                soc_images_paths.clone(),
            );
            let flash_image = std::fs::read(flash_image_path).expect("Failed to read flash image");
            let pldm_manifest =
                get_streaming_boot_pldm_fw_manifest(&get_device_uuid(), &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        } else {
            None
        };

        let test = run_runtime_with_options(&new_options);
        assert_eq!(0, test);
    }

    // Helper to create test options for soc boot tests
    fn create_soc_boot_options(is_flash_based_boot: bool) -> TestOptions {
        env::set_var(
            "CPTRA_EMULATOR_SS_MCI_OFFSET",
            format!("0x{:016x}", MCI_BASE_AXI_ADDRESS),
        );

        let feature = if is_flash_based_boot {
            "test-flash-based-boot"
        } else {
            "test-pldm-streaming-boot"
        };
        let i3c_port = PortPicker::new().pick().unwrap().into();

        // Check if we have prebuilt binaries for this feature
        if has_prebuilt_binaries(feature) {
            println!("Using prebuilt binaries for feature: {}", feature);
            create_soc_boot_test_options_prebuilt(feature, is_flash_based_boot, i3c_port)
        } else {
            println!("Building binaries for feature: {}", feature);
            create_soc_boot_test_options_build(feature, is_flash_based_boot, i3c_port)
        }
    }

    // Creates test options using prebuilt binaries from CPTRA_FIRMWARE_BUNDLE
    fn create_soc_boot_test_options_prebuilt(
        feature: &'static str,
        is_flash_based_boot: bool,
        i3c_port: u32,
    ) -> TestOptions {
        let binaries = FirmwareBinaries::from_env().expect("CPTRA_FIRMWARE_BUNDLE not set");

        // Get prebuilt runtime
        let runtime_data = binaries
            .test_runtime(feature)
            .expect("Prebuilt runtime not found");
        let test_runtime = std::env::temp_dir().join(format!("soc-boot-runtime-{}.bin", feature));
        std::fs::write(&test_runtime, runtime_data).expect("Failed to write runtime");

        // Get prebuilt flash image
        let flash_image_data = binaries
            .test_flash_image(feature)
            .expect("Prebuilt flash image not found");
        let flash_image_path =
            std::env::temp_dir().join(format!("soc-boot-flash-image-{}.bin", feature));
        std::fs::write(&flash_image_path, &flash_image_data).expect("Failed to write flash image");

        // Get prebuilt PLDM package (only for streaming boot)
        let pldm_fw_pkg_path = if is_flash_based_boot {
            None
        } else {
            let pldm_data = binaries
                .test_pldm_fw_pkg(feature)
                .expect("Prebuilt PLDM package not found");
            let path = std::env::temp_dir().join(format!("soc-boot-pldm-fw-pkg-{}.bin", feature));
            std::fs::write(&path, pldm_data).expect("Failed to write PLDM package");
            Some(path)
        };

        // Get prebuilt feature-specific MCU ROM from the bundle
        let mcu_rom_path = std::env::temp_dir().join(format!("soc-boot-mcu-rom-{}.bin", feature));
        std::fs::write(&mcu_rom_path, binaries.test_feature_rom(feature))
            .expect("Failed to write MCU ROM");
        let mcu_rom = mcu_rom_path;

        // Get prebuilt Caliptra ROM (needed for CaliptraBuilder)
        let caliptra_rom_path =
            std::env::temp_dir().join(format!("soc-boot-caliptra-rom-{}.bin", feature));
        std::fs::write(&caliptra_rom_path, &binaries.caliptra_rom)
            .expect("Failed to write Caliptra ROM");

        // Get prebuilt Caliptra firmware (needed for CaliptraBuilder)
        let caliptra_fw_path =
            std::env::temp_dir().join(format!("soc-boot-caliptra-fw-{}.bin", feature));
        std::fs::write(&caliptra_fw_path, &binaries.caliptra_fw)
            .expect("Failed to write Caliptra firmware");

        // Get prebuilt feature-specific SoC manifest (needed for CaliptraBuilder)
        let soc_manifest_data = binaries
            .test_soc_manifest(feature)
            .expect("Prebuilt SoC manifest not found");
        let soc_manifest_path =
            std::env::temp_dir().join(format!("soc-boot-soc-manifest-{}.bin", feature));
        std::fs::write(&soc_manifest_path, &soc_manifest_data)
            .expect("Failed to write SoC manifest");

        // Create SoC images (same as build path, needed for tests that modify manifest)
        let soc_image_fw_1 = [0x55u8; 512];
        let soc_image_fw_2 = [0xAAu8; 256];
        let soc_images_paths = create_soc_images(vec![
            soc_image_fw_1.clone().to_vec(),
            soc_image_fw_2.clone().to_vec(),
        ]);

        // Create SOC image metadata that will be written to the SoC manifest
        let soc_images = vec![
            ImageCfg {
                path: soc_images_paths[0].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
                image_id: 4096,
                component_id: 4096,
                exec_bit: 5,
                ..Default::default()
            },
            ImageCfg {
                path: soc_images_paths[1].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS
                    + MCU_MBOX_SRAM1_OFFSET
                    + soc_image_fw_1.len() as u64,
                image_id: 4097,
                component_id: 4097,
                exec_bit: 6,
                ..Default::default()
            },
        ];

        // Compute vendor_pk_hash from the prebuilt caliptra firmware
        let manifest: ImageManifest = {
            let bundle: [u8; core::mem::size_of::<ImageManifest>()] = binaries.caliptra_fw
                [..core::mem::size_of::<ImageManifest>()]
                .try_into()
                .expect("Caliptra FW too small");
            transmute!(bundle)
        };
        let vendor_pk_hash: String = CaliptraBuilder::vendor_pk_hash(&manifest)
            .expect("Failed to compute vendor_pk_hash")
            .encode_hex();

        // Build the Caliptra builder with prebuilt paths (needed for tests that modify manifest)
        let builder = CaliptraBuilder::new(
            false,
            Some(caliptra_rom_path),
            Some(caliptra_fw_path.clone()),
            Some(soc_manifest_path.clone()),
            Some(vendor_pk_hash),
            Some(test_runtime.clone()),
            Some(soc_images.clone()),
            None,
            None,
            None,
            None,
        );

        // Create partition table matching what's used in the build path
        // This is needed for tests that modify flash images
        let mut partition_table = PartitionTable {
            active_partition: PartitionId::A as u32,
            partition_a_status: PartitionStatus::Valid as u16,
            partition_b_status: PartitionStatus::Invalid as u16,
            rollback_enable: RollbackEnable::Enabled as u32,
            ..Default::default()
        };
        let checksum_calculator = StandAloneChecksumCalculator::new();
        partition_table.populate_checksum(&checksum_calculator);

        let flash_offset = partition_table
            .get_active_partition()
            .1
            .map_or(0, |p| p.offset);

        let primary_flash_image_path = if is_flash_based_boot {
            Some(flash_image_path.clone())
        } else {
            None
        };

        TestOptions {
            feature,
            rom: mcu_rom,
            runtime: test_runtime,
            i3c_port,
            soc_images,
            soc_images_paths,
            primary_flash_image_path: primary_flash_image_path.clone(),
            secondary_flash_image_path: primary_flash_image_path,
            pldm_fw_pkg_path,
            partition_table: Some(partition_table),
            builder: Some(builder),
            flash_offset,
            fuse_soc_manifest_svn: None,
            fuse_soc_manifest_max_svn: None,
            device_security_state: None,
        }
    }

    // Creates test options by building everything from scratch
    fn create_soc_boot_test_options_build(
        feature: &'static str,
        is_flash_based_boot: bool,
        i3c_port: u32,
    ) -> TestOptions {
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2

        // Compile the runtime once with the appropriate feature
        let test_runtime = compile_runtime(Some(feature), false);

        let soc_images_paths = create_soc_images(vec![
            soc_image_fw_1.clone().to_vec(),
            soc_image_fw_2.clone().to_vec(),
        ]);

        // Create SOC image metadata that will be written to the SoC manifest
        let soc_images = vec![
            ImageCfg {
                path: soc_images_paths[0].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
                image_id: 4096,
                component_id: 4096,
                exec_bit: 5,
                ..Default::default()
            },
            ImageCfg {
                path: soc_images_paths[1].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS
                    + MCU_MBOX_SRAM1_OFFSET
                    + soc_image_fw_1.len() as u64,
                image_id: 4097,
                component_id: 4097,
                exec_bit: 6,
                ..Default::default()
            },
        ];

        // Build the Caliptra runtime
        let mut builder = CaliptraBuilder::new(
            false,
            None,
            None,
            None,
            None,
            Some(test_runtime.clone()),
            Some(soc_images.clone()),
            None,
            None,
            None,
            None,
        );

        // Build Caliptra firmware
        let caliptra_fw = builder
            .get_caliptra_fw()
            .expect("Failed to build Caliptra firmware");

        let soc_manifest = builder
            .get_soc_manifest(None)
            .expect("Failed to build SOC manifest");

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

        let flash_offset = partition_table
            .get_active_partition()
            .1
            .map_or(0, |p| p.offset);
        let (soc_images_paths, flash_image_path) = create_flash_image(
            Some(caliptra_fw),
            Some(soc_manifest),
            Some(test_runtime.clone()),
            Some(partition_table.clone()),
            flash_offset,
            soc_images_paths.clone(),
        );

        // Generate the corresponding PLDM package from the flash image
        let pldm_fw_pkg_path = if is_flash_based_boot {
            None
        } else {
            let device_uuid = get_device_uuid();
            let (_, flash_image_path) =
                create_flash_image(None, None, None, None, 0, soc_images_paths.clone());
            let flash_image =
                std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        };

        // For non flash-based boot, the flash image path is not needed to be passed to the emulator
        // as the firmware will be streamed from the PLDM package
        let flash_image_path = if is_flash_based_boot {
            Some(flash_image_path)
        } else {
            None
        };

        let mcu_rom = get_rom_with_feature(feature);

        TestOptions {
            feature,
            rom: mcu_rom,
            runtime: test_runtime.clone(),
            i3c_port,
            soc_images: soc_images.clone(),
            soc_images_paths: soc_images_paths.clone(),
            primary_flash_image_path: flash_image_path.clone(),
            secondary_flash_image_path: flash_image_path.clone(),
            pldm_fw_pkg_path: pldm_fw_pkg_path.clone(),
            partition_table: Some(partition_table.clone()),
            builder: Some(builder.clone()),
            flash_offset,
            fuse_soc_manifest_svn: None,
            fuse_soc_manifest_max_svn: None,
            device_security_state: None,
        }
    }

    // ==================== Flash-based boot tests ====================

    #[test]
    fn test_flash_soc_boot_successful() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_successful_boot(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_secondary_flash() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_boot_secondary_flash(opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_invalid_image_id() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_boot_invalid_image_id(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_unauthorized_image() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_boot_unathorized_image(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_invalid_load_address() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_invalid_load_address(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_partition_table_invalid_checksum() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_boot_partition_table_invalid_checksum(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_flash_soc_boot_one_component_id_for_all() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(true);
        test_one_component_id_for_all(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // ==================== Streaming boot tests ====================

    #[test]
    fn test_streaming_soc_boot_successful() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_successful_boot(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_invalid_image_id() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_boot_invalid_image_id(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_unauthorized_image() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_boot_unathorized_image(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_invalid_load_address() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_invalid_load_address(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_incorrect_pldm_descriptor() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_incorrect_pldm_descriptor(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_incorrect_pldm_component_id() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_incorrect_pldm_component_id(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_corrupted_pldm_fw_package() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_corrupted_pldm_fw_package(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_lower_version_pldm_fw_package() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_lower_version_pldm_fw_package(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_manifest_svn_lt_fuse() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_soc_manifest_svn_lt_fuse(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_manifest_svn_gt_max_svn() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_soc_manifest_svn_gt_max_svn(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_manifest_good_svn() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_soc_manifest_good_svn(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_streaming_soc_boot_one_component_id_for_all() {
        let lock = TEST_LOCK.lock().unwrap();
        let opts = create_soc_boot_options(false);
        test_one_component_id_for_all(&opts);
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Test case: simple successful boot using McuHwModel trait
    /// This test uses the hardware model abstraction instead of spawning a subprocess
    #[test]
    fn test_successful_boot_hw_model() {
        use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
        use std::sync::atomic::Ordering;

        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        // Use the exit-immediately feature for a simple boot test
        let feature = "test-exit-immediately";

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            i3c_port: PortPicker::new().pick().ok(),
            flash_boot: true,
            ..Default::default()
        });

        let result = finish_runtime_hw_model(&mut hw);
        assert_eq!(0, result, "Boot should complete successfully");

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
