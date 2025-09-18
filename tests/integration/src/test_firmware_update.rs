// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{compile_runtime, get_rom_with_feature, run_runtime, TEST_LOCK};
    use chrono::{TimeZone, Utc};
    use flash_image::{MCU_RT_IDENTIFIER, SOC_IMAGES_BASE_IDENTIFIER};
    use mcu_builder::{CaliptraBuilder, ImageCfg};
    use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
    use mcu_config_emulator::flash::{PartitionTable, StandAloneChecksumCalculator};
    use mcu_config_emulator::EMULATOR_MEMORY_MAP;
    use pldm_fw_pkg::manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    };
    use pldm_fw_pkg::FirmwareManifest;
    use std::env;
    use std::path::PathBuf;

    const MCI_BASE_AXI_ADDRESS: u64 = 0xAAAAAAAA_00000000;
    const MCU_MBOX_SRAM1_OFFSET: u64 = 0x80_0000;
    const MCU_SRAM_OFFSET: u64 = 0xc0_0000;

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
        update_flash_image_path: Option<PathBuf>,
        update_caliptra_fw: Option<PathBuf>,
        update_soc_manifest: Option<PathBuf>,
        update_soc_images_paths: Vec<PathBuf>,
        update_runtime_firmware: Option<PathBuf>,
        pldm_fw_pkg_path: Option<PathBuf>,
        partition_table: Option<PartitionTable>,
        builder: Option<CaliptraBuilder>,
        flash_offset: usize,
    }

    macro_rules! run_test {
        ($func:ident, $($args:expr),*) => {{
            println!("Running {}...", stringify!($func));
            $func($($args),*);
        }};
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
        // prevent warning on unused options, this will be used in the future
        let _ = &opts.soc_images_paths;
        let _ = &opts.partition_table;
        let _ = &opts.flash_offset;

        run_runtime(
            opts.feature,
            opts.rom.clone(),
            opts.runtime.clone(),
            opts.i3c_port.to_string(),
            true,
            false,
            Some(opts.soc_images.clone()),
            opts.pldm_fw_pkg_path.clone(),
            opts.primary_flash_image_path.clone(),
            opts.secondary_flash_image_path.clone(),
            opts.builder.clone(),
            Some("2.1.0".to_string()),
            None,
            None,
            None,
        )
    }

    fn create_update_package() -> (PathBuf, PathBuf, PathBuf, String, PathBuf, Vec<PathBuf>) {
        // Build the update PLDM firmware package
        let update_soc_image_fw_1 = [0x66u8; 512];
        let update_soc_image_fw_2 = [0xBBu8; 256];
        let update_soc_images_paths = create_soc_images(vec![
            update_soc_image_fw_1.clone().to_vec(),
            update_soc_image_fw_2.clone().to_vec(),
        ]);
        let update_soc_images = vec![
            ImageCfg {
                path: update_soc_images_paths[0].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
                image_id: SOC_IMAGES_BASE_IDENTIFIER,
                exec_bit: 100,
                ..Default::default()
            },
            ImageCfg {
                path: update_soc_images_paths[1].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS
                    + MCU_MBOX_SRAM1_OFFSET
                    + update_soc_image_fw_1.len() as u64,
                image_id: SOC_IMAGES_BASE_IDENTIFIER + 1,
                exec_bit: 101,
                ..Default::default()
            },
        ];
        let update_runtime_firmware = compile_runtime("test-flash-based-boot", false);
        let mcu_cfg = ImageCfg {
            path: update_runtime_firmware.clone(),
            load_addr: (EMULATOR_MEMORY_MAP.mci_offset as u64) + MCU_SRAM_OFFSET,
            staging_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET + (512 * 1024) as u64,
            image_id: MCU_RT_IDENTIFIER,
            exec_bit: 2,
        };

        let mut update_builder = CaliptraBuilder::new(
            false,
            None,
            None,
            None,
            None,
            Some(update_runtime_firmware.clone()),
            Some(update_soc_images.clone()),
            Some(mcu_cfg.clone()),
            None,
        );
        let update_caliptra_fw = update_builder
            .get_caliptra_fw()
            .expect("Failed to build Caliptra firmware for update");
        let update_soc_manifest = update_builder
            .get_soc_manifest()
            .expect("Failed to build SOC manifest for update");

        let temp_soc_manifest = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_str()
            .unwrap()
            .to_string();

        std::fs::copy(update_soc_manifest.clone(), temp_soc_manifest.clone())
            .expect("Failed to copy SOC manifest");
        let (_, update_flash_image_path) = create_flash_image(
            Some(update_caliptra_fw.clone()),
            Some(temp_soc_manifest.clone().into()),
            Some(update_runtime_firmware.clone()),
            None,
            0,
            update_soc_images_paths.clone(),
        );

        // Generate the corresponding PLDM package from the flash image
        let device_uuid = get_device_uuid();
        let flash_image =
            std::fs::read(update_flash_image_path.clone()).expect("Failed to read flash image");
        let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
        (
            create_pldm_fw_package(&pldm_manifest),
            update_flash_image_path,
            update_caliptra_fw,
            temp_soc_manifest,
            update_runtime_firmware,
            update_soc_images_paths,
        )
    }

    fn fast_update_options(success_opts: &TestOptions) -> TestOptions {
        // Note: This is a hack to speed up testing.
        // This function creates a new option that essentially skips the PLDM download phase of the firmware package.
        // In a full update test, the PLDM FW package contains all the necessary firmware components (e.g., Caliptra Image, MCU Image, etc)
        // The device downloads the flash image component of the PLDM FW package in the staging area, which is the secondary flash.
        // For this hack, we will initialize the secondary flash already with the update flash image.
        // We will truncate the flash image component of the PLDM FW package to the first 1024 bytes.
        // The device will then download only the first 1024 bytes of the full flash image to the secondary flash.
        // But since the secondary flash already contains the full flash image, it essentially didn't change after the PLDM download.
        // The device will then continue with the firmware update with the full flash update image in the secondary flash.

        let mut new_opts = success_opts.clone();
        let update_flash_image_path = new_opts.update_flash_image_path.as_ref().unwrap().clone();
        let flash_image =
            std::fs::read(update_flash_image_path.clone()).expect("Failed to read flash image");
        // Retain the first 1024 bytes flash_image in the PLDM package.
        let truncated_flash_image = &flash_image[..1024];
        let pldm_manifest =
            get_streaming_boot_pldm_fw_manifest(&get_device_uuid(), truncated_flash_image);
        let pldm_fw_pkg_path = create_pldm_fw_package(&pldm_manifest);
        new_opts.pldm_fw_pkg_path = Some(pldm_fw_pkg_path);
        new_opts.secondary_flash_image_path = Some(update_flash_image_path.clone());
        new_opts
    }

    /// Test case: happy path
    fn test_successful_update(opts: &TestOptions) {
        let test = run_runtime_with_options(opts);
        assert_eq!(0, test);
    }

    fn test_successful_fast_update(opts: &TestOptions) {
        let fast_update_opts = fast_update_options(opts);
        let test = run_runtime_with_options(&fast_update_opts);
        assert_eq!(0, test);
    }

    fn test_missing_caliptra_image(opts: &TestOptions) {
        let mut opts = opts.clone();

        // Create a new PLDM package without Caliptra Image
        let (_, update_flash_image_path) = create_flash_image(
            None,
            opts.update_soc_manifest.clone(),
            opts.update_runtime_firmware.clone(),
            None,
            0,
            opts.update_soc_images_paths.clone(),
        );

        opts.update_flash_image_path = Some(update_flash_image_path);
        let opts = fast_update_options(&opts);
        let test = run_runtime_with_options(&opts);
        assert_ne!(0, test);
    }

    fn test_invalid_manifest(opts: &TestOptions) {
        let mut opts = opts.clone();

        // Create a temp file of 1024 bytes with just 0xdeadbeef
        let invalid_manifest_path = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_path_buf();
        std::fs::write(
            &invalid_manifest_path,
            [0xde, 0xad, 0xbe, 0xef].repeat(1024),
        )
        .expect("Failed to write invalid manifest");

        // Create a new PLDM package without Caliptra Image
        let (_, update_flash_image_path) = create_flash_image(
            opts.update_caliptra_fw.clone(),
            Some(invalid_manifest_path),
            opts.update_runtime_firmware.clone(),
            None,
            0,
            opts.update_soc_images_paths.clone(),
        );

        opts.update_flash_image_path = Some(update_flash_image_path);
        let opts = fast_update_options(&opts);
        let test = run_runtime_with_options(&opts);
        assert_ne!(0, test);
    }

    fn test_invalid_mcu_image(opts: &TestOptions) {
        let mut opts = opts.clone();

        // Create a temp file of 1024 bytes with just 0xdeadbeef
        let invalid_mcu_path = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_path_buf();
        std::fs::write(&invalid_mcu_path, [0xde, 0xad, 0xbe, 0xef].repeat(1024))
            .expect("Failed to write invalid manifest");

        // Create a new PLDM package without Caliptra Image
        let (_, update_flash_image_path) = create_flash_image(
            opts.update_caliptra_fw.clone(),
            opts.update_soc_manifest.clone(),
            Some(invalid_mcu_path),
            None,
            0,
            opts.update_soc_images_paths.clone(),
        );

        opts.update_flash_image_path = Some(update_flash_image_path);
        let opts = fast_update_options(&opts);
        let test = run_runtime_with_options(&opts);
        assert_ne!(0, test);
    }

    fn test_invalid_soc_image(opts: &TestOptions) {
        let mut opts = opts.clone();

        // Create a temp file of 1024 bytes with just 0xdeadbeef
        let invalid_soc_path = tempfile::NamedTempFile::new()
            .expect("Failed to create temp file")
            .path()
            .to_path_buf();
        std::fs::write(&invalid_soc_path, [0xde, 0xad, 0xbe, 0xef].repeat(1024))
            .expect("Failed to write invalid manifest");

        let invalid_soc_image_paths = vec![invalid_soc_path];

        // Create a new PLDM package without Caliptra Image
        let (_, update_flash_image_path) = create_flash_image(
            opts.update_caliptra_fw.clone(),
            opts.update_soc_manifest.clone(),
            opts.update_runtime_firmware.clone(),
            None,
            0,
            invalid_soc_image_paths,
        );

        opts.update_flash_image_path = Some(update_flash_image_path);
        let opts = fast_update_options(&opts);
        let test = run_runtime_with_options(&opts);
        assert_ne!(0, test);
    }

    // Common test function for both flash-based and streaming boot
    fn test_firmware_update_common(use_flash: bool) {
        let lock = TEST_LOCK.lock().unwrap();
        let feature = if use_flash {
            "test-firmware-update-flash"
        } else {
            "test-firmware-update-streaming"
        };
        // Set an arbitrary MCI base address
        let mci_base: u64 = 0xAAAAAAAA_00000000;
        env::set_var(
            "CPTRA_EMULATOR_SS_MCI_OFFSET",
            format!("0x{:016x}", mci_base),
        );

        let i3c_port = 65500;
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2

        // Build the PLDM firmware update package
        let (
            pldm_fw_pkg_path,
            update_flash_image_path,
            update_caliptra_fw,
            update_soc_manifest,
            update_runtime_firmware,
            update_soc_images_paths,
        ) = create_update_package();

        // Compile the runtime once with the appropriate feature
        let test_runtime = compile_runtime(feature, false);

        let soc_images_paths = create_soc_images(vec![
            soc_image_fw_1.clone().to_vec(),
            soc_image_fw_2.clone().to_vec(),
        ]);

        // Create SOC image metadata that will be written to the SoC manifest
        let soc_images = vec![
            ImageCfg {
                path: soc_images_paths[0].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
                image_id: SOC_IMAGES_BASE_IDENTIFIER,
                exec_bit: 100,
                ..Default::default()
            },
            ImageCfg {
                path: soc_images_paths[1].clone(),
                load_addr: MCI_BASE_AXI_ADDRESS
                    + MCU_MBOX_SRAM1_OFFSET
                    + soc_image_fw_1.len() as u64,
                image_id: SOC_IMAGES_BASE_IDENTIFIER + 1,
                exec_bit: 101,
                ..Default::default()
            },
        ];

        let mcu_cfg = ImageCfg {
            path: test_runtime.clone(),
            load_addr: (EMULATOR_MEMORY_MAP.mci_offset as u64) + MCU_SRAM_OFFSET,
            staging_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET + (512 * 1024) as u64,
            image_id: MCU_RT_IDENTIFIER,
            exec_bit: 2,
        };

        // Build the Runtime image
        let mut builder = CaliptraBuilder::new(
            false,
            None,
            None,
            None,
            None,
            Some(test_runtime.clone()),
            Some(soc_images.clone()),
            Some(mcu_cfg.clone()),
            None,
        );

        // Build Caliptra firmware
        let caliptra_fw = builder
            .get_caliptra_fw()
            .expect("Failed to build Caliptra firmware");

        let soc_manifest = builder
            .get_soc_manifest()
            .expect("Failed to build SOC manifest");

        // Generate a flash image file to write to the primary flash
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
        let (soc_images_paths, primary_flash_image_path) = create_flash_image(
            Some(caliptra_fw),
            Some(soc_manifest),
            Some(test_runtime.clone()),
            Some(partition_table.clone()),
            flash_offset,
            soc_images_paths.clone(),
        );

        // For non flash-based boot, the flash image path is not needeed to be passed to the emulator
        // as the firmware will be streamed from the PLDM package
        let flash_image_path = if use_flash {
            Some(primary_flash_image_path)
        } else {
            None
        };

        let mcu_rom = get_rom_with_feature(feature);

        // These are the options for a successful boot
        // Each test case will override the options to simulate different scenarios
        let pass_options = TestOptions {
            feature,
            rom: mcu_rom,
            runtime: test_runtime.clone(),
            i3c_port,
            soc_images: soc_images.clone(),
            soc_images_paths: soc_images_paths.clone(),
            primary_flash_image_path: flash_image_path.clone(),
            secondary_flash_image_path: flash_image_path.clone(),
            update_flash_image_path: Some(update_flash_image_path),
            update_caliptra_fw: Some(update_caliptra_fw),
            update_soc_manifest: Some(PathBuf::from(update_soc_manifest)),
            update_runtime_firmware: Some(update_runtime_firmware),
            update_soc_images_paths,
            pldm_fw_pkg_path: Some(pldm_fw_pkg_path),
            partition_table: None,
            builder: Some(builder.clone()),
            flash_offset: 0,
        };

        run_test!(test_successful_update, &pass_options.clone());
        run_test!(test_successful_fast_update, &pass_options.clone());
        run_test!(test_missing_caliptra_image, &pass_options.clone());
        run_test!(test_invalid_manifest, &pass_options.clone());
        run_test!(test_invalid_mcu_image, &pass_options.clone());
        run_test!(test_invalid_soc_image, &pass_options.clone());

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_firmware_update() {
        test_firmware_update_common(true);
    }
}
