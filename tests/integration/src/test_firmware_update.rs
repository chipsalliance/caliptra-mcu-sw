// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{compile_runtime, get_rom_with_feature, run_runtime, TEST_LOCK};
    use chrono::{TimeZone, Utc};
    use mcu_builder::{CaliptraBuilder, SocImage};
    use mcu_config_emulator::flash::PartitionTable;
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
        rom: PathBuf,
        runtime: PathBuf,
        i3c_port: u32,
        soc_images: Vec<SocImage>,
        soc_images_paths: Vec<PathBuf>,
        primary_flash_image_path: Option<PathBuf>,
        secondary_flash_image_path: Option<PathBuf>,
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

    fn run_runtime_with_options(opts: &TestOptions) -> ExitStatus {
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
        )
    }

    /// Test case: happy path
    fn test_successful_update(opts: &TestOptions) {
        let test = run_runtime_with_options(opts);
        assert_eq!(0, test.code().unwrap_or_default());
    }

    // Common test function for both flash-based and streaming boot
    fn test_firmware_update_common() {
        let lock = TEST_LOCK.lock().unwrap();
        let feature = "test-firmware-update";
        let i3c_port = 65500;
        let soc_image_fw_1 = [0x55u8; 512]; // Example firmware data for SOC image 1
        let soc_image_fw_2 = [0xAAu8; 256]; // Example firmware data for SOC image 2

        // Compile the runtime once with the appropriate feature
        let test_runtime = compile_runtime(feature, false);

        let soc_images_paths = create_soc_images(vec![
            soc_image_fw_1.clone().to_vec(),
            soc_image_fw_2.clone().to_vec(),
        ]);

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

        // Build the Caliptra runtime
        let mut builder = CaliptraBuilder::new(
            false,
            None,
            None,
            None,
            None,
            Some(test_runtime.clone()),
            Some(soc_images.clone()),
        );

        // Build Caliptra firmware
        let caliptra_fw = builder
            .get_caliptra_fw()
            .expect("Failed to build Caliptra firmware");

        let soc_manifest = builder
            .get_soc_manifest()
            .expect("Failed to build SOC manifest");

        /*
                let (soc_images_paths, flash_image_path) = create_flash_image(
                    Some(caliptra_fw),
                    Some(soc_manifest),
                    Some(test_runtime.clone()),
                    None,
                    0,
                    soc_images_paths.clone(),
                );
        */
        let (soc_images_paths, flash_image_path) = create_flash_image(
            Some(caliptra_fw),
            Some(soc_manifest),
            None,
            None,
            0,
            Vec::new(),
        );

        // Generate the corresponding PLDM package from the flash image
        let pldm_fw_pkg_path = {
            let device_uuid = get_device_uuid();
            let flash_image =
                std::fs::read(flash_image_path.clone()).expect("Failed to read flash image");
            let pldm_manifest = get_streaming_boot_pldm_fw_manifest(&device_uuid, &flash_image);
            Some(create_pldm_fw_package(&pldm_manifest))
        };

        // For non flash-based boot, the flash image path is not needeed to be passed to the emulator
        // as the firmware will be streamed from the PLDM package
        let flash_image_path = None;

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
            pldm_fw_pkg_path: pldm_fw_pkg_path.clone(),
            partition_table: None,
            builder: Some(builder.clone()),
            flash_offset: 0,
        };

        run_test!(test_successful_update, &pass_options.clone());

        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn test_firmware_update() {
        test_firmware_update_common();
    }
}
