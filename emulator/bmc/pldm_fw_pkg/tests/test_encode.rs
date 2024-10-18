/*++

Licensed under the Apache-2.0 license.

--*/
use pldm_fw_pkg::FirmwareManifest;
use std::path::PathBuf;

#[test]
fn test_parse_valid_manifest_all_fields_present() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_all_fields_present.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify package_header_information
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_header_identifier
            .to_string()
            .to_uppercase()
            .replace("-", ""),
        "7B291C996DB64208801B02026E463C78"
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_header_format_revision,
        1
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_version_string
            .as_deref(),
        Some("HGX-H100x8_0002_230517.3.0")
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_version_string_type
            .to_string(),
        "ASCII"
    );

    // Verify firmware_device_id_records (First record)
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    assert_eq!(firmware_record_1.device_update_option_flags, 1);
    assert_eq!(
        firmware_record_1
            .component_image_set_version_string
            .as_deref(),
        Some("Firmware v1")
    );
    assert_eq!(
        firmware_record_1
            .component_image_set_version_string_type
            .to_string(),
        "ASCII"
    );
    assert_eq!(
        firmware_record_1.applicable_components.as_ref().unwrap(),
        &[0, 1]
    );
    assert_eq!(
        firmware_record_1
            .initial_descriptor
            .descriptor_type
            .to_string(),
        "PCI_VENDOR_ID"
    );
    assert_eq!(
        firmware_record_1.initial_descriptor.descriptor_data,
        vec![0x01, 0x02, 0x03, 0x04]
    );
    if let Some(additional_descriptors) = &firmware_record_1.additional_descriptors {
        assert_eq!(additional_descriptors.len(), 2);
        assert_eq!(
            additional_descriptors[0].descriptor_type.to_string(),
            "PCI_DEVICE_ID"
        );
        assert_eq!(additional_descriptors[0].descriptor_data, vec![0x10, 0x20]);
        assert_eq!(
            additional_descriptors[1].descriptor_type.to_string(),
            "PCI_SUBSYSTEM_ID"
        );
        assert_eq!(additional_descriptors[1].descriptor_data, vec![0x30, 0x40]);
    }
    assert_eq!(
        firmware_record_1
            .firmware_device_package_data
            .as_ref()
            .unwrap(),
        &vec![0xAA, 0xBB, 0xCC, 0xDD]
    );

    // Verify firmware_device_id_records (Second record)
    let firmware_record_2 = &parsed_manifest.firmware_device_id_records[1];
    assert_eq!(firmware_record_2.device_update_option_flags, 0);
    assert_eq!(
        firmware_record_2
            .component_image_set_version_string
            .as_deref(),
        Some("Firmware v2")
    );
    assert_eq!(
        firmware_record_2
            .component_image_set_version_string_type
            .to_string(),
        "ASCII"
    );
    assert_eq!(
        firmware_record_2.applicable_components.as_ref().unwrap(),
        &[1]
    );
    assert_eq!(
        firmware_record_2
            .initial_descriptor
            .descriptor_type
            .to_string(),
        "UUID"
    );
    assert_eq!(
        firmware_record_2.initial_descriptor.descriptor_data,
        vec![0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        firmware_record_2
            .firmware_device_package_data
            .as_ref()
            .unwrap(),
        &vec![0x99, 0x88, 0x77, 0x66]
    );
    assert_eq!(
        firmware_record_2.reference_manifest_data.as_ref().unwrap(),
        &vec![0x55, 0x44]
    );

    // Verify downstream_device_id_records
    if let Some(downstream_record) = parsed_manifest.downstream_device_id_records {
        let downstream_record = &downstream_record[0];
        assert_eq!(downstream_record.update_option_flags, 1);
        assert_eq!(
            downstream_record
                .self_contained_activation_min_version_string_type
                .to_string(),
            "ASCII"
        );
        assert_eq!(
            downstream_record
                .self_contained_activation_min_version_string
                .as_deref(),
            Some("MinVersion 1.0")
        );
        assert_eq!(
            downstream_record
                .self_contained_activation_min_version_comparison_stamp
                .unwrap(),
            12345678
        );
        assert_eq!(
            downstream_record.record_descriptors[0]
                .descriptor_type
                .to_string(),
            "UUID"
        );
        assert_eq!(
            downstream_record.record_descriptors[0].descriptor_data,
            vec![0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            downstream_record.record_descriptors[1]
                .descriptor_type
                .to_string(),
            "IANA_ENTERPRISE_ID"
        );
        assert_eq!(
            downstream_record.record_descriptors[1].descriptor_data,
            vec![0x15, 0x25, 0x35]
        );
        assert_eq!(
            downstream_record.package_data.as_ref().unwrap(),
            &vec![0x88, 0x77, 0x66, 0x55]
        );
        assert_eq!(
            downstream_record.reference_manifest_data.as_ref().unwrap(),
            &vec![0x44, 0x33]
        );
    }

    // Verify component_image_information (First component)
    let component_1 = &parsed_manifest.component_image_information[0];
    assert_eq!(component_1.image_location, "tests/manifests/img_128.bin");
    assert_eq!(component_1.classification, 0x0001);
    assert_eq!(component_1.identifier, 0x0010);
    assert_eq!(component_1.comparison_stamp.unwrap(), 12345);
    assert_eq!(component_1.options, 0x0003);
    assert_eq!(component_1.requested_activation_method, 0x0007);
    assert_eq!(component_1.version_string_type.to_string(), "ASCII");
    assert_eq!(component_1.version_string.as_deref(), Some("v1.0.0"));
    assert_eq!(
        component_1.opaque_data.as_ref().unwrap(),
        &vec![0xAA, 0xBB, 0xCC, 0xDD]
    );

    // Verify component_image_information (Second component)
    let component_2 = &parsed_manifest.component_image_information[1];
    assert_eq!(component_2.image_location, "tests/manifests/img_512.bin");
    assert_eq!(component_2.classification, 0xFFFF);
    assert_eq!(component_2.identifier, 0x0020);
    assert_eq!(component_2.comparison_stamp.unwrap(), 54321);
    assert_eq!(component_2.options, 0x0001);
    assert_eq!(component_2.requested_activation_method, 0x0003);
    assert_eq!(component_2.version_string_type.to_string(), "ASCII");
    assert_eq!(component_2.version_string.as_deref(), Some("v2.3.4"));
    assert_eq!(
        component_2.opaque_data.as_ref().unwrap(),
        &vec![0x11, 0x22, 0x33, 0x44]
    );
}

#[test]
fn test_parse_valid_manifest_no_downstream_one_component() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_no_downstream_one_component.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify package_header_information
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_header_identifier
            .to_string()
            .to_uppercase()
            .replace("-", ""),
        "7B291C996DB64208801B02026E463C78"
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_header_format_revision,
        1
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_version_string
            .as_deref(),
        Some("HGX-H100x8_0002_230517.3.0")
    );
    assert_eq!(
        parsed_manifest
            .package_header_information
            .package_version_string_type
            .to_string(),
        "ASCII"
    );

    // Verify firmware_device_id_records (First record)
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    assert_eq!(firmware_record_1.device_update_option_flags, 1);
    assert_eq!(
        firmware_record_1
            .component_image_set_version_string
            .as_deref(),
        Some("Firmware v1")
    );
    assert_eq!(
        firmware_record_1
            .component_image_set_version_string_type
            .to_string(),
        "ASCII"
    );
    assert_eq!(
        firmware_record_1.applicable_components.as_ref().unwrap(),
        &[0]
    );
    assert_eq!(
        firmware_record_1
            .initial_descriptor
            .descriptor_type
            .to_string(),
        "PCI_VENDOR_ID"
    );
    assert_eq!(
        firmware_record_1.initial_descriptor.descriptor_data,
        vec![0x01, 0x02, 0x03, 0x04]
    );
    if let Some(additional_descriptors) = &firmware_record_1.additional_descriptors {
        assert_eq!(additional_descriptors.len(), 2);
        assert_eq!(
            additional_descriptors[0].descriptor_type.to_string(),
            "PCI_DEVICE_ID"
        );
        assert_eq!(additional_descriptors[0].descriptor_data, vec![0x10, 0x20]);
        assert_eq!(
            additional_descriptors[1].descriptor_type.to_string(),
            "PCI_SUBSYSTEM_ID"
        );
        assert_eq!(additional_descriptors[1].descriptor_data, vec![0x30, 0x40]);
    }
    assert_eq!(
        firmware_record_1
            .firmware_device_package_data
            .as_ref()
            .unwrap(),
        &vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
    // Verify firmware_device_id_records (Second record)
    let firmware_record_2 = &parsed_manifest.firmware_device_id_records[1];
    assert_eq!(firmware_record_2.device_update_option_flags, 0);
    assert_eq!(
        firmware_record_2
            .component_image_set_version_string
            .as_deref(),
        Some("Firmware v2")
    );
    assert_eq!(
        firmware_record_2
            .component_image_set_version_string_type
            .to_string(),
        "ASCII"
    );
    assert_eq!(
        firmware_record_2.applicable_components.as_ref().unwrap(),
        &[0]
    );
    assert_eq!(
        firmware_record_2
            .initial_descriptor
            .descriptor_type
            .to_string(),
        "UUID"
    );
    assert_eq!(
        firmware_record_2.initial_descriptor.descriptor_data,
        vec![0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        firmware_record_2
            .firmware_device_package_data
            .as_ref()
            .unwrap(),
        &vec![0x99, 0x88, 0x77, 0x66]
    );
    assert_eq!(
        firmware_record_2.reference_manifest_data.as_ref().unwrap(),
        &vec![0x55, 0x44]
    );

    // Verify downstream_device_id_records
    // Verify there are no downstream_device_id_records
    assert_eq!(parsed_manifest.downstream_device_id_records, None);

    // Verify component_image_information (First component)
    assert_eq!(parsed_manifest.component_image_information.len(), 1);
    let component_1 = &parsed_manifest.component_image_information[0];
    assert_eq!(component_1.image_location, "tests/manifests/img_128.bin");
    assert_eq!(component_1.classification, 0x0001);
    assert_eq!(component_1.identifier, 0x0010);
    assert_eq!(component_1.comparison_stamp.unwrap(), 12345);
    assert_eq!(component_1.options, 0x0003);
    assert_eq!(component_1.requested_activation_method, 0x0007);
    assert_eq!(component_1.version_string_type.to_string(), "ASCII");
    assert_eq!(component_1.version_string.as_deref(), Some("v1.0.0"));
    assert_eq!(
        component_1.opaque_data.as_ref().unwrap(),
        &vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
}

#[test]
fn test_parse_valid_manifest_no_downstream_nine_components() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path =
        PathBuf::from("tests/manifests/manifest_no_downstream_nine_components.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify component_image_information (First component)
    assert_eq!(parsed_manifest.component_image_information.len(), 9);
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    assert_eq!(
        firmware_record_1.applicable_components.as_ref().unwrap(),
        &[8]
    );

    let firmware_record_2 = &parsed_manifest.firmware_device_id_records[1];
    assert_eq!(
        firmware_record_2.applicable_components.as_ref().unwrap(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn test_parse_valid_manifest_one_fw_record_one_device_id() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_one_fw_record_one_device_id.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify number of firmware record is 1
    assert_eq!(parsed_manifest.firmware_device_id_records.len(), 1);

    // Verify number of device records for this firmware record is 1
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    // Verify additional descriptors is None
    assert_eq!(firmware_record_1.additional_descriptors, None);
}

#[test]
fn test_parse_valid_manifest_no_firmware_package() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_no_firmware_package.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify firmware record 1 has no firmware package data
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    assert_eq!(firmware_record_1.firmware_device_package_data, None);
}

#[test]
fn test_parse_valid_manifest_no_reference() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_no_reference.toml");

    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string())
            .expect("Failed to parse manifest file");

    // Verify firmware record 1 has no firmware package data
    let firmware_record_1 = &parsed_manifest.firmware_device_id_records[0];
    assert_eq!(firmware_record_1.reference_manifest_data, None);
}

#[test]
fn test_parse_not_toml() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_not_toml.txt");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}

#[test]
fn test_parse_out_of_bounds_applicable_components() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path =
        PathBuf::from("tests/manifests/manifest_out_of_bounds_applicable_components.toml");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}

#[test]
fn test_parse_invalid_revision() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path =
        PathBuf::from("tests/manifests/manifest_more_incorrect_revision_format.toml");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}

#[test]
fn test_parse_invalid_string_type() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_invalid_string_type.toml");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}

#[test]
fn test_parse_no_components() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path = PathBuf::from("tests/manifests/manifest_no_components.toml");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}

#[test]
fn test_parse_invalid_component_image_location() {
    // Path to the example manifest file (update to your actual path if needed)
    let manifest_path =
        PathBuf::from("tests/manifests/manifest_invalid_component_image_location.toml");

    // Verify that the manifest file can not be parsed
    let parsed_manifest =
        FirmwareManifest::parse_manifest_file(&manifest_path.to_string_lossy().to_string());
    assert!(parsed_manifest.is_err());
}
