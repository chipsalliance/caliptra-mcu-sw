// Licensed under the Apache-2.0 license

use chrono::Utc;
/*++

Licensed under the Apache-2.0 license.

--*/
use pldm_fw_pkg::{
    manifest::{
        ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
        PackageHeaderInformation, StringType,
    },
    FirmwareManifest,
};
use uuid::Uuid;

#[test]
fn test_encode_decode_firmware_package() {
    // Define a sample FirmwareManifest instance
    let manifest = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: Uuid::parse_str("7B291C996DB64208801B02026E463C78").unwrap(),
            package_header_format_revision: 1,
            package_release_date_time: Utc::now(),
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("1.0.0".to_string()),
            package_header_size: 0, // This will be computed during encoding
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: Some(vec![0x01, 0x02, 0x03, 0x04]),
            device_update_option_flags: 0xFFFF_FFFF,
            component_image_set_version_string_type: StringType::Ascii,
            component_image_set_version_string: Some("ComponentV1".to_string()),
            applicable_components: Some(vec![0x00]),
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: vec![0xAA, 0xBB, 0xCC],
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            image_location: None,
            classification: 0x0001,
            identifier: 0x0002,
            comparison_stamp: Some(999),
            options: 0xAABB,
            requested_activation_method: 0x1122,
            version_string_type: StringType::Utf8,
            version_string: Some("FirmwareV1".to_string()),
            opaque_data: Some(vec![0x77, 0x88, 0x99]),
            offset: 0, // Will be calculated in encoding
            size: 256,
            image_data: Some(vec![0x55u8; 256]),
        }],
    };

    // Create a temporary file to store the encoded firmware package, use NamedTempFile
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_path_buf();
    let temp_path_str = temp_path.to_str().unwrap();
    println!("Temporary file path: {}", temp_path_str);
    // Encode the firmware package to the temporary file
    let result = FirmwareManifest::generate_firmware_package(&manifest, &temp_path_str.to_string());
    assert!(
        result.is_ok(),
        "Failed to encode firmware package: {:?}",
        result.err()
    );
    println!("Encoded firmware package to: {}", temp_path_str);
    // Decode the firmware package from the temporary file
    let decoded_manifest =
        FirmwareManifest::decode_firmware_package(&temp_path_str.to_string(), None);
    assert!(
        decoded_manifest.is_ok(),
        "Failed to decode firmware package: {:?}",
        decoded_manifest.err()
    );
    let decoded_manifest = decoded_manifest.unwrap();

    // Verify that the decoded manifest matches the original
    assert_eq!(
        decoded_manifest
            .package_header_information
            .package_header_identifier,
        manifest
            .package_header_information
            .package_header_identifier
    );
    assert_eq!(
        decoded_manifest
            .package_header_information
            .package_header_format_revision,
        manifest
            .package_header_information
            .package_header_format_revision
    );
    assert_eq!(
        decoded_manifest
            .package_header_information
            .package_version_string_type,
        manifest
            .package_header_information
            .package_version_string_type
    );
    assert_eq!(
        decoded_manifest
            .package_header_information
            .package_version_string,
        manifest.package_header_information.package_version_string
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records.len(),
        manifest.firmware_device_id_records.len()
    );
    assert_eq!(
        decoded_manifest.component_image_information.len(),
        manifest.component_image_information.len()
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0].firmware_device_package_data,
        manifest.firmware_device_id_records[0].firmware_device_package_data
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0].device_update_option_flags,
        manifest.firmware_device_id_records[0].device_update_option_flags
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0].component_image_set_version_string_type,
        manifest.firmware_device_id_records[0].component_image_set_version_string_type
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0].component_image_set_version_string,
        manifest.firmware_device_id_records[0].component_image_set_version_string
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0].applicable_components,
        manifest.firmware_device_id_records[0].applicable_components
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0]
            .initial_descriptor
            .descriptor_type,
        manifest.firmware_device_id_records[0]
            .initial_descriptor
            .descriptor_type
    );
    assert_eq!(
        decoded_manifest.firmware_device_id_records[0]
            .initial_descriptor
            .descriptor_data,
        manifest.firmware_device_id_records[0]
            .initial_descriptor
            .descriptor_data
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].classification,
        manifest.component_image_information[0].classification
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].identifier,
        manifest.component_image_information[0].identifier
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].comparison_stamp,
        manifest.component_image_information[0].comparison_stamp
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].options,
        manifest.component_image_information[0].options
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].requested_activation_method,
        manifest.component_image_information[0].requested_activation_method
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].version_string_type,
        manifest.component_image_information[0].version_string_type
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].version_string,
        manifest.component_image_information[0].version_string
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].opaque_data,
        manifest.component_image_information[0].opaque_data
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].image_data,
        manifest.component_image_information[0].image_data
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].size,
        manifest.component_image_information[0].size
    );
    assert_eq!(
        decoded_manifest.component_image_information[0].image_data,
        manifest.component_image_information[0].image_data
    );
}
