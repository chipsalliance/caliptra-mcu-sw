// Licensed under the Apache-2.0 license

use super::*;
use crate::{ImageCfg, PROJECT_ROOT};
use caliptra_mcu_flash_image::{FlashHeaderV3 as FlashHeader, ImageHeaderV3 as ImageHeader};
use std::fs::{self, File};
use std::io::{self, Write};
use tempfile::NamedTempFile;

const HEADER_SIZE: usize = std::mem::size_of::<FlashHeader>();
const IMAGE_INFO_SIZE: usize = std::mem::size_of::<ImageHeader>();

#[test]
fn test_versioned_builders_match_wire_fixtures() {
    let images = [FirmwareImage::new(2, &[1, 2, 3, 4], None).unwrap()];
    let cases: &[(FlashImageVersion, &[u8], u8, u8)] = &[
        (
            FlashImageVersion::V1,
            &[
                b'F', b'L', b'S', b'H', 1, 0, 1, 0, 16, 0, 0, 0, 0xc1, 0xfe, 0xff, 0xff,
            ],
            36,
            0xe3,
        ),
        (
            FlashImageVersion::V2,
            &[2, 0, 1, 0, 12, 0, 0, 0, 0xf1, 0xff, 0xff, 0xff],
            32,
            0xe7,
        ),
        (
            FlashImageVersion::V3,
            &[3, 0, 1, 0, 12, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff],
            96,
            0xa7,
        ),
    ];
    for &(version, header, payload_offset, entry_checksum_low) in cases {
        let mut expected = header.to_vec();
        expected.extend_from_slice(&[2, 0, 0, 0, payload_offset, 0, 0, 0, 4, 0, 0, 0]);
        if version == FlashImageVersion::V3 {
            expected.extend_from_slice(&[0; 64]);
        }
        expected.extend_from_slice(&[0xf6, 0xff, 0xff, 0xff, entry_checksum_low, 0xfb, 0xff, 0xff]);
        let image = FlashImage::with_version(&images, version);
        assert_eq!(image.to_toc_bytes(), expected, "{version:?}");
        expected.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(image.to_bytes(), expected, "{version:?}");
        if version == FlashImageVersion::V3 {
            let default_image = FlashImage::new(&images, &generate_image_info(images.to_vec()));
            assert_eq!(default_image.to_bytes(), expected);
        }
    }
}

#[test]
fn test_build_and_verify_all_flash_formats() {
    let input = NamedTempFile::new().unwrap();
    fs::write(input.path(), [1, 2, 3, 4]).unwrap();
    for version in [
        FlashImageVersion::V1,
        FlashImageVersion::V2,
        FlashImageVersion::V3,
    ] {
        let output = NamedTempFile::new().unwrap();
        flash_image_create(&CaliptraBuildArgs {
            caliptra_firmware: Some(input.path().to_path_buf()),
            output_path: Some(output.path().to_str().unwrap().to_string()),
            flash_image_version: Some(version as u16),
            ..Default::default()
        })
        .unwrap();
        let bytes = fs::read(output.path()).unwrap();
        let offset = version.header_size() + version.image_header_size();
        assert_eq!(bytes.len(), offset + 4);
        FlashImage::verify_flash_image(&bytes).unwrap();
        let header = super::FlashHeader::parse(&bytes).unwrap();
        assert_eq!(header.version, version as u16);
        assert_eq!(header.image_headers_offset as usize, version.header_size());
        let image = super::ImageHeader::parse(&bytes[version.header_size()..], version).unwrap();
        assert_eq!(image.offset as usize, offset);
        assert_eq!(image.size, 4);
        assert_eq!(&bytes[offset..], &[1, 2, 3, 4]);
        assert!(FlashImage::verify_flash_image(&bytes[..offset - 1]).is_err());
        assert!(FlashImage::verify_flash_image(&bytes[..bytes.len() - 1]).is_err());
    }
}

#[test]
fn test_legacy_packaging_preserves_payloads_and_drops_filenames() {
    let images = [
        FirmwareImage::new(2, &[1, 2, 3, 4], Some(b"runtime.bin")).unwrap(),
        FirmwareImage::new(0x1000, &[5, 6, 7, 8], Some(b"soc.bin")).unwrap(),
    ];
    for version in [
        FlashImageVersion::V1,
        FlashImageVersion::V2,
        FlashImageVersion::V3,
    ] {
        let bytes = FlashImage::with_version(&images, version).to_bytes();
        FlashImage::verify_flash_image(&bytes).unwrap();
        let header = super::FlashHeader::parse(&bytes).unwrap();
        for (index, expected) in images.iter().enumerate() {
            let offset = header.image_header_offset(index).unwrap();
            let image = super::ImageHeader::parse(&bytes[offset..], version).unwrap();
            assert_eq!(image.identifier, expected.identifier);
            assert_eq!(
                &bytes[image.offset as usize..image.offset as usize + image.size as usize],
                expected.data
            );
            if version == FlashImageVersion::V3 {
                let (wire, _) = ImageHeader::read_from_prefix(&bytes[offset..]).unwrap();
                assert_eq!(wire.filename, expected.filename);
            } else {
                let (wire, _) = ImageHeaderV1V2::read_from_prefix(&bytes[offset..]).unwrap();
                assert!(wire.verify());
                assert_eq!(bytes.len(), header.table_end().unwrap() + 8);
            }
        }
    }
}

/// Helper function to create a temporary file with specific content
fn create_temp_file(content: &[u8]) -> io::Result<NamedTempFile> {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");

    temp_file
        .write_all(content)
        .expect("Failed to write to temp file");
    Ok(temp_file)
}

#[test]
fn test_flash_image_build() {
    // Generate test contents for temporary files
    let caliptra_fw_content = b"Caliptra Firmware Data - ABCDEFGH";
    let soc_manifest_content = b"Soc Manifest Data - 123456789";
    let mcu_runtime_content = b"MCU Runtime Data - QWERTYUI";
    let owner_auth_manifest_content = b"Owner Auth Manifest Data - ASDFGHJK";
    let soc_image1_content = b"Soc Image 1 Data - ZXCVBNMLKJ";
    let soc_image2_content = b"Soc Image 2 Data - POIUYTREWQ";

    // Create temporary files with the generated content
    let caliptra_fw = create_temp_file(caliptra_fw_content).expect("Failed to create caliptra_fw");
    let soc_manifest =
        create_temp_file(soc_manifest_content).expect("Failed to create soc_manifest");
    let mcu_runtime = create_temp_file(mcu_runtime_content).expect("Failed to create mcu_runtime");
    let owner_auth_manifest = create_temp_file(owner_auth_manifest_content)
        .expect("Failed to create owner_auth_manifest");
    let soc_image1 = create_temp_file(soc_image1_content).expect("Failed to create soc_image1");
    let soc_image2 = create_temp_file(soc_image2_content).expect("Failed to create soc_image2");

    // Collect SoC image paths
    let soc_image_paths = Some(vec![
        soc_image1.path().to_str().unwrap().to_string(),
        soc_image2.path().to_str().unwrap().to_string(),
    ]);

    // Specify the output file path
    let output_file = NamedTempFile::new().expect("Failed to create temp file");
    let output_path = output_file.path().to_str().unwrap();

    // Build the flash image
    flash_image_create(&CaliptraBuildArgs {
        caliptra_firmware: Some(caliptra_fw.path().to_path_buf()),
        caliptra_firmware_network_filename: Some("caliptra.bin".into()),
        soc_manifest: Some(soc_manifest.path().to_path_buf()),
        soc_manifest_network_filename: Some("soc-manifest.bin".into()),
        mcu_firmware: Some(mcu_runtime.path().to_path_buf()),
        mcu_image_cfg: Some(ImageCfg {
            network_filename: Some("mcu-runtime.bin".into()),
            ..Default::default()
        }),
        owner_auth_manifest: Some(owner_auth_manifest.path().to_path_buf()),
        soc_image_paths,
        soc_images: Some(vec![
            ImageCfg {
                image_id: SOC_IMAGES_BASE_IDENTIFIER,
                component_id: SOC_IMAGES_BASE_IDENTIFIER,
                network_filename: Some("soc-image-1.bin".into()),
                ..Default::default()
            },
            ImageCfg {
                image_id: SOC_IMAGES_BASE_IDENTIFIER + 1,
                component_id: SOC_IMAGES_BASE_IDENTIFIER + 1,
                network_filename: Some("soc-image-2.bin".into()),
                ..Default::default()
            },
        ]),
        offset: 0,
        output_path: Some(output_path.to_string()),
        ..Default::default()
    })
    .expect("Failed to build flash image");

    // Read and verify the generated flash image
    let mut file = File::open(output_path).expect("Failed to open generated flash image");
    let mut data = Vec::new();

    file.read_to_end(&mut data)
        .expect("Failed to read flash image");

    // Verify header
    let header =
        FlashHeader::read_from_bytes(&data[..HEADER_SIZE]).expect("Failed to parse flash header");

    assert_eq!(header.version, HEADER_VERSION);
    assert_eq!(header.image_count, 6); // 4 main images + 2 SoC images

    // Verify checksums
    let calculated_header_checksum =
        calculate_checksum(&data[0..offset_of!(FlashHeader, header_checksum)]);
    assert_eq!(header.header_checksum, calculated_header_checksum);

    let expected_images: Vec<(u32, &[u8])> = vec![
        (CALIPTRA_FMC_RT_IDENTIFIER, caliptra_fw_content),
        (SOC_MANIFEST_IDENTIFIER, soc_manifest_content),
        (MCU_RT_IDENTIFIER, mcu_runtime_content),
        (OWNER_AUTH_MANIFEST_IDENTIFIER, owner_auth_manifest_content),
        (SOC_IMAGES_BASE_IDENTIFIER, soc_image1_content),
        (SOC_IMAGES_BASE_IDENTIFIER + 1, soc_image2_content),
    ];
    let expected_filenames = [
        b"caliptra.bin".as_slice(),
        b"soc-manifest.bin".as_slice(),
        b"mcu-runtime.bin".as_slice(),
        b"owner-auth-manifest.bin".as_slice(),
        b"soc-image-1.bin".as_slice(),
        b"soc-image-2.bin".as_slice(),
    ];
    let mut image_headers = Vec::new();

    for (i, _item) in expected_images
        .iter()
        .enumerate()
        .take(header.image_count as usize)
    {
        let offset =
            header.image_headers_offset as usize + (std::mem::size_of::<ImageHeader>() * i);
        let image_header = ImageHeader::read_from_bytes(&data[offset..offset + IMAGE_INFO_SIZE])
            .expect("Failed to read image header");

        // Verify identifier and size
        assert_eq!(image_header.identifier, expected_images[i].0);
        assert_eq!(
            image_header.size as usize,
            expected_images[i].1.len().next_multiple_of(4)
        );
        assert_eq!(
            &image_header.filename[..expected_filenames[i].len()],
            expected_filenames[i]
        );
        assert!(image_header.filename[expected_filenames[i].len()..]
            .iter()
            .all(|byte| *byte == 0));
        image_headers.push(image_header);
    }

    // Verify image data using offsets
    for (i, header) in image_headers.iter().enumerate() {
        let actual_data =
            &data[header.offset as usize..header.offset as usize + header.size as usize];
        assert_eq!(
            &actual_data[..expected_images[i].1.len()],
            expected_images[i].1
        );
    }
}

#[test]
fn test_build_flash_image_bytes_with_owner_auth_manifest() {
    let image = build_flash_image_bytes(
        Some(b"caliptra"),
        Some(b"soc-manifest"),
        Some(b"mcu-runtime"),
        Some(b"owner-auth-manifest"),
    );

    let header = FlashHeader::read_from_bytes(&image[..HEADER_SIZE]).unwrap();
    assert_eq!(header.image_count, 4);

    let expected_identifiers = [
        CALIPTRA_FMC_RT_IDENTIFIER,
        SOC_MANIFEST_IDENTIFIER,
        MCU_RT_IDENTIFIER,
        OWNER_AUTH_MANIFEST_IDENTIFIER,
    ];
    let mut image_headers = Vec::new();
    for (index, expected_identifier) in expected_identifiers.iter().enumerate() {
        let offset = header.image_headers_offset as usize + IMAGE_INFO_SIZE * index;
        let image_header =
            ImageHeader::read_from_bytes(&image[offset..offset + IMAGE_INFO_SIZE]).unwrap();
        assert_eq!(image_header.identifier, *expected_identifier);
        assert_eq!(image_header.size, 256);
        image_headers.push(image_header);
    }

    let owner_auth_header = image_headers.last().unwrap();
    let owner_auth_data = &image[owner_auth_header.offset as usize
        ..(owner_auth_header.offset + owner_auth_header.size) as usize];
    assert_eq!(
        &owner_auth_data[..b"owner-auth-manifest".len()],
        b"owner-auth-manifest"
    );
    assert!(owner_auth_data[b"owner-auth-manifest".len()..]
        .iter()
        .all(|byte| *byte == 0));
}

#[test]
fn test_flash_image_build_with_owner_measurement_policy() {
    let caliptra_fw = create_temp_file(b"caliptra").unwrap();
    let soc_manifest = create_temp_file(b"soc-manifest").unwrap();
    let mcu_runtime = create_temp_file(b"mcu-runtime").unwrap();
    let owner_auth_manifest = create_temp_file(b"owner-auth-manifest").unwrap();
    let owner_policy = create_temp_file(b"owner-measurement-policy").unwrap();

    let output_file = NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap();

    flash_image_create(&CaliptraBuildArgs {
        caliptra_firmware: Some(caliptra_fw.path().to_path_buf()),
        soc_manifest: Some(soc_manifest.path().to_path_buf()),
        mcu_firmware: Some(mcu_runtime.path().to_path_buf()),
        owner_auth_manifest: Some(owner_auth_manifest.path().to_path_buf()),
        owner_measurement_policy: Some(owner_policy.path().to_path_buf()),
        output_path: Some(output_path.to_string()),
        ..Default::default()
    })
    .unwrap();

    let data = std::fs::read(output_path).unwrap();
    let header = FlashHeader::read_from_bytes(&data[..HEADER_SIZE]).unwrap();
    assert_eq!(header.image_count, 5);

    let expected_identifiers = [
        CALIPTRA_FMC_RT_IDENTIFIER,
        SOC_MANIFEST_IDENTIFIER,
        MCU_RT_IDENTIFIER,
        OWNER_AUTH_MANIFEST_IDENTIFIER,
        OWNER_MEASUREMENT_POLICY_IDENTIFIER,
    ];

    for (i, expected_id) in expected_identifiers.iter().enumerate() {
        let offset = header.image_headers_offset as usize + (IMAGE_INFO_SIZE * i);
        let info = ImageHeader::read_from_bytes(&data[offset..offset + IMAGE_INFO_SIZE]).unwrap();
        assert_eq!(info.identifier, *expected_id);
    }
}

#[test]
fn test_flash_image_verify_happy_path() {
    let tmp_dir = PROJECT_ROOT.join("target").join("tmp");
    fs::create_dir_all(&tmp_dir).expect("Failed to create tmp directory");
    let image_path = tmp_dir.join("flash_image_happy_path.bin");
    let image_path = image_path.to_str().unwrap();

    // Create a valid firmware image
    let expected_images = [
        FirmwareImage {
            identifier: CALIPTRA_FMC_RT_IDENTIFIER,
            data: b"Caliptra Firmware Data - ABCDEFGH",
            filename: [0u8; MAX_FILENAME_LEN],
        },
        FirmwareImage {
            identifier: SOC_MANIFEST_IDENTIFIER,
            data: b"Soc Manifest Data - 123456789",
            filename: [0u8; MAX_FILENAME_LEN],
        },
        FirmwareImage {
            identifier: MCU_RT_IDENTIFIER,
            data: b"MCU Runtime Data - QWERTYUI",
            filename: [0u8; MAX_FILENAME_LEN],
        },
        FirmwareImage {
            identifier: SOC_IMAGES_BASE_IDENTIFIER,
            data: b"Soc Image 1 Data - ZXCVBNMLKJ",
            filename: [0u8; MAX_FILENAME_LEN],
        },
        FirmwareImage {
            identifier: SOC_IMAGES_BASE_IDENTIFIER + 1,
            data: b"Soc Image 2 Data - POIUYTREWQ",
            filename: [0u8; MAX_FILENAME_LEN],
        },
    ];
    // Create a flash image from the mutable slice
    let image_info = generate_image_info(expected_images.to_vec());
    let flash_image = FlashImage::new(&expected_images, &image_info);
    flash_image
        .write_to_file(0, image_path)
        .expect("Failed to write flash image");

    // Verify the firmware image
    let result = flash_image_verify(image_path, 0);
    result.unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    // Cleanup
    fs::remove_file(image_path).expect("Failed to clean up test file");
}

#[test]
fn test_flash_image_verify_corrupted_case() {
    let tmp_dir = PROJECT_ROOT.join("target").join("tmp");
    fs::create_dir_all(&tmp_dir).expect("Failed to create tmp directory");
    let image_path = tmp_dir.join("flash_image_corrupted.bin");
    let image_path = image_path.to_str().unwrap();

    // Create a corrupted firmware image (tamper with the header or data)
    let images = [
        FirmwareImage {
            identifier: CALIPTRA_FMC_RT_IDENTIFIER,
            data: b"Valid Caliptra Firmware Data",
            filename: [0u8; MAX_FILENAME_LEN],
        },
        FirmwareImage {
            identifier: SOC_MANIFEST_IDENTIFIER,
            data: b"Valid SOC Manifest Data",
            filename: [0u8; MAX_FILENAME_LEN],
        },
    ];
    let image_info = generate_image_info(images.to_vec());
    let flash_image = FlashImage::new(&images, &image_info);
    flash_image
        .write_to_file(0, image_path)
        .expect("Failed to write flash image");

    // Corrupt the file by modifying the data
    let mut file = File::options()
        .write(true)
        .open(image_path)
        .expect("Failed to open firmware image for tampering");
    file.write_all(b"Corrupted Data")
        .expect("Failed to corrupt data");

    // Verify the corrupted firmware image
    let result = flash_image_verify(image_path, 0);
    assert!(
        result.is_err(),
        "Expected verification to fail for corrupted firmware image"
    );

    if let Err(e) = result {
        println!("Expected error: {}", e);
    }

    // Cleanup
    fs::remove_file(image_path).expect("Failed to clean up test file");
}

#[test]
fn test_flash_image_uses_component_id_from_config() {
    // Regression for #1580: TOC lookup uses component_id, not fw_id/image_id.
    let soc_image1_content = b"Soc Image 1 - custom id";
    let soc_image2_content = b"Soc Image 2 - custom id";

    let soc_image1 = create_temp_file(soc_image1_content).unwrap();
    let soc_image2 = create_temp_file(soc_image2_content).unwrap();

    let soc_image_paths = Some(vec![
        soc_image1.path().to_str().unwrap().to_string(),
        soc_image2.path().to_str().unwrap().to_string(),
    ]);

    let soc_images = Some(vec![
        ImageCfg {
            path: soc_image1.path().to_path_buf(),
            image_id: 0x1000,
            component_id: 12,
            ..Default::default()
        },
        ImageCfg {
            path: soc_image2.path().to_path_buf(),
            image_id: 0x1001,
            component_id: 6,
            ..Default::default()
        },
    ]);

    let output_file = NamedTempFile::new().unwrap();
    let output_path = output_file.path().to_str().unwrap();

    flash_image_create(&CaliptraBuildArgs {
        soc_image_paths,
        soc_images,
        offset: 0,
        output_path: Some(output_path.to_string()),
        ..Default::default()
    })
    .expect("Failed to build flash image");

    // Read and verify identifiers
    let mut file = File::open(output_path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let header =
        FlashHeader::read_from_bytes(&data[..HEADER_SIZE]).expect("Failed to parse header");
    assert_eq!(header.image_count, 2);

    // First SOC image should have identifier 12
    let offset0 = header.image_headers_offset as usize;
    let img0 = ImageHeader::read_from_bytes(&data[offset0..offset0 + IMAGE_INFO_SIZE]).unwrap();
    assert_eq!(img0.identifier, 12);

    // Second SOC image should have identifier 6
    let offset1 = offset0 + IMAGE_INFO_SIZE;
    let img1 = ImageHeader::read_from_bytes(&data[offset1..offset1 + IMAGE_INFO_SIZE]).unwrap();
    assert_eq!(img1.identifier, 6);
}

#[test]
fn test_flash_image_includes_owner_soc_images() {
    let soc_image_content = b"Vendor SoC Image";
    let owner_image_content = b"Owner SoC Image";
    let soc_image = create_temp_file(soc_image_content).unwrap();
    let owner_image = create_temp_file(owner_image_content).unwrap();

    for version in [
        FlashImageVersion::V1,
        FlashImageVersion::V2,
        FlashImageVersion::V3,
    ] {
        let output_file = NamedTempFile::new().unwrap();
        flash_image_create(&CaliptraBuildArgs {
            soc_image_paths: Some(vec![soc_image.path().to_str().unwrap().to_string()]),
            soc_images: Some(vec![ImageCfg {
                path: soc_image.path().to_path_buf(),
                image_id: 0x1000,
                component_id: 0x1000,
                ..Default::default()
            }]),
            owner_soc_images: Some(vec![ImageCfg {
                path: owner_image.path().to_path_buf(),
                image_id: 0x1_0000,
                component_id: 0x2_0000,
                ..Default::default()
            }]),
            flash_image_version: Some(version as u16),
            output_path: Some(output_file.path().to_str().unwrap().to_string()),
            ..Default::default()
        })
        .expect("Failed to build flash image");

        let data = fs::read(output_file.path()).unwrap();
        FlashImage::verify_flash_image(&data).unwrap();
        let header = super::FlashHeader::parse(&data).unwrap();
        assert_eq!(header.image_count, 2);
        assert_eq!(header.version, version as u16);
        for (index, identifier, content) in [
            (0, 0x1000, soc_image_content.as_slice()),
            (1, 0x2_0000, owner_image_content.as_slice()),
        ] {
            let offset = header.image_header_offset(index).unwrap();
            let image = super::ImageHeader::parse(&data[offset..], version).unwrap();
            assert_eq!(image.identifier, identifier);
            let start = image.offset as usize;
            assert_eq!(&data[start..start + content.len()], content);
        }
    }
}

#[test]
fn test_firmware_image_filename() {
    let filename = vec![b'a'; MAX_FILENAME_LEN];
    let image = FirmwareImage::new(1, b"image", Some(&filename)).unwrap();
    assert_eq!(image.filename, filename[..]);

    let image_info = generate_image_info(vec![image]);
    assert_eq!(image_info[0].filename, filename[..]);

    let filename = vec![b'a'; MAX_FILENAME_LEN + 1];
    let err = FirmwareImage::new(1, b"image", Some(&filename))
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}
