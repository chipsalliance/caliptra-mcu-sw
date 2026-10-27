// Licensed under the Apache-2.0 license

use anyhow::{ensure, Context, Result};
use caliptra_auth_man_types::{
    AuthManifestPreamble, AuthorizationManifest, ImageMetadataFlags, AUTH_MANIFEST_MARKER,
};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, ImageCfg};
use serde_json::json;
use sha2::{Digest, Sha384};
use std::{fs, path::Path};
use zerocopy::FromBytes;

pub(super) fn produce(artifacts: &Path) -> Result<()> {
    let shared = artifacts.join("fixtures");
    fs::create_dir_all(&shared)?;
    let existing = [
        shared.join("caliptra-rom.bin"),
        shared.join("caliptra-firmware.bin"),
        shared.join("vendor-pk-hash.txt"),
    ];
    let reuse = existing.iter().all(|path| path.is_file());
    ensure!(
        reuse || existing.iter().all(|path| !path.exists()),
        "incomplete existing Core fixture set"
    );
    let mut core = CaliptraBuilder::new(&CaliptraBuildArgs {
        caliptra_rom: reuse.then(|| existing[0].clone()),
        caliptra_firmware: reuse.then(|| existing[1].clone()),
        vendor_pk_hash: if reuse {
            Some(fs::read_to_string(&existing[2])?.trim().to_string())
        } else {
            None
        },
        svn: Some(0),
        ..Default::default()
    });
    let rom = core.get_caliptra_rom()?;
    let firmware = core.get_caliptra_fw()?;
    let vendor_pk_hash = core.get_vendor_pk_hash()?.to_string();
    let firmware_bytes = fs::read(&firmware)?;
    let (firmware_manifest, _) = ImageManifest::ref_from_prefix(&firmware_bytes)
        .map_err(|error| anyhow::anyhow!("Invalid generated Core firmware: {error}"))?;
    ensure!(
        firmware_manifest.header.svn == 0
            && firmware_manifest.pqc_key_type == u8::from(FwVerificationPqcKeyType::LMS),
        "Core firmware must use baseline SVN 0 and LMS verification"
    );
    ensure!(
        hex::encode(CaliptraBuilder::vendor_pk_hash(firmware_manifest)?) == vendor_pk_hash,
        "OTP vendor hash does not match generated Core firmware"
    );
    if !reuse {
        fs::copy(rom, shared.join("caliptra-rom.bin"))?;
        fs::copy(firmware, shared.join("caliptra-firmware.bin"))?;
    }
    fs::write(
        shared.join("vendor-pk-hash.txt"),
        format!("{vendor_pk_hash}\n"),
    )?;
    core.get_owner_auth_manifest(Some(
        shared
            .join("owner-auth-manifest.bin")
            .to_str()
            .context("Non-UTF-8 owner manifest path")?,
    ))?;
    core.get_owner_measurement_policy(Some(
        shared
            .join("owner-measurement-policy.bin")
            .to_str()
            .context("Non-UTF-8 owner policy path")?,
    ))?;

    let hash = hex::decode(&vendor_pk_hash)?;
    ensure!(
        hash.len() == 48,
        "vendor public key hash must contain 48 bytes"
    );
    let mut otp = vec![0u8; 0xe88];
    for (destination, source) in otp[0x420..0x450]
        .chunks_exact_mut(4)
        .zip(hash.chunks_exact(4))
    {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }
    otp[0x450] = 0x3f;
    fs::write(shared.join("otp.bin"), &otp)?;
    otp[0x3cc] = 1;
    otp[0x3dc] = 1;
    fs::write(shared.join("otp-svn1.bin"), &otp)?;
    fs::write(shared.join("soc-image-4096.bin"), [0x55; 512])?;
    fs::write(shared.join("soc-image-4097.bin"), [0xaa; 256])?;

    for label in ["rt-sdk-2.1.0", "rt-sdk-2.1.1", "main-2.1"] {
        let runtime = artifacts.join(label).join("image.bin");
        ensure!(
            runtime.is_file(),
            "missing selected runtime {}",
            runtime.display()
        );
        let output = artifacts.join(label).join("fixtures");
        fs::create_dir_all(&output)?;
        for svn in [0, 1] {
            let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                caliptra_rom: Some(shared.join("caliptra-rom.bin")),
                caliptra_firmware: Some(shared.join("caliptra-firmware.bin")),
                vendor_pk_hash: Some(vendor_pk_hash.clone()),
                mcu_firmware: Some(runtime.clone()),
                soc_manifest_svn: Some(svn),
                soc_images: Some(vec![
                    ImageCfg {
                        path: shared.join("soc-image-4096.bin"),
                        load_addr: 0xa880_0000,
                        image_id: 4096,
                        component_id: 4096,
                        exec_bit: 5,
                        ..Default::default()
                    },
                    ImageCfg {
                        path: shared.join("soc-image-4097.bin"),
                        load_addr: 0xa880_0200,
                        image_id: 4097,
                        component_id: 4097,
                        exec_bit: 6,
                        ..Default::default()
                    },
                ]),
                target_dir: Some(output.clone()),
                ..Default::default()
            });
            let filename = if svn == 0 {
                "soc-manifest.bin"
            } else {
                "soc-manifest-svn1.bin"
            };
            let manifest_path = builder.get_soc_manifest(Some(
                output
                    .join(filename)
                    .to_str()
                    .context("non-UTF-8 artifact path")?,
            ))?;
            let manifest_bytes = fs::read(&manifest_path)?;
            let manifest = AuthorizationManifest::ref_from_bytes(&manifest_bytes)
                .map_err(|error| anyhow::anyhow!("Invalid generated manifest: {error}"))?;
            ensure!(
                manifest.preamble.marker == AUTH_MANIFEST_MARKER,
                "wrong manifest marker"
            );
            ensure!(manifest.preamble.svn == svn, "wrong signed manifest SVN");
            ensure!(
                manifest.image_metadata_col.entry_count == 4,
                "wrong manifest entry count"
            );
            let entries = &manifest.image_metadata_col.image_metadata_list[..4];
            for (id, path, address, source, exec_bit) in [
                (
                    2,
                    artifacts.join(label).join("image.bin"),
                    0xa8c0_0000,
                    1,
                    2,
                ),
                (4096, shared.join("soc-image-4096.bin"), 0xa880_0000, 2, 5),
                (4097, shared.join("soc-image-4097.bin"), 0xa880_0200, 2, 6),
            ] {
                let matches: Vec<_> = entries.iter().filter(|entry| entry.fw_id == id).collect();
                ensure!(matches.len() == 1, "expected one metadata entry for {id}");
                let entry = matches[0];
                let flags = ImageMetadataFlags(entry.flags);
                ensure!(
                    entry.digest[..] == Sha384::digest(fs::read(path)?)[..],
                    "manifest does not bind exact selected image {id}"
                );
                ensure!(
                    entry.component_id == id
                        && entry.image_load_address.lo == address
                        && entry.image_load_address.hi == 0
                        && flags.image_source() == source
                        && flags.exec_bit() == exec_bit
                        && !flags.ignore_auth_check(),
                    "wrong authorization metadata for image {id}"
                );
            }
        }
        let mut corrupted_runtime = fs::read(&runtime)?;
        corrupted_runtime[0] ^= 1;
        fs::write(output.join("corrupted-runtime.bin"), corrupted_runtime)?;
        let corrupt_offset = std::mem::offset_of!(AuthManifestPreamble, vendor_pub_keys_signatures);
        let mut corrupted_manifest = fs::read(output.join("soc-manifest.bin"))?;
        corrupted_manifest[corrupt_offset] ^= 1;
        fs::write(output.join("corrupted-manifest.bin"), corrupted_manifest)?;
        fs::write(
            output.join("fixture-metadata.json"),
            serde_json::to_vec_pretty(&json!({
                "runtime_corrupt_offset": 0,
                "manifest_corrupt_offset": corrupt_offset,
                "rollback_manifest_svn": 0,
                "boundary_manifest_svn": 1,
                "otp_minimum_svn": 1,
                "otp_maximum_svn": 1
            }))?,
        )?;
        println!("Created signed selected-runtime manifest for {label}");
    }
    fs::write(
        shared.join("configuration.json"),
        serde_json::to_vec_pretty(&json!({
            "core_rom_source": "e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb",
            "core_firmware_source": "e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb",
            "platform": "emulator",
            "hardware": "2.1.0",
            "signing": "repository-test-keys-lms-default-fuses",
            "vendor_pk_hash": vendor_pk_hash,
            "core_firmware_svn": 0,
            "soc_manifest_svn": 0,
            "soc_images": [
                {"path": "soc-image-4096.bin", "address": 0xa880_0000u32, "length": 512},
                {"path": "soc-image-4097.bin", "address": 0xa880_0200u32, "length": 256}
            ]
        }))?,
    )?;
    Ok(())
}

pub(super) fn runtime_flash(args: &[String]) -> Result<()> {
    use caliptra_mcu_builder::flash_image::{
        flash_image_create, write_partition_table, FlashImage,
    };
    use caliptra_mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
    use caliptra_mcu_config_emulator::flash::{
        PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION,
    };

    ensure!(
        args.len() == 8,
        "expected output, Core firmware, manifest, runtime, owner manifest, owner policy and two SoC images"
    );
    fs::File::create(&args[0])?;
    flash_image_create(&CaliptraBuildArgs {
        output_path: Some(args[0].clone()),
        caliptra_firmware: Some(args[1].clone().into()),
        soc_manifest: Some(args[2].clone().into()),
        mcu_firmware: Some(args[3].clone().into()),
        owner_auth_manifest: Some(args[4].clone().into()),
        owner_measurement_policy: Some(args[5].clone().into()),
        soc_image_paths: Some(args[6..].to_vec()),
        ..Default::default()
    })?;
    let payload = fs::read(&args[0])?;
    FlashImage::verify_flash_image(&payload)?;
    ensure!(
        payload.len() <= IMAGE_A_PARTITION.size,
        "runtime flash partition overflow"
    );
    let mut image = vec![0xff; IMAGE_A_PARTITION.offset];
    image.extend_from_slice(&payload);
    fs::write(&args[0], image)?;
    let mut table = PartitionTable::new(
        PartitionId::A,
        0,
        PartitionStatus::Valid,
        0,
        PartitionStatus::Invalid,
        RollbackEnable::Enabled,
    );
    table.populate_checksum(&StandAloneChecksumCalculator::new());
    write_partition_table(&table, 0, &args[0])?;
    Ok(())
}

pub(super) fn streaming_package(args: &[String]) -> Result<()> {
    use caliptra_mcu_pldm_fw_pkg::{
        manifest::{
            ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
            PackageHeaderInformation, StringType,
        },
        FirmwareManifest,
    };
    use chrono::{TimeZone, Utc};

    ensure!(
        args.len() == 6,
        "expected SoC flash output, PLDM output, owner manifest, owner policy, and two SoC input images"
    );
    fs::File::create(&args[0])?;
    caliptra_mcu_builder::flash_image::flash_image_create(&CaliptraBuildArgs {
        output_path: Some(args[0].clone()),
        owner_auth_manifest: Some(args[2].clone().into()),
        owner_measurement_policy: Some(args[3].clone().into()),
        soc_image_paths: Some(args[4..].to_vec()),
        ..Default::default()
    })?;
    let image = fs::read(&args[0])?;
    caliptra_mcu_builder::flash_image::FlashImage::verify_flash_image(&image)?;
    let manifest = FirmwareManifest {
        package_header_information: PackageHeaderInformation {
            package_header_identifier: uuid::Uuid::parse_str("7B291C996DB64208801B02026E463C78")?,
            package_header_format_revision: 1,
            package_release_date_time: Utc
                .with_ymd_and_hms(2025, 3, 1, 0, 0, 0)
                .single()
                .context("invalid package timestamp")?,
            package_version_string_type: StringType::Utf8,
            package_version_string: Some("0.0.0-release".into()),
            package_header_size: 0,
        },
        firmware_device_id_records: vec![FirmwareDeviceIdRecord {
            firmware_device_package_data: None,
            device_update_option_flags: 0,
            component_image_set_version_string_type: StringType::Utf8,
            component_image_set_version_string: Some("1.2.0".into()),
            applicable_components: Some(vec![0]),
            initial_descriptor: Descriptor {
                descriptor_type: DescriptorType::Uuid,
                descriptor_data: (1..=16).collect(),
            },
            additional_descriptors: None,
            reference_manifest_data: None,
        }],
        downstream_device_id_records: None,
        component_image_information: vec![ComponentImageInformation {
            classification: 0x000a,
            identifier: 0xffff,
            comparison_stamp: Some(0xffffffff),
            options: 0,
            requested_activation_method: 2,
            version_string_type: StringType::Utf8,
            version_string: Some("soc-fw-1.2".into()),
            size: u32::try_from(image.len())?,
            image_data: Some(image.clone()),
            ..Default::default()
        }],
    };
    manifest.verify().map_err(anyhow::Error::msg)?;
    manifest.generate_firmware_package(&args[1])?;
    let decoded = FirmwareManifest::decode_firmware_package(&args[1], None)?;
    ensure!(
        decoded.component_image_information.len() == 1,
        "wrong component count"
    );
    ensure!(
        decoded.component_image_information[0].image_data.as_deref() == Some(image.as_slice()),
        "PLDM payload changed"
    );
    ensure!(
        decoded.firmware_device_id_records[0]
            .initial_descriptor
            .descriptor_data
            == (1..=16).collect::<Vec<u8>>(),
        "wrong device UUID"
    );
    Ok(())
}
