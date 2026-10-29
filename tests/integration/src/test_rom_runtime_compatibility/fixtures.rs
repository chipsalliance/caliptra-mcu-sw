// Licensed under the Apache-2.0 license

//! Native fixture preparation, run once by the workflow before the pair tests.

use super::*;
use crate::test::{build_primary_flash_initial_contents, ECC_DEVID_CERT_DER, MLDSA_IDEVID_CERT};
use caliptra_auth_man_types::{AuthManifestPreamble, AuthorizationManifest};
use caliptra_mcu_builder::{CaliptraBuildArgs, CaliptraBuilder, ImageCfg};
use serde_json::json;
use std::process::Command;

const CONFIGURATIONS: [&str; 5] = [
    "flash",
    "streaming",
    "services-non-tcb",
    "services-tcb",
    "services-mixed",
];

fn artifact(root: &Path, path: &Path) -> Result<serde_json::Value> {
    Ok(json!({
        "path": path.strip_prefix(root)?,
        "sha256": hex::encode(Sha256::digest(fs::read(path)?)),
    }))
}

fn error_value(path: &Path, name: &str) -> Result<u32> {
    let text: String = fs::read_to_string(path)?
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    let literal = text
        .split_once(&format!("({name},"))
        .with_context(|| format!("Missing {name}"))?
        .1
        .split_once(',')
        .context("Missing error value")?
        .0
        .replace('_', "");
    Ok(u32::from_str_radix(
        literal
            .strip_prefix("0x")
            .context("Error must be hexadecimal")?,
        16,
    )?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn seed_idevid_certificates(path: &Path) -> Result<()> {
    ensure!(
        ECC_DEVID_CERT_DER.len() + MLDSA_IDEVID_CERT.len()
            <= caliptra_mcu_config_emulator::flash::EMULATED_EXT_OTP_PARTITION.size,
        "IDevID certificates exceed the external OTP partition"
    );
    let flash = build_primary_flash_initial_contents(
        Some(fs::read(path)?),
        Some(ECC_DEVID_CERT_DER.as_slice()),
        Some(MLDSA_IDEVID_CERT.as_slice()),
        None,
    )
    .context("Missing primary flash with IDevID certificates")?;
    fs::write(path, flash)?;
    Ok(())
}

fn partition_flash_payload(path: &Path, payload: &[u8]) -> Result<()> {
    use caliptra_mcu_builder::flash_image::write_partition_table;
    use caliptra_mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
    use caliptra_mcu_config_emulator::flash::{
        PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION,
    };
    ensure!(
        !payload.is_empty() && payload.len() <= IMAGE_A_PARTITION.size,
        "Flash payload is empty or exceeds image-A partition"
    );
    let mut flash = vec![0xff; IMAGE_A_PARTITION.offset];
    flash.extend_from_slice(payload);
    fs::write(path, flash)?;
    let mut table = PartitionTable::new(
        PartitionId::A,
        0,
        PartitionStatus::Valid,
        0,
        PartitionStatus::Invalid,
        RollbackEnable::Enabled,
    );
    table.populate_checksum(&StandAloneChecksumCalculator::new());
    write_partition_table(&table, 0, path.to_str().context("Non-UTF-8 flash path")?)?;
    seed_idevid_certificates(path)
}

fn runtime_flash(path: &Path, args: CaliptraBuildArgs) -> Result<()> {
    fs::File::create(path)?;
    caliptra_mcu_builder::flash_image::flash_image_create(&CaliptraBuildArgs {
        output_path: Some(path.to_str().context("Non-UTF-8 flash path")?.into()),
        ..args
    })?;
    let payload = fs::read(path)?;
    caliptra_mcu_builder::flash_image::FlashImage::verify_flash_image(&payload)?;
    partition_flash_payload(path, &payload)
}

fn streaming_package(directory: &Path) -> Result<()> {
    use caliptra_mcu_pldm_fw_pkg::{
        manifest::{
            ComponentImageInformation, Descriptor, DescriptorType, FirmwareDeviceIdRecord,
            PackageHeaderInformation, StringType,
        },
        FirmwareManifest,
    };
    use chrono::{TimeZone, Utc};

    let flash_path = directory.join("soc-images.bin");
    let package_path = directory.join("streaming.pldm");
    fs::File::create(&flash_path)?;
    caliptra_mcu_builder::flash_image::flash_image_create(&CaliptraBuildArgs {
        output_path: Some(flash_path.to_str().context("Non-UTF-8 flash path")?.into()),
        owner_auth_manifest: Some(directory.join("owner-auth-manifest.bin")),
        owner_measurement_policy: Some(directory.join("owner-measurement-policy.bin")),
        soc_image_paths: Some(
            [4096, 4097]
                .iter()
                .map(|id| {
                    directory
                        .join(format!("soc-image-{id}.bin"))
                        .to_str()
                        .context("Non-UTF-8 SoC image path")
                        .map(str::to_owned)
                })
                .collect::<Result<Vec<_>>>()?,
        ),
        ..Default::default()
    })?;
    let image = fs::read(&flash_path)?;
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
    let package_path = package_path
        .to_str()
        .context("Non-UTF-8 PLDM path")?
        .to_owned();
    manifest.generate_firmware_package(&package_path)?;
    let decoded = FirmwareManifest::decode_firmware_package(&package_path, None)?;
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

#[test]
fn streaming_package_preserves_fixture_images() -> Result<()> {
    use caliptra_mcu_builder::flash_image::{generate_image_info, FirmwareImage, FlashImage};
    use caliptra_mcu_flash_image::{
        OWNER_AUTH_MANIFEST_IDENTIFIER, OWNER_MEASUREMENT_POLICY_IDENTIFIER,
    };

    let directory = tempfile::tempdir()?;
    let fixtures = [
        ("owner-auth-manifest.bin", 3, vec![1; 256]),
        ("owner-measurement-policy.bin", 5, vec![2; 256]),
        ("soc-image-4096.bin", 4096, vec![0x55; 512]),
        ("soc-image-4097.bin", 4097, vec![0xaa; 256]),
    ];
    for (name, _, bytes) in &fixtures {
        fs::write(directory.path().join(name), bytes)?;
    }
    streaming_package(directory.path())?;
    let image = fs::read(directory.path().join("soc-images.bin"))?;
    let expected_images = fixtures
        .iter()
        .map(|(name, identifier, bytes)| {
            let filename = match *identifier {
                OWNER_AUTH_MANIFEST_IDENTIFIER | OWNER_MEASUREMENT_POLICY_IDENTIFIER => {
                    Some(name.as_bytes())
                }
                _ => None,
            };
            FirmwareImage::new(*identifier, bytes, filename)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let expected_headers = generate_image_info(expected_images.clone());
    assert_eq!(
        image,
        FlashImage::new(&expected_images, &expected_headers).to_bytes()
    );
    Ok(())
}

#[test]
#[ignore = "builds the agreed Core and signs selected-image fixtures"]
fn prepare_inputs() -> Result<()> {
    require_agreement()?;
    let root = artifact_root()?;
    let selected_runtime = std::env::var_os("MCU_COMPAT_RUNTIME");
    let runtimes: Vec<_> = RUNTIMES
        .into_iter()
        .filter(|runtime| {
            selected_runtime
                .as_ref()
                .is_none_or(|selected| selected == runtime)
        })
        .collect();
    ensure!(
        !runtimes.is_empty(),
        "Unknown runtime selected for fixture preparation"
    );
    let capabilities: serde_json::Value = serde_json::from_str(
        &std::env::var("MCU_COMPAT_CAPABILITIES")
            .context("BLOCKED: selected-release capabilities are required")?,
    )
    .context("BLOCKED: capabilities must map runtime labels to flash/streaming hex strings")?;
    for &runtime in &runtimes {
        for mode in ["flash", "streaming"] {
            let bytes = hex::decode(
                capabilities[runtime][mode]
                    .as_str()
                    .context("BLOCKED: missing selected-release capability bytes")?,
            )?;
            ensure!(
                bytes.len() == if runtime == "rt-sdk-2.1.0" { 36 } else { 64 },
                "Wrong selected capability layout"
            );
        }
    }
    let shared = root.join("fixtures");
    fs::create_dir_all(&shared)?;
    let core_directory = root.join("images/core");
    let core_build: Build =
        serde_json::from_slice(&fs::read(core_directory.join("metadata.json"))?)?;
    ensure!(
        core_build.source == CORE && core_build.toolchain == "1.96",
        "Core fixtures must use {CORE} and its native toolchain"
    );
    for name in ["caliptra-rom.bin", "caliptra-firmware.bin"] {
        let bytes = Artifact {
            path: PathBuf::from("images/core").join(name),
            sha256: core_build
                .images
                .get(name)
                .with_context(|| format!("Missing Core image hash for {name}"))?
                .clone(),
        }
        .read(&root)?;
        fs::write(shared.join(name), bytes)?;
    }
    let firmware = fs::read(shared.join("caliptra-firmware.bin"))?;
    let (manifest, _) = caliptra_image_types::ImageManifest::ref_from_prefix(&firmware)
        .map_err(|error| anyhow::anyhow!("Invalid Core firmware manifest: {error}"))?;
    let vendor_hash = hex::encode(CaliptraBuilder::vendor_pk_hash(manifest)?);
    let base_args = CaliptraBuildArgs {
        caliptra_rom: Some(shared.join("caliptra-rom.bin")),
        caliptra_firmware: Some(shared.join("caliptra-firmware.bin")),
        vendor_pk_hash: Some(vendor_hash.clone()),
        ..Default::default()
    };
    let mut builder = CaliptraBuilder::new(&base_args);
    builder.get_owner_auth_manifest(Some(
        shared
            .join("owner-auth-manifest.bin")
            .to_str()
            .context("Owner manifest path")?,
    ))?;
    builder.get_owner_measurement_policy(Some(
        shared
            .join("owner-measurement-policy.bin")
            .to_str()
            .context("Owner policy path")?,
    ))?;
    let hash = hex::decode(&vendor_hash)?;
    ensure!(hash.len() == 48, "Invalid vendor hash");
    let mut otp = vec![0u8; 0xe88];
    for (dst, src) in otp[0x420..0x450]
        .chunks_exact_mut(4)
        .zip(hash.chunks_exact(4))
    {
        dst.copy_from_slice(&[src[3], src[2], src[1], src[0]]);
    }
    otp[0x450] = 0x3f;
    fs::write(shared.join("otp.bin"), &otp)?;
    otp[0x3cc] = 1;
    otp[0x3dc] = 1;
    fs::write(shared.join("otp-svn1.bin"), &otp)?;
    fs::write(shared.join("soc-image-4096.bin"), [0x55; 512])?;
    fs::write(shared.join("soc-image-4097.bin"), [0xaa; 256])?;
    write_json(
        &shared.join("core.json"),
        &json!({
            "source": CORE, "hardware": "2.1.0", "signing": "repository test keys, LMS, default Raw OTP",
            "agreement": std::env::var("MCU_COMPAT_AGREEMENT")?,
        }),
    )?;
    streaming_package(&shared)?;
    let errors = core_directory.join("errors.rs");
    for &runtime in &runtimes {
        for mode in CONFIGURATIONS {
            let (build, _) = image(&root, runtime, mode)?;
            let boot_mode = if mode.starts_with("services-") {
                "streaming"
            } else {
                mode
            };
            if mode.starts_with("services-") {
                for name in [
                    format!("{mode}-attestation_manifest.toml"),
                    format!("{mode}-soc_image_descriptors.toml"),
                ] {
                    Artifact {
                        path: PathBuf::from("images").join(runtime).join(&name),
                        sha256: build
                            .embedded_configuration
                            .get(&name)
                            .context("Missing service configuration hash")?
                            .clone(),
                    }
                    .read(&root)?;
                }
            }
            let runtime_image = root
                .join("images")
                .join(runtime)
                .join(format!("{mode}.bin"));
            let directory = shared.join(runtime).join(mode);
            fs::create_dir_all(&directory)?;
            for svn in [0, 1] {
                let manifest_path = directory.join(if svn == 0 {
                    "soc-manifest.bin"
                } else {
                    "soc-manifest-svn1.bin"
                });
                let mut builder = CaliptraBuilder::new(&CaliptraBuildArgs {
                    mcu_firmware: Some(runtime_image.clone()),
                    soc_manifest_svn: Some(svn),
                    target_dir: Some(directory.clone()),
                    soc_images: Some(
                        (0..2u32)
                            .map(|index| ImageCfg {
                                path: shared.join(format!("soc-image-{}.bin", 4096 + index)),
                                load_addr: 0xa880_0000 + u64::from(index) * 512,
                                image_id: 4096 + index,
                                component_id: 4096 + index,
                                exec_bit: 5 + index,
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..base_args.clone()
                });
                builder.get_soc_manifest(Some(manifest_path.to_str().context("Manifest path")?))?;
                let bytes = fs::read(&manifest_path)?;
                let manifest = AuthorizationManifest::ref_from_bytes(&bytes)
                    .map_err(|error| anyhow::anyhow!("Invalid signed manifest: {error}"))?;
                ensure!(manifest.preamble.svn == svn, "Wrong signed manifest SVN");
                let entries = manifest
                    .image_metadata_col
                    .image_metadata_list
                    .get(..manifest.image_metadata_col.entry_count as usize)
                    .context("Invalid manifest entry count")?;
                let digest = sha2::Sha384::digest(fs::read(&runtime_image)?);
                ensure!(
                    entries
                        .iter()
                        .any(|entry| entry.fw_id == 2 && entry.digest[..] == digest[..]),
                    "Manifest does not bind selected MCU runtime"
                );
                runtime_flash(
                    &directory.join(if svn == 0 {
                        "runtime-flash.bin"
                    } else {
                        "runtime-flash-svn1.bin"
                    }),
                    CaliptraBuildArgs {
                        soc_manifest: Some(manifest_path),
                        mcu_firmware: Some(runtime_image.clone()),
                        owner_auth_manifest: Some(shared.join("owner-auth-manifest.bin")),
                        owner_measurement_policy: Some(shared.join("owner-measurement-policy.bin")),
                        soc_image_paths: Some(vec![
                            shared
                                .join("soc-image-4096.bin")
                                .to_str()
                                .context("SoC path")?
                                .into(),
                            shared
                                .join("soc-image-4097.bin")
                                .to_str()
                                .context("SoC path")?
                                .into(),
                        ]),
                        ..base_args.clone()
                    },
                )?;
            }
            for (rom, _) in ROMS {
                let (rom_build, _) = image(&root, rom, mode)?;
                let pair = root.join("pairs").join(rom).join(runtime).join(mode);
                fs::create_dir_all(&pair)?;
                let rom_flash = pair.join("primary-flash.bin");
                let status = Command::new(root.join("images").join(rom).join("flash-image-tool"))
                    .args(["flash-image", "create", "--caliptra-fw"])
                    .arg(shared.join("caliptra-firmware.bin"))
                    .arg("--soc-manifest")
                    .arg(directory.join("soc-manifest.bin"))
                    .arg("--mcu-runtime")
                    .arg(&runtime_image)
                    .arg("--soc-images")
                    .arg(shared.join("soc-image-4096.bin"))
                    .arg(shared.join("soc-image-4097.bin"))
                    .arg("--output")
                    .arg(&rom_flash)
                    .status()?;
                ensure!(
                    status.success(),
                    "Pinned ROM flash producer failed: {status}"
                );
                // Production ROMs read their native flash header at offset zero.
                seed_idevid_certificates(&rom_flash)?;
                let mut negatives = serde_json::Map::new();
                for (name, symbol, offset) in [
                    (
                        "corrupted_runtime",
                        "IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH",
                        Some(0),
                    ),
                    (
                        "corrupted_manifest",
                        "RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID",
                        Some(std::mem::offset_of!(
                            AuthManifestPreamble,
                            vendor_pub_keys_signatures
                        )),
                    ),
                    (
                        "svn_rollback",
                        "IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE",
                        None,
                    ),
                ] {
                    negatives.insert(name.into(), json!({
                        "expected_mcu_error": rom_build.mcu_error.context("Missing ROM rejection code")?,
                        "expected_core_error": error_value(&errors, symbol)?,
                        "soc_manifest": null, "runtime_flash": null, "corrupt_offset": offset,
                        "otp": if name == "svn_rollback" { artifact(&root, &shared.join("otp-svn1.bin"))? } else { serde_json::Value::Null },
                    }));
                }
                negatives.insert("svn_boundary".into(), json!({
                    "expected_mcu_error": 0, "expected_core_error": 0, "corrupt_offset": null,
                    "soc_manifest": artifact(&root, &directory.join("soc-manifest-svn1.bin"))?,
                    "otp": artifact(&root, &shared.join("otp-svn1.bin"))?,
                    "runtime_flash": artifact(&root, &directory.join("runtime-flash-svn1.bin"))?,
                }));
                let soc = (0..2u32).map(|index| Ok(json!({
                    "address": 0xa880_0000u32 + index * 512, "execution_bit": 5 + index,
                    "image": artifact(&root, &shared.join(format!("soc-image-{}.bin", 4096 + index)))?,
                }))).collect::<Result<Vec<_>>>()?;
                write_json(
                    &pair.join("config.json"),
                    &json!({
                        "rom": rom, "runtime": runtime, "mode": boot_mode,
                        "caliptra_rom": artifact(&root, &shared.join("caliptra-rom.bin"))?,
                        "caliptra_firmware": artifact(&root, &shared.join("caliptra-firmware.bin"))?,
                        "soc_manifest": artifact(&root, &directory.join("soc-manifest.bin"))?,
                        "otp": artifact(&root, &shared.join("otp.bin"))?, "vendor_pk_hash": vendor_hash,
                        "primary_flash": artifact(&root, &rom_flash)?,
                        "runtime_flash": artifact(&root, &directory.join("runtime-flash.bin"))?,
                        "pldm_package": artifact(&root, &shared.join("streaming.pldm"))?,
                        "expected_capabilities": capabilities[runtime][boot_mode],
                        "handoff_address": rom_build.handoff_address.context("Missing ROM handoff address")?,
                        "soc_images": soc, "negative_cases": negatives,
                    }),
                )?;
            }
        }
    }
    let mut hashes = BTreeMap::new();
    for (rom, _) in ROMS {
        for &runtime in &runtimes {
            for mode in CONFIGURATIONS {
                let path = PathBuf::from("pairs")
                    .join(rom)
                    .join(runtime)
                    .join(mode)
                    .join("config.json");
                hashes.insert(
                    path.to_str().context("Config path")?.to_owned(),
                    hex::encode(Sha256::digest(fs::read(root.join(path))?)),
                );
            }
        }
    }
    write_json(&root.join("fixture-hashes.json"), &json!(hashes))?;
    Ok(())
}
