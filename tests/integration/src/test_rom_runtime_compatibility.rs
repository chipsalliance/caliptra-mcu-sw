// Licensed under the Apache-2.0 license

mod attestation;
mod mailbox;
mod spdm;

use anyhow::{bail, ensure, Context, Result};
use caliptra_api::{calc_checksum, SocManager};
use caliptra_mcu_builder::flash_image::calculate_checksum;
use caliptra_mcu_flash_image::{
    CALIPTRA_FMC_RT_IDENTIFIER, MCU_RT_IDENTIFIER, OWNER_AUTH_MANIFEST_IDENTIFIER,
    OWNER_MEASUREMENT_POLICY_IDENTIFIER, SOC_MANIFEST_IDENTIFIER,
};
use caliptra_mcu_hw_model::{DefaultHwModel, Fuses, InitParams, McuHwModel, McuManager};
use caliptra_mcu_mbox_common::messages::{CommandId, MailboxRespHeader, MailboxRespHeaderVarSize};
use caliptra_mcu_romtime::McuBootMilestones;
use caliptra_ureg::Mmio;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    mem::size_of,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use zerocopy::FromBytes;

const RUNTIME_2_1_0_SHA: &str = "24ea8b90bb56c0aed5512232dfbbca3dd2e39716";
const RUNTIME_2_1_1_SHA: &str = "8c9c8ff27de1babf63c0be74e973185837439040";
// Both released sources report 2.1.0, including the SDK's 2.1.1 tag.
const RELEASED_RUNTIME_VERSION: &str = "2.1.0";
const PLDM_TID: u8 = 1;

struct RomRelease {
    source: &'static str,
    flash_version: u16,
}

fn rom_release(label: &str) -> Result<RomRelease> {
    match label {
        "rom-sdk-2.1.0" => Ok(RomRelease {
            source: "da451221542758758f1c4ce35efbe48da9935dd8",
            flash_version: 2,
        }),
        "rom-sdk-2.1.0rc1" => Ok(RomRelease {
            source: "12b6dc3f760767a17e931db3b4a4aa5dca47b95f",
            flash_version: 1,
        }),
        _ => bail!("Unsupported compatibility ROM: {label}"),
    }
}

fn runtime_source<'a>(label: &str, current_source: &'a str) -> Result<&'a str> {
    match label {
        "rt-sdk-2.1.0" => Ok(RUNTIME_2_1_0_SHA),
        "rt-sdk-2.1.1" => Ok(RUNTIME_2_1_1_SHA),
        "main-2.1" => {
            ensure!(
                current_source.len() == 40
                    && current_source.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "Current runtime must be resolved to a full commit SHA"
            );
            Ok(current_source)
        }
        _ => bail!("Unsupported compatibility runtime: {label}"),
    }
}

fn runtime_version(directory: &Path, label: &str) -> Result<String> {
    let version = fs::read_to_string(directory.join("version.txt"))
        .with_context(|| format!("Missing runtime version in {}", directory.display()))?;
    let version = version.trim();
    let parts: Vec<_> = version.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|part| { !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()) }),
        "Invalid runtime version: {version:?}"
    );
    for (part, maximum) in parts.iter().zip([255u32, 255, 65535]) {
        ensure!(
            part.parse::<u32>()? <= maximum,
            "Runtime version component out of range: {version}"
        );
    }
    if label != "main-2.1" {
        ensure!(
            version == RELEASED_RUNTIME_VERSION,
            "Expected {label} version {RELEASED_RUNTIME_VERSION}, got {version}"
        );
    }
    Ok(version.to_string())
}

fn verify_flash_selection(flash: &[u8], version: u16, selected: [&[u8]; 3]) -> Result<()> {
    let prefix = match version {
        1 => {
            ensure!(
                flash.starts_with(b"FLSH"),
                "Missing released v1 flash magic"
            );
            4
        }
        2 => 0,
        _ => bail!("Unsupported released flash format {version}"),
    };
    let header_size = prefix + 12;
    ensure!(flash.len() >= header_size, "Truncated flash header");
    let word = |bytes: &[u8]| -> Result<u32> { Ok(u32::from_le_bytes(bytes.try_into()?)) };
    ensure!(
        u16::from_le_bytes(flash[prefix..prefix + 2].try_into()?) == version,
        "Wrong flash format for selected ROM"
    );
    ensure!(
        word(&flash[header_size - 4..header_size])?
            == calculate_checksum(&flash[..header_size - 4]),
        "Invalid flash header checksum"
    );
    let count = usize::from(u16::from_le_bytes(
        flash[prefix + 2..prefix + 4].try_into()?,
    ));
    let headers = usize::try_from(word(&flash[prefix + 4..prefix + 8])?)?;
    ensure!(
        headers >= header_size,
        "Flash image headers overlap the header"
    );
    let payload_start = headers
        .checked_add(count.checked_mul(20).context("Too many flash images")?)
        .context("Flash headers overflow")?;
    ensure!(
        payload_start <= flash.len(),
        "Truncated flash image headers"
    );
    let mut seen = [false; 3];
    let mut identifiers = std::collections::BTreeSet::new();
    let mut previous_end = payload_start;
    for header in flash[headers..payload_start].chunks_exact(20) {
        let identifier = word(&header[..4])?;
        ensure!(
            identifiers.insert(identifier),
            "Duplicate flash image identifier"
        );
        ensure!(
            word(&header[16..20])? == calculate_checksum(&header[..16]),
            "Invalid flash image header checksum"
        );
        let offset = usize::try_from(word(&header[4..8])?)?;
        let size = usize::try_from(word(&header[8..12])?)?;
        let end = offset
            .checked_add(size)
            .context("Flash image offset overflow")?;
        ensure!(
            offset >= previous_end && end <= flash.len(),
            "Invalid/overlapping flash image range"
        );
        previous_end = end;
        let bytes = &flash[offset..end];
        ensure!(
            word(&header[12..16])? == calculate_checksum(bytes),
            "Invalid flash image checksum"
        );
        if let Some(index) = [
            CALIPTRA_FMC_RT_IDENTIFIER,
            SOC_MANIFEST_IDENTIFIER,
            MCU_RT_IDENTIFIER,
        ]
        .iter()
        .position(|id| *id == identifier)
        {
            let expected = selected[index];
            ensure!(
                [4, 256]
                    .iter()
                    .any(|alignment| bytes.len() == expected.len().next_multiple_of(*alignment))
                    && bytes.starts_with(expected)
                    && bytes[expected.len()..].iter().all(|byte| *byte == 0),
                "Flash image {identifier} does not contain the selected artifact"
            );
            seen[index] = true;
        }
    }
    ensure!(
        seen.iter().all(|seen| *seen),
        "Flash package is missing a selected image"
    );
    Ok(())
}

fn verified_image(directory: &Path, expected_source: &str) -> Result<Vec<u8>> {
    let source = fs::read_to_string(directory.join("source.sha"))
        .with_context(|| format!("Missing source metadata in {}", directory.display()))?;
    ensure!(
        source.trim() == expected_source,
        "Source mismatch in {}: expected {expected_source}, got {}",
        directory.display(),
        source.trim()
    );
    let checksum = fs::read_to_string(directory.join("image.sha256"))
        .with_context(|| format!("Missing image checksum in {}", directory.display()))?;
    let fields: Vec<_> = checksum.split_whitespace().collect();
    ensure!(
        fields.len() == 2 && fields[0].len() == 64 && fields[1] == "image.bin",
        "Invalid image.sha256 in {}",
        directory.display()
    );
    let image_path = directory.join("image.bin");
    let bytes = fs::read(&image_path)
        .with_context(|| format!("Cannot read selected image {}", image_path.display()))?;
    ensure!(
        !bytes.is_empty(),
        "Empty selected image {}",
        image_path.display()
    );
    let actual = hex::encode(Sha256::digest(&bytes));
    ensure!(
        actual == fields[0],
        "SHA-256 mismatch for {}: expected {}, got {actual}",
        image_path.display(),
        fields[0]
    );
    println!(
        "Selected {}: source={expected_source}, sha256={actual}, bytes={}",
        directory.display(),
        bytes.len()
    );
    Ok(bytes)
}

fn check_version_response(response: &[u8], expected_version: &str) -> Result<()> {
    let (header, version) = MailboxRespHeaderVarSize::ref_from_prefix(response)
        .map_err(|e| anyhow::anyhow!("Invalid firmware-version response: {e}"))?;
    ensure!(
        response.len() == size_of::<MailboxRespHeaderVarSize>() + header.data_len as usize,
        "Firmware-version response length mismatch"
    );
    ensure!(
        header.hdr.chksum == calc_checksum(0, &response[size_of::<u32>()..]),
        "Firmware-version response checksum mismatch"
    );
    ensure!(
        header.hdr.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED,
        "Firmware-version command returned status {}",
        header.hdr.fips_status
    );
    ensure!(
        version == expected_version.as_bytes(),
        "Expected runtime version {expected_version}, got {version:?}"
    );
    Ok(())
}

const SCENARIOS: [&str; 12] = [
    "recovery_cold_boot",
    "flash_cold_boot",
    "streaming_boot",
    "handoff",
    "runtime_commands",
    "discovery",
    "cold_reboot",
    "corrupted_runtime",
    "corrupted_manifest",
    "svn_rollback",
    "svn_boundary",
    "warm_reset",
];
const SUITES: [&str; 14] = [
    "suite_attestation_ocp_eat_non_tcb",
    "suite_attestation_ocp_eat_tcb",
    "suite_attestation_ocp_eat_mixed",
    "suite_attestation_pcr_quote",
    "suite_spdm_mctp",
    "suite_spdm_doe",
    "suite_spdm_rs",
    "suite_mailbox",
    "suite_provisioning",
    "suite_ownership_dot",
    "suite_owner_stable_key",
    "suite_ownership_handoff",
    "suite_network_boot",
    "suite_usb_recovery",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    sha256: String,
}

impl Artifact {
    fn read(&self, root: &Path) -> Result<Vec<u8>> {
        let bytes = fs::read(root.join(&self.path))
            .with_context(|| format!("Missing selected fixture {}", self.path.display()))?;
        ensure!(!bytes.is_empty(), "Empty fixture {}", self.path.display());
        ensure!(
            self.sha256.len() == 64 && hex::encode(Sha256::digest(&bytes)) == self.sha256,
            "Fixture SHA-256 mismatch: {}",
            self.path.display()
        );
        Ok(bytes)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpdmContract {
    versions: Vec<String>,
    algorithms: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
enum Applicability {
    Supported {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contract: Option<SpdmContract>,
    },
    Blocked {
        reason: String,
    },
    NotApplicable {
        reason: String,
    },
}

impl Applicability {
    fn disposition(&self) -> Result<Option<&str>> {
        match self {
            Self::Supported { .. } => Ok(None),
            Self::Blocked { reason } => {
                ensure!(!reason.trim().is_empty(), "BLOCKED requires a reason");
                bail!("BLOCKED: {reason}")
            }
            Self::NotApplicable { reason } => {
                ensure!(
                    !reason.trim().is_empty(),
                    "NOT APPLICABLE requires a reason"
                );
                Ok(Some(reason))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryCheck {
    address: u32,
    execution_bit: u8,
    image: Artifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeCase {
    expected_mcu_error: u32,
    expected_core_error: u32,
    // SVN cases must reuse the selected runtime with a separately signed manifest/OTP fixture.
    soc_manifest: Option<Artifact>,
    otp: Option<Artifact>,
    corrupt_offset: Option<usize>,
    runtime_flash: Option<Artifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairConfig {
    agreed: bool,
    agreement: String,
    rom: String,
    runtime: String,
    hardware: String,
    core_rom_source: String,
    core_firmware_source: String,
    signing: String,
    build_configuration: String,
    caliptra_rom: Artifact,
    caliptra_firmware: Artifact,
    soc_manifest: Artifact,
    otp: Artifact,
    vendor_pk_hash: String,
    primary_flash: Option<Artifact>,
    runtime_flash: Option<Artifact>,
    expected_capabilities: Option<String>,
    owner_auth_manifest: Option<Artifact>,
    owner_measurement_policy: Option<Artifact>,
    handoff_address: Option<u32>,
    handoff_major: Option<u16>,
    handoff_minor: Option<u16>,
    expected_rom_capabilities: Option<u32>,
    soc_images: Vec<MemoryCheck>,
    scenarios: BTreeMap<String, Applicability>,
    #[serde(default)]
    suites: BTreeMap<String, Applicability>,
    #[serde(default)]
    suite_support: Option<Artifact>,
    negative_cases: BTreeMap<String, NegativeCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildEvidence {
    label: String,
    source: String,
    toolchain: String,
    hardware: String,
    platform: String,
    configuration: String,
    lockfile_sha256: String,
    toolchain_file_sha256: String,
}

fn verify_build_evidence(
    directory: &Path,
    label: &str,
    source: &str,
    configuration: Option<&str>,
) -> Result<()> {
    let bytes = fs::read(directory.join("build-metadata.json"))
        .context("Missing pinned-image build metadata")?;
    let evidence: BuildEvidence = serde_json::from_slice(&bytes)?;
    let toolchain = match label {
        "rom-sdk-2.1.0" | "rom-sdk-2.1.0rc1" | "rt-sdk-2.1.0" => "1.85",
        "rt-sdk-2.1.1" | "main-2.1" => "1.96.1",
        _ => bail!("Unknown build label {label}"),
    };
    ensure!(
        evidence.label == label && evidence.source == source && evidence.toolchain == toolchain,
        "Pinned build label, source or toolchain mismatch"
    );
    ensure!(
        evidence.hardware == "2.1.0" && evidence.platform == "emulator",
        "Build did not select 2.1 emulator fixtures"
    );
    ensure!(
        !evidence.configuration.trim().is_empty(),
        "Missing build command"
    );
    if let Some(expected) = configuration {
        ensure!(
            evidence.configuration == expected,
            "Build configuration differs from owner agreement"
        );
    }
    for (filename, expected) in [
        ("Cargo.lock", &evidence.lockfile_sha256),
        ("rust-toolchain.toml", &evidence.toolchain_file_sha256),
    ] {
        let content = fs::read(directory.join(filename))?;
        ensure!(
            hex::encode(Sha256::digest(content)) == *expected,
            "Build input hash mismatch: {filename}"
        );
    }
    ensure!(
        fs::read_to_string(directory.join("exit-code.txt"))?.trim() == "0",
        "Pinned image build did not succeed"
    );
    println!("Build evidence: {}", String::from_utf8(bytes)?);
    Ok(())
}

impl PairConfig {
    fn validate(&self, rom: &str, runtime: &str) -> Result<()> {
        ensure!(
            self.agreed && !self.agreement.trim().is_empty(),
            "BLOCKED: owner agreement on fixtures and supported scenarios is unresolved"
        );
        ensure!(
            self.rom == rom && self.runtime == runtime,
            "Fixture pair mismatch"
        );
        ensure!(
            self.hardware == "2.1.0",
            "Only the 2.1.0 emulator is supported"
        );
        for source in [&self.core_rom_source, &self.core_firmware_source] {
            ensure!(
                source.len() == 40 && source.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "Core fixtures require immutable source SHAs"
            );
        }
        ensure!(
            self.signing == "repository-test-keys-lms-default-fuses",
            "BLOCKED: signing/fuse setup has no validated harness implementation"
        );
        ensure!(
            !self.build_configuration.trim().is_empty(),
            "Missing build configuration"
        );
        ensure!(
            self.scenarios.len() == SCENARIOS.len()
                && SCENARIOS
                    .iter()
                    .all(|name| self.scenarios.contains_key(*name)),
            "An explicit support decision is required for every scenario"
        );
        ensure!(
            self.negative_cases.keys().all(|name| matches!(
                name.as_str(),
                "corrupted_runtime" | "corrupted_manifest" | "svn_rollback" | "svn_boundary"
            )),
            "Fixture overrides are only allowed for authentication/SVN cases"
        );
        for decision in self.scenarios.values() {
            match decision {
                Applicability::Blocked { reason } | Applicability::NotApplicable { reason } => {
                    ensure!(
                        !reason.trim().is_empty(),
                        "Scenario disposition requires a reason"
                    );
                }
                Applicability::Supported { .. } => {}
            }
        }
        ensure!(
            self.suites.is_empty()
                || (self.suites.len() == SUITES.len()
                    && SUITES.iter().all(|name| self.suites.contains_key(*name))),
            "Step 5 requires an explicit support decision for every suite"
        );
        for decision in self.suites.values() {
            if let Applicability::Blocked { reason } | Applicability::NotApplicable { reason } =
                decision
            {
                ensure!(
                    !reason.trim().is_empty(),
                    "Suite disposition requires a reason"
                );
            }
        }
        Ok(())
    }
}

struct SelectedPair {
    config: PairConfig,
    root: PathBuf,
    rom: Vec<u8>,
    runtime: Vec<u8>,
    version: String,
    configuration_sha256: String,
}

impl SelectedPair {
    fn load(artifacts: &Path) -> Result<Self> {
        let rom_label = std::env::var("MCU_COMPAT_ROM").context("MCU_COMPAT_ROM is required")?;
        let runtime_label =
            std::env::var("MCU_COMPAT_RUNTIME").context("MCU_COMPAT_RUNTIME is required")?;
        let current_source = std::env::var("MCU_COMPAT_CURRENT_RUNTIME_SHA")
            .context("MCU_COMPAT_CURRENT_RUNTIME_SHA is required")?;
        let config_path = PathBuf::from(std::env::var_os("MCU_COMPAT_CONFIG").context(
            "BLOCKED: missing agreed per-pair fixture configuration (MCU_COMPAT_CONFIG)",
        )?);
        let config_path = config_path.canonicalize().context(
            "BLOCKED: missing agreed per-pair fixture configuration (MCU_COMPAT_CONFIG)",
        )?;
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&config_path)?)?;
        ensure!(
            value.get("agreed") == Some(&serde_json::Value::Bool(true)),
            "BLOCKED: owner agreement on fixtures and supported scenarios is unresolved"
        );
        let config: PairConfig = serde_json::from_value(value)?;
        let configuration_sha256 = hex::encode(Sha256::digest(fs::read(&config_path)?));
        config.validate(&rom_label, &runtime_label)?;
        verify_build_evidence(
            &artifacts.join(&rom_label),
            &rom_label,
            rom_release(&rom_label)?.source,
            None,
        )?;
        verify_build_evidence(
            &artifacts.join(&runtime_label),
            &runtime_label,
            runtime_source(&runtime_label, &current_source)?,
            Some(&config.build_configuration),
        )?;
        let rom = verified_image(&artifacts.join(&rom_label), rom_release(&rom_label)?.source)?;
        let runtime = verified_image(
            &artifacts.join(&runtime_label),
            runtime_source(&runtime_label, &current_source)?,
        )?;
        let version = runtime_version(&artifacts.join(&runtime_label), &runtime_label)?;
        println!(
            "Pair={rom_label}/{runtime_label}, hardware={}, Core ROM={}, Core FW={}, \
             build={}, signing={}, config.sha256={}",
            config.hardware,
            config.core_rom_source,
            config.core_firmware_source,
            config.build_configuration,
            config.signing,
            hex::encode(Sha256::digest(fs::read(&config_path)?))
        );
        Ok(Self {
            config,
            root: config_path
                .parent()
                .context("Fixture configuration has no parent")?
                .to_path_buf(),
            rom,
            runtime,
            version,
            configuration_sha256,
        })
    }

    fn boot(
        &self,
        flash: bool,
        negative: Option<(&str, &NegativeCase)>,
        preserved: Option<(Vec<u8>, Vec<u8>)>,
        transport: bool,
    ) -> Result<DefaultHwModel> {
        let caliptra_rom = self.config.caliptra_rom.read(&self.root)?;
        let caliptra_fw = self.config.caliptra_firmware.read(&self.root)?;
        let mut soc_manifest = self.config.soc_manifest.read(&self.root)?;
        let mut otp = self.config.otp.read(&self.root)?;
        let mut runtime = self.runtime.clone();
        if let Some((name, case)) = negative {
            if let Some(manifest) = &case.soc_manifest {
                soc_manifest = manifest.read(&self.root)?;
            }
            if let Some(image) = &case.otp {
                otp = image.read(&self.root)?;
            }
            if matches!(name, "corrupted_runtime" | "corrupted_manifest") {
                let bytes = if name == "corrupted_runtime" {
                    &mut runtime
                } else {
                    &mut soc_manifest
                };
                let offset = case
                    .corrupt_offset
                    .context("Missing release-specific corruption offset")?;
                let byte = bytes
                    .get_mut(offset)
                    .context("Corruption offset outside selected image")?;
                *byte ^= 1;
            } else {
                ensure!(
                    case.corrupt_offset.is_none(),
                    "SVN cases must not modify firmware"
                );
                ensure!(
                    case.otp.is_some(),
                    "SVN case requires an explicit OTP fixture"
                );
            }
        }
        let vendor_pk_hash: [u8; 48] = hex::decode(&self.config.vendor_pk_hash)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Expected a 48-byte vendor public-key hash"))?;
        let (otp, flash_image) = match preserved {
            Some((otp, flash)) => (otp, Some(flash)),
            None if flash => (
                otp,
                Some(
                    self.config
                        .primary_flash
                        .as_ref()
                        .context("BLOCKED: flash test requires a signed selected-image package")?
                        .read(&self.root)?,
                ),
            ),
            None => {
                let selected = negative
                    .and_then(|(_, case)| case.runtime_flash.as_ref())
                    .or(self.config.runtime_flash.as_ref());
                ensure!(
                    self.streaming() || selected.is_some(),
                    "BLOCKED: flash-enabled runtime requires a selected runtime flash package"
                );
                let seed_manifest = negative
                    .and_then(|(_, case)| case.soc_manifest.as_ref())
                    .unwrap_or(&self.config.soc_manifest)
                    .read(&self.root)?;
                let image = selected
                    .map(|artifact| self.runtime_flash(artifact, &seed_manifest))
                    .transpose()?;
                (otp, image)
            }
        };
        if flash {
            let bytes = flash_image.as_ref().context("Missing ROM flash")?;
            verify_flash_selection(
                bytes,
                rom_release(&self.config.rom)?.flash_version,
                [&caliptra_fw, &soc_manifest, &runtime],
            )?;
        }
        let mut flash_image = flash_image;
        if !flash {
            if let Some(image) = &mut flash_image {
                crate::test::write_valid_partition_table_for_runtime_flash_load(image);
            }
        }
        let vendor_pqc_type = caliptra_image_types::FwVerificationPqcKeyType::LMS;
        let fuse_vendor_pk_hash = std::array::from_fn(|index| {
            let offset = index * 4;
            u32::from_be_bytes(vendor_pk_hash[offset..offset + 4].try_into().unwrap())
        });
        Ok(caliptra_mcu_hw_model::new(InitParams {
            hw_revision: Some(
                self.config
                    .hardware
                    .parse()
                    .context("Invalid hardware revision")?,
            ),
            fuses: Fuses {
                fuse_pqc_key_type: vendor_pqc_type as u32,
                vendor_pk_hash: fuse_vendor_pk_hash,
                ..Default::default()
            },
            caliptra_rom: &caliptra_rom,
            mcu_rom: &self.rom,
            caliptra_firmware: if flash { &[] } else { &caliptra_fw },
            soc_manifest: if flash { &[] } else { &soc_manifest },
            mcu_firmware: if flash { &[] } else { &runtime },
            vendor_pk_hash: Some(vendor_pk_hash),
            vendor_pqc_type: Some(vendor_pqc_type),
            active_mode: true,
            i3c_port: if transport {
                Some(
                    random_port::PortPicker::new()
                        .random(true)
                        .pick()
                        .context("No free I3C port")?,
                )
            } else {
                None
            },
            capture_mcu_exit: true,
            enable_mcu_uart_log: true,
            check_booted_to_runtime: false,
            otp_memory: Some(&otp),
            primary_flash_initial_contents: flash_image,
            flash_boot: flash,
            ..Default::default()
        })?)
    }

    fn streaming(&self) -> bool {
        self.config
            .build_configuration
            .split_whitespace()
            .any(|argument| argument == "streaming-boot")
    }

    fn runtime_flash(&self, artifact: &Artifact, manifest: &[u8]) -> Result<Vec<u8>> {
        use caliptra_mcu_config_emulator::flash::{
            PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION,
        };
        let bytes = artifact.read(&self.root)?;
        let (table, _) = PartitionTable::read_from_prefix(&bytes).map_err(|_| {
            anyhow::anyhow!("Truncated runtime partition table: {} bytes", bytes.len())
        })?;
        ensure!(
            table.verify_checksum(&StandAloneChecksumCalculator::new())
                && table.active_partition == 1,
            "Invalid runtime flash partition selection/checksum"
        );
        let core = self.config.caliptra_firmware.read(&self.root)?;
        let owner = self
            .config
            .owner_auth_manifest
            .as_ref()
            .context("BLOCKED: missing owner authorization manifest")?
            .read(&self.root)?;
        let policy = self
            .config
            .owner_measurement_policy
            .as_ref()
            .context("BLOCKED: missing owner measurement policy")?
            .read(&self.root)?;
        let soc = self
            .config
            .soc_images
            .iter()
            .map(|image| image.image.read(&self.root))
            .collect::<Result<Vec<_>>>()?;
        let mut selected = vec![
            (CALIPTRA_FMC_RT_IDENTIFIER, core.as_slice()),
            (SOC_MANIFEST_IDENTIFIER, manifest),
            (MCU_RT_IDENTIFIER, self.runtime.as_slice()),
            (OWNER_AUTH_MANIFEST_IDENTIFIER, owner.as_slice()),
            (OWNER_MEASUREMENT_POLICY_IDENTIFIER, policy.as_slice()),
        ];
        for (index, image) in soc.iter().enumerate() {
            selected.push((4096 + u32::try_from(index)?, image.as_slice()));
        }
        verify_v3_selection(
            bytes
                .get(IMAGE_A_PARTITION.offset..)
                .context("Missing runtime partition")?,
            &selected,
        )?;
        Ok(bytes)
    }
}

fn check_no_fatal(hw: &mut impl McuHwModel) -> Result<()> {
    if let Some(status) = hw.mcu_exit_status() {
        ensure!(
            status == 0,
            "MCU firmware requested exit {status}; Core nonfatal error={:#x}",
            hw.caliptra_soc_manager()
                .soc_ifc()
                .cptra_fw_error_non_fatal()
                .read()
        );
    }
    ensure!(
        hw.mci_fw_fatal_error().is_none(),
        "Fatal MCU error: {:?}",
        hw.mci_fw_fatal_error()
    );
    let fatal = hw
        .caliptra_soc_manager()
        .soc_ifc()
        .cptra_fw_error_fatal()
        .read();
    ensure!(fatal == 0, "Fatal Core error: {fatal:#x}");
    Ok(())
}

fn verify_v3_selection(bytes: &[u8], selected: &[(u32, &[u8])]) -> Result<()> {
    use caliptra_mcu_flash_image::{FlashHeader, ImageHeader};
    caliptra_mcu_builder::flash_image::FlashImage::verify_flash_image(bytes)?;
    let (header, _) = FlashHeader::ref_from_prefix(bytes)
        .map_err(|error| anyhow::anyhow!("Invalid runtime flash header: {error}"))?;
    ensure!(
        header.version == 3 && usize::from(header.image_count) == selected.len(),
        "Wrong runtime flash format/count"
    );
    for (index, (id, image)) in selected.iter().enumerate() {
        let offset =
            usize::try_from(header.image_headers_offset)? + index * size_of::<ImageHeader>();
        let (entry, _) = ImageHeader::ref_from_prefix(
            bytes
                .get(offset..)
                .context("Image header outside package")?,
        )
        .map_err(|error| anyhow::anyhow!("Invalid runtime image header: {error}"))?;
        let offset = usize::try_from(entry.offset)?;
        let size = usize::try_from(entry.size)?;
        let end = offset.checked_add(size).context("Image range overflow")?;
        let payload = bytes.get(offset..end).context("Image outside package")?;
        ensure!(
            entry.identifier == *id
                && payload.starts_with(image)
                && [4, 256]
                    .into_iter()
                    .any(|alignment| image.len().next_multiple_of(alignment) == size)
                && payload[image.len()..].iter().all(|byte| *byte == 0),
            "Runtime package differs from selected image {id}"
        );
    }
    Ok(())
}

fn verify_svn_boundary(manifest: &[u8], otp: &[u8], runtime: &[u8]) -> Result<u32> {
    use caliptra_auth_man_types::AuthorizationManifest;
    use sha2::Sha384;
    ensure!(otp.len() == 0xe88, "Wrong SVN OTP size");
    let signed = AuthorizationManifest::ref_from_bytes(manifest)
        .map_err(|error| anyhow::anyhow!("Invalid boundary manifest: {error}"))?;
    let floor: u32 = otp[0x3cc..0x3dc].iter().map(|byte| byte.count_ones()).sum();
    let ceiling = u32::from_le_bytes(otp[0x3dc..0x3e0].try_into()?);
    ensure!(
        floor > 0 && signed.preamble.svn == floor && floor <= ceiling,
        "Not an exact signed SVN boundary"
    );
    let entries = signed
        .image_metadata_col
        .image_metadata_list
        .get(..usize::try_from(signed.image_metadata_col.entry_count)?)
        .context("Invalid manifest entry count")?;
    let mut mcu = entries
        .iter()
        .filter(|entry| entry.fw_id == MCU_RT_IDENTIFIER);
    let entry = mcu.next().context("Missing boundary MCU entry")?;
    ensure!(
        mcu.next().is_none() && entry.digest[..] == Sha384::digest(runtime)[..],
        "Boundary does not bind the unchanged selected runtime"
    );
    println!("Verified signed SVN {floor} equals OTP minimum; OTP maximum={ceiling}");
    Ok(floor)
}

fn streaming_package(pair: &SelectedPair) -> Result<caliptra_mcu_pldm_fw_pkg::FirmwareManifest> {
    let inputs: serde_json::Value =
        serde_json::from_slice(&fs::read(pair.root.join("streaming-inputs.json"))?)?;
    let package: Artifact = serde_json::from_value(inputs["pldm_package"].clone())?;
    package.read(&pair.root)?;
    let image: Artifact = serde_json::from_value(inputs["soc_images"].clone())?;
    let image = image.read(&pair.root)?;
    let soc = pair
        .config
        .soc_images
        .iter()
        .map(|check| check.image.read(&pair.root))
        .collect::<Result<Vec<_>>>()?;
    let owner = pair
        .config
        .owner_auth_manifest
        .as_ref()
        .context("BLOCKED: missing owner authorization manifest")?
        .read(&pair.root)?;
    let policy = pair
        .config
        .owner_measurement_policy
        .as_ref()
        .context("BLOCKED: missing owner measurement policy")?
        .read(&pair.root)?;
    let mut selected = vec![
        (OWNER_AUTH_MANIFEST_IDENTIFIER, owner.as_slice()),
        (OWNER_MEASUREMENT_POLICY_IDENTIFIER, policy.as_slice()),
    ];
    selected.extend(
        soc.iter()
            .enumerate()
            .map(|(index, bytes)| Ok((4096 + u32::try_from(index)?, bytes.as_slice())))
            .collect::<Result<Vec<_>>>()?,
    );
    verify_v3_selection(&image, &selected)?;
    let path = pair
        .root
        .join(package.path)
        .canonicalize()?
        .to_str()
        .context("Non-UTF-8 PLDM path")?
        .to_owned();
    let manifest =
        caliptra_mcu_pldm_fw_pkg::FirmwareManifest::decode_firmware_package(&path, None)?;
    ensure!(
        manifest.component_image_information.len() == 1
            && manifest.firmware_device_id_records.len() == 1,
        "Wrong PLDM component/device count"
    );
    let component = &manifest.component_image_information[0];
    let descriptor = &manifest.firmware_device_id_records[0].initial_descriptor;
    ensure!(
        component.classification == 0x000a
            && component.identifier == 0xffff
            && component.image_data.as_deref() == Some(image.as_slice()),
        "PLDM package differs from selected component/payload"
    );
    ensure!(
        matches!(
            descriptor.descriptor_type,
            caliptra_mcu_pldm_fw_pkg::manifest::DescriptorType::Uuid
        ) && descriptor.descriptor_data == (1..=16).collect::<Vec<u8>>(),
        "Wrong PLDM device UUID"
    );
    Ok(manifest)
}

struct DiscoveryObserver(Arc<AtomicBool>);

impl caliptra_mcu_pldm_ua::discovery_sm::StateMachineActions for DiscoveryObserver {
    fn on_set_tid_response(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::SetTidResponse,
    ) -> std::result::Result<(), ()> {
        if response.hdr.instance_id() != ctx.instance_id || response.completion_code != 0 {
            eprintln!("Invalid PLDM SetTID response: {response:?}");
            return Err(());
        }
        caliptra_mcu_pldm_ua::discovery_sm::DefaultActions {}.on_set_tid_response(ctx, response)
    }

    fn on_get_tid_response(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::GetTidResponse,
    ) -> std::result::Result<(), ()> {
        if response.hdr.instance_id() != ctx.instance_id
            || response.completion_code != 0
            || response.tid != PLDM_TID
        {
            eprintln!("Invalid PLDM GetTID response: {response:?}");
            return Err(());
        }
        caliptra_mcu_pldm_ua::discovery_sm::DefaultActions {}.on_get_tid_response(ctx, response)
    }

    fn on_pldm_commands_response_type5(
        &self,
        ctx: &mut caliptra_mcu_pldm_ua::discovery_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        response: caliptra_mcu_pldm_common::message::control::GetPldmCommandsResponse,
    ) -> std::result::Result<(), ()> {
        use caliptra_mcu_pldm_ua::discovery_sm::DefaultActions;
        DefaultActions {}.on_pldm_commands_response_type5(ctx, response)?;
        self.0.store(true, Ordering::Release);
        Ok(())
    }
}

struct UpdateObserver(Arc<AtomicU8>);

impl caliptra_mcu_pldm_ua::update_sm::StateMachineActions for UpdateObserver {
    fn on_verify_complete_request(
        &mut self,
        ctx: &mut caliptra_mcu_pldm_ua::update_sm::InnerContext<
            impl caliptra_mcu_pldm_ua::transport::PldmSocket + Send + 'static,
        >,
        request: caliptra_mcu_pldm_common::message::firmware_update::verify_complete::VerifyCompleteRequest,
    ) -> std::result::Result<(), ()> {
        let result = request.verify_result;
        caliptra_mcu_pldm_ua::update_sm::DefaultActions {}
            .on_verify_complete_request(ctx, request)?;
        self.0.store(result, Ordering::Release);
        Ok(())
    }
}

struct TransportSession {
    daemon: caliptra_mcu_pldm_ua::daemon::PldmDaemon<
        caliptra_mcu_testing_common::mctp_transport::MctpPldmSocket,
        DiscoveryObserver,
        UpdateObserver,
    >,
    socket: caliptra_mcu_testing_common::mctp_transport::MctpPldmSocket,
    discovered: Arc<AtomicBool>,
    verification_error: Arc<AtomicU8>,
}

impl TransportSession {
    fn finish(&mut self, hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
        use caliptra_mcu_pldm_ua::{transport::PldmSocket, update_sm::States};
        let start = Instant::now();
        let cycles = hw.cycle_count();
        while !matches!(self.daemon.get_update_sm_state(), States::Done) {
            check_no_fatal(hw)?;
            let verification_error = self.verification_error.load(Ordering::Acquire);
            ensure!(
                verification_error == 0,
                "PLDM verification failed: result={verification_error:#x}, Core nonfatal error={:#x}",
                hw.caliptra_soc_manager().soc_ifc().cptra_fw_error_non_fatal().read()
            );
            ensure!(
                hw.mcu_exit_status().is_none(),
                "MCU exited before PLDM completion"
            );
            ensure!(
                hw.cycle_count() - cycles < 200_000_000
                    && start.elapsed() < Duration::from_secs(180),
                "PLDM transport timed out: discovered={}, state={:?}",
                self.discovered.load(Ordering::Acquire),
                self.daemon.get_update_sm_state()
            );
            hw.step();
        }
        ensure!(
            self.discovered.load(Ordering::Acquire),
            "PLDM discovery did not complete"
        );
        let device = self
            .daemon
            .get_device_id()
            .context("PLDM device identification did not complete")?;
        ensure!(
            device.initial_descriptor.descriptor_data == (1..=16).collect::<Vec<u8>>(),
            "Discovered wrong PLDM device"
        );
        check_soc_images(hw, pair)?;
        self.daemon.stop();
        self.socket.disconnect();
        check_no_fatal(hw)?;
        println!("MCTP/PLDM discovery, update completion, SoC payloads and activation verified");
        Ok(())
    }
}

fn check_mctp_discovery(port: u16, address: u8) -> Result<()> {
    use caliptra_mcu_testing_common::{
        i3c_socket::BufferedStream,
        mctp_util::{
            common::MctpUtil,
            ctrl_protocol::{MCTPCtrlCmd, MCTPCtrlMsgHdr},
        },
    };
    let mut stream = BufferedStream::new(std::net::TcpStream::connect(("127.0.0.1", port))?);
    let mut protocol = MctpUtil::new();
    protocol.set_boot_delay_ticks(0);
    for cmd in [
        MCTPCtrlCmd::GetEID,
        MCTPCtrlCmd::GetEndpointUUID,
        MCTPCtrlCmd::GetMsgTypeSupport,
    ] {
        let command = cmd as u8;
        let mut header = MCTPCtrlMsgHdr::new();
        header.set_rq(1);
        header.set_instance_id(command);
        header.set_cmd(command);
        let mut request = vec![0];
        request.extend_from_slice(&header.0);
        let response = protocol
            .wait_for_responder(0, &request, &mut stream, address)
            .context("No MCTP discovery response")?;
        check_mctp_response(command, header.0[0], &response)?;
        println!(
            "MCTP discovery command {command}: {}",
            hex::encode(response)
        );
    }
    Ok(())
}

fn check_mctp_response(command: u8, request_header: u8, response: &[u8]) -> Result<()> {
    use caliptra_mcu_testing_common::mctp_util::base_protocol::MctpMsgType;
    ensure!(
        response.len() >= 4 && response[..4] == [0, request_header & 0x7f, command, 0],
        "Invalid MCTP discovery response: {}",
        hex::encode(response)
    );
    match command {
        2 => ensure!(
            response.len() == 7 && response[4] != 255,
            "Invalid MCTP endpoint ID response"
        ),
        3 => ensure!(response.len() == 20, "Invalid MCTP UUID response"),
        5 => ensure!(
            response.len() >= 5
                && response.len() == 5 + usize::from(response[4])
                && [
                    MctpMsgType::Ctrl,
                    MctpMsgType::Pldm,
                    MctpMsgType::Spdm,
                    MctpMsgType::Caliptra
                ]
                .iter()
                .all(|kind| response[5..].contains(&(*kind as u8))),
            "Missing configured MCTP message types"
        ),
        _ => bail!("Unexpected MCTP discovery command {command}"),
    }
    Ok(())
}

fn start_transport(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<TransportSession> {
    use caliptra_mcu_pldm_ua::{
        daemon::{Options, PldmDaemon},
        transport::{EndpointId, PldmSocket, PldmTransport},
    };
    use caliptra_mcu_testing_common::{mctp_transport::MctpTransport, spawn_with_emulator_state};
    let manifest = streaming_package(pair)?;
    let port = hw.i3c_port().context("Missing selected-image I3C port")?;
    let address = hw.i3c_address().context("Missing dynamic I3C address")?;
    hw.start_i3c_controller();
    let discovered = Arc::new(AtomicBool::new(false));
    let observer = discovered.clone();
    let verification_error = Arc::new(AtomicU8::new(0));
    let update_observer = verification_error.clone();
    let (tx, rx) = mpsc::channel();
    spawn_with_emulator_state(move || {
        let result = (|| -> Result<TransportSession> {
            check_mctp_discovery(port, address)?;
            let socket = MctpTransport::new(port, address.into())
                .create_socket(EndpointId(8), EndpointId(0))
                .map_err(|error| anyhow::anyhow!("I3C PLDM socket failed: {error:?}"))?;
            let daemon = PldmDaemon::run(
                socket.clone(),
                Options {
                    caliptra_mcu_pldm_fw_pkg: Some(manifest),
                    discovery_sm_actions: DiscoveryObserver(observer),
                    update_sm_actions: UpdateObserver(update_observer),
                    fd_tid: PLDM_TID,
                    rerun_count: 0,
                },
            )
            .map_err(|()| anyhow::anyhow!("Cannot start selected-image PLDM daemon"))?;
            Ok(TransportSession {
                daemon,
                socket,
                discovered,
                verification_error,
            })
        })();
        if tx.send(result).is_err() {
            eprintln!("Selected-image transport receiver exited");
        }
    });
    let start = Instant::now();
    let cycles = hw.cycle_count();
    loop {
        match rx.try_recv() {
            Ok(result) => return result,
            Err(mpsc::TryRecvError::Disconnected) => {
                bail!("Selected-image transport worker terminated")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        check_no_fatal(hw)?;
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited during MCTP discovery"
        );
        ensure!(
            hw.cycle_count() - cycles < 100_000_000 && start.elapsed() < Duration::from_secs(120),
            "MCTP discovery timed out"
        );
        hw.step();
    }
}

fn wait_ready(hw: &mut impl McuHwModel) -> Result<()> {
    let start = Instant::now();
    let initial_cycles = hw.cycle_count();
    loop {
        check_no_fatal(hw)?;
        let milestones = hw.mci_boot_milestones();
        if milestones.contains(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE)
            && milestones.contains(McuBootMilestones::FIRMWARE_MAILBOX_READY)
        {
            return Ok(());
        }
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited before service readiness"
        );
        ensure!(
            hw.cycle_count() - initial_cycles < 100_000_000
                && start.elapsed() < Duration::from_secs(180),
            "Boot/mailbox readiness timed out; milestones={:#x}",
            milestones.bits()
        );
        hw.step();
    }
}

fn mailbox(hw: &mut impl McuHwModel, command: u32, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        hw.mcu_exit_status().is_none(),
        "MCU exited before mailbox command {command:#x}"
    );
    let mut request = calc_checksum(command, payload).to_le_bytes().to_vec();
    request.extend_from_slice(payload);
    hw.start_mailbox_execute(command, &request)?;
    let start = Instant::now();
    let cycles = hw.cycle_count();
    while hw.cmd_status().cmd_busy() {
        check_no_fatal(hw)?;
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited during mailbox command {command:#x}"
        );
        ensure!(
            hw.cycle_count() - cycles < 40_000_000 && start.elapsed() < Duration::from_secs(60),
            "Mailbox command timed out"
        );
        hw.step();
    }
    hw.finish_mailbox_execute()?
        .context("Mailbox command returned no response")
}

fn check_version(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
    check_version_response(
        &mailbox(hw, CommandId::MC_FIRMWARE_VERSION.0, &1u32.to_le_bytes())?,
        &pair.version,
    )?;
    check_no_fatal(hw)
}

fn read_memory<M: McuManager>(manager: &mut M, address: u32, length: usize) -> Result<Vec<u8>> {
    read_memory_mmio(&manager.mmio_mut(), M::MBOX_1_ADDR, address, length)
}

fn read_memory_mmio(
    mmio: &impl Mmio,
    mailbox1_base: u32,
    address: u32,
    length: usize,
) -> Result<Vec<u8>> {
    const SOC_MAILBOX1_BASE: u32 = 0xa880_0000;
    let map = &caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;
    let end = u64::from(address)
        .checked_add(u64::try_from(length)?)
        .context("Memory check address overflow")?;
    let regions = [
        (map.sram_offset, map.sram_size),
        (map.dccm_offset, map.dccm_size),
        (
            SOC_MAILBOX1_BASE,
            caliptra_mcu_emulator_consts::MCU_MAILBOX1_SRAM_SIZE,
        ),
    ];
    ensure!(
        length > 0
            && regions
                .iter()
                .any(|&(base, size)| u64::from(address) >= base as u64
                    && end <= (base + size) as u64),
        "Memory check is outside emulator RAM"
    );
    let address = if address >= SOC_MAILBOX1_BASE {
        mailbox1_base
            .checked_add(address - SOC_MAILBOX1_BASE)
            .context("Mailbox SRAM address overflow")?
    } else {
        address
    };
    let byte_offset = address as usize % size_of::<u32>();
    let aligned_address = address as usize - byte_offset;
    Ok((0..(length + byte_offset).div_ceil(size_of::<u32>()))
        .flat_map(|index| {
            // Mailbox SRAM is a word-only CSR aperture, unlike ordinary MCU RAM.
            unsafe {
                mmio.read_volatile((aligned_address + index * size_of::<u32>()) as *const u32)
            }
            .to_le_bytes()
        })
        .skip(byte_offset)
        .take(length)
        .collect())
}

fn check_soc_images(hw: &mut impl McuHwModel, pair: &SelectedPair) -> Result<()> {
    ensure!(
        !pair.config.soc_images.is_empty(),
        "BLOCKED: no expected SoC images supplied"
    );
    let start = Instant::now();
    let initial_cycles = hw.cycle_count();
    let images = pair
        .config
        .soc_images
        .iter()
        .map(|check| Ok((check.address, check.image.read(&pair.root)?)))
        .collect::<Result<Vec<_>>>()?;
    loop {
        check_no_fatal(hw)?;
        let mut complete = true;
        for (address, expected) in &images {
            complete &= read_memory(&mut hw.mcu_manager(), *address, expected.len())? == *expected;
        }
        if complete {
            let mut required = [0u32; 4];
            for image in &pair.config.soc_images {
                ensure!(image.execution_bit < 128, "Invalid SoC execution bit");
                required[usize::from(image.execution_bit / 32)] |= 1 << (image.execution_bit % 32);
            }
            if required.iter().enumerate().all(|(index, bits)| {
                hw.caliptra_soc_manager()
                    .soc_ifc()
                    .ss_generic_fw_exec_ctrl()
                    .at(index)
                    .read()
                    & bits
                    == *bits
            }) {
                return Ok(());
            }
        }
        ensure!(
            hw.mcu_exit_status().is_none(),
            "MCU exited before SoC loading and activation completed"
        );
        ensure!(
            hw.cycle_count() - initial_cycles < 100_000_000
                && start.elapsed() < Duration::from_secs(180),
            "SoC loading/activation timed out; payloads_match={complete}"
        );
        hw.step();
    }
}

fn check_capabilities(response: &[u8], expected: &[u8]) -> Result<()> {
    let (header, payload) = MailboxRespHeader::ref_from_prefix(response)
        .map_err(|error| anyhow::anyhow!("Invalid capabilities response: {error}"))?;
    ensure!(
        matches!(expected.len(), 36 | 64),
        "Expected capabilities must use the selected release's 36- or 64-byte layout"
    );
    ensure!(
        response.len() == size_of::<MailboxRespHeader>() + expected.len(),
        "Capabilities length mismatch"
    );
    ensure!(
        header.fips_status == MailboxRespHeader::FIPS_STATUS_APPROVED,
        "Capabilities status mismatch"
    );
    ensure!(
        header.chksum == calc_checksum(0, &response[4..]),
        "Capabilities checksum mismatch"
    );
    ensure!(
        payload == expected,
        "Capabilities differ from selected release metadata"
    );
    Ok(())
}

fn require_implemented_scenario(scenario: &str) -> Result<()> {
    if scenario == "warm_reset" {
        bail!("BLOCKED: warm_reset requires the FPGA selected-image reset lane");
    }
    Ok(())
}

fn rejection_complete(mcu_error: u32, core_error: u32, expected: &NegativeCase) -> Result<bool> {
    ensure!(
        expected.expected_mcu_error != 0 || expected.expected_core_error != 0,
        "Rejection requires an exact nonzero error"
    );
    ensure!(
        (mcu_error == 0 || mcu_error == expected.expected_mcu_error)
            && (core_error == 0 || core_error == expected.expected_core_error),
        "Wrong rejection: MCU={mcu_error:#x}, Core={core_error:#x}"
    );
    Ok(mcu_error == expected.expected_mcu_error && core_error == expected.expected_core_error)
}

fn exercise(pair: &SelectedPair, scenario: &str) -> Result<()> {
    require_implemented_scenario(scenario)?;
    ensure!(
        !matches!(scenario, "streaming_boot" | "discovery") || pair.streaming(),
        "BLOCKED: transport scenario requires a streaming/service runtime configuration"
    );
    let negative = pair.config.negative_cases.get(scenario);
    let is_negative = matches!(
        scenario,
        "corrupted_runtime" | "corrupted_manifest" | "svn_rollback"
    );
    ensure!(
        !is_negative || negative.is_some(),
        "BLOCKED: missing release-specific authentication/SVN expectations"
    );
    let flash = matches!(scenario, "flash_cold_boot" | "cold_reboot");
    if scenario == "svn_boundary" {
        let case = negative.context("BLOCKED: missing signed SVN boundary fixtures")?;
        verify_svn_boundary(
            &case
                .soc_manifest
                .as_ref()
                .context("Missing boundary manifest")?
                .read(&pair.root)?,
            &case
                .otp
                .as_ref()
                .context("Missing boundary OTP")?
                .read(&pair.root)?,
            &pair.runtime,
        )?;
    }
    let mut hw = pair.boot(
        flash,
        negative.map(|case| (scenario, case)),
        None,
        pair.streaming() && !is_negative,
    )?;
    if is_negative {
        let expected = negative.context("Missing negative case")?;
        let start = Instant::now();
        let initial_cycles = hw.cycle_count();
        loop {
            ensure!(
                hw.mcu_exit_status().is_none(),
                "MCU exited without the expected authentication rejection"
            );
            let mcu_error = hw.mci_fw_fatal_error().unwrap_or(0);
            let core_error = hw
                .caliptra_soc_manager()
                .soc_ifc()
                .cptra_fw_error_fatal()
                .read();
            if rejection_complete(mcu_error, core_error, expected)? {
                return Ok(());
            }
            ensure!(
                !hw.mci_boot_milestones()
                    .contains(McuBootMilestones::FIRMWARE_MAILBOX_READY),
                "Invalid firmware reached runtime readiness"
            );
            ensure!(
                hw.cycle_count() - initial_cycles < 100_000_000
                    && start.elapsed() < Duration::from_secs(180),
                "Timed out without the complete expected rejection: MCU={mcu_error:#x}, Core={core_error:#x}"
            );
            hw.step();
        }
    }
    wait_ready(&mut hw)?;
    check_version(&mut hw, pair)?;
    let mut transport = if pair.streaming() {
        Some(start_transport(&mut hw, pair)?)
    } else {
        None
    };
    match scenario {
        "flash_cold_boot" => {
            check_soc_images(&mut hw, pair)?;
            check_version(&mut hw, pair)?;
        }
        "runtime_commands" => {
            let expected = hex::decode(
                pair.config
                    .expected_capabilities
                    .as_ref()
                    .context("BLOCKED: missing selected-release capabilities")?,
            )?;
            check_capabilities(
                &mailbox(&mut hw, CommandId::MC_DEVICE_CAPABILITIES.0, &[])?,
                &expected,
            )?;
            check_no_fatal(&mut hw)?;
        }
        "handoff" => {
            let address = pair
                .config
                .handoff_address
                .context("BLOCKED: missing handoff address")?;
            let bytes = read_memory(&mut hw.mcu_manager(), address, 28)?;
            ensure!(
                &bytes[..4] == b"MCUH",
                "Invalid ROM handoff marker at {address:#x}: {}",
                hex::encode(&bytes)
            );
            let major = u16::from_le_bytes(bytes[4..6].try_into()?);
            let minor = u16::from_le_bytes(bytes[6..8].try_into()?);
            ensure!(
                major == 1,
                "BLOCKED: unsupported handoff major version {major}"
            );
            ensure!(
                Some(major) == pair.config.handoff_major
                    && Some(minor) == pair.config.handoff_minor,
                "Selected ROM handoff version mismatch"
            );
            // Pre-1.2 ROMs have no boot-source field; reserved bytes are not evidence.
            if minor >= 2 {
                ensure!(bytes[20] == 2, "Recovery boot source handoff mismatch");
            }
            if minor >= 3 {
                ensure!(
                    Some(u32::from_le_bytes(bytes[24..28].try_into()?))
                        == pair.config.expected_rom_capabilities,
                    "ROM handoff capabilities mismatch"
                );
            }
        }
        "cold_reboot" => {
            check_soc_images(&mut hw, pair)?;
            let otp = hw.read_otp_memory();
            drop(hw);
            let flash =
                fs::read("primary_flash").context("Cannot preserve emulator primary flash")?;
            println!(
                "Preserved primary_flash.sha256={}",
                hex::encode(Sha256::digest(&flash))
            );
            hw = pair.boot(true, None, Some((otp.clone(), flash)), false)?;
            ensure!(
                hw.read_otp_memory() == otp,
                "Cold reboot did not preserve OTP"
            );
            wait_ready(&mut hw)?;
            check_version(&mut hw, pair)?;
            check_soc_images(&mut hw, pair)?;
            check_version(&mut hw, pair)?;
        }
        _ => {}
    }
    if let Some(session) = &mut transport {
        session.finish(&mut hw, pair)?;
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct CaseResult {
    scenario: String,
    result: String,
    reason: String,
    exit_code: Option<i32>,
    #[serde(default)]
    configuration_sha256: Option<String>,
}

fn require_suite_prerequisites(pair: &SelectedPair, artifacts: &Path) -> Result<()> {
    ensure!(
        std::env::var("MCU_COMPAT_PHASE").as_deref() == Ok("suites"),
        "BLOCKED: run step-5 suites through the ordered xtask compatibility phases"
    );
    let mut prerequisites = vec!["recovery_cold_boot", "runtime_commands"];
    if pair.streaming() {
        prerequisites.extend(["streaming_boot", "discovery"]);
    }
    let results = artifacts
        .join("results")
        .join(&pair.config.rom)
        .join(&pair.config.runtime);
    for scenario in prerequisites {
        let path = results.join(format!("{scenario}.json"));
        let record: CaseResult = serde_json::from_slice(
            &fs::read(&path)
                .with_context(|| format!("BLOCKED: missing {scenario} boot prerequisite"))?,
        )
        .with_context(|| format!("BLOCKED: invalid {scenario} boot evidence"))?;
        validate_suite_prerequisite(&record, scenario, &pair.configuration_sha256)?;
    }
    Ok(())
}

fn validate_suite_prerequisite(record: &CaseResult, scenario: &str, hash: &str) -> Result<()> {
    ensure!(
        record.scenario == scenario
            && record.result == "PASS"
            && record.exit_code == Some(0)
            && record.configuration_sha256.as_deref() == Some(hash),
        "BLOCKED: {scenario} must pass for these exact image/configuration hashes before step 5"
    );
    Ok(())
}

fn suite_disposition<'a>(pair: &'a SelectedPair, scenario: &str) -> Result<Option<&'a str>> {
    let support = pair
        .config
        .suite_support
        .as_ref()
        .context("BLOCKED: missing source-derived step-5 support evidence")?;
    let support: serde_json::Value = serde_json::from_slice(&support.read(&pair.root)?)?;
    ensure!(
        support["rom_source"] == rom_release(&pair.config.rom)?.source
            && support["runtime_source"]
                == runtime_source(
                    &pair.config.runtime,
                    &std::env::var("MCU_COMPAT_CURRENT_RUNTIME_SHA")?
                )?
            && support["build_configuration"] == pair.config.build_configuration,
        "BLOCKED: step-5 support evidence does not describe the selected images"
    );
    let decision = pair
        .config
        .suites
        .get(scenario)
        .context("BLOCKED: missing explicit step-5 support decision")?;
    ensure!(
        support["decisions"][scenario] == serde_json::to_value(decision)?,
        "BLOCKED: suite disposition differs from its source/configuration evidence"
    );
    decision.disposition()
}

fn exercise_suite(pair: &SelectedPair, scenario: &str) -> Result<()> {
    let output = PathBuf::from(
        std::env::var_os("MCU_COMPAT_EVIDENCE_DIR")
            .context("BLOCKED: suite evidence directory is required")?,
    );
    if scenario == "suite_ownership_handoff" {
        let artifacts = PathBuf::from(
            std::env::var_os("MCU_COMPAT_ARTIFACT_DIR")
                .context("Missing selected artifact directory")?,
        );
        let source = artifacts
            .join("results")
            .join(&pair.config.rom)
            .join(&pair.config.runtime)
            .join("handoff.json");
        let bytes = fs::read(&source).context("BLOCKED: missing selected-layout handoff check")?;
        let record: CaseResult = serde_json::from_slice(&bytes)?;
        fs::write(output.join("reused-handoff.json"), &bytes)?;
        validate_suite_prerequisite(&record, "handoff", &pair.configuration_sha256)?;
        println!("Reused the boot phase's selected-ROM-layout handoff assertions; no feature-specific handoff firmware was built.");
        return Ok(());
    }
    let support = pair
        .config
        .suite_support
        .as_ref()
        .context("Missing suite support evidence")?;
    let support: serde_json::Value = serde_json::from_slice(&support.read(&pair.root)?)?;
    // Keep service runtimes waiting for their PLDM payload while exercising the
    // independent services; completing image loading can terminate the emulator.
    let mut hw = pair.boot(false, None, None, pair.streaming())?;
    wait_ready(&mut hw)?;
    check_version(&mut hw, pair)?;
    match scenario {
        "suite_mailbox" | "suite_provisioning" => {
            let expected = serde_json::from_value(support["mailbox"].clone())
                .context("BLOCKED: missing or invalid selected-source mailbox expectations")?;
            if scenario == "suite_mailbox" {
                mailbox::run_selected_mailbox_checks(&mut hw, &expected)?;
            } else {
                mailbox::run_selected_provisioning_checks(&mut hw, &expected)?;
            }
        }
        "suite_spdm_mctp" => {
            ensure!(pair.streaming(), "BLOCKED: MCTP service configuration is required");
            hw.start_i3c_controller();
            spdm::run_compatibility_conformance(&mut hw)?;
        }
        "suite_attestation_ocp_eat_non_tcb" | "suite_attestation_ocp_eat_tcb"
        | "suite_attestation_ocp_eat_mixed" | "suite_attestation_pcr_quote" => {
            let kind = match scenario {
                "suite_attestation_ocp_eat_non_tcb" => "ocp-eat-non-tcb",
                "suite_attestation_ocp_eat_tcb" => "ocp-eat-tcb",
                "suite_attestation_ocp_eat_mixed" => "ocp-eat-mixed",
                _ => "pcr-quote",
            };
            hw.start_i3c_controller();
            attestation::run_compatibility_attestation(&mut hw, kind)?;
        }
        _ => bail!("BLOCKED: {scenario} has no supported adapter for the agreed selected-image configuration"),
    }
    check_no_fatal(&mut hw)?;
    ensure!(
        hw.mcu_exit_status().is_none(),
        "MCU exited during {scenario}"
    );
    Ok(())
}

fn run_case(scenario: &str) -> Result<()> {
    let artifacts = PathBuf::from(
        std::env::var_os("MCU_COMPAT_ARTIFACT_DIR")
            .context("MCU_COMPAT_ARTIFACT_DIR is required")?,
    );
    fs::create_dir_all(artifacts.join("results"))?;
    let artifacts = artifacts.canonicalize()?;
    let rom = std::env::var("MCU_COMPAT_ROM")?;
    let runtime = std::env::var("MCU_COMPAT_RUNTIME")?;
    rom_release(&rom)?;
    runtime_source(&runtime, &std::env::var("MCU_COMPAT_CURRENT_RUNTIME_SHA")?)?;
    let results = artifacts.join("results").join(rom).join(runtime);
    fs::create_dir_all(&results)?;
    let result_path = results.join(format!("{scenario}.json"));
    if std::env::var("MCU_COMPAT_ISOLATED").as_deref() != Ok(scenario) {
        let work = tempfile::tempdir()?;
        let test_name = format!("test_rom_runtime_compatibility::test_{scenario}");
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", &test_name, "--ignored", "--nocapture"])
            .env("MCU_COMPAT_ISOLATED", scenario)
            .env("MCU_COMPAT_ARTIFACT_DIR", &artifacts)
            .current_dir(work.path());
        if SUITES.contains(&scenario) {
            let evidence = results.join(format!("{scenario}-artifacts"));
            fs::create_dir_all(&evidence)?;
            command.env("MCU_COMPAT_EVIDENCE_DIR", evidence);
        }
        if let Some(config) = std::env::var_os("MCU_COMPAT_CONFIG") {
            command.env("MCU_COMPAT_CONFIG", std::env::current_dir()?.join(config));
        }
        fs::write(
            results.join(format!("{scenario}.command.txt")),
            format!("{command:?}\n"),
        )?;
        let log = fs::File::create(results.join(format!("{scenario}.log")))?;
        if result_path.exists() {
            fs::remove_file(&result_path)?;
        }
        let status = command.stdout(log.try_clone()?).stderr(log).status()?;
        let mut record: CaseResult = if result_path.exists() {
            serde_json::from_slice(&fs::read(&result_path)?)?
        } else {
            CaseResult {
                scenario: scenario.into(),
                result: "FAIL".into(),
                reason: "Child terminated or selected zero tests without recording a result".into(),
                exit_code: status.code(),
                configuration_sha256: None,
            }
        };
        record.exit_code = status.code();
        fs::write(&result_path, serde_json::to_vec_pretty(&record)?)?;
        ensure!(
            status.success()
                && record.scenario == scenario
                && matches!(record.result.as_str(), "PASS" | "NOT APPLICABLE"),
            "{}: {scenario}: {}; see {}",
            record.result,
            record.reason,
            results.join(format!("{scenario}.log")).display()
        );
        return Ok(());
    }
    let mut configuration_sha256 = None;
    let result = (|| -> Result<Option<String>> {
        let pair = SelectedPair::load(&artifacts)?;
        configuration_sha256 = Some(pair.configuration_sha256.clone());
        if SUITES.contains(&scenario) {
            if scenario.starts_with("suite_spdm_") {
                let output = PathBuf::from(
                    std::env::var_os("MCU_COMPAT_EVIDENCE_DIR")
                        .context("Missing suite evidence directory")?,
                );
                fs::write(
                    output.join("spdm-source-requirements.json"),
                    serde_json::to_vec_pretty(&spdm::compatibility_spdm_source_checks())?,
                )?;
            }
            if scenario.starts_with("suite_attestation_") {
                let output = PathBuf::from(
                    std::env::var_os("MCU_COMPAT_EVIDENCE_DIR")
                        .context("Missing suite evidence directory")?,
                );
                attestation::write_compatibility_attestation_support(&output)?;
            }
            if let Some(reason) = suite_disposition(&pair, scenario)? {
                return Ok(Some(reason.into()));
            }
            require_suite_prerequisites(&pair, &artifacts)?;
            exercise_suite(&pair, scenario)?;
            return Ok(None);
        }
        let decision = pair
            .config
            .scenarios
            .get(scenario)
            .context("Missing scenario disposition")?;
        if let Some(reason) = decision.disposition()? {
            return Ok(Some(reason.into()));
        }
        exercise(&pair, scenario)?;
        Ok(None)
    })();
    let (outcome, reason) = match &result {
        Ok(None) => ("PASS", String::new()),
        Ok(Some(reason)) => ("NOT APPLICABLE", reason.clone()),
        Err(error) => {
            let reason = format!("{error:#}");
            (
                if reason.contains("BLOCKED:") {
                    "BLOCKED"
                } else {
                    "FAIL"
                },
                reason,
            )
        }
    };
    let record = CaseResult {
        scenario: scenario.into(),
        result: outcome.into(),
        reason,
        exit_code: Some(if result.is_ok() { 0 } else { 1 }),
        configuration_sha256,
    };
    println!("{}: {scenario}: {}", record.result, record.reason);
    fs::write(result_path, serde_json::to_vec_pretty(&record)?)?;
    result.map(|_| ())
}

macro_rules! compatibility_test {
    ($name:ident, $scenario:literal) => {
        #[test]
        #[ignore = "requires agreed pinned release artifacts; unresolved inputs fail as BLOCKED"]
        fn $name() -> Result<()> {
            run_case($scenario)
        }
    };
}

compatibility_test!(test_recovery_cold_boot, "recovery_cold_boot");
compatibility_test!(test_flash_cold_boot, "flash_cold_boot");
compatibility_test!(test_streaming_boot, "streaming_boot");
compatibility_test!(test_handoff, "handoff");
compatibility_test!(test_runtime_commands, "runtime_commands");
compatibility_test!(test_discovery, "discovery");
compatibility_test!(test_cold_reboot, "cold_reboot");
compatibility_test!(test_corrupted_runtime, "corrupted_runtime");
compatibility_test!(test_corrupted_manifest, "corrupted_manifest");
compatibility_test!(test_svn_rollback, "svn_rollback");
compatibility_test!(test_svn_boundary, "svn_boundary");
compatibility_test!(test_warm_reset, "warm_reset");
compatibility_test!(
    test_suite_attestation_ocp_eat_non_tcb,
    "suite_attestation_ocp_eat_non_tcb"
);
compatibility_test!(
    test_suite_attestation_ocp_eat_tcb,
    "suite_attestation_ocp_eat_tcb"
);
compatibility_test!(
    test_suite_attestation_ocp_eat_mixed,
    "suite_attestation_ocp_eat_mixed"
);
compatibility_test!(
    test_suite_attestation_pcr_quote,
    "suite_attestation_pcr_quote"
);
compatibility_test!(test_suite_spdm_mctp, "suite_spdm_mctp");
compatibility_test!(test_suite_spdm_doe, "suite_spdm_doe");
compatibility_test!(test_suite_spdm_rs, "suite_spdm_rs");
compatibility_test!(test_suite_mailbox, "suite_mailbox");
compatibility_test!(test_suite_provisioning, "suite_provisioning");
compatibility_test!(test_suite_ownership_dot, "suite_ownership_dot");
compatibility_test!(test_suite_owner_stable_key, "suite_owner_stable_key");
compatibility_test!(test_suite_ownership_handoff, "suite_ownership_handoff");
compatibility_test!(test_suite_network_boot, "suite_network_boot");
compatibility_test!(test_suite_usb_recovery, "suite_usb_recovery");

#[test]
#[ignore = "requires generated step-2 artifacts; validates inputs without booting firmware"]
fn test_artifact_integrity() -> Result<()> {
    use caliptra_auth_man_types::AuthorizationManifest;
    use sha2::Sha384;

    let artifacts = PathBuf::from(
        std::env::var_os("MCU_COMPAT_ARTIFACT_DIR")
            .context("MCU_COMPAT_ARTIFACT_DIR is required")?,
    );
    let pair = SelectedPair::load(&artifacts)?;
    let core = pair.config.caliptra_firmware.read(&pair.root)?;
    pair.config.caliptra_rom.read(&pair.root)?;
    let manifest = pair.config.soc_manifest.read(&pair.root)?;
    let parsed = AuthorizationManifest::ref_from_bytes(&manifest)
        .map_err(|error| anyhow::anyhow!("Invalid authorization manifest: {error}"))?;
    let entries = parsed
        .image_metadata_col
        .image_metadata_list
        .get(..usize::try_from(parsed.image_metadata_col.entry_count)?)
        .context("Manifest entry count exceeds capacity")?;
    let mcu_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry.fw_id == MCU_RT_IDENTIFIER)
        .collect();
    ensure!(
        mcu_entries.len() == 1,
        "Expected exactly one selected MCU entry"
    );
    ensure!(
        mcu_entries[0].digest[..] == Sha384::digest(&pair.runtime)[..],
        "Manifest digest does not bind selected runtime"
    );
    let flash = pair
        .config
        .primary_flash
        .as_ref()
        .context("Missing flash package")?
        .read(&pair.root)?;
    verify_flash_selection(
        &flash,
        rom_release(&pair.config.rom)?.flash_version,
        [&core, &manifest, &pair.runtime],
    )?;
    let otp = pair.config.otp.read(&pair.root)?;
    ensure!(otp.len() == 0xe88, "Wrong baseline OTP size");
    ensure!(parsed.preamble.svn == 0, "Wrong baseline manifest SVN");
    ensure!(
        hex::decode(
            pair.config
                .expected_capabilities
                .as_ref()
                .context("Missing capabilities")?
        )?
        .len()
            == if pair.config.runtime == "rt-sdk-2.1.0" {
                36
            } else {
                64
            },
        "Wrong capability size"
    );
    for image in &pair.config.soc_images {
        image.image.read(&pair.root)?;
    }
    if pair.streaming() {
        streaming_package(&pair)?;
    } else {
        pair.runtime_flash(
            pair.config
                .runtime_flash
                .as_ref()
                .context("Missing recovery runtime flash")?,
            &manifest,
        )?;
    }
    let boundary = pair
        .config
        .negative_cases
        .get("svn_boundary")
        .context("Missing boundary fixture")?;
    let boundary_bytes = boundary
        .soc_manifest
        .as_ref()
        .context("Missing boundary manifest")?
        .read(&pair.root)?;
    let svn_otp = boundary
        .otp
        .as_ref()
        .context("Missing SVN OTP")?
        .read(&pair.root)?;
    let floor = verify_svn_boundary(&boundary_bytes, &svn_otp, &pair.runtime)?;
    if !pair.streaming() {
        pair.runtime_flash(
            boundary
                .runtime_flash
                .as_ref()
                .context("Missing boundary runtime flash")?,
            &boundary_bytes,
        )?;
    }
    for scenario in ["corrupted_runtime", "corrupted_manifest", "svn_rollback"] {
        let case = pair
            .config
            .negative_cases
            .get(scenario)
            .context("Missing negative fixture")?;
        ensure!(
            case.expected_mcu_error != 0 && case.expected_core_error != 0,
            "Missing exact rejection errors"
        );
        if scenario == "svn_rollback" {
            ensure!(
                case.otp
                    .as_ref()
                    .context("Missing rollback OTP")?
                    .read(&pair.root)?
                    == svn_otp
                    && parsed.preamble.svn < floor,
                "Not an actual rollback"
            );
        } else {
            let source = if scenario == "corrupted_runtime" {
                &pair.runtime
            } else {
                &manifest
            };
            let mut corrupted = source.clone();
            *corrupted
                .get_mut(case.corrupt_offset.context("Missing corruption offset")?)
                .context("Invalid corruption offset")? ^= 1;
            let index: serde_json::Value =
                serde_json::from_slice(&fs::read(pair.root.join("expectation-sources.json"))?)?;
            let stored: Artifact = serde_json::from_value(index[scenario].clone())?;
            ensure!(
                stored.read(&pair.root)? == corrupted,
                "Corruption fixture differs from actual consumer mutation"
            );
        }
    }
    Ok(())
}

#[test]
fn preserves_supported_spdm_contract_and_rejects_unknown_fields() -> Result<()> {
    for decision in [
        serde_json::json!({"status": "SUPPORTED"}),
        serde_json::json!({
            "status": "SUPPORTED",
            "contract": {
                "versions": ["V13", "V12"],
                "algorithms": {"base_hash_sel": "HashAlgos::SHA_384"}
            }
        }),
    ] {
        let applicability: Applicability = serde_json::from_value(decision.clone())?;
        assert!(applicability.disposition()?.is_none());
        assert_eq!(serde_json::to_value(applicability)?, decision);
    }
    for decision in [
        serde_json::json!({"status": "SUPPORTED", "unexpected": true}),
        serde_json::json!({
            "status": "SUPPORTED",
            "contract": {"versions": [], "algorithms": {}, "unexpected": true}
        }),
        serde_json::json!({
            "status": "SUPPORTED",
            "contract": {"versions": "V13", "algorithms": {}}
        }),
    ] {
        assert!(serde_json::from_value::<Applicability>(decision).is_err());
    }
    Ok(())
}

#[test]
fn reads_memory_through_aligned_mcu_apertures() -> Result<()> {
    use caliptra_emu_bus::{testing::FakeBus, BusMmio};

    let mut bus = FakeBus::new();
    bus.read_result = Ok(0x4433_2211);
    let log = bus.log.clone();
    let mmio = BusMmio::new(bus);
    let mailbox1_base = <&mut DefaultHwModel as McuManager>::MBOX_1_ADDR;
    let map = &caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;
    for (address, mapped_address) in [
        (map.sram_offset, map.sram_offset),
        (map.dccm_offset, map.dccm_offset),
        (0xa880_0000, mailbox1_base),
        (0xa884_0000, mailbox1_base + 0x40000),
    ] {
        for offset in 0..4usize {
            for length in 1..10usize {
                assert_eq!(
                    read_memory_mmio(&mmio, mailbox1_base, address + offset as u32, length)?,
                    (offset..offset + length)
                        .map(|index| [0x11, 0x22, 0x33, 0x44][index % 4])
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    log.take(),
                    (0..(offset + length).div_ceil(4))
                        .map(|index| format!(
                            "read(RvSize::Word, {:#x})\n",
                            mapped_address + index as u32 * 4
                        ))
                        .collect::<String>()
                );
            }
        }
    }
    let mailbox_end = 0xa880_0000 + caliptra_mcu_emulator_consts::MCU_MAILBOX1_SRAM_SIZE;
    assert_eq!(
        read_memory_mmio(&mmio, mailbox1_base, mailbox_end - 3, 3)?,
        [0x22, 0x33, 0x44]
    );
    assert_eq!(
        log.take(),
        format!(
            "read(RvSize::Word, {:#x})\n",
            mailbox1_base + caliptra_mcu_emulator_consts::MCU_MAILBOX1_SRAM_SIZE - 4
        )
    );
    for (address, length) in [
        (0xa880_0000, 0),
        (0xa87f_ffff, 1),
        (mailbox_end, 1),
        (mailbox_end - 1, 2),
        (map.sram_offset + map.sram_size - 1, 2),
        (map.dccm_offset + map.dccm_size - 1, 2),
        (u32::MAX, usize::MAX),
    ] {
        assert!(read_memory_mmio(&mmio, mailbox1_base, address, length).is_err());
        assert!(log.take().is_empty());
    }
    Ok(())
}

#[test]
fn waits_for_complete_rejection_and_rejects_wrong_errors() -> Result<()> {
    let mut expected = NegativeCase {
        expected_mcu_error: 0x1234,
        expected_core_error: 0x5678,
        soc_manifest: None,
        otp: None,
        corrupt_offset: None,
        runtime_flash: None,
    };
    for errors in [(0, 0), (0, 0x5678), (0x1234, 0)] {
        assert!(!rejection_complete(errors.0, errors.1, &expected)?);
    }
    assert!(rejection_complete(0x1234, 0x5678, &expected)?);
    for errors in [(0x9999, 0), (0, 0x9999), (0x9999, 0x5678), (0x1234, 0x9999)] {
        assert!(rejection_complete(errors.0, errors.1, &expected).is_err());
    }
    expected.expected_mcu_error = 0;
    assert!(!rejection_complete(0, 0, &expected)?);
    assert!(rejection_complete(0, 0x5678, &expected)?);
    assert!(rejection_complete(0x1234, 0x5678, &expected).is_err());
    expected.expected_mcu_error = 0x1234;
    expected.expected_core_error = 0;
    assert!(!rejection_complete(0, 0, &expected)?);
    assert!(rejection_complete(0x1234, 0, &expected)?);
    assert!(rejection_complete(0x1234, 0x5678, &expected).is_err());
    expected.expected_mcu_error = 0;
    assert!(rejection_complete(0, 0, &expected).is_err());
    Ok(())
}

#[test]
fn blocks_unimplemented_scenarios_before_boot() -> Result<()> {
    for scenario in SCENARIOS {
        let result = require_implemented_scenario(scenario);
        if scenario == "warm_reset" {
            assert!(result.unwrap_err().to_string().starts_with("BLOCKED:"));
        } else {
            result?;
        }
    }
    Ok(())
}

#[test]
fn rejects_unknown_rom() {
    assert!(rom_release("main-2.1").is_err());
}

#[test]
fn validates_mctp_discovery_responses() -> Result<()> {
    check_mctp_response(2, 0x82, &[0, 2, 2, 0, 0, 0, 0])?;
    let mut uuid = vec![0, 3, 3, 0];
    uuid.extend(1..=16);
    check_mctp_response(3, 0x83, &uuid)?;
    let valid = [0, 5, 5, 0, 4, 0, 1, 5, 0x7f];
    check_mctp_response(5, 0x85, &valid)?;
    for (offset, value) in [(0, 1), (1, 0x85), (2, 2), (3, 1), (4, 3), (8, 0x7e)] {
        let mut invalid = valid;
        invalid[offset] = value;
        assert!(check_mctp_response(5, 0x85, &invalid).is_err());
    }
    for length in 0..valid.len() {
        assert!(check_mctp_response(5, 0x85, &valid[..length]).is_err());
    }
    Ok(())
}

#[test]
fn checks_svn_equality_and_selected_runtime_digest() -> Result<()> {
    use caliptra_auth_man_types::AuthorizationManifest;
    use sha2::Sha384;
    use zerocopy::IntoBytes;
    let runtime = [0x55; 32];
    let mut manifest = AuthorizationManifest::default();
    manifest.preamble.svn = 1;
    manifest.image_metadata_col.entry_count = 1;
    manifest.image_metadata_col.image_metadata_list[0].fw_id = MCU_RT_IDENTIFIER;
    manifest.image_metadata_col.image_metadata_list[0]
        .digest
        .copy_from_slice(&Sha384::digest(runtime));
    let mut otp = vec![0; 0xe88];
    otp[0x3cc] = 1;
    otp[0x3dc] = 1;
    assert_eq!(verify_svn_boundary(manifest.as_bytes(), &otp, &runtime)?, 1);
    manifest.preamble.svn = 0;
    assert!(verify_svn_boundary(manifest.as_bytes(), &otp, &runtime).is_err());
    manifest.preamble.svn = 2;
    assert!(verify_svn_boundary(manifest.as_bytes(), &otp, &runtime).is_err());
    manifest.preamble.svn = 1;
    assert!(verify_svn_boundary(manifest.as_bytes(), &otp, &[0; 32]).is_err());
    otp[0x3dc] = 0;
    assert!(verify_svn_boundary(manifest.as_bytes(), &otp, &runtime).is_err());
    assert!(verify_svn_boundary(manifest.as_bytes(), &otp[..4], &runtime).is_err());
    Ok(())
}

#[test]
fn selects_all_six_pairs() -> Result<()> {
    let current_source = "cc35e8489dbd22391a15223f8834310dd6660314";
    let mut pairs = 0;
    for rom in ["rom-sdk-2.1.0", "rom-sdk-2.1.0rc1"] {
        rom_release(rom)?;
        for (runtime, expected_source) in [
            ("rt-sdk-2.1.0", RUNTIME_2_1_0_SHA),
            ("rt-sdk-2.1.1", RUNTIME_2_1_1_SHA),
            ("main-2.1", current_source),
        ] {
            assert_eq!(runtime_source(runtime, current_source)?, expected_source);
            pairs += 1;
        }
    }
    assert_eq!(pairs, 6);
    assert!(runtime_source("main", current_source).is_err());
    assert!(runtime_source("main-2.1", "").is_err());
    assert!(runtime_source("main-2.1", "main-2.1").is_err());
    assert!(runtime_source("main-2.1", &"z".repeat(40)).is_err());
    Ok(())
}

#[test]
fn validates_runtime_version_metadata() -> Result<()> {
    let directory = tempfile::tempdir()?;
    assert!(runtime_version(directory.path(), "main-2.1").is_err());
    let path = directory.path().join("version.txt");
    fs::write(&path, RELEASED_RUNTIME_VERSION)?;
    for label in ["rt-sdk-2.1.0", "rt-sdk-2.1.1", "main-2.1"] {
        assert_eq!(
            runtime_version(directory.path(), label)?,
            RELEASED_RUNTIME_VERSION
        );
    }
    fs::write(&path, "2.1.2\n")?;
    assert_eq!(runtime_version(directory.path(), "main-2.1")?, "2.1.2");
    assert!(runtime_version(directory.path(), "rt-sdk-2.1.0").is_err());
    assert!(runtime_version(directory.path(), "rt-sdk-2.1.1").is_err());
    for invalid in ["", "2.1", "2.1.0.0", "2.1.x", "256.1.0", "2.1.65536"] {
        fs::write(&path, invalid)?;
        assert!(runtime_version(directory.path(), "main-2.1").is_err());
    }
    Ok(())
}

#[test]
fn validates_selected_flash_packages() -> Result<()> {
    let images = [vec![1], vec![2], vec![3]];
    // Historical CLI and in-memory producers use four- and 256-byte padding respectively.
    for (version, alignment, headers) in [
        (
            1,
            4,
            concat!(
                "464c53480100030010000000bffeffff",
                "000000004c00000004000000ffffffffb4fbffff",
                "010000005000000004000000feffffffb0fbffff",
                "020000005400000004000000fdffffffacfbffff",
            ),
        ),
        (
            2,
            4,
            concat!(
                "020003000c000000efffffff",
                "000000004800000004000000ffffffffb8fbffff",
                "010000004c00000004000000feffffffb4fbffff",
                "020000005000000004000000fdffffffb0fbffff",
            ),
        ),
        (
            1,
            256,
            concat!(
                "464c53480100030010000000bffeffff",
                "000000004c00000000010000ffffffffb7fbffff",
                "010000004c01000000010000feffffffb6fbffff",
                "020000004c02000000010000fdffffffb5fbffff",
            ),
        ),
        (
            2,
            256,
            concat!(
                "020003000c000000efffffff",
                "000000004800000000010000ffffffffbbfbffff",
                "010000004801000000010000feffffffbafbffff",
                "020000004802000000010000fdffffffb9fbffff",
            ),
        ),
    ] {
        let mut flash = hex::decode(headers)?;
        for bytes in &images {
            flash.extend_from_slice(bytes);
            flash.resize(flash.len() + alignment - 1, 0);
        }
        let selected = images.each_ref().map(Vec::as_slice);
        verify_flash_selection(&flash, version, selected)?;
        let other_runtime = vec![4];
        assert!(
            verify_flash_selection(&flash, version, [&images[0], &images[1], &other_runtime])
                .is_err()
        );
        for length in [0, 4, 12, 16, 30, flash.len() - 1] {
            assert!(verify_flash_selection(&flash[..length], version, selected).is_err());
        }
        let mut corrupted = flash;
        *corrupted.last_mut().context("Empty flash")? ^= 1;
        assert!(verify_flash_selection(&corrupted, version, selected).is_err());
    }
    Ok(())
}

#[test]
fn requires_explicit_scenario_dispositions() -> Result<()> {
    assert!(Applicability::Blocked {
        reason: "Owner input unresolved".into()
    }
    .disposition()
    .is_err());
    assert!(Applicability::NotApplicable {
        reason: String::new()
    }
    .disposition()
    .is_err());
    assert_eq!(
        Applicability::NotApplicable {
            reason: "Release does not support this transport".into()
        }
        .disposition()?,
        Some("Release does not support this transport")
    );
    assert!(Applicability::Supported { contract: None }
        .disposition()?
        .is_none());
    assert!(serde_json::from_str::<Applicability>(r#"{"status":"PASS"}"#).is_err());
    assert!(serde_json::from_str::<Applicability>(r#"{"status":"NOT_APPLICABLE"}"#).is_err());
    assert!(
        serde_json::from_str::<Applicability>(r#"{"status":"SUPPORTED","skip":true}"#).is_err()
    );
    Ok(())
}

#[test]
fn suite_prerequisites_reject_failed_stale_or_unproven_boots() -> Result<()> {
    let mut record = CaseResult {
        scenario: "recovery_cold_boot".into(),
        result: "PASS".into(),
        reason: String::new(),
        exit_code: Some(0),
        configuration_sha256: Some("selected".into()),
    };
    validate_suite_prerequisite(&record, "recovery_cold_boot", "selected")?;
    assert!(validate_suite_prerequisite(&record, "runtime_commands", "selected").is_err());
    assert!(validate_suite_prerequisite(&record, "recovery_cold_boot", "other").is_err());
    record.configuration_sha256 = None;
    assert!(validate_suite_prerequisite(&record, "recovery_cold_boot", "selected").is_err());
    record.configuration_sha256 = Some("selected".into());
    record.exit_code = Some(1);
    assert!(validate_suite_prerequisite(&record, "recovery_cold_boot", "selected").is_err());
    record.exit_code = Some(0);
    for result in ["FAIL", "BLOCKED", "NOT APPLICABLE"] {
        record.result = result.into();
        assert!(validate_suite_prerequisite(&record, "recovery_cold_boot", "selected").is_err());
    }
    Ok(())
}

#[test]
fn validates_fixture_hashes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("fixture.bin");
    let fixture = Artifact {
        path: PathBuf::from("fixture.bin"),
        sha256: hex::encode(Sha256::digest(b"selected")),
    };
    assert!(fixture.read(root.path()).is_err());
    fs::write(&path, b"selected")?;
    assert_eq!(fixture.read(root.path())?, b"selected");
    fs::write(&path, b"other")?;
    assert!(fixture.read(root.path()).is_err());
    fs::write(&path, b"")?;
    assert!(fixture.read(root.path()).is_err());
    Ok(())
}

#[test]
fn requires_agreed_2_1_pair_configuration() -> Result<()> {
    let image = serde_json::json!({"path": "fixture.bin", "sha256": "0".repeat(64)});
    let scenarios: BTreeMap<_, _> = SCENARIOS
        .iter()
        .map(|name| {
            (
                name.to_string(),
                serde_json::json!({"status": "BLOCKED", "reason": "Owner decision unresolved"}),
            )
        })
        .collect();
    let mut value = serde_json::json!({
        "agreed": true, "agreement": "Owner-approved test configuration",
        "rom": "rom-sdk-2.1.0", "runtime": "rt-sdk-2.1.0", "hardware": "2.1.0",
        "core_rom_source": "a".repeat(40), "core_firmware_source": "b".repeat(40),
        "signing": "repository-test-keys-lms-default-fuses", "build_configuration": "runtime-build",
        "caliptra_rom": image, "caliptra_firmware": image, "soc_manifest": image,
        "otp": image, "vendor_pk_hash": "0".repeat(96), "soc_images": [],
        "scenarios": scenarios, "negative_cases": {}
    });
    let validate = |value: &serde_json::Value| -> Result<()> {
        serde_json::from_value::<PairConfig>(value.clone())?
            .validate("rom-sdk-2.1.0", "rt-sdk-2.1.0")
    };
    validate(&value)?;
    value["suites"] = serde_json::json!({"suite_mailbox": {"status": "SUPPORTED"}});
    assert!(validate(&value).is_err());
    value["suites"] = serde_json::to_value(
        SUITES
            .iter()
            .map(|name| {
                (
                    *name,
                    serde_json::json!({"status": "NOT_APPLICABLE", "reason": "Not selected"}),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )?;
    validate(&value)?;
    value["suites"]["suite_mailbox"]["reason"] = serde_json::json!("");
    assert!(validate(&value).is_err());
    value.as_object_mut().unwrap().remove("suites");
    value["negative_cases"] = serde_json::json!({
        "handoff": {"expected_mcu_error": 1, "expected_core_error": 0}
    });
    assert!(validate(&value).is_err());
    value["negative_cases"] = serde_json::json!({});
    value["agreed"] = serde_json::json!(false);
    assert!(validate(&value).is_err());
    value["agreed"] = serde_json::json!(true);
    value["hardware"] = serde_json::json!("2.0.0");
    assert!(validate(&value).is_err());
    value["hardware"] = serde_json::json!("2.1.0");
    value["runtime"] = serde_json::json!("rt-sdk-2.1.1");
    assert!(validate(&value).is_err());
    value["runtime"] = serde_json::json!("rt-sdk-2.1.0");
    value["scenarios"]
        .as_object_mut()
        .context("Missing scenarios")?
        .remove("warm_reset");
    assert!(validate(&value).is_err());
    Ok(())
}

#[test]
fn validates_pinned_build_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("Cargo.lock"), b"original lockfile")?;
    fs::write(
        directory.path().join("rust-toolchain.toml"),
        b"original toolchain",
    )?;
    fs::write(directory.path().join("exit-code.txt"), "0\n")?;
    let metadata = serde_json::json!({
        "label": "rt-sdk-2.1.0", "source": RUNTIME_2_1_0_SHA, "toolchain": "1.85",
        "hardware": "2.1.0", "platform": "emulator", "configuration": "runtime-build",
        "lockfile_sha256": hex::encode(Sha256::digest(b"original lockfile")),
        "toolchain_file_sha256": hex::encode(Sha256::digest(b"original toolchain")),
    });
    fs::write(
        directory.path().join("build-metadata.json"),
        serde_json::to_vec(&metadata)?,
    )?;
    verify_build_evidence(
        directory.path(),
        "rt-sdk-2.1.0",
        RUNTIME_2_1_0_SHA,
        Some("runtime-build"),
    )?;
    assert!(verify_build_evidence(
        directory.path(),
        "rt-sdk-2.1.0",
        RUNTIME_2_1_0_SHA,
        Some("other")
    )
    .is_err());
    assert!(
        verify_build_evidence(directory.path(), "rt-sdk-2.1.0", RUNTIME_2_1_1_SHA, None).is_err()
    );
    fs::write(directory.path().join("exit-code.txt"), "1\n")?;
    assert!(
        verify_build_evidence(directory.path(), "rt-sdk-2.1.0", RUNTIME_2_1_0_SHA, None).is_err()
    );
    fs::write(directory.path().join("exit-code.txt"), "0\n")?;
    fs::write(directory.path().join("Cargo.lock"), b"modified lockfile")?;
    assert!(
        verify_build_evidence(directory.path(), "rt-sdk-2.1.0", RUNTIME_2_1_0_SHA, None).is_err()
    );
    Ok(())
}

#[test]
fn validates_capability_response() -> Result<()> {
    for size in [36, 64] {
        let expected = vec![0x12; size];
        let mut response = vec![0; size_of::<MailboxRespHeader>()];
        response.extend_from_slice(&expected);
        let checksum = calc_checksum(0, &response[4..]);
        response[..4].copy_from_slice(&checksum.to_le_bytes());
        check_capabilities(&response, &expected)?;
        assert!(check_capabilities(&response, &vec![0; size]).is_err());
        assert!(check_capabilities(&response, &expected[..size - 1]).is_err());
        response[4] ^= 1;
        assert!(check_capabilities(&response, &expected).is_err());
        response.pop();
        assert!(check_capabilities(&response, &expected).is_err());
    }
    Ok(())
}

#[test]
fn validates_selected_image() -> Result<()> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("source.sha"), RUNTIME_2_1_1_SHA)?;
    fs::write(directory.path().join("image.bin"), b"selected release")?;
    fs::write(
        directory.path().join("image.sha256"),
        format!(
            "{}  image.bin\n",
            hex::encode(Sha256::digest(b"selected release"))
        ),
    )?;
    assert_eq!(
        verified_image(directory.path(), RUNTIME_2_1_1_SHA)?,
        b"selected release"
    );
    assert!(verified_image(directory.path(), "wrong source").is_err());
    fs::write(directory.path().join("image.bin"), b"corrupted")?;
    assert!(verified_image(directory.path(), RUNTIME_2_1_1_SHA).is_err());
    fs::remove_file(directory.path().join("image.bin"))?;
    assert!(verified_image(directory.path(), RUNTIME_2_1_1_SHA).is_err());
    Ok(())
}

#[test]
fn rejects_missing_image_metadata() -> Result<()> {
    let directory = tempfile::tempdir()?;
    assert!(verified_image(directory.path(), RUNTIME_2_1_1_SHA).is_err());
    fs::write(directory.path().join("source.sha"), RUNTIME_2_1_1_SHA)?;
    assert!(verified_image(directory.path(), RUNTIME_2_1_1_SHA).is_err());
    fs::write(directory.path().join("image.sha256"), "not a checksum")?;
    assert!(verified_image(directory.path(), RUNTIME_2_1_1_SHA).is_err());
    Ok(())
}

#[test]
fn validates_version_response() -> Result<()> {
    let mut response = vec![0; size_of::<MailboxRespHeaderVarSize>()];
    let header = MailboxRespHeaderVarSize::mut_from_bytes(&mut response)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    header.data_len = RELEASED_RUNTIME_VERSION.len() as u32;
    header.hdr.fips_status = MailboxRespHeader::FIPS_STATUS_APPROVED;
    response.extend_from_slice(RELEASED_RUNTIME_VERSION.as_bytes());
    let checksum = calc_checksum(0, &response[4..]);
    response[..4].copy_from_slice(&checksum.to_le_bytes());
    check_version_response(&response, RELEASED_RUNTIME_VERSION)?;
    assert!(check_version_response(&response, "2.1.2").is_err());
    response.push(0);
    assert!(check_version_response(&response, RELEASED_RUNTIME_VERSION).is_err());
    response.pop();
    response[4] ^= 1;
    assert!(check_version_response(&response, RELEASED_RUNTIME_VERSION).is_err());
    let checksum = calc_checksum(0, &response[4..]);
    response[..4].copy_from_slice(&checksum.to_le_bytes());
    assert!(check_version_response(&response, RELEASED_RUNTIME_VERSION).is_err());
    response[4] ^= 1;
    *response.last_mut().unwrap() = b'1';
    let checksum = calc_checksum(0, &response[4..]);
    response[..4].copy_from_slice(&checksum.to_le_bytes());
    assert!(check_version_response(&response, RELEASED_RUNTIME_VERSION).is_err());
    assert!(check_version_response(&[], RELEASED_RUNTIME_VERSION).is_err());
    Ok(())
}
