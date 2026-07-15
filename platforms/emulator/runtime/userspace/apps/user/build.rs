/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

use caliptra_mcu_measurement_api::attestation_manifest::{
    ATTESTATION_FLAG_AK_TARGET, ATTESTATION_FLAG_SOC_TCB_DPE, ATTESTATION_MANIFEST_ENTRY_SIZE,
    ATTESTATION_MANIFEST_FIXED_HEADER_SIZE, ATTESTATION_MANIFEST_MARKER,
    ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN, ATTESTATION_MANIFEST_VERSION,
};
use caliptra_ocp_eat::{
    CborEncoder, ClassIdTypeChoice, ClassMap, ConciseEvidence, ConciseEvidenceMap, DebugStatus,
    DigestEntry, EnvironmentMap, EvTriplesMap, EvidenceTripleRecord, MeasurementFormat,
    MeasurementMap, MeasurementValue, OcpEatClaims, TaggedBytes,
};
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashSet},
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationManifestConfig {
    vendor: String,
    model: String,
    components: Vec<AttestationManifestComponentConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationManifestComponentConfig {
    fw_id: u32,
    is_tcb: bool,
    is_ak_target: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocImageDescriptorsConfig {
    images: Vec<SocImageDescriptorConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocImageDescriptorConfig {
    fw_id: u32,
}

fn main() {
    println!("cargo:rerun-if-changed=../app_layout.ld");
    println!("cargo:rerun-if-changed=../user-app-layout.ld");

    // With userspace logging the app links the userlog `#[global_logger]`, so the
    // device link needs defmt's linker script and `DEFMT_LOG` set to compile in
    // the call sites. Scoped to the riscv32 device link only. Production logging
    // floors at `info`; the round-trip tests need every level, so they use `trace`.
    println!("cargo:rerun-if-env-changed=DEFMT_LOG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_USERSPACE_LOG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_DEFMT_LOGGING_MAILBOX");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_DEFMT_LOGGING_VDM");
    if env::var_os("CARGO_FEATURE_USERSPACE_LOG").is_some()
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv32")
    {
        println!("cargo:rustc-link-arg=-Tdefmt.x");
        let test_defmt = env::var_os("CARGO_FEATURE_TEST_DEFMT_LOGGING_MAILBOX").is_some()
            || env::var_os("CARGO_FEATURE_TEST_DEFMT_LOGGING_VDM").is_some();
        let level = if test_defmt { "trace" } else { "info" };
        println!("cargo:rustc-env=DEFMT_LOG={level}");
    }

    let config = write_attestation_manifest();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    write_soc_image_descriptors(&out_dir, &config);
    write_eat_claims_template(&out_dir, &config.vendor, &config.model);
}

fn attestation_manifest_config_path() -> PathBuf {
    generated_config_path("attestation_manifest.toml")
}

fn soc_image_descriptors_config_path() -> PathBuf {
    generated_config_path("soc_image_descriptors.toml")
}

fn generated_config_path(file_name: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(target_dir).join("generated").join(file_name);
    }

    if let Some(target_dir) = target_dir_from_out_dir() {
        return target_dir.join("generated").join(file_name);
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = find_workspace_root(&manifest_dir)
        .expect("Unable to determine workspace root from user-app path");
    workspace_root.join("target/generated").join(file_name)
}

fn target_dir_from_out_dir() -> Option<PathBuf> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR")?);
    let build_dir = out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))?;
    let profile_dir = build_dir.parent()?;
    let parent = profile_dir.parent()?;
    let target = env::var_os("TARGET");
    if target
        .as_deref()
        .is_some_and(|target| parent.file_name().is_some_and(|name| name == target))
    {
        return parent.parent().map(Path::to_path_buf);
    }
    Some(parent.to_path_buf())
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|path| {
            fs::read_to_string(path.join("Cargo.toml"))
                .map(|contents| contents.lines().any(|line| line.trim() == "[workspace]"))
                .unwrap_or(false)
        })
        .map(Path::to_path_buf)
}

fn write_attestation_manifest() -> AttestationManifestConfig {
    let config_file = attestation_manifest_config_path();
    println!("cargo:rerun-if-changed={}", config_file.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::create_dir_all(&out_dir).unwrap();

    let config = read_attestation_manifest_config(&config_file);
    validate_attestation_manifest_config(&config);
    let bytes = serialize_attestation_manifest(&config);

    let mut out = String::new();
    out.push_str("// Licensed under the Apache-2.0 license\n");
    out.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
    out.push_str(
        "// Generated by user-app build.rs from target/generated/attestation_manifest.toml\n\n",
    );
    out.push_str("pub(crate) const ATTESTATION_MANIFEST_BYTES: &[u8] = &[\n");
    for chunk in bytes.chunks(12) {
        out.push_str("    ");
        for byte in chunk {
            out.push_str(&format!("0x{byte:02x}, "));
        }
        out.push('\n');
    }
    out.push_str("];\n");

    fs::write(out_dir.join("attestation_manifest.rs"), out)
        .expect("Failed to write generated attestation_manifest.rs");
    config
}

fn write_soc_image_descriptors(out_dir: &Path, attestation_config: &AttestationManifestConfig) {
    let config_file = soc_image_descriptors_config_path();
    println!("cargo:rerun-if-changed={}", config_file.display());

    let config = read_soc_image_descriptors_config(&config_file);
    validate_soc_image_descriptors_config(&config);
    validate_soc_image_descriptors_match_attestation_manifest(
        attestation_config,
        &config,
        attestation_manifest_config_path().exists(),
        config_file.exists(),
    );

    let mut out = String::new();
    out.push_str("// Licensed under the Apache-2.0 license\n");
    out.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
    out.push_str(
        "// Generated by user-app build.rs from target/generated/soc_image_descriptors.toml\n\n",
    );
    out.push_str("#[allow(dead_code)]\n");
    out.push_str("pub const SOC_IMAGE_LOAD_LIST: &[u32] = &[\n");
    for image in &config.images {
        out.push_str(&format!("    {},\n", image.fw_id));
    }
    out.push_str("];\n");

    fs::write(out_dir.join("soc_image_descriptors.rs"), out)
        .expect("Failed to write generated soc_image_descriptors.rs");
}

fn read_attestation_manifest_config(path: &Path) -> AttestationManifestConfig {
    let contents = fs::read_to_string(path).unwrap_or_else(|_| {
        println!(
            "cargo:warning=attestation_manifest.toml missing at {}; emitted empty Attestation Manifest",
            path.display()
        );
        default_attestation_manifest_config()
    });
    toml::from_str(&contents).expect("Failed to parse attestation_manifest.toml")
}

fn read_soc_image_descriptors_config(path: &Path) -> SocImageDescriptorsConfig {
    let contents = fs::read_to_string(path).unwrap_or_else(|_| {
        println!(
            "cargo:warning=soc_image_descriptors.toml missing at {}; emitted default SoC image descriptors",
            path.display()
        );
        default_soc_image_descriptors_config()
    });
    toml::from_str(&contents).expect("Failed to parse soc_image_descriptors.toml")
}

fn default_attestation_manifest_config() -> String {
    r#"vendor = "UNKNOWN"
model = "UNKNOWN"
components = []
"#
    .to_string()
}

fn default_soc_image_descriptors_config() -> String {
    r#"[[images]]
fw_id = 4096

[[images]]
fw_id = 4097
"#
    .to_string()
}

fn validate_attestation_manifest_config(config: &AttestationManifestConfig) {
    validate_platform_info_len("vendor", &config.vendor);
    validate_platform_info_len("model", &config.model);

    let mut seen_fw_ids = HashSet::new();
    let mut ak_target_count = 0usize;

    for component in &config.components {
        if !seen_fw_ids.insert(component.fw_id) {
            panic!(
                "attestation_manifest.toml component fw_id {} appears more than once",
                component.fw_id
            );
        }

        if component.is_ak_target {
            ak_target_count += 1;
            if !component.is_tcb {
                panic!(
                    "attestation_manifest.toml component fw_id {} is AK target but is_tcb is false",
                    component.fw_id
                );
            }
        }
    }

    if ak_target_count > 1 {
        panic!("attestation_manifest.toml must not contain more than one AK target component");
    }
}

fn validate_soc_image_descriptors_config(config: &SocImageDescriptorsConfig) {
    let mut seen_fw_ids = HashSet::new();

    for image in &config.images {
        if !seen_fw_ids.insert(image.fw_id) {
            panic!(
                "soc_image_descriptors.toml image fw_id {} appears more than once",
                image.fw_id
            );
        }
    }
}

fn validate_soc_image_descriptors_match_attestation_manifest(
    attestation_config: &AttestationManifestConfig,
    descriptor_config: &SocImageDescriptorsConfig,
    attestation_config_present: bool,
    descriptor_config_present: bool,
) {
    match (attestation_config_present, descriptor_config_present) {
        (true, true) => {}
        (false, false) => return,
        (true, false) => {
            panic!("soc_image_descriptors.toml is required when attestation_manifest.toml exists")
        }
        (false, true) => {
            panic!("attestation_manifest.toml is required when soc_image_descriptors.toml exists")
        }
    }

    let manifest_fw_ids: BTreeSet<_> = attestation_config
        .components
        .iter()
        .map(|component| component.fw_id)
        .collect();
    let descriptor_fw_ids: BTreeSet<_> = descriptor_config
        .images
        .iter()
        .map(|image| image.fw_id)
        .collect();

    if manifest_fw_ids != descriptor_fw_ids {
        panic!(
            "attestation_manifest.toml components and soc_image_descriptors.toml images must contain the same fw_id set; manifest={:?}, descriptors={:?}",
            manifest_fw_ids, descriptor_fw_ids
        );
    }
}

fn validate_platform_info_len(name: &str, value: &str) {
    if value.len() > ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN {
        panic!(
            "attestation_manifest.toml {} length {} exceeds maximum {} bytes",
            name,
            value.len(),
            ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN
        );
    }
}

fn serialize_attestation_manifest(config: &AttestationManifestConfig) -> Vec<u8> {
    let vendor = config.vendor.as_bytes();
    let model = config.model.as_bytes();
    let header_size = ATTESTATION_MANIFEST_FIXED_HEADER_SIZE;
    let entry_count = config.components.len();
    let size = header_size
        .checked_add(entry_count * ATTESTATION_MANIFEST_ENTRY_SIZE)
        .expect("attestation manifest size overflow");
    let tcb_entry_count = config
        .components
        .iter()
        .filter(|component| component.is_tcb)
        .count();

    let mut out = Vec::with_capacity(size);
    push_u32(&mut out, ATTESTATION_MANIFEST_MARKER);
    push_u32(
        &mut out,
        size.try_into()
            .expect("attestation manifest size exceeds u32::MAX"),
    );
    push_u32(&mut out, ATTESTATION_MANIFEST_VERSION);
    push_u32(
        &mut out,
        header_size
            .try_into()
            .expect("attestation manifest header size exceeds u32::MAX"),
    );
    push_u32(
        &mut out,
        entry_count
            .try_into()
            .expect("attestation manifest entry count exceeds u32::MAX"),
    );
    push_u32(
        &mut out,
        tcb_entry_count
            .try_into()
            .expect("attestation manifest TCB entry count exceeds u32::MAX"),
    );
    push_u16(
        &mut out,
        vendor
            .len()
            .try_into()
            .expect("attestation manifest vendor length exceeds u16::MAX"),
    );
    push_u16(
        &mut out,
        model
            .len()
            .try_into()
            .expect("attestation manifest model length exceeds u16::MAX"),
    );

    push_fixed_platform_info(&mut out, vendor);
    push_fixed_platform_info(&mut out, model);

    for component in &config.components {
        push_u32(&mut out, component.fw_id);
        push_u32(&mut out, attestation_flags(component));
    }

    assert_eq!(out.len(), size);
    out
}

fn attestation_flags(component: &AttestationManifestComponentConfig) -> u32 {
    let mut flags = 0;
    if component.is_tcb {
        flags |= ATTESTATION_FLAG_SOC_TCB_DPE;
    }
    if component.is_ak_target {
        flags |= ATTESTATION_FLAG_AK_TARGET;
    }
    flags
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_fixed_platform_info(out: &mut Vec<u8>, value: &[u8]) {
    debug_assert!(value.len() <= ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN);
    out.extend_from_slice(value);
    out.extend(std::iter::repeat(0).take(ATTESTATION_MANIFEST_PLATFORM_INFO_MAX_LEN - value.len()));
}

fn write_eat_claims_template(out_dir: &std::path::Path, vendor: &str, model: &str) {
    let nonce_marker = marker::<32>(0xa0);
    let digest_marker = marker::<48>(0xd0);

    let digest = [DigestEntry {
        alg_id: 7, // SHA-384
        value: &digest_marker,
    }];
    let measurement = [MeasurementMap {
        key: 0,
        mval: MeasurementValue {
            version: None,
            svn: None,
            digests: Some(&digest),
            integrity_registers: None,
            raw_value: None,
            raw_value_mask: None,
        },
    }];
    let triple = [EvidenceTripleRecord {
        environment: EnvironmentMap {
            class: ClassMap {
                class_id: ClassIdTypeChoice::TaggedBytes(TaggedBytes::new(b"platform-state")),
                vendor: Some(vendor),
                model: Some(model),
            },
        },
        measurements: &measurement,
    }];
    let ev_triples = EvTriplesMap {
        evidence_triples: Some(&triple),
        identity_triples: None,
        dependency_triples: None,
        membership_triples: None,
        coswid_triples: None,
        attest_key_triples: None,
    };
    let evidence = ConciseEvidence::Map(ConciseEvidenceMap {
        ev_triples,
        evidence_id: None,
        profile: None,
    });
    let measurement_format = [MeasurementFormat::new(&evidence)];
    let claims = OcpEatClaims {
        nonce: &nonce_marker,
        dbgstat: DebugStatus::Disabled,
        eat_profile: OcpEatClaims::DEFAULT_PROFILE_OID,
        measurements: &measurement_format,
        issuer: Some("CN=Caliptra EAT DPE Attestation Key"),
        cti: None,
        ueid: None,
        sueid: None,
        oemid: None,
        hwmodel: None,
        uptime: None,
        bootcount: None,
        bootseed: None,
        dloas: None,
        rim_locators: None,
        private_claims: &[],
    };

    let mut template = [0u8; 1024];
    let mut evidence_scratch = [0u8; 512];
    let mut encoder = CborEncoder::new(&mut template);
    claims
        .encode(&mut encoder, &mut evidence_scratch)
        .expect("Failed to encode EAT claims template");
    let template_len = encoder.len();
    let mut template = template[..template_len].to_vec();
    let nonce_offset = find_subslice(&template, &nonce_marker).expect("nonce marker not found");
    let digest_offset = find_subslice(&template, &digest_marker).expect("digest marker not found");
    template[nonce_offset..nonce_offset + nonce_marker.len()].fill(0);
    template[digest_offset..digest_offset + digest_marker.len()].fill(0);

    let mut out = String::new();
    out.push_str("// Licensed under the Apache-2.0 license\n");
    out.push_str("// AUTO-GENERATED FILE. DO NOT EDIT.\n");
    out.push_str("// Generated by user-app build.rs\n");
    out.push_str(&format!(
        "pub const EAT_PAYLOAD_LEN: usize = {};\n",
        template.len()
    ));
    out.push_str(&format!(
        "pub const NONCE_OFFSET: usize = {};\n",
        nonce_offset
    ));
    out.push_str("pub const MEASUREMENT_DIGEST_OFFSETS: [usize; 1] = [");
    out.push_str(&digest_offset.to_string());
    out.push_str("];\n");
    out.push_str("pub const EAT_PAYLOAD_TEMPLATE: [u8; EAT_PAYLOAD_LEN] = [\n");
    for chunk in template.chunks(12) {
        out.push_str("    ");
        for byte in chunk {
            out.push_str(&format!("0x{:02x}, ", byte));
        }
        out.push('\n');
    }
    out.push_str("];\n");

    fs::write(out_dir.join("eat_claims_template.rs"), out)
        .expect("Failed to write eat_claims_template.rs");
}

fn marker<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
