/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

use caliptra_ocp_eat::{
    CborEncoder, ClassIdTypeChoice, ClassMap, ConciseEvidence, ConciseEvidenceMap, DebugStatus,
    DigestEntry, EnvironmentMap, EvTriplesMap, EvidenceTripleRecord, MeasurementFormat,
    MeasurementMap, MeasurementValue, OcpEatClaims, TaggedBytes,
};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../app_layout.ld");
    println!("cargo:rerun-if-changed=../user-app-layout.ld");

    // With userspace logging the app links the userlog `#[global_logger]`, so the
    // device link needs defmt's linker script and `DEFMT_LOG` set to compile in
    // the call sites. Scoped to the riscv32 device link only. Production logging
    // floors at `info`; the round-trip test needs every level, so it uses `trace`.
    if env::var_os("CARGO_FEATURE_USERSPACE_LOG").is_some()
        && env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv32")
    {
        println!("cargo:rustc-link-arg=-Tdefmt.x");
        let level = if env::var_os("CARGO_FEATURE_TEST_DEFMT_LOGGING").is_some() {
            "trace"
        } else {
            "info"
        };
        println!("cargo:rustc-env=DEFMT_LOG={level}");
    }

    write_fw_components_config();
}

/// Copy the generated `soc_env_config.rs` into `OUT_DIR` or emit a stub if it is missing.
/// In strict mode (`FW_COMPONENTS_STRICT` set) absence of the source file causes a panic.
fn write_fw_components_config() {
    // Locate workspace root by walking up the directory tree.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Ancestors: user -> apps -> userspace -> runtime -> emulator -> platforms -> <root>
    let workspace_root = manifest_dir
        .ancestors()
        .nth(6)
        .expect("Unable to determine workspace root from user-app path");

    let src_file = workspace_root.join("target/generated/soc_env_config.rs");
    println!("cargo:rerun-if-changed={}", src_file.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::create_dir_all(&out_dir).unwrap();
    let dest = out_dir.join("soc_env_config.rs");

    let (vendor, model) = if !src_file.exists() {
        let strict = env::var("FW_COMPONENTS_STRICT").is_ok();
        if strict {
            panic!(
                "Required generated file '{}' not found (strict mode). Run generation first or unset FW_COMPONENTS_STRICT.",
                src_file.display()
            );
        }
        let stub = r#"// Stub generated because real soc_env_config.rs not found.
pub const VENDOR: &str = "UNKNOWN";
pub const MODEL: &str = "UNKNOWN";
pub const NUM_FW_COMPONENTS: usize = 0;
pub const FW_IDS: [u32; 0] = [];
pub const FW_ID_STRS: [&str; 0] = [];
"#;
        fs::write(&dest, stub).expect("Failed to write stub soc_env_config.rs");
        println!("cargo:warning=soc_env_config.rs missing at {}; emitted stub (set FW_COMPONENTS_STRICT=1 to make this a build error)", src_file.display());
        ("UNKNOWN".to_string(), "UNKNOWN".to_string())
    } else {
        fs::copy(&src_file, &dest).expect("Failed to copy soc_env_config.rs into OUT_DIR");
        let cfg = fs::read_to_string(&src_file).expect("Failed to read soc_env_config.rs");
        (
            parse_str_const(&cfg, "VENDOR").unwrap_or_else(|| "UNKNOWN".to_string()),
            parse_str_const(&cfg, "MODEL").unwrap_or_else(|| "UNKNOWN".to_string()),
        )
    };

    write_eat_claims_template(&out_dir, &vendor, &model);
}

fn parse_str_const(src: &str, name: &str) -> Option<String> {
    let prefix = format!("pub const {}: &str = \"", name);
    let line = src.lines().find(|line| line.starts_with(&prefix))?;
    let rest = &line[prefix.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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
