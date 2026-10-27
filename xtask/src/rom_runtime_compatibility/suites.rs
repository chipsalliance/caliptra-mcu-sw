// Licensed under the Apache-2.0 license

use super::{sha256, write_json, Context, ROMS, SUITES};
use anyhow::{ensure, Context as _, Result};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

pub(super) fn prepare(
    context: &Context,
    directory: &Path,
    rom: &str,
    runtime: &str,
    streaming: bool,
    configuration: &str,
    mailbox: Value,
) -> Result<Value> {
    let source = context.sources.join(runtime);
    let mut hashes = BTreeMap::new();
    for relative in [
        "platforms/emulator/runtime/Cargo.toml",
        "platforms/emulator/runtime/userspace/apps/user/Cargo.toml",
        "platforms/emulator/runtime/userspace/apps/user/src/caliptra_cmd_handler/mod.rs",
        "common/mcu-mbox/src/messages.rs",
        "common/config/src/capabilities.rs",
        "runtime/userspace/api/spdm-lib/stack/src/version.rs",
        "runtime/userspace/api/spdm-lib/stack/src/stack.rs",
    ] {
        hashes.insert(relative, sha256(&source.join(relative))?);
    }
    let rom_manifest = context
        .sources
        .join(rom)
        .join("platforms/emulator/rom/Cargo.toml");
    let rom_features: toml::Value = toml::from_str(&fs::read_to_string(&rom_manifest)?)?;
    let runtime_manifest: toml::Value = toml::from_str(&fs::read_to_string(
        source.join("platforms/emulator/runtime/Cargo.toml"),
    )?)?;
    let mut decisions: BTreeMap<&str, Value> = SUITES
        .iter()
        .map(|&name| (name, json!({"status": "SUPPORTED"})))
        .collect();
    for suite in [
        "suite_attestation_ocp_eat_non_tcb",
        "suite_attestation_ocp_eat_tcb",
        "suite_attestation_ocp_eat_mixed",
        "suite_attestation_pcr_quote",
        "suite_spdm_mctp",
        "suite_spdm_doe",
        "suite_spdm_rs",
    ] {
        if !streaming {
            decisions.insert(
                suite,
                json!({
                    "status": "NOT_APPLICABLE",
                    "reason": "The agreed flash-boot baseline does not enable SPDM or MCTP service."
                }),
            );
        }
    }
    if streaming {
        let version_source =
            fs::read_to_string(source.join("runtime/userspace/api/spdm-lib/stack/src/version.rs"))?;
        let stack_source =
            fs::read_to_string(source.join("runtime/userspace/api/spdm-lib/stack/src/stack.rs"))?;
        decisions.insert(
            "suite_spdm_mctp",
            match spdm_contract(&version_source, &stack_source) {
                Ok(contract) => json!({"status": "SUPPORTED", "contract": contract}),
                Err(error) => json!({
                    "status": "BLOCKED",
                    "reason": format!("Selected SPDM version/algorithm contract is unresolved: {error:#}"),
                }),
            },
        );
        for suite in [
            "suite_attestation_ocp_eat_non_tcb",
            "suite_attestation_ocp_eat_tcb",
            "suite_attestation_ocp_eat_mixed",
        ] {
            decisions.insert(suite, json!({
                "status": "BLOCKED",
                "reason": "EAT component classes are compiled into the selected runtime, successful production image loading exits the emulator, and owner-policy reference appraisal is incomplete. Host-only manifest changes cannot provide the requested cold-boot evidence modes; substituting feature-specific firmware is forbidden."
            }));
        }
        decisions.insert("suite_attestation_pcr_quote", json!({
            "status": "NOT_APPLICABLE",
            "reason": "The agreed production SPDM configuration uses OCP EAT measurements, not the PCR-quote test-feature configuration."
        }));
        for suite in ["suite_spdm_doe", "suite_spdm_rs"] {
            decisions.insert(suite, json!({
                "status": "NOT_APPLICABLE",
                "reason": "The agreed service configuration selects MCTP, not the DOE/TDISP/IDE feature-specific responder."
            }));
        }
    }
    for (suite, reason) in [
        ("suite_ownership_dot", "The agreed default OTP configuration does not enable DOT ownership."),
        ("suite_owner_stable_key", "The selected ROM was built with hw-2-1 only, not stable-owner-key."),
        ("suite_network_boot", "No network-ROM image or network-boot configuration is selected in this matrix."),
        ("suite_usb_recovery", "The agreed recovery configuration is I3C; no USB recovery configuration or host fixtures are selected."),
    ] {
        decisions.insert(suite, json!({"status": "NOT_APPLICABLE", "reason": reason}));
    }
    if mailbox["status"] != "SUPPORTED" {
        for suite in ["suite_mailbox", "suite_provisioning"] {
            decisions.insert(suite, json!({
                "status": "BLOCKED",
                "reason": format!("Selected mailbox/authorization contract is unresolved: {mailbox}"),
            }));
        }
    }
    let selected = context.selected_sources();
    let runtime_source = selected
        .iter()
        .find(|(label, _)| *label == runtime)
        .context("Missing selected runtime source")?
        .1;
    let rom_source = ROMS
        .iter()
        .find(|(label, _)| *label == rom)
        .context("Missing selected ROM source")?
        .1;
    let support = json!({
        "rom_source": rom_source, "runtime_source": runtime_source,
        "build_configuration": configuration,
        "decisions": decisions,
        "runtime_source_hashes": hashes,
        "rom_manifest_sha256": sha256(&rom_manifest)?,
        "rom_features": rom_features.get("features"),
        "runtime_features": runtime_manifest.get("features"),
        "mailbox": mailbox,
        "spdm_source_requirements": {
            "runtime/userspace/api/spdm-lib/stack/src/version.rs": "SUPPORTED_VERSIONS",
            "runtime/userspace/api/spdm-lib/stack/src/stack.rs": "ConnectionState::caliptra",
        },
    });
    write_json(&directory.join("suite-support.json"), &support)?;
    Ok(support)
}

fn spdm_contract(version_source: &str, stack_source: &str) -> Result<Value> {
    let version_source = super::mailbox::compact(version_source);
    let prefix = "constSUPPORTED_VERSIONS:&[SpdmVersion]=&[";
    ensure!(
        version_source.matches(prefix).count() == 1,
        "missing or ambiguous SPDM version declaration"
    );
    let versions = version_source
        .split_once(prefix)
        .and_then(|(_, value)| value.split_once("];"))
        .context("unknown SPDM version declaration")?
        .0
        .trim_end_matches(',')
        .split(',')
        .map(|version| {
            version
                .strip_prefix("SpdmVersion::")
                .context("unknown SPDM version expression")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        matches!(versions.as_slice(), ["V13", "V12"] | ["V14", "V13", "V12"]),
        "unresolved validator support for advertised SPDM versions {versions:?}"
    );
    let stack_source = super::mailbox::compact(stack_source);
    ensure!(
        stack_source.matches("pubfncaliptra()->Self{").count() == 1,
        "missing or ambiguous SPDM local-policy constructor"
    );
    let body = super::mailbox::declaration(&stack_source, "fn", "caliptra()->Self")?;
    let fields = body
        .split_once("Self{")
        .context("unknown SPDM local-policy initializer")?
        .1
        .trim_end_matches('}');
    let mut algorithms = BTreeMap::new();
    for (field, expected, optional) in [
        ("meas_hash_algo", "MeasHashAlgos::SHA_384", false),
        ("base_asym_sel", "AsymAlgos::ECDSA_ECC_NIST_P384", false),
        ("base_hash_sel", "HashAlgos::SHA_384", false),
        ("dhe", "DheAlgos::SECP_384_R1", false),
        ("aead", "AeadAlgos::AES_256_GCM", false),
        ("key_schedule", "KeyScheduleAlgos::SPDM", false),
        ("pqc_asym_sel", "PqcAsymAlgos::ML_DSA_87", true),
        ("kem", "KemAlgos::ML_KEM1024", true),
    ] {
        let prefix = format!("{field}:");
        let values = fields
            .split(',')
            .filter_map(|value| value.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        if optional && values.is_empty() {
            continue;
        }
        ensure!(
            values.as_slice() == [expected],
            "unresolved validator support for SPDM {field}: {values:?}"
        );
        algorithms.insert(field, values[0]);
    }
    Ok(json!({"versions": versions, "algorithms": algorithms}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK: &str = r#"
        pub fn caliptra() -> Self {
            Self {
                meas_hash_algo: MeasHashAlgos::SHA_384,
                base_asym_sel: AsymAlgos::ECDSA_ECC_NIST_P384,
                base_hash_sel: HashAlgos::SHA_384,
                dhe: DheAlgos::SECP_384_R1,
                aead: AeadAlgos::AES_256_GCM,
                key_schedule: KeyScheduleAlgos::SPDM,
            }
        }
    "#;

    #[test]
    fn recognizes_selected_spdm_profiles() {
        for versions in [
            "SpdmVersion::V13, SpdmVersion::V12",
            "SpdmVersion::V14, SpdmVersion::V13, SpdmVersion::V12",
        ] {
            let source =
                format!("pub(crate) const SUPPORTED_VERSIONS: &[SpdmVersion] = &[{versions}];");
            let contract = spdm_contract(&source, STACK).unwrap();
            assert_eq!(
                contract["algorithms"]["base_hash_sel"],
                "HashAlgos::SHA_384"
            );
        }
    }

    #[test]
    fn rejects_unknown_spdm_versions_and_algorithms() {
        let source =
            "const SUPPORTED_VERSIONS: &[SpdmVersion] = &[SpdmVersion::V13, SpdmVersion::V12];";
        assert!(spdm_contract(&source.replace("V13", "V15"), STACK).is_err());
        assert!(spdm_contract(source, &STACK.replace("SHA_384", "SHA_256")).is_err());
        assert!(spdm_contract(source, &STACK.replace("dhe:", "other_dhe:")).is_err());
    }
}
