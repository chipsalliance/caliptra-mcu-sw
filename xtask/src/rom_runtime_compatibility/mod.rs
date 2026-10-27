// Licensed under the Apache-2.0 license

use anyhow::{bail, ensure, Context as _, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

mod artifacts;
mod fixtures;
mod mailbox;
mod suites;

pub(super) const ROMS: [(&str, &str); 2] = [
    ("rom-sdk-2.1.0", "da451221542758758f1c4ce35efbe48da9935dd8"),
    (
        "rom-sdk-2.1.0rc1",
        "12b6dc3f760767a17e931db3b4a4aa5dca47b95f",
    ),
];
pub(super) const RUNTIMES: [&str; 3] = ["rt-sdk-2.1.0", "rt-sdk-2.1.1", "main-2.1"];
pub(super) const SCENARIOS: [&str; 12] = [
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
pub(super) const SUITES: [&str; 14] = [
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

#[derive(Clone, Copy)]
enum Phase {
    Boot,
    Suites,
}

impl Phase {
    fn scenarios(self) -> &'static [&'static str] {
        match self {
            Self::Boot => &SCENARIOS,
            Self::Suites => &SUITES,
        }
    }

    fn prefix(self, variant: &str) -> String {
        match self {
            Self::Boot => variant.to_string(),
            Self::Suites => format!("{variant}-suites"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Suites => "suites",
        }
    }

    fn filter(self) -> &'static str {
        match self {
            Self::Boot => "test(test_rom_runtime_compatibility) - test(test_suite_)",
            Self::Suites => "test(test_rom_runtime_compatibility::test_suite_)",
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum CompatibilityCommands {
    /// Build immutable released images, retaining source and build evidence.
    BuildImages {
        #[arg(long)]
        label: String,
    },
    /// Produce fixed Core, signed manifests, OTP, flash/PLDM packages and configurations.
    PrepareFixtures,
    /// Run boot checks, then supported CI suites, for both emulator configurations.
    RunPair {
        #[arg(long)]
        rom: String,
        #[arg(long)]
        runtime: String,
    },
    /// Collect all six pairs and fail if any result or execution is unsuccessful.
    Report,
}

pub(super) struct Context {
    pub(super) repo: PathBuf,
    pub(super) root: PathBuf,
    pub(super) sources: PathBuf,
    pub(super) current_runtime: String,
}

impl Context {
    fn new() -> Result<Self> {
        let repo = caliptra_mcu_builder::PROJECT_ROOT.to_path_buf();
        let current_runtime = std::env::var("MCU_COMPAT_CURRENT_RUNTIME_SHA")
            .context("MCU_COMPAT_CURRENT_RUNTIME_SHA must be resolved once before running")?;
        ensure!(
            current_runtime.len() == 40
                && current_runtime
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Current runtime must be an immutable lowercase 40-character SHA"
        );
        let resolve = |name, default| {
            let path = std::env::var_os(name).map(PathBuf::from).unwrap_or(default);
            if path.is_absolute() {
                path
            } else {
                repo.join(path)
            }
        };
        let root = resolve(
            "MCU_COMPAT_ROOT",
            repo.join("target/rom-runtime-compatibility/ci"),
        );
        let sources = resolve(
            "MCU_COMPAT_SOURCES",
            repo.parent()
                .context("Repository has no parent directory")?
                .join("caliptra-compatibility-builds"),
        );
        Ok(Self {
            repo,
            root,
            sources,
            current_runtime,
        })
    }

    pub(super) fn selected_sources(&self) -> Vec<(&'static str, &str)> {
        vec![
            ROMS[0],
            ROMS[1],
            ("rt-sdk-2.1.0", "24ea8b90bb56c0aed5512232dfbbca3dd2e39716"),
            ("rt-sdk-2.1.1", "8c9c8ff27de1babf63c0be74e973185837439040"),
            ("main-2.1", &self.current_runtime),
        ]
    }

    pub(super) fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        command.current_dir(&self.repo);
        for key in [
            "CPTRA_FIRMWARE_BUNDLE",
            "CPTRA_EMULATOR_BUNDLE",
            "CALIPTRA_ROM_REF",
            "CPTRA_CI_ROM_VERSION",
            "CPTRA_ROM_TYPE",
            "CARGO_BUILD_TARGET",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CALIPTRA_HW_REV",
        ] {
            command.env_remove(key);
        }
        command
            .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true")
            .env(
                "CARGO_BUILD_JOBS",
                std::env::var_os("CARGO_BUILD_JOBS").unwrap_or_else(|| "2".into()),
            )
            .env(
                "RAYON_NUM_THREADS",
                std::env::var_os("RAYON_NUM_THREADS").unwrap_or_else(|| "2".into()),
            );
        command
    }

    fn variants(&self) -> [(&str, PathBuf); 2] {
        [
            ("baseline", self.root.clone()),
            ("service", self.root.join("streaming-emulator")),
        ]
    }
}

pub(crate) fn run(command: &CompatibilityCommands) -> Result<()> {
    let context = Context::new()?;
    match command {
        CompatibilityCommands::BuildImages { label } => {
            ensure!(
                context
                    .selected_sources()
                    .iter()
                    .any(|(name, _)| name == label),
                "Unsupported image label {label}"
            );
            artifacts::build_images(&context, label)
        }
        CompatibilityCommands::PrepareFixtures => artifacts::prepare_fixtures(&context),
        CompatibilityCommands::RunPair { rom, runtime } => {
            ensure!(
                ROMS.iter().any(|(label, _)| label == rom) && RUNTIMES.contains(&runtime.as_str()),
                "Unsupported compatibility pair {rom}/{runtime}"
            );
            run_pair(&context, rom, runtime)
        }
        CompatibilityCommands::Report => report(&context),
    }
}

pub(super) fn sha256(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        fs::read(path).with_context(|| format!("Reading {}", path.display()))?,
    )))
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("Writing {}", path.display()))
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("Reading {}", path.display()))?)
        .with_context(|| format!("Parsing {}", path.display()))
}

fn run_pair(context: &Context, rom: &str, runtime: &str) -> Result<()> {
    let directory = context.root.join("reports").join(rom).join(runtime);
    fs::create_dir_all(&directory)?;
    let mut errors = Vec::new();
    for (variant, root) in context.variants() {
        for phase in [Phase::Boot, Phase::Suites] {
            let prefix = phase.prefix(variant);
            for suffix in ["metadata.json", "execution.json", "junit.xml"] {
                let path = directory.join(format!("{prefix}-{suffix}"));
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
            for scenario in phase.scenarios() {
                let path = root
                    .join("artifacts/results")
                    .join(rom)
                    .join(runtime)
                    .join(format!("{scenario}.json"));
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
        }
    }
    for (variant, root) in context.variants() {
        // A broken baseline must not prevent service evidence from being collected.
        for phase in [Phase::Boot, Phase::Suites] {
            if let Err(error) =
                run_variant(context, &directory, variant, &root, rom, runtime, phase)
            {
                eprintln!("{variant} {} {rom}/{runtime}: {error:#}", phase.name());
                errors.push(format!("{variant} {}: {error:#}", phase.name()));
            }
        }
    }
    ensure!(
        errors.is_empty(),
        "Compatibility pair failed:\n{}",
        errors.join("\n")
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_variant(
    context: &Context,
    directory: &Path,
    variant: &str,
    root: &Path,
    rom: &str,
    runtime: &str,
    phase: Phase,
) -> Result<()> {
    let artifacts = root.join("artifacts");
    let prefix = phase.prefix(variant);
    let config = artifacts
        .join("pairs")
        .join(rom)
        .join(runtime)
        .join("config.json");
    let metadata = json!({
        "variant": variant,
        "configuration_sha256": sha256(&config)?,
        "rom": read_json(&artifacts.join(rom).join("build-metadata.json"))?,
        "runtime": read_json(&artifacts.join(runtime).join("build-metadata.json"))?,
        "rom_image_sha256": sha256(&artifacts.join(rom).join("image.bin"))?,
        "runtime_image_sha256": sha256(&artifacts.join(runtime).join("image.bin"))?,
        "fixtures": read_json(&config)?,
    });
    write_json(
        &directory.join(format!("{prefix}-metadata.json")),
        &metadata,
    )?;
    let junit = Path::new("/tmp/junit.xml");
    if junit.exists() {
        fs::remove_file(junit)?;
    }
    let archive = std::env::var_os("MCU_COMPAT_TEST_ARCHIVE").map(PathBuf::from);
    let args = nextest_args(phase, archive.as_deref())?;
    let log_path = directory.join(format!("{prefix}-nextest.log"));
    let log = fs::File::create(&log_path)?;
    println!("Running {prefix} {rom}/{runtime}: cargo {}", args.join(" "));
    let status = context
        .command("cargo")
        .args(&args)
        .env("RUSTUP_TOOLCHAIN", "1.96.1")
        .env("CALIPTRA_HW_REV", "2.1")
        .env("MCU_COMPAT_ARTIFACT_DIR", &artifacts)
        .env("MCU_COMPAT_CONFIG", &config)
        .env("MCU_COMPAT_ROM", rom)
        .env("MCU_COMPAT_RUNTIME", runtime)
        .env("MCU_COMPAT_PHASE", phase.name())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()
        .context("Starting cargo nextest")?;
    let output = fs::read_to_string(&log_path)?;
    let mut skipped = output.contains("Skipping test");
    let cases = artifacts.join("results").join(rom).join(runtime);
    if cases.is_dir() {
        for scenario in phase.scenarios() {
            let path = cases.join(format!("{scenario}.log"));
            if path.is_file() {
                skipped |= fs::read_to_string(path)?.contains("Skipping test");
            }
        }
    }
    let has_junit = junit.is_file();
    if has_junit {
        fs::copy(junit, directory.join(format!("{prefix}-junit.xml")))?;
    }
    let command: Vec<_> = std::iter::once("cargo")
        .chain(args.iter().map(String::as_str))
        .collect();
    write_json(
        &directory.join(format!("{prefix}-execution.json")),
        &json!({
            "command": command, "exit_code": status.code(),
            "junit": has_junit, "silent_skip_detected": skipped,
        }),
    )?;
    if !status.success() {
        let lines: Vec<_> = output.lines().collect();
        eprintln!("{}", lines[lines.len().saturating_sub(40)..].join("\n"));
    }
    ensure!(
        status.success() && has_junit && !skipped,
        "Nextest exited {status}; JUnit={has_junit}, silent_skip={skipped}"
    );
    Ok(())
}

fn nextest_args(phase: Phase, archive: Option<&Path>) -> Result<Vec<String>> {
    let mut args = vec!["nextest".to_owned(), "run".to_owned()];
    if let Some(archive) = archive {
        ensure!(
            archive.is_file(),
            "Test archive is missing: {}",
            archive.display()
        );
        args.extend([
            "--archive-file".to_owned(),
            archive
                .to_str()
                .context("Test archive path must be UTF-8")?
                .to_owned(),
            "--workspace-remap".to_owned(),
            ".".to_owned(),
        ]);
    } else {
        args.extend(
            ["--locked", "-p", "caliptra-mcu-tests-integration"]
                .into_iter()
                .map(str::to_owned),
        );
    }
    args.extend(
        [
            "--profile",
            "emulator",
            "--run-ignored",
            "only",
            "--test-threads=1",
            "--no-fail-fast",
            "--no-tests",
            "fail",
            "-E",
            phase.filter(),
        ]
        .into_iter()
        .map(str::to_owned),
    );
    Ok(args)
}

fn read_evidence(path: &Path, errors: &mut Vec<String>) -> Option<Value> {
    match read_json(path).and_then(|value| {
        ensure!(
            value.is_object(),
            "{}: expected a JSON object",
            path.display()
        );
        Ok(value)
    }) {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{error:#}"));
            None
        }
    }
}

fn validate_junit(path: &Path, phase: Phase) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let document = roxmltree::Document::parse(&text)?;
    let cases: Vec<_> = document
        .descendants()
        .filter(|node| node.has_tag_name("testcase"))
        .collect();
    let names = cases
        .iter()
        .map(|node| node.attribute("name").context("JUnit testcase has no name"))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let expected = phase
        .scenarios()
        .iter()
        .map(|scenario| format!("test_rom_runtime_compatibility::test_{scenario}"))
        .chain(
            matches!(phase, Phase::Boot)
                .then(|| "test_rom_runtime_compatibility::test_artifact_integrity".to_string()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        matches!(
            document.root_element().tag_name().name(),
            "testsuite" | "testsuites"
        ) && cases.len() == expected.len()
            && names
                .iter()
                .copied()
                .eq(expected.iter().map(String::as_str)),
        "{} does not contain exactly the expected {} cases",
        path.display(),
        phase.name()
    );
    ensure!(
        !document.descendants().any(|node| {
            node.has_tag_name("failure")
                || node.has_tag_name("error")
                || node.has_tag_name("skipped")
        }),
        "{} contains unsuccessful or skipped Nextest tests",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_build_preserves_phase_filters_and_execution_guards() -> Result<()> {
        for phase in [Phase::Boot, Phase::Suites] {
            let args = nextest_args(phase, None)?;
            assert_eq!(
                &args[..5],
                [
                    "nextest",
                    "run",
                    "--locked",
                    "-p",
                    "caliptra-mcu-tests-integration"
                ]
            );
            assert_eq!(args.last().map(String::as_str), Some(phase.filter()));
            for flag in ["--test-threads=1", "--no-fail-fast"] {
                assert!(args.iter().any(|arg| arg == flag));
            }
            assert!(args.windows(2).any(|args| args == ["--no-tests", "fail"]));
        }
        Ok(())
    }

    #[test]
    fn archive_reuses_binaries_without_cargo_build_options() -> Result<()> {
        let archive = tempfile::NamedTempFile::new()?;
        for phase in [Phase::Boot, Phase::Suites] {
            let args = nextest_args(phase, Some(archive.path()))?;
            assert!(args.windows(2).any(|args| {
                args[0] == "--archive-file" && Path::new(&args[1]) == archive.path()
            }));
            assert!(args.windows(2).any(|args| args == ["--workspace-remap", "."]));
            assert!(!args.iter().any(|arg| arg == "--locked" || arg == "-p"));
            assert_eq!(args.last().map(String::as_str), Some(phase.filter()));
        }
        Ok(())
    }

    #[test]
    fn missing_archive_fails_without_rebuilding() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing.tar.zst");
        let error = nextest_args(Phase::Boot, Some(&missing)).unwrap_err();
        assert!(error.to_string().contains("Test archive is missing"));
        Ok(())
    }
}

fn report(context: &Context) -> Result<()> {
    let mut records = Vec::new();
    let mut executions = Vec::new();
    let selected = context.selected_sources();
    for (rom, rom_source) in ROMS {
        for runtime in RUNTIMES {
            let runtime_source = selected
                .iter()
                .find(|(label, _)| *label == runtime)
                .context("Missing selected runtime")?
                .1;
            let directory = context.root.join("reports").join(rom).join(runtime);
            for (variant, root) in context.variants() {
                for phase in [Phase::Boot, Phase::Suites] {
                    let prefix = phase.prefix(variant);
                    let mut errors = Vec::new();
                    let metadata = read_evidence(
                        &directory.join(format!("{prefix}-metadata.json")),
                        &mut errors,
                    );
                    let status = read_evidence(
                        &directory.join(format!("{prefix}-execution.json")),
                        &mut errors,
                    );
                    if let Some(status) = &status {
                        if status["exit_code"] != 0
                            || status["junit"] != true
                            || status["silent_skip_detected"] != false
                        {
                            errors.push(format!("Nextest execution failed: {status}"));
                        }
                    }
                    let junit = directory.join(format!("{prefix}-junit.xml"));
                    if let Err(error) = validate_junit(&junit, phase) {
                        errors.push(format!("{}: {error:#}", junit.display()));
                    }
                    executions.push(json!({
                        "rom": rom, "runtime": runtime, "variant": variant, "phase": phase.name(),
                        "ok": errors.is_empty(), "status": status, "errors": errors,
                    }));
                    for &scenario in phase.scenarios() {
                        let path = root
                            .join("artifacts/results")
                            .join(rom)
                            .join(runtime)
                            .join(format!("{scenario}.json"));
                        let mut errors = Vec::new();
                        let evidence = read_evidence(&path, &mut errors);
                        let valid = evidence.as_ref().is_some_and(|record| {
                            record["scenario"] == scenario
                                && matches!(
                                    record["result"].as_str(),
                                    Some("PASS" | "FAIL" | "BLOCKED" | "NOT APPLICABLE")
                                )
                                && record["reason"].as_str().is_some_and(|reason| {
                                    record["result"] == "PASS" || !reason.trim().is_empty()
                                })
                                && metadata.as_ref().is_some_and(|metadata| {
                                    metadata["rom"]["source"].as_str() == Some(rom_source)
                                        && metadata["variant"].as_str() == Some(variant)
                                        && metadata["runtime"]["source"].as_str()
                                            == Some(runtime_source)
                                        && metadata["configuration_sha256"].as_str().is_some_and(
                                            |hash| {
                                                hash.len() == 64
                                                    && record["configuration_sha256"].as_str()
                                                        == Some(hash)
                                            },
                                        )
                                })
                        });
                        let mut record = if valid {
                            evidence.context("Validated evidence is missing")?
                        } else {
                            json!({
                                "scenario": scenario, "result": "BLOCKED", "exit_code": null,
                                "reason": if errors.is_empty() {
                                    format!("Invalid scenario result or configuration provenance: {}; evidence={evidence:?}", path.display())
                                } else { errors.join("\n") },
                            })
                        };
                        let fields = record
                            .as_object_mut()
                            .context("Case evidence must be an object")?;
                        fields.extend([
                            ("variant".into(), json!(variant)),
                            ("phase".into(), json!(phase.name())),
                            ("rom".into(), json!(rom)),
                            ("runtime".into(), json!(runtime)),
                            ("rom_source".into(), json!(rom_source)),
                            ("runtime_source".into(), json!(runtime_source)),
                            ("metadata".into(), json!(metadata)),
                        ]);
                        records.push(record);
                    }
                }
            }
        }
    }
    write_json(&context.root.join("matrix-results.json"), &records)?;
    write_json(&context.root.join("execution-results.json"), &executions)?;
    write_report(context, &records, &executions)?;
    ensure!(
        records
            .iter()
            .all(|record| matches!(record["result"].as_str(), Some("PASS" | "NOT APPLICABLE")))
            && executions.iter().all(|execution| execution["ok"] == true),
        "Compatibility failures, blocked cases, or execution/evidence errors; see summary.md"
    );
    Ok(())
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_report(context: &Context, records: &[Value], executions: &[Value]) -> Result<()> {
    let count = |result: &str| {
        records
            .iter()
            .filter(|record| record["result"] == result)
            .count()
    };
    let execution_errors = executions
        .iter()
        .filter(|execution| execution["ok"] != true)
        .count();
    let mut junit = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"ROM/runtime compatibility\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\">\n",
        records.len() + execution_errors, count("FAIL"), count("BLOCKED") + execution_errors,
        count("NOT APPLICABLE")
    );
    for record in records {
        let text = |key: &str| {
            record[key]
                .as_str()
                .with_context(|| format!("Missing {key}"))
        };
        junit.push_str(&format!(
            "<testcase classname=\"{}.{}.{}\" name=\"{}\">",
            xml(text("variant")?),
            xml(text("rom")?),
            xml(text("runtime")?),
            xml(text("scenario")?)
        ));
        let element = match text("result")? {
            "PASS" => None,
            "FAIL" => Some("failure"),
            "BLOCKED" => Some("error"),
            "NOT APPLICABLE" => Some("skipped"),
            other => bail!("Unknown result {other}"),
        };
        if let Some(element) = element {
            let reason = xml(text("reason")?);
            junit.push_str(&format!(
                "<{element} message=\"{reason}\">{reason}</{element}>"
            ));
        }
        junit.push_str("</testcase>\n");
    }
    for execution in executions
        .iter()
        .filter(|execution| execution["ok"] != true)
    {
        junit.push_str(&format!(
            "<testcase classname=\"{}.{}\" name=\"{}-{}-nextest-execution\"><error message=\"Nextest execution failed or evidence is missing\">{}</error></testcase>\n",
            xml(execution["rom"].as_str().context("Missing ROM")?),
            xml(execution["runtime"].as_str().context("Missing runtime")?),
            xml(execution["variant"].as_str().context("Missing variant")?),
            xml(execution["phase"].as_str().context("Missing phase")?),
            xml(&execution["errors"].to_string())
        ));
    }
    junit.push_str("</testsuite>\n");
    fs::write(context.root.join("junit.xml"), junit)?;
    let mut summary = format!(
        "# Released ROM/runtime compatibility\n\nCurrent runtime: `{}`; hardware: 2.1 emulator.\n\
         Fixed Core: `e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb`.\n\n\
         | Phase | Variant | ROM | Runtime | PASS | FAIL | BLOCKED | N/A |\n\
         |---|---|---|---|---:|---:|---:|---:|\n",
        context.current_runtime
    );
    for (variant, _) in context.variants() {
        for phase in [Phase::Boot, Phase::Suites] {
            for (rom, _) in ROMS {
                for runtime in RUNTIMES {
                    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                    for record in records.iter().filter(|record| {
                        record["variant"] == variant
                            && record["rom"] == rom
                            && record["runtime"] == runtime
                            && record["phase"] == phase.name()
                    }) {
                        *counts
                            .entry(record["result"].as_str().context("Missing result")?)
                            .or_default() += 1;
                    }
                    summary.push_str(&format!(
                        "| {} | {variant} | {rom} | {runtime} | {} | {} | {} | {} |\n",
                        phase.name(),
                        counts.get("PASS").unwrap_or(&0),
                        counts.get("FAIL").unwrap_or(&0),
                        counts.get("BLOCKED").unwrap_or(&0),
                        counts.get("NOT APPLICABLE").unwrap_or(&0)
                    ));
                }
            }
        }
    }
    summary.push_str(
        "\nWarm reset is explicitly excluded on the emulator; this is not FPGA coverage.\n\
         See matrix-results.json for per-case reasons and image/configuration metadata, \
         execution-results.json for Nextest exit/evidence status, and pair artifacts for raw logs/JUnit.\n\
         \n## Failures, blocked cases, and exclusions\n\n"
    );
    for record in records.iter().filter(|record| record["result"] != "PASS") {
        summary.push_str(&format!(
            "- {} {}/{} {}: **{}** - {}\n",
            record["variant"].as_str().context("Missing variant")?,
            record["rom"].as_str().context("Missing ROM")?,
            record["runtime"].as_str().context("Missing runtime")?,
            record["scenario"].as_str().context("Missing scenario")?,
            record["result"].as_str().context("Missing result")?,
            record["reason"].as_str().context("Missing reason")?
        ));
    }
    summary.push_str("\n## Execution/evidence errors\n\n");
    for execution in executions
        .iter()
        .filter(|execution| execution["ok"] != true)
    {
        summary.push_str(&format!(
            "- {} {} {}/{}: {}\n",
            execution["variant"],
            execution["phase"],
            execution["rom"],
            execution["runtime"],
            execution["errors"]
        ));
    }
    fs::write(context.root.join("summary.md"), &summary)?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(summary.as_bytes())?;
    }
    Ok(())
}
