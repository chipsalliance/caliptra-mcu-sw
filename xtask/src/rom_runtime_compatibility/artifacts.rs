// Licensed under the Apache-2.0 license

use super::{fixtures, sha256, write_json, Context, ROMS, RUNTIMES, SCENARIOS};
use anyhow::{bail, ensure, Context as _, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha384};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const CORE: &str = "e5d1f27b15ba02e4e0a57b942bbde39b74cab2eb";
const HANDLER: &str =
    "platforms/emulator/runtime/userspace/apps/user/src/caliptra_cmd_handler/mod.rs";
const PROTOCOL: &str = "platforms/emulator/runtime/userspace/apps/user/src/image_loader/config.rs";

fn artifact_build_command(context: &Context, program: &str) -> Command {
    let mut command = context.command(program);
    // CI's warnings policy is for the current host tools, not pinned firmware
    // or the evaluator compiled from those historical sources.
    command.env_remove("EXTRA_CARGO_CONFIG");
    command
}

fn read_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("Reading {}", path.display()))?)
        .with_context(|| format!("Parsing {}", path.display()))
}

fn capture(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("Starting {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn checked(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("Starting {command:?}"))?;
    ensure!(status.success(), "{command:?} failed ({status})");
    Ok(())
}

fn logged(command: &mut Command, log: &Path, append: bool) -> Result<std::process::ExitStatus> {
    println!("+ {command:?}");
    let stream = OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(log)
        .with_context(|| format!("Opening {}", log.display()))?;
    let status = command
        .stdout(Stdio::from(stream.try_clone()?))
        .stderr(Stdio::from(stream))
        .status()
        .with_context(|| format!("Starting {command:?}"))?;
    println!("exit {status}, log {}", log.display());
    if !status.success() {
        let contents = fs::read(log)?;
        let contents = String::from_utf8_lossy(&contents);
        let lines: Vec<_> = contents.lines().collect();
        eprintln!("{}", lines[lines.len().saturating_sub(60)..].join("\n"));
    }
    Ok(status)
}

fn run(command: &mut Command, log: &Path) -> Result<()> {
    let status = logged(command, log, false)?;
    ensure!(
        status.success(),
        "{command:?} failed ({status}); see {}",
        log.display()
    );
    Ok(())
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return -signal;
        }
    }
    -1
}

fn initialize_submodules(
    context: &Context,
    checkout: &Path,
    relative: &Path,
    log: &Path,
) -> Result<()> {
    if !checkout.join(".gitmodules").is_file() {
        return Ok(());
    }
    let entries = capture(context.command("git").current_dir(checkout).args([
        "config",
        "--file",
        ".gitmodules",
        "--get-regexp",
        r"submodule\..*\.path",
    ]))?;
    for entry in entries.lines() {
        let (_, path) = entry
            .split_once(char::is_whitespace)
            .context("Invalid submodule path entry")?;
        let path = path.trim_start();
        ensure!(
            !Path::new(path).is_absolute()
                && !Path::new(path)
                    .components()
                    .any(|component| component == Component::ParentDir),
            "Invalid submodule path {path}"
        );
        let reference = context.repo.join(relative).join(path);
        let mut command = context.command("git");
        command
            .current_dir(checkout)
            .args(["submodule", "update", "--init"]);
        if reference.join(".git").exists() {
            command.arg("--reference").arg(reference);
        }
        command.args(["--", path]);
        let status = logged(&mut command, log, true)?;
        ensure!(status.success(), "Initializing submodule {path}: {status}");
        initialize_submodules(context, &checkout.join(path), &relative.join(path), log)?;
    }
    Ok(())
}

fn source_status(context: &Context, checkout: &Path) -> Result<String> {
    capture(context.command("git").current_dir(checkout).args([
        "submodule",
        "status",
        "--recursive",
    ]))
}

fn clean_source(context: &Context, checkout: &Path) -> Result<()> {
    checked(context.command("git").current_dir(checkout).args([
        "diff",
        "--exit-code",
        "HEAD",
        "--",
    ]))?;
    checked(context.command("git").current_dir(checkout).args([
        "submodule",
        "foreach",
        "--recursive",
        "git diff --exit-code HEAD --",
    ]))
}

fn prepare_source(
    context: &Context,
    label: &str,
    source: &str,
    evidence: &Path,
) -> Result<PathBuf> {
    fs::create_dir_all(&context.sources)?;
    fs::create_dir_all(evidence)?;
    let checkout = context.sources.join(label);
    if !checkout.exists() {
        checked(
            context
                .command("git")
                .args(["worktree", "add", "--detach"])
                .arg(&checkout)
                .arg(source),
        )?;
    }
    ensure!(
        capture(
            context
                .command("git")
                .current_dir(&checkout)
                .args(["rev-parse", "HEAD"])
        )? == source,
        "{label} checkout does not match pinned source {source}"
    );
    for parent in checkout.ancestors().skip(1) {
        ensure!(
            !parent.join("Cargo.toml").exists(),
            "Source checkout is nested inside a Cargo workspace: {}",
            parent.display()
        );
    }
    let log = evidence.join("submodule-init.log");
    fs::write(&log, "")?;
    initialize_submodules(context, &checkout, Path::new(""), &log)?;
    clean_source(context, &checkout)?;
    Ok(checkout)
}

fn toolchain(label: &str) -> &'static str {
    if ROMS.iter().any(|(rom, _)| *rom == label) || label == "rt-sdk-2.1.0" {
        "1.85"
    } else {
        "1.96.1"
    }
}

fn build_one(
    context: &Context,
    root: &Path,
    label: &str,
    source: &str,
    streaming: bool,
) -> Result<Value> {
    let evidence = root.join("artifacts").join(label);
    fs::create_dir_all(&evidence)?;
    let rom = ROMS.iter().any(|(rom, _)| *rom == label);
    let mut configuration: Vec<String> = if rom {
        [
            "rom-build",
            "--platform",
            "emulator",
            "--features",
            "hw-2-1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    } else {
        [
            "runtime-build",
            "--platform",
            "emulator",
            "--profile",
            "release",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    };
    if !rom {
        let features = if streaming {
            &[
                "hw-2-1",
                "mcu-mbox-service",
                "streaming-boot",
                "spdm",
                "mctp-vdm-service",
            ][..]
        } else {
            &["hw-2-1", "flash-boot", "mcu-mbox-service"][..]
        };
        for feature in features {
            configuration.extend(["--features".to_owned(), (*feature).to_owned()]);
        }
        configuration.extend([
            "--output".to_owned(),
            "compatibility-runtime.bin".to_owned(),
        ]);
    }
    let checkout = prepare_source(context, label, source, &evidence)?;
    for name in ["Cargo.lock", "rust-toolchain.toml"] {
        fs::copy(checkout.join(name), evidence.join(name))?;
    }
    fs::write(evidence.join("source.sha"), format!("{source}\n"))?;
    let submodules = source_status(context, &checkout)?;
    fs::write(evidence.join("submodules.txt"), format!("{submodules}\n"))?;
    let mut rustc = artifact_build_command(context, "rustc");
    rustc
        .current_dir(&checkout)
        .env("RUSTUP_TOOLCHAIN", toolchain(label))
        .env("CARGO_TARGET_DIR", checkout.join("target"))
        .arg("--version");
    let rustc = capture(&mut rustc)?;
    write_json(
        &evidence.join("build-metadata.json"),
        &json!({
            "label": label, "source": source, "toolchain": toolchain(label),
            "hardware": "2.1.0", "platform": "emulator",
            "configuration": configuration.join(" "),
            "lockfile_sha256": sha256(&evidence.join("Cargo.lock"))?,
            "toolchain_file_sha256": sha256(&evidence.join("rust-toolchain.toml"))?,
        }),
    )?;
    fs::write(
        evidence.join("build.txt"),
        format!(
            "{rustc}\ncommand=cargo run --locked --package caliptra-mcu-xtask -- {}\n",
            configuration.join(" ")
        ),
    )?;
    if !rom {
        let version = fs::read_to_string(checkout.join("common/config/src/version.rs"))?;
        let mut components = Vec::new();
        for (name, maximum) in [("MAJOR", 255), ("MINOR", 255), ("PATCH", 65535)] {
            let prefix = format!("pub const MCU_RUNTIME_VERSION_{name}: u32 = ");
            let matches: Vec<_> = version
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix)?.strip_suffix(';'))
                .collect();
            ensure!(matches.len() == 1, "Missing or ambiguous runtime {name}");
            let value: u32 = matches[0].parse()?;
            ensure!(value <= maximum, "Runtime {name} is out of range");
            components.push(matches[0]);
        }
        fs::write(
            evidence.join("version.txt"),
            format!("{}\n", components.join(".")),
        )?;
    }
    let status = logged(
        artifact_build_command(context, "cargo")
            .current_dir(&checkout)
            .env("RUSTUP_TOOLCHAIN", toolchain(label))
            .env("CARGO_TARGET_DIR", checkout.join("target"))
            .args(["run", "--locked", "--package", "caliptra-mcu-xtask", "--"])
            .args(&configuration),
        &evidence.join("build.log"),
        false,
    )?;
    let exit_code = exit_code(status);
    fs::write(evidence.join("exit-code.txt"), format!("{exit_code}\n"))?;
    if !status.success() {
        return Ok(json!({"label": label, "status": "BUILD_FAILED", "exit_code": exit_code}));
    }
    clean_source(context, &checkout)?;
    for name in ["Cargo.lock", "rust-toolchain.toml"] {
        ensure!(
            fs::read(checkout.join(name))? == fs::read(evidence.join(name))?,
            "{label}: {name} changed during build"
        );
    }
    ensure!(
        submodules == source_status(context, &checkout)?,
        "{label}: submodule revisions changed during build"
    );
    let output = checkout
        .join("target/riscv32imc-unknown-none-elf/release")
        .join(if rom {
            "caliptra-mcu-rom-emulator-hw-2-1.bin"
        } else {
            "compatibility-runtime.bin"
        });
    let size = fs::metadata(&output)
        .with_context(|| format!("Missing output {}", output.display()))?
        .len();
    ensure!(size > 0, "Empty image {}", output.display());
    fs::copy(&output, evidence.join("image.bin"))?;
    if rom {
        let scripts =
            linker_scripts(&checkout.join("target/riscv32imc-unknown-none-elf/linker-scripts"))?;
        ensure!(!scripts.is_empty(), "Missing generated ROM linker scripts");
        fs::create_dir_all(evidence.join("linker-scripts"))?;
        for script in scripts {
            fs::copy(
                &script,
                evidence.join("linker-scripts").join(
                    script
                        .file_name()
                        .context("Linker script has no filename")?,
                ),
            )?;
        }
    }
    let hash = sha256(&evidence.join("image.bin"))?;
    fs::write(
        evidence.join("image.sha256"),
        format!("{hash}  image.bin\n"),
    )?;
    let error = evidence.join("error.json");
    if error.exists() {
        fs::remove_file(error)?;
    }
    Ok(json!({
        "label": label, "status": "BUILT", "source": source, "size": size, "sha256": hash,
    }))
}

fn linker_scripts(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("caliptra-mcu-rom-emulator-") && name.ends_with(".ld") {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn record_build(
    context: &Context,
    root: &Path,
    label: &str,
    source: &str,
    streaming: bool,
    results: &mut Map<String, Value>,
    index: &Path,
) -> Result<()> {
    match build_one(context, root, label, source, streaming) {
        Ok(result) => {
            let success = result["status"] == "BUILT";
            println!("{result}");
            results.insert(
                if streaming { "service" } else { "baseline" }.into(),
                result,
            );
            write_json(index, results)?;
            ensure!(
                success,
                "{label} image build failed; see {}",
                index.display()
            );
            Ok(())
        }
        Err(error) => {
            let result = json!({"label": label, "status": "ERROR", "error": format!("{error:#}")});
            let evidence = root.join("artifacts").join(label);
            fs::create_dir_all(&evidence)?;
            write_json(&evidence.join("error.json"), &result)?;
            results.insert(
                if streaming { "service" } else { "baseline" }.into(),
                result,
            );
            write_json(index, results)?;
            Err(error).with_context(|| format!("Building {label}; evidence {}", index.display()))
        }
    }
}

pub(super) fn build_images(context: &Context, label: &str) -> Result<()> {
    let selected = context.selected_sources();
    let source = selected
        .iter()
        .find_map(|(name, source)| (*name == label).then_some(*source))
        .with_context(|| format!("Unknown compatibility image {label}"))?;
    let index = context
        .root
        .join("image-builds")
        .join(format!("{label}.json"));
    fs::create_dir_all(index.parent().context("Missing image index directory")?)?;
    let mut results = Map::new();
    record_build(
        context,
        &context.root,
        label,
        source,
        false,
        &mut results,
        &index,
    )?;
    let service = context.root.join("streaming-emulator");
    if ROMS.iter().any(|(rom, _)| *rom == label) {
        copy_tree(
            &context.root.join("artifacts").join(label),
            &service.join("artifacts").join(label),
        )?;
        results.insert("service".into(), results["baseline"].clone());
        write_json(&index, &results)?;
    } else {
        record_build(context, &service, label, source, true, &mut results, &index)?;
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        !destination.exists(),
        "Evidence destination already exists: {}",
        destination.display()
    );
    fs::create_dir_all(destination)?;
    for entry in walkdir::WalkDir::new(source).min_depth(1) {
        let entry = entry?;
        let output = destination.join(entry.path().strip_prefix(source)?);
        if entry.file_type().is_dir() {
            fs::create_dir_all(output)?;
        } else {
            ensure!(entry.file_type().is_file(), "Unexpected non-file evidence");
            fs::copy(entry.path(), output)?;
        }
    }
    Ok(())
}

pub(super) fn prepare_fixtures(context: &Context) -> Result<()> {
    let selected = context.selected_sources();
    for (label, source) in &selected {
        prepare_source(
            context,
            label,
            source,
            &context.root.join("artifacts").join(label),
        )?;
    }
    for (variant, root) in [
        ("baseline", context.root.clone()),
        ("service", context.root.join("streaming-emulator")),
    ] {
        let mut results = Vec::new();
        for (label, source) in &selected {
            let index = read_json(
                &context
                    .root
                    .join("image-builds")
                    .join(format!("{label}.json")),
            )?;
            let result = index
                .get(variant)
                .with_context(|| format!("Missing {variant} build for {label}"))?;
            ensure!(
                result["status"] == "BUILT"
                    && result["label"] == *label
                    && result["source"] == *source,
                "Incomplete or mismatched {variant} image build for {label}"
            );
            results.push(result.clone());
        }
        fs::create_dir_all(&root)?;
        write_json(&root.join("build-results.json"), &results)?;
    }
    write_json(
        &context.root.join("runtime-resolution.json"),
        &json!({"ref": "refs/heads/main-2.1", "source": context.current_runtime}),
    )?;
    run(
        core_command(context, "cargo", &context.repo)
            .args(["fetch", "--locked", "--manifest-path"])
            .arg(context.repo.join("Cargo.toml")),
        &context.root.join("fixture-dependency-fetch.log"),
    )?;
    for runtime in RUNTIMES {
        run(
            artifact_build_command(context, "cargo")
                .current_dir(context.sources.join(runtime))
                .env(
                    "RUSTUP_TOOLCHAIN",
                    if runtime == "rt-sdk-2.1.0" {
                        "1.85"
                    } else {
                        "1.96.1"
                    },
                )
                .args(["fetch", "--locked"]),
            &context
                .root
                .join(format!("{runtime}-abi-dependency-fetch.log")),
        )?;
    }
    finish_fixtures(context, &context.root, false)?;
    finish_fixtures(context, &context.root.join("streaming-emulator"), true)
}

fn core_command(context: &Context, program: &str, cwd: &Path) -> Command {
    let mut command = artifact_build_command(context, program);
    command
        .current_dir(cwd)
        .env("RUSTUP_TOOLCHAIN", "1.96.1")
        .env("CALIPTRA_HW_REV", "2.1")
        .env("CPTRA_ROM_TYPE", "ROM_WITH_UART")
        .env("CARGO_TARGET_DIR", context.root.join("core-build-target"))
        .env_remove("CALIPTRA_IMAGE_NO_GIT_REVISION");
    command
}

fn produce_fixtures(context: &Context, core: &Path, artifacts: &Path) -> Result<()> {
    let command = core_command(context, "cargo", core);
    fs::create_dir_all(context.root.join("core-build-target"))?;
    let previous_directory = std::env::current_dir()?;
    let previous_environment: Vec<_> = command
        .get_envs()
        .map(|(key, _)| (key.to_owned(), std::env::var_os(key)))
        .collect();
    // The builder APIs spawn their own commands. Apply the same pinned environment
    // in-process while those APIs run, then restore it before historical producers.
    std::env::set_current_dir(core)
        .with_context(|| format!("Entering pinned Core source {}", core.display()))?;
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
    let result = fixtures::produce(artifacts).context("Producing signed Core and MCU fixtures");
    for (key, value) in previous_environment {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
    let restored = std::env::set_current_dir(&previous_directory).with_context(|| {
        format!(
            "Restoring working directory {}",
            previous_directory.display()
        )
    });
    match (result, restored) {
        (Err(error), Err(restore)) => Err(error.context(format!("{restore:#}"))),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), restored) => restored,
    }
}

fn validate_images(context: &Context, artifacts: &Path, root: &Path) -> Result<()> {
    let results = read_json(&root.join("build-results.json"))?;
    let results = results
        .as_array()
        .context("Build results must be an array")?;
    let selected = context.selected_sources();
    ensure!(
        results.len() == selected.len(),
        "Incomplete image build results"
    );
    let mut seen = BTreeSet::new();
    for result in results {
        let label = result["label"].as_str().context("Missing build label")?;
        let source = selected
            .iter()
            .find_map(|(name, source)| (*name == label).then_some(*source))
            .context("Unexpected image build label")?;
        ensure!(seen.insert(label), "Duplicate image build label {label}");
        ensure!(
            result["status"] == "BUILT" && result["source"] == source,
            "{label}: image is not built from selected source"
        );
        let evidence = artifacts.join(label);
        let image = evidence.join("image.bin");
        let bytes = fs::read(&image)?;
        ensure!(
            result["sha256"] == sha256(&image)?
                && result["size"].as_u64() == Some(bytes.len() as u64)
                && fs::read_to_string(evidence.join("exit-code.txt"))?.trim() == "0",
            "{label}: image build evidence mismatch"
        );
        if ROMS.iter().any(|(rom, _)| *rom == label) {
            ensure!(
                bytes.len() == 65536
                    && bytes[bytes.len() - 48..] == Sha384::digest(&bytes[..bytes.len() - 48])[..],
                "{label}: invalid ROM length or SHA-384 trailer"
            );
        } else {
            ensure!(
                !bytes.is_empty() && bytes.len() <= 512 * 1024,
                "{label}: runtime image exceeds SRAM bounds"
            );
        }
        for name in ["Cargo.lock", "rust-toolchain.toml"] {
            let output = context
                .command("git")
                .args(["show", &format!("{source}:{name}")])
                .output()
                .with_context(|| format!("Reading pinned {label} {name}"))?;
            ensure!(
                output.status.success(),
                "git show {source}:{name} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ensure!(
                output.stdout == fs::read(evidence.join(name))?,
                "{label}: {name} differs from pinned source"
            );
        }
    }
    Ok(())
}

fn finish_fixtures(context: &Context, root: &Path, streaming: bool) -> Result<()> {
    let artifacts = root.join("artifacts");
    validate_images(context, &artifacts, root)?;
    let shared = artifacts.join("fixtures");
    fs::create_dir_all(&shared)?;
    if streaming {
        for name in [
            "caliptra-rom.bin",
            "caliptra-firmware.bin",
            "vendor-pk-hash.txt",
        ] {
            fs::copy(
                context.root.join("artifacts/fixtures").join(name),
                shared.join(name),
            )?;
        }
    }
    let metadata: Value = serde_json::from_str(&capture(
        core_command(context, "cargo", &context.repo).args([
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
        ]),
    )?)?;
    write_json(&shared.join("cargo-metadata.json"), &metadata)?;
    let builders: Vec<_> = metadata["packages"]
        .as_array()
        .context("Cargo metadata is missing packages")?
        .iter()
        .filter(|package| package["name"] == "caliptra-builder")
        .collect();
    ensure!(
        builders.len() == 1,
        "Expected exactly one pinned Core builder"
    );
    ensure!(
        builders[0]["source"]
            .as_str()
            .context("Core builder has no Git source")?
            .ends_with(&format!("#{CORE}")),
        "Core builder is not pinned to {CORE}"
    );
    let core_manifest = Path::new(
        builders[0]["manifest_path"]
            .as_str()
            .context("Core builder has no manifest path")?,
    );
    let core = core_manifest
        .parent()
        .and_then(Path::parent)
        .context("Core builder manifest has no source root")?;
    ensure!(
        capture(core_command(context, "git", core).args(["rev-parse", "HEAD"]))? == CORE,
        "Core checkout does not match pinned revision"
    );
    run(
        core_command(context, "git", core).args(["diff", "--exit-code", "HEAD", "--"]),
        &shared.join("core-source-before.log"),
    )?;
    fs::copy(core.join("Cargo.lock"), shared.join("core-source.lock"))?;
    fs::copy(
        core.join("rust-toolchain.toml"),
        shared.join("core-rust-toolchain.toml"),
    )?;
    fs::copy(
        context.repo.join("Cargo.lock"),
        shared.join("fixture-builder.lock"),
    )?;
    fs::write(
        shared.join("fixture-build.log"),
        format!("In-process Rust fixture producer; pinned Core {CORE}\n"),
    )?;
    produce_fixtures(context, core, &artifacts)?;
    run(
        core_command(context, "git", core).args(["diff", "--exit-code", "HEAD", "--"]),
        &shared.join("core-source-after.log"),
    )?;
    ensure!(
        fs::read(context.repo.join("Cargo.lock"))?
            == fs::read(shared.join("fixture-builder.lock"))?,
        "Fixture builder lockfile changed during build"
    );
    write_json(
        &shared.join("build-evidence.json"),
        &json!({
            "core_source": CORE, "hardware": "2.1.0", "platform": "emulator",
            "core_build_working_directory": core,
            "rom": "ROM_WITH_UART", "firmware": ["FMC_WITH_UART", "APP_WITH_UART"],
            "svn": 0, "pqc": "LMS",
            "rustc": capture(core_command(context, "rustc", &context.repo).arg("--version"))?,
            "helper_lock_sha256": sha256(&context.repo.join("Cargo.lock"))?,
            "helper_source_sha256": sha256(&context.repo.join("xtask/src/rom_runtime_compatibility/fixtures.rs"))?,
            "mcu_builder_source": capture(context.command("git").args(["rev-parse", "HEAD"]))?,
            "mcu_builder_sha256": sha256(&context.repo.join("builder/src/caliptra.rs"))?,
            "core_rom_sha256": sha256(&shared.join("caliptra-rom.bin"))?,
            "core_firmware_sha256": sha256(&shared.join("caliptra-firmware.bin"))?,
            "otp_sha256": sha256(&shared.join("otp.bin"))?,
        }),
    )?;
    let vendor_hash = hex::decode(fs::read_to_string(shared.join("vendor-pk-hash.txt"))?.trim())?;
    ensure!(
        vendor_hash.len() == 48,
        "Invalid vendor public key hash size"
    );
    let mut expected_otp = vec![0u8; 0xe88];
    for (destination, source) in expected_otp[0x420..0x450]
        .chunks_exact_mut(4)
        .zip(vendor_hash.chunks_exact(4))
    {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }
    expected_otp[0x450] = 0x3f;
    ensure!(
        fs::read(shared.join("otp.bin"))? == expected_otp,
        "Baseline OTP differs from exact default-fuse fixture"
    );
    expected_otp[0x3cc] = 1;
    expected_otp[0x3dc] = 1;
    ensure!(
        fs::read(shared.join("otp-svn1.bin"))? == expected_otp,
        "SVN-1 OTP differs from exact fuse fixture"
    );
    let core_errors = core.join("error/src/lib.rs");
    let mut error_values = BTreeMap::new();
    for (scenario, symbol) in [
        (
            "corrupted_runtime",
            "IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH",
        ),
        (
            "corrupted_manifest",
            "RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID",
        ),
        (
            "svn_rollback",
            "IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE",
        ),
    ] {
        error_values.insert(scenario, error_value(&core_errors, symbol)?);
    }
    let expected_caps = capabilities(context, root, &artifacts, streaming)?;
    validate_runtime_abi(context)?;
    let soc_package = shared.join("soc-images-v3.bin");
    let streaming_package = shared.join("streaming-v3.pldm");
    if streaming {
        fixtures::streaming_package(&path_arguments(&[
            soc_package.clone(),
            streaming_package.clone(),
            shared.join("owner-auth-manifest.bin"),
            shared.join("owner-measurement-policy.bin"),
            shared.join("soc-image-4096.bin"),
            shared.join("soc-image-4097.bin"),
        ])?)
        .context("Producing streaming PLDM and SoC packages")?;
        fs::write(
            shared.join("streaming-pldm.log"),
            "In-process Rust streaming package producer completed\n",
        )?;
    } else {
        for runtime in RUNTIMES {
            let fixtures = artifacts.join(runtime).join("fixtures");
            for suffix in ["", "-svn1"] {
                fixtures::runtime_flash(&path_arguments(&[
                    fixtures.join(format!("runtime-flash{suffix}.bin")),
                    shared.join("caliptra-firmware.bin"),
                    fixtures.join(format!("soc-manifest{suffix}.bin")),
                    artifacts.join(runtime).join("image.bin"),
                    shared.join("owner-auth-manifest.bin"),
                    shared.join("owner-measurement-policy.bin"),
                    shared.join("soc-image-4096.bin"),
                    shared.join("soc-image-4097.bin"),
                ])?)
                .with_context(|| format!("Producing {runtime} runtime flash{suffix}"))?;
                fs::write(fixtures.join(format!("runtime-flash{suffix}.log")), "In-process Rust runtime flash producer completed; payload integrity checked by producer\n")?;
            }
        }
    }
    let inputs = PairInputs {
        context,
        artifacts: &artifacts,
        shared: &shared,
        core,
        core_errors: &core_errors,
        error_values: &error_values,
        expected_caps: &expected_caps,
        vendor_hash: &vendor_hash,
        streaming,
        soc_package: &soc_package,
        streaming_package: &streaming_package,
    };
    let mut pairs = Vec::new();
    for (rom, _) in ROMS {
        let checkout = context.sources.join(rom);
        let handoff = fs::read_to_string(checkout.join("romtime/src/handoff.rs"))?;
        ensure!(
            handoff.contains("pub const FHT_MAJOR_VERSION: u16 = 1;")
                && handoff.contains("pub const FHT_MINOR_VERSION: u16 = 0;"),
            "{rom}: unsupported handoff ABI"
        );
        let mut addresses = BTreeSet::new();
        for script in linker_scripts(&artifacts.join(rom).join("linker-scripts"))? {
            let contents = fs::read_to_string(script)?;
            for line in contents.lines() {
                if let Some(address) = line
                    .strip_prefix("HANDOFF_ADDR = 0x")
                    .and_then(|value| value.strip_suffix(';'))
                {
                    addresses.insert(u32::from_str_radix(address, 16)?);
                }
            }
        }
        ensure!(
            addresses.len() == 1,
            "{rom}: ambiguous or absent handoff address"
        );
        let handoff_address = *addresses.iter().next().context("Missing handoff address")?;
        for runtime in RUNTIMES {
            pairs.push(prepare_pair(&inputs, rom, runtime, handoff_address)?);
        }
    }
    write_json(&root.join("fixture-results.json"), &pairs)?;
    let mut hashes = BTreeMap::new();
    for entry in walkdir::WalkDir::new(&artifacts) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        let name = path.file_name().and_then(|value| value.to_str());
        if matches!(extension, Some("bin" | "pldm"))
            || matches!(
                name,
                Some(
                    "config.json"
                        | "build-metadata.json"
                        | "fixture-metadata.json"
                        | "expectation-sources.json"
                        | "streaming-inputs.json"
                        | "suite-support.json"
                )
            )
        {
            hashes.insert(
                path.strip_prefix(&artifacts)?
                    .to_string_lossy()
                    .into_owned(),
                sha256(path)?,
            );
        }
    }
    write_json(&root.join("artifact-hashes.json"), &hashes)
}

fn path_arguments(paths: &[PathBuf]) -> Result<Vec<String>> {
    paths
        .iter()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .with_context(|| format!("Non-UTF-8 fixture path {}", path.display()))
        })
        .collect()
}

fn compact(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn braced(source: &str, marker: &str) -> Result<String> {
    let start = source
        .find(marker)
        .with_context(|| format!("Missing source declaration {marker}"))?;
    let opening = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .with_context(|| format!("Missing body for {marker}"))?;
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[opening..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(source[start..=opening + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    bail!("Unclosed source declaration {marker}")
}

fn declaration(source: &str, name: &str) -> Result<String> {
    let marker = format!("pub const {name}:");
    let start = source
        .find(&marker)
        .with_context(|| format!("Missing source constant {name}"))?;
    let end = source[start..]
        .find(';')
        .map(|offset| start + offset + 1)
        .with_context(|| format!("Unterminated source constant {name}"))?;
    Ok(source[start..end].to_owned())
}

fn constant_number(source: &str, name: &str) -> Result<usize> {
    let value = declaration(source, name)?;
    value
        .split_once('=')
        .context("Constant has no initializer")?
        .1
        .trim()
        .trim_end_matches(';')
        .parse()
        .with_context(|| format!("Invalid numeric source constant {name}"))
}

fn struct_layout(source: &str, name: &str) -> Result<Vec<String>> {
    let body = braced(source, &format!("pub struct {name}"))?;
    let body = body
        .split_once('{')
        .context("Struct has no body")?
        .1
        .trim_end_matches('}');
    let uncommented = body
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(before, _)| before))
        .collect::<Vec<_>>()
        .join("\n");
    let fields = uncommented
        .split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(|field| {
            ensure!(
                field.starts_with("pub "),
                "Unexpected private field in {name}"
            );
            Ok(compact(field))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!fields.is_empty(), "Empty source layout {name}");
    Ok(fields)
}

fn validate_runtime_abi(context: &Context) -> Result<()> {
    let current_format = fs::read_to_string(context.repo.join("common/flash-image/src/lib.rs"))?;
    let current_partition =
        fs::read_to_string(context.repo.join("platforms/emulator/config/src/flash.rs"))?;
    for runtime in RUNTIMES {
        let selected = context.sources.join(runtime);
        let format = fs::read_to_string(selected.join("common/flash-image/src/lib.rs"))?;
        ensure!(
            compact(&declaration(&format, "HEADER_VERSION")?)
                == "pubconstHEADER_VERSION:u16=0x0003;",
            "{runtime}: expected native runtime flash v3"
        );
        for name in ["FlashHeader", "ImageHeader"] {
            ensure!(
                struct_layout(&format, name)? == struct_layout(&current_format, name)?,
                "{runtime}: runtime flash producer/parser ABI mismatch for {name}"
            );
        }
        ensure!(
            constant_number(&format, "MAX_FILENAME_LEN")?
                == constant_number(&current_format, "MAX_FILENAME_LEN")?,
            "{runtime}: runtime flash filename ABI mismatch"
        );
        let partition =
            fs::read_to_string(selected.join("platforms/emulator/config/src/flash.rs"))?;
        ensure!(
            struct_layout(&partition, "PartitionTable")?
                == struct_layout(&current_partition, "PartitionTable")?,
            "{runtime}: partition-table ABI mismatch"
        );
        for name in ["BLOCK_SIZE", "IMAGE_A_PARTITION"] {
            ensure!(
                declaration(&partition, name)? == declaration(&current_partition, name)?,
                "{runtime}: partition constant mismatch for {name}"
            );
        }
    }
    Ok(())
}

fn error_value(path: &Path, symbol: &str) -> Result<u32> {
    let source = compact(&fs::read_to_string(path)?);
    let marker = format!("({symbol},");
    let rest = source
        .split_once(&marker)
        .with_context(|| format!("Missing pinned error {symbol} in {}", path.display()))?
        .1;
    let value = rest
        .split_once(',')
        .context("Missing pinned error value delimiter")?
        .0;
    u32::from_str_radix(
        &value
            .strip_prefix("0x")
            .context("Pinned error is not hexadecimal")?
            .replace('_', ""),
        16,
    )
    .with_context(|| format!("Invalid pinned error {symbol}"))
}

fn capabilities(
    context: &Context,
    root: &Path,
    artifacts: &Path,
    streaming: bool,
) -> Result<BTreeMap<String, String>> {
    let directory = root.join("capability-evaluator");
    fs::create_dir_all(directory.join("src"))?;
    let mut features = vec!["release", "userspace-log", "hw-2-1", "mcu-mbox-service"];
    if streaming {
        features.extend(["streaming-boot", "spdm", "mctp-vdm-service"]);
    } else {
        features.push("flash-boot");
    }
    let lock: toml::Value = toml::from_str(&fs::read_to_string(context.repo.join("Cargo.lock"))?)?;
    let requirement = semver::VersionReq::parse("^2.4.0")?;
    let bitflags = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .context("Workspace lockfile has no packages")?
        .iter()
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("bitflags"))
        .map(|package| {
            semver::Version::parse(
                package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .context("Locked bitflags dependency has no version")?,
            )
            .context("Invalid locked bitflags version")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|version| requirement.matches(version))
        .max()
        .context("Workspace lockfile has no compatible bitflags 2 dependency")?;
    // The workspace fetch above populates this exact version even when only a
    // prebuilt xtask binary, rather than an image-job Cargo cache, was downloaded.
    let manifest = format!(
        "[package]\nname=\"compatibility-capability-evaluator\"\nversion=\"0.1.0\"\nedition=\"2021\"\n\
         [workspace]\n[dependencies]\nbitflags=\"={bitflags}\"\n[features]\n{}\n",
        features
            .iter()
            .map(|feature| format!("{feature}=[]"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write(directory.join("Cargo.toml"), manifest)?;
    let mut program = "// Licensed under the Apache-2.0 license\n".to_owned();
    for (index, label) in RUNTIMES.iter().enumerate() {
        let checkout = context.sources.join(label);
        let handler = checkout.join(HANDLER);
        let definitions = checkout.join("common/config/src/capabilities.rs");
        let source = fs::read_to_string(&handler)?;
        let normalized = compact(&source);
        ensure!(
            normalized.contains(
                "EvidenceFormat::OcpEat,AsymAlgo::EccP384)=>SIGNED_OCP_EAT_MAX_SIZE"
            ) || normalized.contains(
                "EvidenceFormat::OcpEat,AsymAlgo::EccP384|AsymAlgo::Mldsa87)=>SIGNED_OCP_EAT_MAX_SIZE"
            ),
            "{label}: recheck source-derived nonzero OCP EAT evidence support"
        );
        let cargo = handler
            .ancestors()
            .nth(3)
            .context("Capability handler has no package directory")?
            .join("Cargo.toml");
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(cargo)?)?;
        ensure!(
            manifest
                .get("features")
                .and_then(|features| features.get("release"))
                .and_then(toml::Value::as_array)
                .context("Runtime package has no release feature")?
                .iter()
                .any(|feature| feature.as_str() == Some("userspace-log")),
            "{label}: release no longer enables userspace-log"
        );
        fs::write(artifacts.join(label).join("capability-handler.rs"), &source)?;
        fs::copy(
            &definitions,
            artifacts.join(label).join("capability-definitions.rs"),
        )?;
        program.push_str(&format!(
            "mod runtime{index} {{\n{}\nconst SUPPORTED_EVIDENCE_FORMATS: u32 = 2;\n",
            fs::read_to_string(definitions)?
        ));
        for name in [
            "mcu_runtime_capabilities",
            "external_command_capabilities",
            "authorized_subcommand_capabilities",
        ] {
            program.push_str(&braced(&source, &format!("fn {name}("))?);
            program.push('\n');
        }
        program.push_str(
            "pub fn evaluate() -> [u8; 12] {\n\
             let mut result = [0; 12];\n\
             result[..4].copy_from_slice(&encode_capabilities(mcu_runtime_capabilities().bits()));\n\
             result[4..8].copy_from_slice(&encode_capabilities(external_command_capabilities().bits()));\n\
             result[8..].copy_from_slice(&encode_capabilities(authorized_subcommand_capabilities().bits()));\n\
             result\n}\n}\n",
        );
    }
    program.push_str("\nfn main() {\n");
    for (index, label) in RUNTIMES.iter().enumerate() {
        program.push_str(&format!(
            "print!(\"{label} \");\nfor byte in runtime{index}::evaluate() {{ print!(\"{{byte:02x}}\"); }}\nprintln!();\n"
        ));
    }
    program.push_str("}\n");
    fs::write(directory.join("src/main.rs"), program)?;
    run(
        artifact_build_command(context, "cargo")
            .current_dir(&directory)
            .env("RUSTUP_TOOLCHAIN", "1.96.1")
            .env("CARGO_TARGET_DIR", directory.join("target"))
            .args(["generate-lockfile", "--offline"]),
        &directory.join("resolution.log"),
    )?;
    run(
        artifact_build_command(context, "cargo")
            .current_dir(&directory)
            .env("RUSTUP_TOOLCHAIN", "1.96.1")
            .env("CARGO_TARGET_DIR", directory.join("target"))
            .args(["run", "--offline", "--locked", "--features"])
            .arg(features.join(",")),
        &directory.join("evaluation.log"),
    )?;
    let mut result = BTreeMap::new();
    for line in fs::read_to_string(directory.join("evaluation.log"))?.lines() {
        let Some((label, encoded)) = line.split_once(' ') else {
            continue;
        };
        if !RUNTIMES.contains(&label) {
            continue;
        }
        let suffix = hex::decode(encoded)?;
        ensure!(suffix.len() == 12, "{label}: invalid capabilities suffix");
        let layout = context
            .sources
            .join(label)
            .join("common/mcu-mbox/src/messages.rs");
        let size = constant_number(&fs::read_to_string(&layout)?, "DEVICE_CAPS_SIZE")?;
        ensure!(
            size == if label == "rt-sdk-2.1.0" { 36 } else { 64 },
            "{label}: unexpected capabilities wire size"
        );
        fs::copy(layout, artifacts.join(label).join("capability-layout.rs"))?;
        let mut bytes = vec![0u8; size];
        bytes[7] = 1;
        bytes[20..32].copy_from_slice(&suffix);
        ensure!(
            result
                .insert(label.to_owned(), hex::encode(bytes))
                .is_none(),
            "Duplicate capabilities output for {label}"
        );
    }
    ensure!(
        result.len() == RUNTIMES.len(),
        "Missing source-derived runtime capabilities"
    );
    Ok(result)
}

fn relative_path(path: &Path, root: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute() && root.is_absolute(),
        "Artifact paths must be absolute: {} relative to {}",
        path.display(),
        root.display()
    );
    let path: Vec<_> = path.components().collect();
    let root: Vec<_> = root.components().collect();
    let common = path
        .iter()
        .zip(&root)
        .take_while(|(left, right)| left == right)
        .count();
    ensure!(common > 0, "Artifact and configuration have no common root");
    let mut relative = PathBuf::new();
    for _ in common..root.len() {
        relative.push("..");
    }
    for component in &path[common..] {
        relative.push(component.as_os_str());
    }
    Ok(relative)
}

fn artifact(path: &Path, root: &Path) -> Result<Value> {
    Ok(json!({"path": relative_path(path, root)?, "sha256": sha256(path)?}))
}

fn archive(path: &Path, extension: &str, remove_original: bool) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("Artifact has no UTF-8 stem")?;
    let previous = path.with_file_name(format!("{stem}.{}.previous.{extension}", sha256(path)?));
    if previous.exists() {
        ensure!(
            fs::read(&previous)? == fs::read(path)?,
            "Archived artifact hash collision at {}",
            previous.display()
        );
        if remove_original {
            fs::remove_file(path)?;
        }
    } else if remove_original {
        fs::rename(path, previous)?;
    } else {
        fs::copy(path, previous)?;
    }
    Ok(())
}

struct PairInputs<'a> {
    context: &'a Context,
    artifacts: &'a Path,
    shared: &'a Path,
    core: &'a Path,
    core_errors: &'a Path,
    error_values: &'a BTreeMap<&'static str, u32>,
    expected_caps: &'a BTreeMap<String, String>,
    vendor_hash: &'a [u8],
    streaming: bool,
    soc_package: &'a Path,
    streaming_package: &'a Path,
}

fn prepare_pair(
    inputs: &PairInputs<'_>,
    rom: &str,
    runtime: &str,
    handoff_address: u32,
) -> Result<Value> {
    let PairInputs {
        context,
        artifacts,
        shared,
        core,
        core_errors,
        error_values,
        expected_caps,
        vendor_hash,
        streaming,
        soc_package,
        streaming_package,
    } = *inputs;
    let checkout = context.sources.join(rom);
    let directory = artifacts.join("pairs").join(rom).join(runtime);
    fs::create_dir_all(&directory)?;
    let package = directory.join("primary-flash.bin");
    archive(&package, "bin", true)?;
    let runtime_fixtures = artifacts.join(runtime).join("fixtures");
    let soc_manifest = runtime_fixtures.join("soc-manifest.bin");
    let selected = BTreeMap::from([
        (0u32, shared.join("caliptra-firmware.bin")),
        (1, soc_manifest.clone()),
        (2, artifacts.join(runtime).join("image.bin")),
        (4096, shared.join("soc-image-4096.bin")),
        (4097, shared.join("soc-image-4097.bin")),
    ]);
    // Historical ROMs consume different native layouts. Invoke each pinned producer,
    // rather than changing the current production flash format to emulate them.
    run(
        artifact_build_command(context, "cargo")
            .current_dir(&checkout)
            .env("RUSTUP_TOOLCHAIN", "1.85")
            .env("CARGO_TARGET_DIR", checkout.join("target"))
            .args([
                "run",
                "--locked",
                "--package",
                "caliptra-mcu-xtask",
                "--",
                "flash-image",
                "create",
                "--caliptra-fw",
            ])
            .arg(&selected[&0])
            .arg("--soc-manifest")
            .arg(&selected[&1])
            .arg("--mcu-runtime")
            .arg(&selected[&2])
            .arg("--soc-images")
            .arg(&selected[&4096])
            .arg(&selected[&4097])
            .arg("--output")
            .arg(&package),
        &directory.join("flash-build.log"),
    )?;
    verify_flash(
        &package,
        if rom == "rom-sdk-2.1.0" { 2 } else { 1 },
        &selected,
    )?;
    let mut decisions: BTreeMap<_, _> = SCENARIOS
        .iter()
        .map(|scenario| (*scenario, json!({"status": "SUPPORTED"})))
        .collect();
    decisions.insert(
        "warm_reset",
        json!({
            "status": "NOT_APPLICABLE",
            "reason": "Requires the FPGA warm-reset lane; emulator warm reset is not supported."
        }),
    );
    if streaming {
        for scenario in ["flash_cold_boot", "cold_reboot"] {
            decisions.insert(
                scenario,
                json!({
                    "status": "NOT_APPLICABLE",
                    "reason": "Requires the separately built flash-boot baseline configuration."
                }),
            );
        }
    } else {
        for scenario in ["streaming_boot", "discovery"] {
            decisions.insert(
                scenario,
                json!({
                    "status": "NOT_APPLICABLE",
                    "reason": "Requires the separately built streaming/service configuration."
                }),
            );
        }
    }
    let fixture_metadata = read_json(&runtime_fixtures.join("fixture-metadata.json"))?;
    let rom_errors = checkout.join("error/src/lib.rs");
    let mcu_error = error_value(&rom_errors, "ROM_SOC_CALIPTRA_FATAL_ERROR_BEFORE_FW_READY")?;
    let mut negative_cases = Map::new();
    for name in ["corrupted_runtime", "corrupted_manifest", "svn_rollback"] {
        let corrupt_offset = match name {
            "corrupted_runtime" => fixture_metadata["runtime_corrupt_offset"].clone(),
            "corrupted_manifest" => fixture_metadata["manifest_corrupt_offset"].clone(),
            _ => Value::Null,
        };
        negative_cases.insert(
            name.to_owned(),
            json!({
                "expected_mcu_error": mcu_error,
                "expected_core_error": error_values[name],
                "soc_manifest": null,
                "otp": if name == "svn_rollback" {
                    artifact(&shared.join("otp-svn1.bin"), &directory)?
                } else { Value::Null },
                "corrupt_offset": corrupt_offset,
            }),
        );
    }
    let mut boundary = json!({
        "expected_mcu_error": 0, "expected_core_error": 0,
        "soc_manifest": artifact(&runtime_fixtures.join("soc-manifest-svn1.bin"), &directory)?,
        "otp": artifact(&shared.join("otp-svn1.bin"), &directory)?,
        "corrupt_offset": null,
    });
    if !streaming {
        boundary["runtime_flash"] =
            artifact(&runtime_fixtures.join("runtime-flash-svn1.bin"), &directory)?;
    }
    negative_cases.insert("svn_boundary".to_owned(), boundary);
    for (name, original, offset) in [
        (
            "corrupted-runtime.bin",
            &selected[&2],
            &fixture_metadata["runtime_corrupt_offset"],
        ),
        (
            "corrupted-manifest.bin",
            &soc_manifest,
            &fixture_metadata["manifest_corrupt_offset"],
        ),
    ] {
        let offset: usize = offset
            .as_u64()
            .context("Invalid corruption offset")?
            .try_into()?;
        let mut expected = fs::read(original)?;
        let byte = expected
            .get_mut(offset)
            .context("Corruption offset exceeds original fixture")?;
        *byte ^= 1;
        ensure!(
            fs::read(runtime_fixtures.join(name))? == expected,
            "{runtime}: negative fixture {name} is not the exact single-bit corruption"
        );
    }
    write_json(
        &directory.join("expectation-sources.json"),
        &json!({
            "core_source": CORE,
            "rom_source": fs::read_to_string(artifacts.join(rom).join("source.sha"))?.trim(),
            "core_errors_sha256": sha256(core_errors)?,
            "rom_errors_sha256": sha256(&rom_errors)?,
            "core_recovery_sha256": sha256(&core.join("runtime/src/recovery_flow.rs"))?,
            "core_authentication_sha256": sha256(&core.join("runtime/src/set_auth_manifest.rs"))?,
            "rom_fuse_transfer_sha256": sha256(&checkout.join("rom/src/rom.rs"))?,
            "svn": fixture_metadata,
            "corrupted_runtime": artifact(&runtime_fixtures.join("corrupted-runtime.bin"), &directory)?,
            "corrupted_manifest": artifact(&runtime_fixtures.join("corrupted-manifest.bin"), &directory)?,
        }),
    )?;
    let configuration = read_json(&artifacts.join(runtime).join("build-metadata.json"))?;
    let configuration = configuration["configuration"]
        .as_str()
        .context("Runtime build metadata has no configuration")?;
    let soc_images = [(4096u32, 0xa880_0000u32), (4097, 0xa880_0200)]
        .into_iter()
        .map(|(identifier, address)| {
            Ok(json!({
                "address": address, "execution_bit": 5 + identifier - 4096,
                "image": artifact(&selected[&identifier], &directory)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let capabilities = hex::decode(
        expected_caps
            .get(runtime)
            .context("Missing selected capabilities")?,
    )?;
    let version = fs::read_to_string(artifacts.join(runtime).join("version.txt"))?;
    let mailbox = super::mailbox::expectations(
        &context.repo,
        &context.sources.join(runtime),
        version.trim(),
        capabilities
            .get(16..)
            .context("Missing MCU capability bytes after Core prefix")?,
    )?;
    let suite_support = super::suites::prepare(
        context,
        &directory,
        rom,
        runtime,
        streaming,
        configuration,
        mailbox,
    )?;
    let config = json!({
        "agreed": true,
        "agreement": "Repository baseline selected in compatibility matrix section 1; actual hash-checked generated fixtures.",
        "rom": rom, "runtime": runtime, "hardware": "2.1.0",
        "core_rom_source": CORE, "core_firmware_source": CORE,
        "signing": "repository-test-keys-lms-default-fuses",
        "build_configuration": configuration,
        "caliptra_rom": artifact(&shared.join("caliptra-rom.bin"), &directory)?,
        "caliptra_firmware": artifact(&selected[&0], &directory)?,
        "soc_manifest": artifact(&soc_manifest, &directory)?,
        "otp": artifact(&shared.join("otp.bin"), &directory)?,
        "vendor_pk_hash": hex::encode(vendor_hash),
        "primary_flash": artifact(&package, &directory)?,
        "expected_capabilities": expected_caps.get(runtime).context("Missing runtime capabilities")?,
        "handoff_address": handoff_address,
        "handoff_major": 1, "handoff_minor": 0,
        "expected_rom_capabilities": null,
        "soc_images": soc_images,
        "scenarios": decisions,
        "suites": suite_support["decisions"],
        "suite_support": artifact(&directory.join("suite-support.json"), &directory)?,
        "negative_cases": negative_cases,
        "runtime_flash": if streaming { Value::Null } else {
            artifact(&runtime_fixtures.join("runtime-flash.bin"), &directory)?
        },
        "owner_auth_manifest": artifact(&shared.join("owner-auth-manifest.bin"), &directory)?,
        "owner_measurement_policy": artifact(&shared.join("owner-measurement-policy.bin"), &directory)?,
    });
    let config_path = directory.join("config.json");
    archive(&config_path, "json", false)?;
    write_json(&config_path, &config)?;
    if streaming {
        let protocol = context.sources.join(runtime).join(PROTOCOL);
        let source = fs::read_to_string(&protocol)?;
        ensure!(
            source.contains("ComponentClassification::Firmware") && source.contains("0xffff"),
            "{runtime}: unsupported streaming component protocol"
        );
        let normalized = compact(&source);
        let uuid = normalized
            .split_once("constDEVICE_UUID:[u8;16]=[")
            .context("Missing streaming device UUID")?
            .1
            .split_once(']')
            .context("Unterminated streaming device UUID")?
            .0;
        let uuid = uuid
            .split(',')
            .filter(|value| !value.is_empty())
            .map(|value| {
                u8::from_str_radix(
                    value
                        .strip_prefix("0x")
                        .context("Streaming device UUID is not hexadecimal")?,
                    16,
                )
                .context("Invalid streaming device UUID byte")
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            uuid == (1..=16).collect::<Vec<u8>>(),
            "{runtime}: unexpected streaming device UUID"
        );
        write_json(
            &directory.join("streaming-inputs.json"),
            &json!({
                "pldm_package": artifact(streaming_package, &directory)?,
                "soc_images": artifact(soc_package, &directory)?,
                "runtime_protocol_config_sha256": sha256(&protocol)?,
            }),
        )?;
    }
    println!("Verified positive baseline fixtures: {rom} {runtime}");
    Ok(json!({
        "rom": rom, "runtime": runtime,
        "config_sha256": sha256(&config_path)?,
        "flash_sha256": sha256(&package)?,
    }))
}

fn word(bytes: &[u8], offset: usize, length: usize) -> Result<u32> {
    let end = offset
        .checked_add(length)
        .context("Flash offset overflow")?;
    let bytes = bytes.get(offset..end).context("Truncated flash header")?;
    ensure!(length == 2 || length == 4, "Invalid flash word size");
    let mut value = [0u8; 4];
    value[..length].copy_from_slice(bytes);
    Ok(u32::from_le_bytes(value))
}

fn checksum(bytes: &[u8]) -> u32 {
    0u32.wrapping_sub(
        bytes
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte))),
    )
}

fn verify_flash(path: &Path, version: u32, selected: &BTreeMap<u32, PathBuf>) -> Result<()> {
    let flash = fs::read(path)?;
    let prefix = if version == 1 { 4 } else { 0 };
    let header_size = prefix + 12;
    ensure!(
        flash.len() >= header_size,
        "Truncated historical flash image"
    );
    if version == 1 {
        ensure!(&flash[..4] == b"FLSH", "Missing native v1 flash magic");
    }
    ensure!(
        word(&flash, prefix, 2)? == version
            && word(&flash, header_size - 4, 4)? == checksum(&flash[..header_size - 4]),
        "Invalid native v{version} flash header"
    );
    let count = word(&flash, prefix + 2, 2)? as usize;
    let start = word(&flash, prefix + 4, 4)? as usize;
    ensure!(
        count == selected.len() && start == header_size,
        "Wrong native v{version} flash image count or header offset"
    );
    let mut previous_end = start
        .checked_add(count.checked_mul(20).context("Flash header overflow")?)
        .context("Flash header table overflow")?;
    ensure!(
        previous_end <= flash.len(),
        "Truncated flash image header table"
    );
    let mut seen = BTreeSet::new();
    for offset in (start..previous_end).step_by(20) {
        let header = &flash[offset..offset + 20];
        let identifier = word(header, 0, 4)?;
        let position = word(header, 4, 4)? as usize;
        let length = word(header, 8, 4)? as usize;
        let source = selected
            .get(&identifier)
            .context("Unexpected historical flash image identifier")?;
        ensure!(
            seen.insert(identifier),
            "Duplicate flash identifier {identifier}"
        );
        ensure!(
            position == previous_end && length % 4 == 0,
            "Non-contiguous or unaligned flash payload {identifier}"
        );
        let end = position
            .checked_add(length)
            .context("Flash payload overflow")?;
        let payload = flash
            .get(position..end)
            .context("Truncated flash payload")?;
        ensure!(
            word(header, 12, 4)? == checksum(payload)
                && word(header, 16, 4)? == checksum(&header[..16]),
            "Invalid flash checksums for {identifier}"
        );
        let mut expected = fs::read(source)?;
        expected.resize(expected.len().next_multiple_of(4), 0);
        ensure!(
            payload == expected,
            "Native v{version} producer did not bind selected image {identifier}"
        );
        previous_end = end;
    }
    ensure!(
        seen.len() == selected.len() && previous_end == flash.len(),
        "Historical flash image has missing entries or trailing data"
    );
    Ok(())
}
