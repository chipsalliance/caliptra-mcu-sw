// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use cargo_metadata::MetadataCommand;

use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use mcu_builder::PROJECT_ROOT;

/// Check that host system has all the tools that the xtask FPGA flows depends on.
pub fn check_host_dependencies() -> Result<()> {
    let tools = [
        (
            "docker --version",
            "'docker' not found on PATH. Please install docker.",
        ),
        (
            "rsync --version",
            "'rsync' not found on PATH. Please install rsync.",
        ),
        (
            "cargo nextest --version",
            "'cargo-nextest' not found on PATH. Please install with `cargo install cargo-nextest`.",
        ),
    ];
    check_dependencies(None, &tools)
}

/// Check that FPGA  has all the tools that the xtask FPGA flows depends on.
pub fn check_fpga_dependencies(target_host: Option<&str>) -> Result<()> {
    let tools = [
        (
            "rsync --version",
            "'rsync' not found on FPGA PATH. Please install rsync on FPGA.",
        ),
        (
            "cargo-nextest --version",
            "'cargo-nextest' not found on FPGA PATH. Please install with `cargo install cargo-nextest` on FPGA.",
        ),
    ];
    check_dependencies(target_host, &tools)
}

fn check_dependencies(target_host: Option<&str>, tools: &[(&str, &str)]) -> Result<()> {
    for (command, error_msg) in tools {
        if run_command_extended(RunCommandArgs {
            target_host,
            command,
            output: Output::Silence,
            ..Default::default()
        })
        .is_err()
        {
            let error_msg = error_msg.to_string();
            bail!(error_msg);
        }
    }
    Ok(())
}

/// Copies a file to FPGA over rsync to the FPGA home folder.
pub fn rsync_file(target_host: &str, file: &str, dest_file: &str, from_fpga: bool) -> Result<()> {
    // TODO(clundin): We assume are files are dropped in the root / home folder. May want to find a
    // put things in their own directory.
    let copy = if from_fpga {
        format!("{target_host}:{file}")
    } else {
        format!("{target_host}:{dest_file}")
    };
    let args = if from_fpga {
        ["-avxz", &copy, "."]
    } else {
        ["-avxz", file, &copy]
    };
    let status = Command::new("rsync")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .status()?;
    if !status.success() {
        bail!("failed rsync file: {file} to {target_host}");
    }
    Ok(())
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
/// Captures output of command and returns it as a string
pub fn run_command_with_output(target_host: Option<&str>, command: &str) -> Result<String> {
    let res = run_command_extended(RunCommandArgs {
        target_host,
        command,
        output: Output::Capture,
    })?;
    if let Some(output) = res {
        Ok(output)
    } else {
        bail!("Missing command output for command: '{command}'")
    }
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
pub fn run_command(target_host: Option<&str>, command: &str) -> Result<()> {
    let _ = run_command_extended(RunCommandArgs {
        target_host,
        command,
        ..Default::default()
    })?;
    Ok(())
}

#[derive(Default, PartialEq)]
enum Output {
    Silence,
    Capture,
    #[default]
    Inherit,
}

#[derive(Default)]
pub struct RunCommandArgs<'a> {
    target_host: Option<&'a str>,
    command: &'a str,
    output: Output,
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
/// Set `silence_output` to true to avoid outputting command logs.
pub fn run_command_extended(args: RunCommandArgs) -> Result<Option<String>> {
    let mut command = if let Some(target_host) = args.target_host {
        if args.output != Output::Silence {
            println!("[FPGA] Running command: {}", args.command);
        }
        let mut cmd = Command::new("ssh");
        cmd.current_dir(&*PROJECT_ROOT)
            .args([target_host, "-t", args.command]);
        cmd
    } else {
        if args.output != Output::Silence {
            println!("[HOST] Running command: {}", args.command);
        }
        let mut cmd = Command::new("sh");
        cmd.current_dir(&*PROJECT_ROOT).args(["-c", args.command]);
        cmd
    };

    match args.output {
        Output::Capture => {
            let output = command.output()?;
            Ok(Some(String::from_utf8(output.stdout)?))
        }
        Output::Silence => {
            let status = command
                .stdout(Stdio::null())
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if !status.success() {
                bail!("Failed to run command");
            }
            Ok(None)
        }
        Output::Inherit => {
            let status = command
                .stdout(Stdio::inherit())
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;
            if !status.success() {
                bail!("Failed to run command");
            }
            Ok(None)
        }
    }
}

/// create a base docker command
pub fn build_base_docker_command() -> Result<Command> {
    let home = std::env::var("HOME").unwrap();
    let project_root = PROJECT_ROOT.clone();
    let project_root = project_root.display();

    // TODO(clundin): Clean this docker command up.
    let mut cmd = Command::new("docker");
    cmd.current_dir(&*PROJECT_ROOT).args([
        "run",
        "--rm",
        "-e",
        "\"TERM=xterm-256color\"",
        &format!("-v{project_root}:/work-dir"),
        "-w/work-dir",
        &format!("-v{home}/.cargo/registry:/root/.cargo/registry"),
        &format!("-v{home}/.cargo/git:/root/.cargo/git"),
    ]);
    if let Some(caliptra_sw) = caliptra_sw_workspace_root() {
        let caliptra_path = caliptra_sw.canonicalize()?;
        let basename = caliptra_sw.file_name().unwrap().to_str().unwrap();
        let display = caliptra_path.display();
        cmd.arg(format!("-v{display}:/{basename}"));
    }
    cmd.arg("ghcr.io/chipsalliance/caliptra-build-image:latest")
        .arg("/bin/bash")
        .arg("-c");
    Ok(cmd)
}

pub fn run_test_suite(
    test_dir: &str,
    prelude: &str,
    test_filter: &str,
    test_output: &str,
    target_host: Option<&str>,
) -> Result<()> {
    let test_command = format!(
        "(cd {test_dir} && \
                sudo {prelude} \
                cargo-nextest nextest run \
                --workspace-remap=. --archive-file $HOME/caliptra-test-binaries.tar.zst \
                {test_output} --no-fail-fast --profile=nightly \
                -E \"{test_filter}\")"
    );
    // Run test suite.
    // Ignore error so we still copy the logs.
    let _ = run_command(target_host, test_command.as_str());
    if let Some(target_host) = target_host {
        println!("Copying test log from FPGA to junit.xml");
        rsync_file(target_host, "/tmp/junit.xml", ".", true)?;
    }
    Ok(())
}

/// Checks if any caliptra_sw dependencies are a local path.
///
/// If so, returns the Path to the caliptra_sw workspace root.
pub fn caliptra_sw_workspace_root() -> Option<PathBuf> {
    let metadata = MetadataCommand::new().exec().unwrap();

    // Look at the workspace dependencies for xtask and find a caliptra-sw crate.
    // Check if the crate contains a path, that indicates that caliptra-sw is local.
    //
    // We have to look at workspace, otherwise `path` may not be set (opposed to looking at the
    // local xtask dependencies).
    let caliptra_path = metadata
        .workspace_packages()
        .iter()
        .find(|p| p.name.as_ref() == "xtask")
        .and_then(|xtask| {
            xtask
                .dependencies
                .iter()
                .find(|p| p.name == "caliptra-api-types")
        })
        .and_then(|caliptra_package| caliptra_package.path.clone());

    match caliptra_path {
        Some(path) => {
            // This code should search for the caliptra_sw Cargo.toml, for now hard code the folder
            // structure.
            let path = path
                .ancestors()
                .nth(2)
                .expect("caliptra-api-types should be nested two directories in caliptra-sw");
            Some(path.into())
        }
        _ => None,
    }
}
