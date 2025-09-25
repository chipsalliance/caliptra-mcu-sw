// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};

use std::{
    path::Path,
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
    for (command_str, error_msg) in tools {
        if run_command(target_host, command_str, true).is_err() {
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
pub fn run_command_with_output(target_host: Option<&str>, command: &str) -> Result<String> {
    // TODO(clundin): Refactor to share code with `run_command`

    let output = {
        if let Some(target_host) = target_host {
            Command::new("ssh")
                .current_dir(&*PROJECT_ROOT)
                .args([target_host, "-t", command])
                .output()
        } else {
            Command::new("sh")
                .current_dir(&*PROJECT_ROOT)
                .args(["-c", command])
                .output()
        }
    }?;

    Ok(String::from_utf8(output.stdout)?)
}

/// Runs a command over SSH if `target_host` is `Some`. Otherwise runs command on current machine.
pub fn run_command(target_host: Option<&str>, command: &str, silence_output: bool) -> Result<()> {
    let (stdout, stderr) = if silence_output {
        (Stdio::null(), Stdio::null())
    } else {
        (Stdio::inherit(), Stdio::inherit())
    };
    if let Some(target_host) = target_host {
        if !silence_output {
            println!("[FPGA] Running command: {command}");
        }
        let status = Command::new("ssh")
            .current_dir(&*PROJECT_ROOT)
            .args([target_host, "-t", command])
            .stdin(Stdio::inherit())
            .stdout(stdout)
            .stderr(stderr)
            .status()?;
        if !status.success() {
            bail!("\"{command}\" failed to run on FPGA over ssh");
        }
    } else {
        if !silence_output {
            println!("[HOST] Running command: {command}");
        }
        let status = Command::new("sh")
            .current_dir(&*PROJECT_ROOT)
            .args(["-c", command])
            .stdin(Stdio::inherit())
            .stdout(stdout)
            .stderr(stderr)
            .status()?;
        if !status.success() {
            bail!("Failed to run command");
        }
    }

    Ok(())
}

/// create a base docker command
///
/// `caliptra_sw`: Optional path to `caliptra-sw`
pub fn build_base_docker_command(caliptra_sw: Option<impl AsRef<Path>>) -> Result<Command> {
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
    if let Some(caliptra_sw) = caliptra_sw {
        let caliptra_path = caliptra_sw.as_ref().canonicalize()?;
        let basename = caliptra_sw.as_ref().file_name().unwrap().to_str().unwrap();
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
    let _ = run_command(target_host, test_command.as_str(), false);
    if let Some(target_host) = target_host {
        println!("Copying test log from FPGA to junit.xml");
        rsync_file(target_host, "/tmp/junit.xml", ".", true)?;
    }
    Ok(())
}
