// Licensed under the Apache-2.0 license

use anyhow::{bail, ensure, Context, Result};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
use caliptra_mcu_testing_common::spdm_responder_validator::{
    execute_spdm_attestation_with_port, execute_spdm_responder_validator, SpdmValidatorRunner,
    SERVER_LISTENING,
};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const TEST_NAME: &str = "MCTP-SPDM-RESPONDER-VALIDATOR";

/// The caller owns the selected image, boot readiness and live transport
/// services. Copy the complete tool bundle into persistent per-case evidence
/// storage; the existing launcher writes through `SPDM_VALIDATOR_DIR`.
pub(crate) fn run_compatibility_conformance(hw: &mut DefaultHwModel) -> Result<()> {
    let output_dir =
        stage_compatibility_validator("spdm_device_validator_sample", "suite_spdm_mctp")?;

    let timeout = Duration::from_secs(9000);
    let port = hw
        .i3c_port()
        .context("BLOCKED: selected model has no I3C port")?;
    let address = hw
        .i3c_address()
        .context("BLOCKED: selected model has no I3C target address")?;
    let result = start_protocol(port, address.into(), false)?;
    drive_compatibility_protocol(hw, result, timeout)?;

    // The validator can exit successfully even when individual suites fail.
    // Retain the workflow's result-log checks as part of the selected case.
    let log = std::fs::read_to_string(output_dir.join("test.log"))
        .context("SPDM validator did not produce test.log")?;
    validate_conformance_log(&log)
}

fn validate_conformance_log(log: &str) -> Result<()> {
    if !log.lines().any(|line| line == "test result done") {
        bail!("SPDM validator did not report 'test result done'");
    }
    let mut passed = 0u64;
    let mut summaries = 0;
    for line in log.lines().filter(|line| line.contains("test suite (")) {
        let (_, counts) = line
            .rsplit_once(" - pass: ")
            .with_context(|| format!("invalid SPDM validator suite summary: {line}"))?;
        let (pass, fail) = counts
            .split_once(", fail: ")
            .with_context(|| format!("invalid SPDM validator suite counts: {line}"))?;
        let pass: u64 = pass.trim().parse().context("invalid SPDM pass count")?;
        let fail: u64 = fail.trim().parse().context("invalid SPDM failure count")?;
        if fail != 0 {
            bail!("SPDM validator reported failures: {line}");
        }
        passed = passed
            .checked_add(pass)
            .context("SPDM pass count overflow")?;
        summaries += 1;
    }
    if summaries == 0 || passed == 0 {
        bail!("SPDM validator reported no positively passing tests");
    }
    Ok(())
}

pub(crate) fn run_compatibility_attestation(
    hw: &mut DefaultHwModel,
    references: &std::path::Path,
    trust_store: &std::path::Path,
    scenario: &str,
) -> Result<()> {
    let output_dir = stage_compatibility_validator("spdm_requester_emu", scenario)?;
    let verifier = output_dir.join("ocptoken");
    ensure!(verifier.is_file(), "BLOCKED: OCP EAT verifier is missing");
    let references = references.join("signed");
    ensure!(
        references.is_dir() && trust_store.is_dir(),
        "BLOCKED: signed reference values or trust anchors are missing"
    );
    let nonce = std::env::var("SPDM_NONCE").context("BLOCKED: SPDM_NONCE is required")?;
    ensure!(
        nonce.len() == 64 && hex::decode(&nonce)?.len() == 32,
        "Invalid SPDM nonce"
    );
    let port = hw.i3c_port().context("Missing I3C port")?;
    let address = hw.i3c_address().context("Missing I3C address")?;
    let result = start_protocol(port, address.into(), true)?;
    drive_compatibility_protocol(hw, result, Duration::from_secs(180))?;
    for name in ["measurement_block_fd.bin", "certificate_chain_slot_00.der"] {
        ensure!(
            std::fs::metadata(output_dir.join(name))
                .with_context(|| format!("Missing attestation evidence {name}"))?
                .len()
                > 0,
            "Empty attestation evidence {name}"
        );
    }
    for action in ["authenticate", "appraise"] {
        let output = std::process::Command::new(&verifier)
            .arg(action)
            .arg("-e")
            .arg(output_dir.join("measurement_block_fd.bin"))
            .arg("-c")
            .arg(output_dir.join("certificate_chain_slot_00.der"))
            .env("TA_STORE_PATH", trust_store)
            .env("SIGNED_REFVAL_CORIM_PATH", &references)
            .env("SPDM_NONCE", &nonce)
            .output()
            .with_context(|| format!("Cannot execute OCP EAT {action}"))?;
        let log = output_dir.join(format!("{action}.log"));
        let mut bytes = output.stdout.clone();
        bytes.extend_from_slice(&output.stderr);
        std::fs::write(&log, bytes)?;
        ensure!(
            output.status.success(),
            "OCP EAT {action} failed: {}; evidence={}",
            output.status,
            log.display()
        );
        if action == "appraise" {
            ensure!(
                String::from_utf8_lossy(&output.stdout).contains("ATTESTATION RESULT: PASS"),
                "OCP EAT appraisal did not report PASS; evidence={}",
                log.display()
            );
        }
    }
    Ok(())
}

fn stage_compatibility_validator(binary: &str, scenario: &str) -> Result<std::path::PathBuf> {
    let original_dir = std::env::var_os("SPDM_VALIDATOR_DIR")
        .context("BLOCKED: SPDM_VALIDATOR_DIR is required for the selected SPDM suite")?;
    let source = std::fs::canonicalize(&original_dir)
        .context("BLOCKED: SPDM_VALIDATOR_DIR is not an accessible directory")?;
    let path = source.join(binary);
    let metadata = std::fs::metadata(&path)
        .with_context(|| format!("BLOCKED: required tool {} is missing", path.display()))?;
    if !metadata.is_file() {
        bail!("BLOCKED: {} is not a validator executable", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("BLOCKED: {} is not executable", path.display());
        }
    }
    let evidence = std::env::var_os("MCU_COMPAT_EVIDENCE_DIR")
        .context("BLOCKED: MCU_COMPAT_EVIDENCE_DIR is required for persistent SPDM evidence")?;
    std::fs::create_dir_all(&evidence)
        .context("BLOCKED: could not create persistent SPDM evidence directory")?;
    let evidence = std::fs::canonicalize(evidence)?;
    if evidence.starts_with(&source) {
        bail!("BLOCKED: SPDM evidence directory must be outside the shared tool bundle");
    }
    let output_dir = evidence.join(scenario);
    // Never reuse or remove a previous attempt: even a failed attempt's raw
    // files are evidence, and stale validator results cannot establish PASS.
    std::fs::create_dir(&output_dir).with_context(|| {
        format!(
            "BLOCKED: {} must be a new per-case SPDM directory; existing evidence is retained",
            output_dir.display()
        )
    })?;
    copy_compatibility_tool_bundle(&source, &source, &output_dir, &mut Vec::new())?;
    // Each compatibility case runs in its own child process.
    std::env::set_var("SPDM_VALIDATOR_DIR", &output_dir);
    Ok(output_dir)
}

fn copy_compatibility_tool_bundle(
    root: &std::path::Path,
    source: &std::path::Path,
    dest: &std::path::Path,
    ancestors: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let canonical = std::fs::canonicalize(source)?;
    if !canonical.starts_with(root) || ancestors.contains(&canonical) {
        bail!(
            "BLOCKED: tool bundle must be self-contained and acyclic: {}",
            source.display()
        );
    }
    ancestors.push(canonical);
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        // These are generated outputs, not tool dependencies. Do not seed
        // a new case with a shared directory's old protocol results.
        if matches!(
            name.to_str(),
            Some(
                "test.log"
                    | "caliptra_spdm_validator.pcap"
                    | "spdm_device_validator_output.txt"
                    | "spdm_requester_emu_output.txt"
                    | "caliptra-evidence.pcap"
                    | "measurement_block_fd.bin"
                    | "certificate_chain_slot_00.der"
            )
        ) {
            continue;
        }
        let path = entry.path();
        let resolved = std::fs::canonicalize(&path)?;
        if !resolved.starts_with(root) {
            bail!(
                "BLOCKED: tool asset points outside its bundle: {}",
                path.display()
            );
        }
        let dest = dest.join(name);
        let metadata = std::fs::metadata(&path)?;
        if metadata.is_dir() {
            std::fs::create_dir(&dest)?;
            copy_compatibility_tool_bundle(root, &path, &dest, ancestors)?;
        } else if metadata.is_file() {
            std::fs::copy(&path, &dest)
                .with_context(|| format!("BLOCKED: staging SPDM tool asset {}", path.display()))?;
        } else {
            bail!("BLOCKED: unsupported SPDM tool asset {}", path.display());
        }
    }
    ancestors.pop();
    Ok(())
}

fn drive_compatibility_protocol(
    hw: &mut DefaultHwModel,
    result: Receiver<std::result::Result<(), String>>,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        match result.try_recv() {
            Ok(result) => return result.map_err(anyhow::Error::msg),
            Err(mpsc::TryRecvError::Disconnected) => {
                caliptra_mcu_testing_common::stop_emulator();
                bail!("SPDM worker exited without reporting a protocol result");
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if started.elapsed() >= timeout {
            caliptra_mcu_testing_common::stop_emulator();
            bail!(
                "SPDM protocol timed out after {} seconds",
                timeout.as_secs()
            );
        }
        if !caliptra_mcu_testing_common::is_emulator_running() {
            return result
                .recv_timeout(Duration::from_secs(1))
                .context("selected model stopped before reporting an SPDM protocol result")?
                .map_err(anyhow::Error::msg);
        }
        if let Some(error) = hw.mci_fw_fatal_error() {
            caliptra_mcu_testing_common::stop_emulator();
            bail!("selected firmware reported fatal error 0x{error:08x}");
        }
        if hw.mcu_exit_status().is_some() || hw.output().exit_status().is_some() {
            caliptra_mcu_testing_common::stop_emulator();
            bail!("selected firmware exited before reporting an SPDM protocol result");
        }
        hw.step();
    }
}

fn start_protocol(
    port: u16,
    target_addr: DynamicI3cAddress,
    attestation: bool,
) -> Result<Receiver<Result<(), String>>> {
    let (result_tx, result_rx) = mpsc::channel();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).context("could not connect to selected I3C port")?;
    let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
    SERVER_LISTENING.store(false, Ordering::Relaxed);
    caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
        let result = (|| -> Result<(), String> {
            let listener = TcpListener::bind(("127.0.0.1", if attestation { 0 } else { 2323 }))
                .map_err(|err| format!("could not bind SPDM listener: {err}"))?;
            let spdm_port = listener
                .local_addr()
                .map_err(|err| format!("could not read SPDM listener address: {err}"))?
                .port();
            println!("[{TEST_NAME}]: SPDM server listening on port {spdm_port}");
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            listener
                .set_nonblocking(true)
                .map_err(|err| format!("could not configure SPDM listener: {err}"))?;
            let validator = if attestation {
                execute_spdm_attestation_with_port(
                    "MCTP",
                    Some(spdm_port),
                    std::env::var("SPDM_NONCE").ok(),
                )
            } else {
                execute_spdm_responder_validator("MCTP")
            };
            let (mut spdm_stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if !caliptra_mcu_testing_common::is_emulator_running()
                            || validator.is_finished()
                        {
                            caliptra_mcu_testing_common::stop_emulator();
                            let _ = validator.join();
                            return Err("SPDM validator stopped before connecting".to_string());
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => {
                        caliptra_mcu_testing_common::stop_emulator();
                        let _ = validator.join();
                        return Err(format!("failed to accept SPDM connection: {err}"));
                    }
                }
            };
            let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
            test.run_test(&mut spdm_stream);
            if !test.is_passed() {
                caliptra_mcu_testing_common::stop_emulator();
                let _ = validator.join();
                return Err("SPDM transport bridge failed".to_string());
            }

            let validator_passed = validator
                .join()
                .map_err(|_| "SPDM validator worker panicked".to_string())?;
            if !validator_passed {
                return Err("SPDM validator exited unsuccessfully".to_string());
            }

            println!("[{TEST_NAME}]: SPDM protocol completed");
            Ok(())
        })();

        let _ = result_tx.send(result);
    });

    Ok(result_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_requires_positive_counts_and_no_failures() {
        assert!(validate_conformance_log(
            "test suite (version) - pass: 2, fail: 0\ntest result done"
        )
        .is_ok());
        for log in [
            "test result done",
            "test suite (version) - pass: 0, fail: 0\ntest result done",
            "test suite (version) - pass: 2, fail: 1\ntest result done",
            "test suite (version) - pass: 2, fail: 0",
            "test suite (version) - pass: invalid, fail: 0\ntest result done",
        ] {
            assert!(validate_conformance_log(log).is_err(), "{log}");
        }
    }

    #[test]
    fn service_selection_preserves_boot_configurations() {
        use super::super::SelectedPair;
        for scenario in [
            "suite_spdm_mctp",
            "suite_attestation_ocp_eat_non_tcb",
            "suite_attestation_ocp_eat_tcb",
            "suite_attestation_ocp_eat_mixed",
        ] {
            assert_eq!(
                SelectedPair::service_configuration(scenario, "flash"),
                "flash"
            );
        }
        for (scenario, expected) in [
            ("suite_spdm_mctp", "services-non-tcb"),
            ("suite_attestation_ocp_eat_non_tcb", "services-non-tcb"),
            ("suite_attestation_ocp_eat_tcb", "services-tcb"),
            ("suite_attestation_ocp_eat_mixed", "services-mixed"),
            ("warm_reset", "streaming"),
            ("suite_provisioning", "streaming"),
        ] {
            assert_eq!(
                SelectedPair::service_configuration(scenario, "streaming"),
                expected
            );
        }
    }
}
