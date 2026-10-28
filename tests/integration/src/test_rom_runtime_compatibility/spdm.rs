// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
use caliptra_mcu_testing_common::spdm_responder_validator::{
    execute_spdm_responder_validator, SpdmValidatorRunner, SERVER_LISTENING,
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
    let output_dir = stage_compatibility_validator("spdm_device_validator_sample")?;

    let timeout = Duration::from_secs(9000);
    let port = hw
        .i3c_port()
        .context("BLOCKED: selected model has no I3C port")?;
    let address = hw
        .i3c_address()
        .context("BLOCKED: selected model has no I3C target address")?;
    let result = start_conformance(port, address.into())?;
    drive_compatibility_protocol(hw, result, timeout)?;

    // The validator can exit successfully even when individual suites fail.
    // Retain the workflow's result-log checks as part of the selected case.
    let log = std::fs::read_to_string(output_dir.join("test.log"))
        .context("SPDM validator did not produce test.log")?;
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

fn stage_compatibility_validator(binary: &str) -> Result<std::path::PathBuf> {
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
    let output_dir = evidence.join("spdm-validator");
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
            bail!("selected model stopped before reporting an SPDM protocol result");
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

fn start_conformance(
    port: u16,
    target_addr: DynamicI3cAddress,
) -> Result<Receiver<Result<(), String>>> {
    let (result_tx, result_rx) = mpsc::channel();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect(addr).context("could not connect to selected I3C port")?;
    let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
    SERVER_LISTENING.store(false, Ordering::Relaxed);
    caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
        let result = (|| -> Result<(), String> {
            let listener = TcpListener::bind("127.0.0.1:2323")
                .map_err(|err| format!("could not bind SPDM listener: {err}"))?;
            println!("[{TEST_NAME}]: SPDM server listening on port 2323");
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            listener
                .set_nonblocking(true)
                .map_err(|err| format!("could not configure SPDM listener: {err}"))?;
            let validator = execute_spdm_responder_validator("MCTP");
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

            println!("[{TEST_NAME}]: SPDM responder conformance passed");
            Ok(())
        })();

        let _ = result_tx.send(result);
        caliptra_mcu_testing_common::stop_emulator();
    });

    Ok(result_rx)
}
