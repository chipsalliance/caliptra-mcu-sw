// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use caliptra_mcu_hw_model::{DefaultHwModel, McuHwModel};
use caliptra_mcu_testing_common::i3c::DynamicI3cAddress;
use caliptra_mcu_testing_common::i3c_socket::BufferedStream;
use caliptra_mcu_testing_common::spdm_responder_validator::mctp::MctpTransport;
use caliptra_mcu_testing_common::spdm_responder_validator::{
    execute_spdm_responder_validator, SpdmValidatorRunner, SERVER_LISTENING,
};
use caliptra_mcu_testing_common::{
    wait_for_runtime_start, wait_for_spdm_responder_ready, SpdmResponderTransport,
};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const TEST_NAME: &str = "MCTP-SPDM-RESPONDER-VALIDATOR";

/// Verification inputs for the parent's pinned-source support report.
/// Advertised versions/algorithms must be read from these definitions, not
/// inferred from release labels or from the current host crate.
#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn compatibility_spdm_source_checks() -> serde_json::Value {
    serde_json::json!([
        {
            "path": "platforms/emulator/runtime/userspace/apps/user/Cargo.toml",
            "symbols": ["spdm", "doe", "pcr-quote", "test-mctp-spdm-attestation-pcr-quote", "test-doe-spdm-tdisp-ide-validator"],
            "role": "Compare actual selected feature closure; baseline lacks spdm, service lacks doe and the test-selected PCR provider"
        },
        {
            "path": "platforms/emulator/runtime/userspace/apps/user/src/main.rs",
            "symbols": ["async_main", "boot_init", "spawn_spdm_tasks"],
            "role": "Measurement boot initialization precedes SPDM task startup"
        },
        {
            "path": "platforms/emulator/runtime/userspace/apps/user/src/spdm/mod.rs",
            "symbols": ["spawn_spdm_tasks", "spdm_mctp_responder", "spdm_doe_responder", "measurement_provider", "pci_sig_vdm"],
            "role": "MCTP startup; DOE requires doe; spdm-rs TDISP/IDE path requires test-doe-spdm-tdisp-ide-validator; OCP EAT is default; PCR provider requires test-mctp-spdm-attestation-pcr-quote"
        },
        {
            "path": "runtime/userspace/api/spdm-lib/stack/src/version.rs",
            "symbols": ["SUPPORTED_VERSIONS", "handle_get_version"],
            "role": "Exact advertised version list from pinned source"
        },
        {
            "path": "runtime/userspace/api/spdm-lib/stack/src/stack.rs",
            "symbols": ["ConnectionState", "caliptra"],
            "role": "Exact capability and algorithm defaults: meas_hash_algo, base_asym_sel, base_hash_sel, dhe, aead, key_schedule, and optional pqc_asym_sel/kem"
        },
        {
            "path": "runtime/userspace/api/spdm-lib/stack/src/algorithms.rs",
            "symbols": ["handle_negotiate_algorithms"],
            "role": "Version/capability-dependent algorithm selection; defaults alone do not prove every combination"
        },
        {
            "path": "runtime/userspace/api/spdm-lib/pal/src/measurements/providers/ocp_eat.rs",
            "symbols": ["OcpEatMeasurementProvider", "get_measurement_value"],
            "role": "Production OCP EAT measurement provider implementation"
        }
    ])
}

/// The caller owns the selected image, boot readiness and live transport
/// services. Copy the complete tool bundle into persistent per-case evidence
/// storage; the existing launcher writes through `SPDM_VALIDATOR_DIR`.
#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn run_compatibility_conformance(hw: &mut DefaultHwModel) -> Result<()> {
    let bundle = std::sync::Arc::new(stage_compatibility_validator(
        "spdm_device_validator_sample",
    )?);
    let output_dir = &bundle.output_dir;
    std::fs::write(
        output_dir.join("spdm-source-checks.json"),
        serde_json::to_vec_pretty(&compatibility_spdm_source_checks())?,
    )
    .context("could not retain SPDM source-support verification inputs")?;

    let timeout = Duration::from_secs(9000);
    let port = hw
        .i3c_port()
        .context("BLOCKED: selected model has no I3C port")?;
    let address = hw
        .i3c_address()
        .context("BLOCKED: selected model has no I3C target address")?;
    let result = run_mctp_spdm_conformance_test_inner(
        port,
        address.into(),
        timeout,
        true,
        Some(bundle.clone()),
    );
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

#[cfg(not(feature = "fpga_realtime"))]
struct StagedValidatorBundle {
    output_dir: std::path::PathBuf,
    original_dir: std::ffi::OsString,
}

#[cfg(not(feature = "fpga_realtime"))]
impl Drop for StagedValidatorBundle {
    fn drop(&mut self) {
        std::env::set_var("SPDM_VALIDATOR_DIR", &self.original_dir);
    }
}

#[cfg(not(feature = "fpga_realtime"))]
fn stage_compatibility_validator(binary: &str) -> Result<StagedValidatorBundle> {
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
    std::env::set_var("SPDM_VALIDATOR_DIR", &output_dir);
    Ok(StagedValidatorBundle {
        output_dir,
        original_dir,
    })
}

#[cfg(not(feature = "fpga_realtime"))]
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

#[cfg(not(feature = "fpga_realtime"))]
pub(crate) fn drive_compatibility_protocol(
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
        if hw.output().exit_status().is_some() {
            caliptra_mcu_testing_common::stop_emulator();
            bail!("selected firmware exited before reporting an SPDM protocol result");
        }
        hw.step();
    }
}

fn run_mctp_spdm_conformance_test_inner<Guard: Send + 'static>(
    port: u16,
    target_addr: DynamicI3cAddress,
    test_timeout: Duration,
    selected_model_ready: bool,
    bundle_guard: Option<Guard>,
) -> Receiver<Result<(), String>> {
    let (result_tx, result_rx) = mpsc::channel();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = match TcpStream::connect(addr) {
        Ok(stream) => stream,
        Err(err) if selected_model_ready => {
            let _ = result_tx.send(Err(format!(
                "could not connect to selected I3C port: {err}"
            )));
            return result_rx;
        }
        Err(err) => panic!("could not connect to I3C port: {err}"),
    };
    let transport = MctpTransport::new(BufferedStream::new(stream), target_addr.into(), 1);
    let (timeout_cancel_tx, timeout_cancel_rx) = mpsc::channel();

    let timeout_result_tx = result_tx.clone();
    caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
        if timeout_cancel_rx.recv_timeout(test_timeout).is_err() {
            let message = format!(
                "{TEST_NAME} timed out after {} seconds",
                test_timeout.as_secs()
            );
            println!("[{TEST_NAME}] {message}");
            let _ = timeout_result_tx.send(Err(message));
            caliptra_mcu_testing_common::stop_emulator();
        }
    });

    SERVER_LISTENING.store(false, Ordering::Relaxed);
    caliptra_mcu_testing_common::spawn_with_emulator_state(move || {
        // A failed model can return to the caller before this worker exits.
        // Retain the staged environment until its launcher has finished.
        let _bundle_guard = bundle_guard;
        if !selected_model_ready {
            wait_for_runtime_start();
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }
            wait_for_spdm_responder_ready(SpdmResponderTransport::Mctp);
            if !caliptra_mcu_testing_common::is_emulator_running() {
                return;
            }
        }

        let result = (|| -> Result<(), String> {
            let listener = TcpListener::bind("127.0.0.1:2323")
                .map_err(|err| format!("could not bind SPDM listener: {err}"))?;
            println!("[{TEST_NAME}]: SPDM server listening on port 2323");
            SERVER_LISTENING.store(true, Ordering::Relaxed);

            if selected_model_ready {
                listener
                    .set_nonblocking(true)
                    .map_err(|err| format!("could not configure SPDM listener: {err}"))?;
            }
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
                        if selected_model_ready {
                            caliptra_mcu_testing_common::stop_emulator();
                            let _ = validator.join();
                        }
                        return Err(format!("failed to accept SPDM connection: {err}"));
                    }
                }
            };
            let mut test = SpdmValidatorRunner::new(Box::new(transport), TEST_NAME);
            test.run_test(&mut spdm_stream);
            if selected_model_ready && !test.is_passed() {
                caliptra_mcu_testing_common::stop_emulator();
                let _ = validator.join();
                return Err("SPDM transport bridge failed".to_string());
            }

            let validator_passed = validator
                .join()
                .map_err(|_| "SPDM validator worker panicked".to_string())?;
            if !test.is_passed() {
                return Err("SPDM transport bridge failed".to_string());
            }
            if !validator_passed {
                return Err("SPDM validator exited unsuccessfully".to_string());
            }

            println!("[{TEST_NAME}]: SPDM responder conformance passed");
            Ok(())
        })();

        let _ = timeout_cancel_tx.send(());
        let _ = result_tx.send(result);
        caliptra_mcu_testing_common::stop_emulator();
    });

    result_rx
}
