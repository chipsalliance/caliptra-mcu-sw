// Licensed under the Apache-2.0 license

//! SPDM VDM validation runner for Caliptra VDM commands.
//!
//! Uses `SpdmVdmClient` typed interfaces for command execution,
//! handles result collection and reporting.
//!
//! To add a new command:
//! 1. Add a typed method in `SpdmVdmClient` (lib.rs)
//! 2. Add `run_<command>()` function below
//! 3. Call it from `run_all()`
//! 4. Add a config section in `config.rs`

use crate::config::{DeviceMode, TestConfig};
use crate::SpdmVdmClient;
use caliptra_mcu_core_util_host_command_types::certificate::AttestedCsrValidationError;

/// Result of a single validation check.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub status: ValidationStatus,
    pub detail: Option<String>,
}

/// Outcome of a validation check.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationStatus {
    Pass,
    Fail,
    Skip,
}

impl ValidationResult {
    pub fn pass(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Pass,
            detail: Some(detail.into()),
        }
    }

    pub fn fail(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Fail,
            detail: Some(detail.into()),
        }
    }

    pub fn skip(test_name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            status: ValidationStatus::Skip,
            detail: Some(detail.into()),
        }
    }
}

/// Print a summary table of validation results.
pub fn print_summary(results: &[ValidationResult]) {
    println!("\nValidation Summary");
    println!("==================");
    for r in results {
        let tag = match r.status {
            ValidationStatus::Pass => "PASS",
            ValidationStatus::Fail => "FAIL",
            ValidationStatus::Skip => "SKIP",
        };
        print!("  [{tag}] {}", r.test_name);
        if let Some(msg) = &r.detail {
            print!(" — {msg}");
        }
        println!();
    }
    let passed = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Pass)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.status == ValidationStatus::Skip)
        .count();
    let total = results.len() - skipped;
    println!("\n  {passed}/{total} tests passed ({skipped} skipped)");
}

/// Returns true if all non-skipped results passed.
pub fn all_passed(results: &[ValidationResult]) -> bool {
    results
        .iter()
        .all(|r| r.status == ValidationStatus::Pass || r.status == ValidationStatus::Skip)
}

/// Run all VDM command validations using the typed SpdmVdmClient.
///
/// Test suite depends on the configured DeviceMode:
/// - Production: ExportAttestedCsr + ExportIdevidCsr(expect_fail)
/// - Manufacturing: ExportIdevidCsr only
pub fn run_all(
    client: &mut SpdmVdmClient,
    config: &TestConfig,
    verbose: bool,
) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    match config.mode {
        DeviceMode::Production => {
            results.extend(run_export_attested_csr(
                client,
                &config.export_attested_csr.key_ids,
                config.export_attested_csr.algorithm,
                verbose,
            ));
            results.extend(run_export_idevid_csr_expect_fail(
                client,
                &config.export_idevid_csr.algorithms,
                verbose,
            ));
        }
        DeviceMode::Manufacturing => {
            results.extend(run_export_idevid_csr(
                client,
                &config.export_idevid_csr.algorithms,
                verbose,
            ));
        }
    }

    results
}

/// Validate ExportAttestedCsr for each key ID using the typed client.
pub fn run_export_attested_csr(
    client: &mut SpdmVdmClient,
    key_ids: &[u32],
    algorithm: u32,
    verbose: bool,
) -> Vec<ValidationResult> {
    let nonce = [0xABu8; 32];
    key_ids
        .iter()
        .map(|&key_id| {
            let test_name = format!("ExportAttestedCsr(key_id={})", key_id);
            match client.export_attested_csr(key_id, algorithm, &nonce) {
                Ok(response) => match response.validate_csr_payload() {
                    Ok(len) => {
                        if verbose {
                            println!("  csr: {} bytes", len);
                        }
                        ValidationResult::pass(test_name, format!("{} bytes", len))
                    }
                    Err(AttestedCsrValidationError::Empty) => {
                        ValidationResult::fail(test_name, "CSR data is empty")
                    }
                    Err(AttestedCsrValidationError::TooLarge(len)) => ValidationResult::fail(
                        test_name,
                        format!("CSR data_len {} exceeds maximum", len),
                    ),
                },
                Err(msg) => {
                    let msg_str = format!("{}", msg);
                    if msg_str.contains("NotSupported") {
                        ValidationResult::skip(test_name, msg_str)
                    } else {
                        ValidationResult::fail(test_name, msg_str)
                    }
                }
            }
        })
        .collect()
}

/// Validate ExportIdevidCsr for each algorithm (manufacturing mode).
pub fn run_export_idevid_csr(
    client: &mut SpdmVdmClient,
    algorithms: &[u32],
    verbose: bool,
) -> Vec<ValidationResult> {
    algorithms
        .iter()
        .map(|&algorithm| {
            let test_name = format!("ExportIdevidCsr(algorithm={})", algorithm);
            match client.export_idevid_csr(algorithm) {
                Ok(response) => match response.validate_csr_payload() {
                    Ok(len) => {
                        if verbose {
                            println!("  csr: {} bytes", len);
                        }
                        ValidationResult::pass(test_name, format!("{} bytes", len))
                    }
                    Err(AttestedCsrValidationError::Empty) => {
                        ValidationResult::fail(test_name, "CSR data is empty")
                    }
                    Err(AttestedCsrValidationError::TooLarge(len)) => ValidationResult::fail(
                        test_name,
                        format!("CSR data_len {} exceeds maximum", len),
                    ),
                },
                Err(msg) => {
                    let msg_str = format!("{}", msg);
                    if msg_str.contains("NotSupported") {
                        ValidationResult::skip(test_name, msg_str)
                    } else {
                        ValidationResult::fail(test_name, msg_str)
                    }
                }
            }
        })
        .collect()
}

/// Negative test: ExportIdevidCsr should be rejected in production mode.
pub fn run_export_idevid_csr_expect_fail(
    client: &mut SpdmVdmClient,
    algorithms: &[u32],
    verbose: bool,
) -> Vec<ValidationResult> {
    algorithms
        .iter()
        .map(|&algorithm| {
            let test_name = format!("ExportIdevidCsr(algorithm={},expect_fail)", algorithm);
            match client.export_idevid_csr(algorithm) {
                Ok(_response) => {
                    if verbose {
                        println!("  Expected rejection but got success");
                    }
                    ValidationResult::fail(
                        test_name,
                        "Expected device to reject ExportIdevidCsr in production mode",
                    )
                }
                Err(_) => ValidationResult::pass(
                    test_name,
                    "Device correctly rejected ExportIdevidCsr in production mode",
                ),
            }
        })
        .collect()
}
