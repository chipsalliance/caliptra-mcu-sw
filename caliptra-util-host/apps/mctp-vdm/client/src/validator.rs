// Licensed under the Apache-2.0 license

//! Validator for MCTP VDM client — runs the supported direct MCTP VDM commands
//! against a VDM server and reports pass/fail. Optionally also runs a defmt
//! debug-log round-trip check that exercises `VdmClient::drain_debug_log` +
//! `decode_defmt_stream` against the device's user-app ELF.

use crate::{decode_defmt_stream, DynamicI3cAddress, MctpVdmSocketDriver, TestConfig, VdmClient};
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Optional defmt debug-log round-trip check.
#[derive(Debug, Clone)]
pub struct DefmtRoundTripCheck {
    /// User-app ELF bytes (must contain the `.defmt` table for the firmware
    /// the device is currently running).
    pub elf: Vec<u8>,
    /// Messages that must appear in the decoded stream.
    pub expected_messages: Vec<String>,
    /// Substring that must NOT appear in any decoded message (used to assert
    /// oversized-frame drops).
    pub forbidden_substring: Option<String>,
    /// How long to keep draining + decoding before giving up.
    pub timeout: Duration,
    /// Sleep between drain iterations while waiting for expected messages.
    pub poll_interval: Duration,
}

impl DefmtRoundTripCheck {
    pub fn new(elf: Vec<u8>, expected_messages: Vec<String>) -> Self {
        Self {
            elf,
            expected_messages,
            forbidden_substring: None,
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(100),
        }
    }

    pub fn with_forbidden_substring(mut self, marker: impl Into<String>) -> Self {
        self.forbidden_substring = Some(marker.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }
}

/// Single validation result.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub passed: bool,
    pub error_message: Option<String>,
}

/// MCTP VDM Validator.
pub struct Validator {
    port: u16,
    target_addr: DynamicI3cAddress,
    verbose: bool,
    defmt_check: Option<DefmtRoundTripCheck>,
}

impl Validator {
    /// Create a validator from a test configuration.
    pub fn new(config: &TestConfig) -> Result<Self> {
        let addr: SocketAddr = config.network.default_server_address.parse()?;
        Ok(Self {
            port: addr.port(),
            target_addr: DynamicI3cAddress::from(config.network.target_i3c_address),
            verbose: config.validation.verbose_output,
            defmt_check: None,
        })
    }

    /// Toggle verbose output.
    pub fn set_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Configure an additional defmt debug-log round-trip check. When set,
    /// `start()` issues `drain_debug_log` until all expected messages decode
    /// against the supplied ELF (or until the timeout elapses) and appends a
    /// `DefmtRoundTrip` entry to the validation results.
    pub fn with_defmt_round_trip(mut self, check: DefmtRoundTripCheck) -> Self {
        self.defmt_check = Some(check);
        self
    }

    /// Run all validation tests and return results.
    pub fn start(&self) -> Result<Vec<ValidationResult>> {
        let mut driver = MctpVdmSocketDriver::new(self.port, self.target_addr);
        let mut client = VdmClient::new(&mut driver);
        client.connect()?;

        let mut results = vec![
            self.validate_get_device_capabilities(&mut client),
            self.validate_get_firmware_version(&mut client),
        ];

        if let Some(check) = &self.defmt_check {
            results.push(self.validate_defmt_round_trip(&mut client, check));
        }

        results.push(self.validate_clear_debug_log(&mut client));

        client.disconnect().ok();

        self.print_summary(&results);
        Ok(results)
    }

    // ------------------------------------------------------------------
    // Individual validators
    // ------------------------------------------------------------------

    fn validate_get_device_capabilities(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetDeviceCapabilities".to_string();
        match client.get_device_capabilities() {
            Ok(resp) => {
                if self.verbose {
                    println!(
                        "  Capabilities: caps=0x{:08X} lifecycle={}",
                        resp.capabilities, resp.device_lifecycle,
                    );
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    fn validate_get_firmware_version(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "GetFirmwareVersion".to_string();
        match client.get_firmware_version(0) {
            Ok(resp) => {
                if self.verbose {
                    println!(
                        "  FirmwareVersion: {}.{}.{}.{}",
                        resp.version[0], resp.version[1], resp.version[2], resp.version[3],
                    );
                }
                ValidationResult {
                    test_name,
                    passed: true,
                    error_message: None,
                }
            }
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    fn validate_clear_debug_log(&self, client: &mut VdmClient) -> ValidationResult {
        let test_name = "ClearDebugLog".to_string();
        match client.clear_debug_log() {
            Ok(_) => ValidationResult {
                test_name,
                passed: true,
                error_message: None,
            },
            Err(e) => ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("{e:#}")),
            },
        }
    }

    /// Drain the device debug log via `VdmClient::drain_debug_log`, decode the
    /// accumulated frames against the supplied user-app ELF using
    /// `decode_defmt_stream`, and verify that every expected message is
    /// present (with optional negative assertion on a forbidden substring).
    ///
    /// The drain is retried in a poll loop because the device-side log flush
    /// is asynchronous — frames may not all be available on the first call
    /// after boot.
    fn validate_defmt_round_trip(
        &self,
        client: &mut VdmClient,
        check: &DefmtRoundTripCheck,
    ) -> ValidationResult {
        let test_name = "DefmtRoundTrip".to_string();

        let mut bytes: Vec<u8> = Vec::new();
        let mut messages: Vec<String> = Vec::new();
        let mut last_decode_err: Option<String> = None;
        let deadline = Instant::now() + check.timeout;

        while Instant::now() < deadline {
            match client.drain_debug_log() {
                Ok(page) => {
                    if !page.is_empty() {
                        bytes.extend_from_slice(&page);
                        match decode_defmt_stream(&check.elf, &bytes) {
                            Ok(msgs) => {
                                messages = msgs;
                                last_decode_err = None;
                            }
                            Err(e) => {
                                last_decode_err = Some(format!("{e:#}"));
                            }
                        }
                    }
                }
                Err(e) => {
                    if self.verbose {
                        println!("  drain_debug_log failed: {e:#}");
                    }
                }
            }

            if check
                .expected_messages
                .iter()
                .all(|expected| messages.iter().any(|m| m == expected))
            {
                break;
            }
            std::thread::sleep(check.poll_interval);
        }

        if let Some(err) = last_decode_err {
            return ValidationResult {
                test_name,
                passed: false,
                error_message: Some(format!("decode error: {err}")),
            };
        }

        for expected in &check.expected_messages {
            if !messages.iter().any(|m| m == expected) {
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!(
                        "expected message {expected:?} not found; decoded {:?}",
                        messages
                    )),
                };
            }
        }

        if let Some(marker) = &check.forbidden_substring {
            if let Some(bad) = messages.iter().find(|m| m.contains(marker)) {
                return ValidationResult {
                    test_name,
                    passed: false,
                    error_message: Some(format!(
                        "forbidden substring {marker:?} found in decoded message {bad:?}"
                    )),
                };
            }
        }

        if self.verbose {
            println!(
                "  DefmtRoundTrip: decoded {} messages, {} bytes drained",
                messages.len(),
                bytes.len()
            );
        }

        ValidationResult {
            test_name,
            passed: true,
            error_message: None,
        }
    }

    // ------------------------------------------------------------------

    fn print_summary(&self, results: &[ValidationResult]) {
        println!("\nValidation Summary");
        println!("==================");
        for r in results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            print!("  [{status}] {}", r.test_name);
            if let Some(msg) = &r.error_message {
                print!(" — {msg}");
            }
            println!();
        }
        let passed = results.iter().filter(|r| r.passed).count();
        println!("\n  {passed}/{} tests passed", results.len());
    }
}
