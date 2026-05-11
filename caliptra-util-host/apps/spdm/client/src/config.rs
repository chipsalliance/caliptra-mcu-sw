// Licensed under the Apache-2.0 license

//! Validator test configuration (TOML-based).
//!
//! Each VDM command has its own config section. Adding a new command:
//! 1. Add a new config struct (e.g., `GetFirmwareVersionConfig`)
//! 2. Add it as a `#[serde(default)]` field in `TestConfig`

use clap::ValueEnum;
use serde::Deserialize;
use std::path::Path;

/// Device mode determines which test suite to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    /// Production mode: ExportAttestedCsr + ExportIdevidCsr(expect_fail)
    #[default]
    Production,
    /// Manufacturing mode: ExportIdevidCsr only
    Manufacturing,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TestConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub spdm: SpdmTestConfig,
    #[serde(default)]
    pub mode: DeviceMode,
    #[serde(default)]
    pub export_attested_csr: ExportAttestedCsrConfig,
    #[serde(default)]
    pub export_idevid_csr: ExportIdevidCsrConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_server_address")]
    pub server_address: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            server_address: default_server_address(),
        }
    }
}

fn default_server_address() -> String {
    "127.0.0.1:2323".to_string()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SpdmTestConfig {
    #[serde(default)]
    pub slot_id: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportAttestedCsrConfig {
    #[serde(default = "default_key_ids")]
    pub key_ids: Vec<u32>,
    #[serde(default = "default_algorithm")]
    pub algorithm: u32,
}

fn default_key_ids() -> Vec<u32> {
    vec![0, 1, 2]
}

fn default_algorithm() -> u32 {
    1
}

impl Default for ExportAttestedCsrConfig {
    fn default() -> Self {
        Self {
            key_ids: default_key_ids(),
            algorithm: default_algorithm(),
        }
    }
}

impl TestConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportIdevidCsrConfig {
    /// Algorithms to test (0x0001=ECC384, 0x0002=MLDSA87)
    #[serde(default = "default_idevid_algorithms")]
    pub algorithms: Vec<u32>,
}

fn default_idevid_algorithms() -> Vec<u32> {
    vec![1] // ECC384 by default
}

impl Default for ExportIdevidCsrConfig {
    fn default() -> Self {
        Self {
            algorithms: default_idevid_algorithms(),
        }
    }
}
