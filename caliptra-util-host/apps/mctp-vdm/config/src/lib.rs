// Licensed under the Apache-2.0 license

//! Shared configuration for MCTP VDM test client and server.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level test configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub device: DeviceConfig,
    pub network: NetworkConfig,
    pub validation: ValidationConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub device_capabilities: Option<DeviceCapabilitiesConfig>,
    #[serde(default)]
    pub firmware_version: Option<FirmwareVersionConfig>,
    #[serde(default)]
    pub device_info: Option<DeviceInfoConfig>,
}

/// Device identification values returned by the emulated device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: u16,
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

/// Network configuration (TCP socket to I3C controller).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub default_server_address: String,
    /// I3C dynamic address of the target device (default: 0x08).
    #[serde(default = "default_target_i3c_address")]
    pub target_i3c_address: u8,
}

fn default_target_i3c_address() -> u8 {
    0x08
}

/// Validation test tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub verbose_output: bool,
}

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub max_connections: u32,
}

/// Expected device capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilitiesConfig {
    pub capabilities: u32,
    pub max_cert_size: u32,
    pub max_csr_size: u32,
    pub device_lifecycle: u32,
    pub fips_status: u32,
}

/// Expected firmware version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareVersionConfig {
    pub rom_version: String,
    pub runtime_version: String,
    pub fips_status: u32,
    pub rom_firmware_id: u32,
    pub runtime_firmware_id: u32,
}

/// Expected device information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfoConfig {
    pub info_index: u32,
    pub expected_info: String,
    pub min_info_length: u32,
    pub max_info_length: u32,
    pub fips_status: u32,
}

impl TestConfig {
    /// Load configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: TestConfig =
            toml::from_str(&contents).with_context(|| "Failed to parse TOML configuration")?;
        Ok(config)
    }

    /// Search standard locations for a `test-config.toml`.
    pub fn load_default() -> Result<Self> {
        let mut current_dir = std::env::current_dir()?;
        loop {
            for candidate in &[
                current_dir.join("test-config.toml"),
                current_dir
                    .join("apps")
                    .join("mctp-vdm")
                    .join("test-config.toml"),
                current_dir
                    .join("caliptra-util-host")
                    .join("apps")
                    .join("mctp-vdm")
                    .join("test-config.toml"),
            ] {
                if candidate.exists() {
                    return Self::from_file(candidate);
                }
            }
            if let Some(parent) = current_dir.parent() {
                current_dir = parent.to_path_buf();
            } else {
                break;
            }
        }
        Ok(Self::default())
    }

    /// Save configuration to a TOML file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize configuration to TOML")?;
        std::fs::write(path.as_ref(), contents)
            .with_context(|| format!("Failed to write config file: {:?}", path.as_ref()))?;
        Ok(())
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            device: DeviceConfig {
                device_id: 0x0010,
                vendor_id: 0x1414,
                subsystem_vendor_id: 0x0001,
                subsystem_id: 0x0002,
            },
            network: NetworkConfig {
                default_server_address: "127.0.0.1:63333".to_string(),
                target_i3c_address: 0x08,
            },
            validation: ValidationConfig {
                timeout_seconds: 30,
                retry_count: 3,
                verbose_output: false,
            },
            server: ServerConfig {
                bind_address: "127.0.0.1:63333".to_string(),
                max_connections: 10,
            },
            device_capabilities: Some(DeviceCapabilitiesConfig {
                capabilities: 0x000001F3,
                max_cert_size: 4096,
                max_csr_size: 2048,
                device_lifecycle: 1,
                fips_status: 0x00000001,
            }),
            firmware_version: Some(FirmwareVersionConfig {
                rom_version: "1.0.0".to_string(),
                runtime_version: "1.0.0".to_string(),
                fips_status: 0x00000001,
                rom_firmware_id: 0,
                runtime_firmware_id: 1,
            }),
            device_info: Some(DeviceInfoConfig {
                info_index: 0,
                expected_info: "Caliptra VDM Test Device v1.0".to_string(),
                min_info_length: 16,
                max_info_length: 64,
                fips_status: 0,
            }),
        }
    }
}
