// Licensed under the Apache-2.0 license

//! Shared configuration for MCTP VDM test client and server.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const DEVICE_CAPABILITIES_SIZE: usize = 64;

const DEFAULT_DEVICE_CAPABILITIES: [u8; DEVICE_CAPABILITIES_SIZE] = {
    let mut capabilities = [0; DEVICE_CAPABILITIES_SIZE];
    capabilities[7] = 1;
    capabilities[15] = 1;
    capabilities[23] = 0xFF;
    capabilities[25] = 2;
    capabilities[27] = 0xEF;
    capabilities[31] = 9;
    capabilities
};

/// Top-level test configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub network: NetworkConfig,
    pub validation: ValidationConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub device_capabilities: Option<DeviceCapabilitiesConfig>,
    #[serde(default)]
    pub firmware_version: Option<FirmwareVersionConfig>,
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
    #[serde(with = "capabilities_serde")]
    pub capabilities: [u8; DEVICE_CAPABILITIES_SIZE],
    pub fips_status: u32,
}

mod capabilities_serde {
    use super::DEVICE_CAPABILITIES_SIZE;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        capabilities: &[u8; DEVICE_CAPABILITIES_SIZE],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        capabilities.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; DEVICE_CAPABILITIES_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        let capabilities = Vec::<u8>::deserialize(deserializer)?;
        let len = capabilities.len();
        capabilities.try_into().map_err(|_| {
            D::Error::custom(format!(
                "expected {DEVICE_CAPABILITIES_SIZE} capability bytes, got {len}"
            ))
        })
    }
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
                capabilities: DEFAULT_DEVICE_CAPABILITIES,
                fips_status: 0x00000001,
            }),
            firmware_version: Some(FirmwareVersionConfig {
                rom_version: "1.0.0".to_string(),
                runtime_version: "1.0.0".to_string(),
                fips_status: 0x00000001,
                rom_firmware_id: 0,
                runtime_firmware_id: 1,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_has_complete_device_capabilities() {
        let config: TestConfig = toml::from_str(include_str!("../../test-config.toml")).unwrap();
        let capabilities = config.device_capabilities.unwrap().capabilities;

        assert_eq!(capabilities.len(), DEVICE_CAPABILITIES_SIZE);
        assert_eq!(&capabilities[20..24], &0x0000_00FFu32.to_be_bytes());
        assert_eq!(&capabilities[24..28], &0x0002_00EFu32.to_be_bytes());
        assert_eq!(&capabilities[28..32], &0x0000_0009u32.to_be_bytes());
        assert_eq!(&capabilities[32..48], &[0; 16]);
        assert_eq!(&capabilities[48..64], &[0; 16]);
    }
}
