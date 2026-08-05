// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_DEVICE_CAPABILITIES: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 2, 0, 0xEF, 0, 0,
    0, 9, 0, 0, 0, 0,
];

/// Shared configuration for caliptra-util-host tests
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

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub default_server_address: String,
}

/// Validation test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub verbose_output: bool,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub max_connections: u32,
}

/// Device capabilities configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilitiesConfig {
    #[serde(with = "capabilities_serde")]
    pub capabilities: [u8; 36],
    pub fips_status: u32,
}

mod capabilities_serde {
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(capabilities: &[u8; 36], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        capabilities.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 36], D::Error>
    where
        D: Deserializer<'de>,
    {
        let capabilities = Vec::<u8>::deserialize(deserializer)?;
        let len = capabilities.len();
        capabilities
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected 36 capability bytes, got {len}")))
    }
}

/// Firmware version configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareVersionConfig {
    pub rom_version: String,
    pub runtime_version: String,
    pub fips_status: u32,
    pub rom_firmware_id: u32,
    pub runtime_firmware_id: u32,
}

impl TestConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;

        let config: TestConfig =
            toml::from_str(&contents).with_context(|| "Failed to parse TOML configuration")?;

        Ok(config)
    }

    /// Load default configuration from the standard test-config.toml location
    pub fn load_default() -> Result<Self> {
        // Try to find test-config.toml in current directory or parent directories
        let mut current_dir = std::env::current_dir()?;

        loop {
            let config_path = current_dir.join("test-config.toml");
            if config_path.exists() {
                return Self::from_file(config_path);
            }

            // Try apps/mailbox subdirectory (new standard location)
            let mailbox_config = current_dir
                .join("apps")
                .join("mailbox")
                .join("test-config.toml");
            if mailbox_config.exists() {
                return Self::from_file(mailbox_config);
            }

            // Try caliptra-util-host subdirectory
            let caliptra_config = current_dir
                .join("caliptra-util-host")
                .join("test-config.toml");
            if caliptra_config.exists() {
                return Self::from_file(caliptra_config);
            }

            // Try caliptra-util-host/apps/mailbox subdirectory
            let caliptra_mailbox_config = current_dir
                .join("caliptra-util-host")
                .join("apps")
                .join("mailbox")
                .join("test-config.toml");
            if caliptra_mailbox_config.exists() {
                return Self::from_file(caliptra_mailbox_config);
            }

            // Move up one directory
            if let Some(parent) = current_dir.parent() {
                current_dir = parent.to_path_buf();
            } else {
                break;
            }
        }

        // If no config file found, return default values
        Ok(Self::default())
    }

    /// Save configuration to a TOML file
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
                default_server_address: "127.0.0.1:62222".to_string(),
            },
            validation: ValidationConfig {
                timeout_seconds: 30,
                retry_count: 3,
                verbose_output: false,
            },
            server: ServerConfig {
                bind_address: "127.0.0.1:62222".to_string(),
                max_connections: 10,
            },
            device_capabilities: Some(DeviceCapabilitiesConfig {
                capabilities: DEFAULT_DEVICE_CAPABILITIES,
                fips_status: 0x00000001,
            }),
            firmware_version: Some(FirmwareVersionConfig {
                rom_version: "1.2.3.4567-mock_commit_hash".to_string(),
                runtime_version: "1.2.3.4567-mock_commit_hash".to_string(),
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

        assert_eq!(capabilities.len(), 36);
        assert_eq!(&capabilities[20..24], &0x0000_00FFu32.to_be_bytes());
        assert_eq!(&capabilities[24..28], &0x0002_00EFu32.to_be_bytes());
        assert_eq!(&capabilities[28..32], &0x0000_0009u32.to_be_bytes());
    }
}
