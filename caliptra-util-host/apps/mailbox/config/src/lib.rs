// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Shared configuration for caliptra-util-host tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub device: DeviceConfig,
    pub network: NetworkConfig,
    pub validation: ValidationConfig,
    pub server: ServerConfig,
}

/// Device identification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub device_id: u16,
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
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
            device: DeviceConfig {
                device_id: 0x0010,
                vendor_id: 0x1414,
                subsystem_vendor_id: 0x0001,
                subsystem_id: 0x0002,
            },
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
        }
    }
}
