// Licensed under the Apache-2.0 license

//! Target platform definitions for MCU firmware builds.

use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use clap::ValueEnum;

/// Target platform for MCU firmware builds.
///
/// Represents the hardware target for which firmware is being built.
/// The platform affects which manifest files are used, which features
/// are enabled, and where output binaries are placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, ValueEnum)]
pub enum Platform {
    /// Software emulator platform (default).
    #[default]
    Emulator,
    /// FPGA hardware platform.
    Fpga,
}

impl Platform {
    /// Returns the string representation of the platform.
    ///
    /// This is used for file paths, manifest lookups, and display purposes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Emulator => "emulator",
            Platform::Fpga => "fpga",
        }
    }

    /// Returns the platform based on compile-time feature flags.
    ///
    /// Returns `Platform::Fpga` if the `fpga_realtime` feature is enabled,
    /// otherwise returns `Platform::Emulator`.
    pub fn from_feature_flag() -> Self {
        if cfg!(feature = "fpga_realtime") {
            Platform::Fpga
        } else {
            Platform::Emulator
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Platform {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "emulator" => Ok(Platform::Emulator),
            "fpga" => Ok(Platform::Fpga),
            _ => Err(anyhow!(
                "Invalid platform '{}', expected 'emulator' or 'fpga'",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_emulator() {
        assert_eq!(Platform::default(), Platform::Emulator);
    }

    #[test]
    fn test_as_str() {
        assert_eq!(Platform::Emulator.as_str(), "emulator");
        assert_eq!(Platform::Fpga.as_str(), "fpga");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Platform::Emulator), "emulator");
        assert_eq!(format!("{}", Platform::Fpga), "fpga");
    }

    #[test]
    fn test_from_str() {
        assert_eq!("emulator".parse::<Platform>().unwrap(), Platform::Emulator);
        assert_eq!("fpga".parse::<Platform>().unwrap(), Platform::Fpga);
        assert!("invalid".parse::<Platform>().is_err());
    }

    #[test]
    fn test_equality() {
        assert_eq!(Platform::Emulator, Platform::Emulator);
        assert_eq!(Platform::Fpga, Platform::Fpga);
        assert_ne!(Platform::Emulator, Platform::Fpga);
    }
}
