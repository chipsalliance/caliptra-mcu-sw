// Licensed under the Apache-2.0 license

//! Integration tests for caliptra-util-host
//!
//! This module organizes all integration tests in a single library
//! to avoid the need to list each test file in Cargo.toml

// Common test utilities and mock implementations
pub mod common;

// Test modules - each contains its own #[test] functions
#[cfg(test)]
pub mod integration_tests;

#[cfg(test)]
pub mod test_get_device_id;

#[cfg(test)]
pub mod test_get_device_info;

#[cfg(test)]
pub mod test_get_device_capabilities;

#[cfg(test)]
pub mod test_get_firmware_version;

#[cfg(test)]
pub mod test_aes;

#[cfg(test)]
pub mod test_hmac;

#[cfg(test)]
pub mod test_sha;
