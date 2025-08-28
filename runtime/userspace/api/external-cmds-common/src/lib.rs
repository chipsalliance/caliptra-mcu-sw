// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![feature(impl_trait_in_assoc_type)]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;

/// Common error type for unified commands.
#[derive(Debug)]
pub enum CommandError {
    InvalidCommand,
    InvalidInput,
    InternalError,
    NotSupported,
    Busy,
}

/// Firmware Version structure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub len: usize,
    pub ver_str: [u8; 32],
}

/// Device ID structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
}

/// Device Info structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uid {
    pub unique_chip_id: [u8; 32],
    pub len: usize,
}

pub enum DeviceInfo {
    Uid,
}

/// Device Capabilities structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub supports_csr: bool,
    pub supports_cert_import: bool,
    pub supports_log: bool,
    pub supports_debug_unlock: bool,
    // Add more capabilities as needed.
}

/// Unified command handler trait.
///
/// Each command has its own async handler. The trait is protocol-agnostic.
#[async_trait]
pub trait UnifiedCommandHandler {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> Result<(), CommandError>;

    async fn get_device_id(&self) -> Result<DeviceId, CommandError>;

    // Index 0 is to get chip UID
    async fn get_device_info(&self, index: u32) -> Result<DeviceInfo, CommandError>;

    async fn get_device_capabilities(&self) -> Result<DeviceCapabilities, CommandError>;
    // Add more commands as needed...
}
