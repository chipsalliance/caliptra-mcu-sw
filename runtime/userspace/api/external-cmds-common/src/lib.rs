// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![feature(impl_trait_in_assoc_type)]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use zerocopy::{Immutable, IntoBytes};

pub const MAX_FW_VERSION_LEN: usize = 32;
pub const MAX_UID_LEN: usize = 32;

/// Common error type for unified commands.
#[derive(Debug)]
pub enum CommandError {
    InvalidParams,
    RespLengthTooLarge,
    InternalError,
    NotSupported,
    Busy,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FirmwareVersion {
    pub len: usize,
    pub ver_str: [u8; MAX_FW_VERSION_LEN],
}

#[repr(C)]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Uid {
    pub len: usize,
    pub unique_chip_id: [u8; MAX_UID_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceInfo {
    Uid(Uid),
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, Immutable, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub caliptra_rt: [u8; 8],  // Bytes [0:7]
    pub caliptra_fmc: [u8; 4], // Bytes [8:11]
    pub caliptra_rom: [u8; 4], // Bytes [12:15]
    pub mcu_rt: [u8; 8],       // Bytes [16:23]
    pub mcu_rom: [u8; 4],      // Bytes [24:27]
    pub reserved: [u8; 4],     // Bytes [28:31]
}

/// Asynchronous trait for handling commands common to both external MCU mailbox and MCTP VDM protocols.
///
/// Each function represents a protocol-agnostic command handler. Implementors should provide
/// the specific logic for each command as required by their application.
#[async_trait]
pub trait UnifiedCommandHandler {
    /// Retrieves the firmware version for the given index.
    ///
    /// # Arguments
    /// * `index` - The firmware index to query.
    /// * `version` - Mutable reference to store the firmware version.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> Result<(), CommandError>;

    /// Retrieves the device ID.
    ///
    /// # Arguments
    /// * `device_id` - Mutable reference to store the device ID.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_id(&self, device_id: &mut DeviceId) -> Result<(), CommandError>;

    /// Retrieves device information for the given index.
    ///
    /// # Arguments
    /// * `index` - The device info index to query.
    /// * `info` - Mutable reference to store the device info.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> Result<(), CommandError>;

    /// Retrieves the device capabilities.
    ///
    /// # Arguments
    /// * `capabilities` - Mutable reference to store the device capabilities.
    ///
    /// # Returns
    /// * `Result<(), CommandError>` - Ok on success, or an error.
    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> Result<(), CommandError>;
}
