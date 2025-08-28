// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::cell::RefCell;
use embassy_sync::lazy_lock::LazyLock;

// Add the correct import for UnifiedCommandHandler
use crate::mcu_mbox::config;
use external_cmds_common::{
    CommandError, DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, UnifiedCommandHandler,
};

pub struct NonCryptoCmdHandlerMock;

#[allow(dead_code)]
impl NonCryptoCmdHandlerMock {
    pub fn new() -> Self {
        NonCryptoCmdHandlerMock
    }
}

#[async_trait]
/// Mock implementation of the `UnifiedCommandHandler` trait for non-cryptographic commands.
///
/// This handler provides stubbed or mock responses for firmware version queries,
/// device ID, device information, and device capabilities. Intended for use in
/// testing or emulation environments where actual hardware interaction is not required.
impl UnifiedCommandHandler for NonCryptoCmdHandlerMock {
    /// Retrieves the firmware version string for the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The firmware component index:
    ///     * `0` - Caliptra core firmware version
    ///     * `1` - MCU runtime firmware version
    ///     * `2` - SOC firmware version
    /// * `version` - Mutable reference to a `FirmwareVersion` struct to be populated.
    ///
    /// # Errors
    ///
    /// Returns `CommandError::InvalidInput` if the index is not recognized.
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> Result<(), CommandError> {
        let s = match index {
            0 => config::CALIPTRA_CORE_VERSION,
            1 => config::MCU_RT_VERSION,
            2 => config::SOC_FW_VERSION,
            _ => return Err(CommandError::InvalidInput),
        };

        let bytes = s.as_bytes();
        if bytes.len() > 32 {
            return Err(CommandError::InvalidInput);
        }
        let len = bytes.len().min(version.ver_str.len());
        version.ver_str[..len].copy_from_slice(&bytes[..len]);
        version.len = len;

        Ok(())
    }

    async fn get_device_id(&self) -> Result<DeviceId, CommandError> {
        todo!()
    }

    // Index 0 is to get chip UID
    async fn get_device_info(&self, index: u32) -> Result<DeviceInfo, CommandError> {
        todo!()
    }

    async fn get_device_capabilities(&self) -> Result<DeviceCapabilities, CommandError> {
        todo!()
    }
}
