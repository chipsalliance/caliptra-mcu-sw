// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use core::fmt::Write;
use external_cmds_common::{
    CommandError, DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, Uid,
    UnifiedCommandHandler, MAX_FW_VERSION_LEN, MAX_UID_LEN,
};
use libsyscall_caliptra::logging::LoggingSyscall;
use libsyscall_caliptra::DefaultSyscalls;
use libtock_console::Console;
use mcu_mbox_common::config;

#[derive(Default)]
pub struct NonCryptoCmdHandlerMock;

/// Max size for a single log entry read buffer.
const LOG_ENTRY_BUF_SIZE: usize = 256;

/// Mock implementation of the `UnifiedCommandHandler` trait.
///
/// This handler provides mock responses for firmware version queries,
/// device ID, device information, and device capabilities. Intended to use for
/// integration testing on the emulator platform.
///
/// For logging commands, the handler uses the real `LoggingSyscall` API to
/// read/clear entries from the flash-backed logging driver.
#[async_trait]
impl UnifiedCommandHandler for NonCryptoCmdHandlerMock {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> Result<(), CommandError> {
        let s = match index {
            0 => config::TEST_FIRMWARE_VERSIONS[0],
            1 => config::TEST_FIRMWARE_VERSIONS[1],
            2 => config::TEST_FIRMWARE_VERSIONS[2],
            _ => return Err(CommandError::InvalidParams),
        };

        let bytes = s.as_bytes();
        if bytes.len() > MAX_FW_VERSION_LEN {
            return Err(CommandError::RespLengthTooLarge);
        }
        let len = bytes.len().min(version.ver_str.len());
        version.ver_str[..len].copy_from_slice(&bytes[..len]);
        version.len = len;
        Ok(())
    }

    async fn get_device_id(&self, device_id: &mut DeviceId) -> Result<(), CommandError> {
        let test_device_id = &config::TEST_DEVICE_ID;
        device_id.vendor_id = test_device_id.vendor_id;
        device_id.device_id = test_device_id.device_id;
        device_id.subsystem_vendor_id = test_device_id.subsystem_vendor_id;
        device_id.subsystem_id = test_device_id.subsystem_id;
        Ok(())
    }

    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> Result<(), CommandError> {
        match index {
            0 => {
                let test_uid = &config::TEST_UID;
                if test_uid.len() > MAX_UID_LEN {
                    return Err(CommandError::RespLengthTooLarge);
                }
                let mut unique_chip_id = [0u8; MAX_UID_LEN];
                unique_chip_id[..test_uid.len()].copy_from_slice(&test_uid[..]);
                let uid = Uid {
                    len: test_uid.len(),
                    unique_chip_id,
                };
                *info = DeviceInfo::Uid(uid);
                Ok(())
            }
            _ => Err(CommandError::InvalidParams),
        }
    }

    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> Result<(), CommandError> {
        let test_capabilities = &config::TEST_DEVICE_CAPABILITIES;
        capabilities.caliptra_rt = test_capabilities.caliptra_rt;
        capabilities.caliptra_fmc = test_capabilities.caliptra_fmc;
        capabilities.caliptra_rom = test_capabilities.caliptra_rom;
        capabilities.mcu_rt = test_capabilities.mcu_rt;
        capabilities.mcu_rom = test_capabilities.mcu_rom;
        capabilities.reserved = test_capabilities.reserved;
        Ok(())
    }

    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> Result<usize, CommandError> {
        if log_type != 0 {
            return Err(CommandError::InvalidParams);
        }

        let mut console_writer = Console::<DefaultSyscalls>::writer();
        writeln!(console_writer, "GetLog: start log_type={}", log_type).unwrap();

        let log: LoggingSyscall = LoggingSyscall::new();

        if log.exists().is_err() {
            // Logging driver not available — return empty data
            writeln!(console_writer, "GetLog: logging driver not available").unwrap();
            return Ok(0);
        }

        log.seek_beginning()
            .await
            .map_err(|_| CommandError::InternalError)?;
        writeln!(console_writer, "GetLog: seek_beginning OK").unwrap();

        let mut offset = 0;
        let mut entry_buf = [0u8; LOG_ENTRY_BUF_SIZE];
        loop {
            match log.read_entry(&mut entry_buf).await {
                Ok(len) => {
                    if offset + len > data.len() {
                        writeln!(
                            console_writer,
                            "GetLog: buffer full offset={} len={} data_len={}",
                            offset,
                            len,
                            data.len()
                        )
                        .unwrap();
                        break;
                    }
                    data[offset..offset + len].copy_from_slice(&entry_buf[..len]);
                    offset += len;
                }
                Err(_) => {
                    break;
                }
            }
        }

        writeln!(console_writer, "GetLog: done bytes_read={}", offset).unwrap();

        Ok(offset)
    }

    async fn clear_log(&self, log_type: u32) -> Result<(), CommandError> {
        if log_type != 0 {
            return Err(CommandError::InvalidParams);
        }

        let log: LoggingSyscall = LoggingSyscall::new();
        log.clear().await.map_err(|_| CommandError::InternalError)
    }
}
