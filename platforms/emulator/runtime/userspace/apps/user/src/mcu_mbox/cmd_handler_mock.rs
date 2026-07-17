// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DebugUnlockChallenge,
    DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion, GetLogResult, Uid,
    MAX_FW_VERSION_LEN, MAX_UID_LEN,
};
use caliptra_mcu_mbox_common::config;
use mcu_caliptra_api_lite::ApiAlloc;

use crate::caliptra_cmd_handler::CaliptraCmdBackend;

// TODO: Remove this mock and use CaliptraCmdBackend directly.
#[derive(Default)]
pub struct NonCryptoCmdHandlerMock;

/// Mock implementation of the `CaliptraCmdHandler` trait.
///
/// This handler provides mock responses for firmware version queries,
/// device ID, device information, and device capabilities. Intended to use for
/// integration testing on the emulator platform.
impl CaliptraCmdHandler for NonCryptoCmdHandlerMock {
    async fn get_firmware_version(
        &self,
        index: u32,
        version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        let s = match index {
            0 => config::TEST_FIRMWARE_VERSIONS[0],
            1 => config::TEST_FIRMWARE_VERSIONS[1],
            2 => config::TEST_FIRMWARE_VERSIONS[2],
            3 => config::TEST_FIRMWARE_VERSIONS[3],
            _ => return Err(CaliptraCompletionCode::InvalidParameter),
        };

        let bytes = s.as_bytes();
        if bytes.len() > MAX_FW_VERSION_LEN {
            return Err(CaliptraCompletionCode::InvalidPayloadSize);
        }
        let len = bytes.len().min(version.ver_str.len());
        version.ver_str[..len].copy_from_slice(&bytes[..len]);
        version.len = len;
        Ok(())
    }

    async fn get_device_id(&self, device_id: &mut DeviceId) -> CaliptraCmdResult<()> {
        let test_device_id = &config::TEST_DEVICE_ID;
        device_id.vendor_id = test_device_id.vendor_id;
        device_id.device_id = test_device_id.device_id;
        device_id.subsystem_vendor_id = test_device_id.subsystem_vendor_id;
        device_id.subsystem_id = test_device_id.subsystem_id;
        Ok(())
    }

    async fn get_device_info(&self, index: u32, info: &mut DeviceInfo) -> CaliptraCmdResult<()> {
        match index {
            0 => {
                let test_uid = &config::TEST_UID;
                if test_uid.len() > MAX_UID_LEN {
                    return Err(CaliptraCompletionCode::InvalidPayloadSize);
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
            _ => Err(CaliptraCompletionCode::InvalidParameter),
        }
    }

    async fn get_device_capabilities(
        &self,
        capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        let test_capabilities = &config::TEST_DEVICE_CAPABILITIES;
        capabilities.caliptra_rt = test_capabilities.caliptra_rt;
        capabilities.caliptra_fmc = test_capabilities.caliptra_fmc;
        capabilities.caliptra_rom = test_capabilities.caliptra_rom;
        capabilities.mcu_rt = test_capabilities.mcu_rt;
        capabilities.mcu_rom = test_capabilities.mcu_rom;
        capabilities.reserved = test_capabilities.reserved;
        Ok(())
    }

    async fn export_attested_csr<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        // Delegate to real CaliptraCmdBackend for actual Caliptra mailbox interaction
        let handler = CaliptraCmdBackend;
        handler
            .export_attested_csr(alloc, device_key_id, algorithm, nonce, csr_buf)
            .await
    }

    async fn request_debug_unlock<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        unlock_level: u8,
        challenge: &mut DebugUnlockChallenge,
    ) -> CaliptraCmdResult<()> {
        let handler = CaliptraCmdBackend;
        handler
            .request_debug_unlock(alloc, unlock_level, challenge)
            .await
    }

    async fn authorize_debug_unlock_token<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        token_request: &[u8],
    ) -> CaliptraCmdResult<()> {
        let handler = CaliptraCmdBackend;
        handler
            .authorize_debug_unlock_token(alloc, token_request)
            .await
    }

    async fn get_log(&self, log_type: u32, data: &mut [u8]) -> CaliptraCmdResult<GetLogResult> {
        // Delegate to the production backend so the real Tock logging-flash
        // path is exercised end-to-end by mailbox command tests.
        CaliptraCmdBackend.get_log(log_type, data).await
    }

    async fn clear_log(&self, log_type: u32) -> CaliptraCmdResult<()> {
        CaliptraCmdBackend.clear_log(log_type).await
    }

    async fn program_field_entropy<Alloc: ApiAlloc>(
        &self,
        alloc: &Alloc,
        partition: u32,
    ) -> CaliptraCmdResult<()> {
        CaliptraCmdBackend
            .program_field_entropy(alloc, partition)
            .await
    }
}
