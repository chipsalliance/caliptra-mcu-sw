// Licensed under the Apache-2.0 license

//! Baseline Caliptra MCU implementation of `UnifiedCommandHandler`.
//!
//! This module provides the production command handler backed by the Caliptra
//! mailbox API. It is consumed by both the SPDM VDM handler and the MCU
//! mailbox command interface.

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_external_cmds_common::{
    AttestedCsrData, CommandError, DeviceCapabilities, DeviceId, DeviceInfo, FirmwareVersion,
    UnifiedCommandHandler,
};
use caliptra_mcu_libapi_caliptra::certificate::CertContext;
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;

/// Production command handler that delegates to the Caliptra mailbox API.
///
/// Currently only `export_attested_csr` is implemented; all other commands
/// return `NotSupported` until their backend integrations are complete.
pub struct CaliptraCmdHandler;

#[async_trait]
impl UnifiedCommandHandler for CaliptraCmdHandler {
    async fn get_firmware_version(
        &self,
        _index: u32,
        _version: &mut FirmwareVersion,
    ) -> Result<(), CommandError> {
        Err(CommandError::NotSupported)
    }

    async fn get_device_id(&self, _device_id: &mut DeviceId) -> Result<(), CommandError> {
        Err(CommandError::NotSupported)
    }

    async fn get_device_info(
        &self,
        _index: u32,
        _info: &mut DeviceInfo,
    ) -> Result<(), CommandError> {
        Err(CommandError::NotSupported)
    }

    async fn get_device_capabilities(
        &self,
        _capabilities: &mut DeviceCapabilities,
    ) -> Result<(), CommandError> {
        Err(CommandError::NotSupported)
    }

    async fn export_attested_csr(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_data: &mut AttestedCsrData,
    ) -> Result<(), CommandError> {
        let algo = AsymAlgo::try_from_u32(algorithm).ok_or(CommandError::InvalidParams)?;

        let mut cert_ctx = CertContext::new();

        // Write directly into csr_data.data to avoid a redundant 12800-byte
        // buffer that would inflate the boxed async_trait future beyond the
        // MCU heap budget.
        let len = cert_ctx
            .get_attested_csr(algo, device_key_id, nonce, &mut csr_data.data)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CommandError::Busy,
                CaliptraApiError::InvalidArgument(_) => CommandError::InvalidParams,
                CaliptraApiError::AsymAlgoUnsupported => CommandError::InvalidParams,
                _ => CommandError::InternalError,
            })?;

        csr_data.len = len;
        Ok(())
    }
}
