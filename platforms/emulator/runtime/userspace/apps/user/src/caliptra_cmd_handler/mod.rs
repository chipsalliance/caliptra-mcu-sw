// Licensed under the Apache-2.0 license

//! Baseline Caliptra MCU implementation of `CaliptraCmdHandler`.
//!
//! This module provides the production command handler backed by the Caliptra
//! mailbox API. It is consumed by both the SPDM VDM handler and the MCU
//! mailbox command interface.

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_common_commands::{
    CaliptraCmdHandler, CaliptraCmdResult, CaliptraCompletionCode, DeviceCapabilities, DeviceId,
    DeviceInfo, FirmwareVersion,
};
use caliptra_mcu_libapi_caliptra::certificate::{CertContext, IDEV_ECC_CSR_MAX_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::error::CaliptraApiError;

/// Production command handler that delegates to the Caliptra mailbox API.
///
/// Currently only `export_attested_csr` is implemented; all other commands
/// return `NotSupported` until their backend integrations are complete.
pub struct CaliptraCmdBackend;

#[async_trait]
impl CaliptraCmdHandler for CaliptraCmdBackend {
    async fn get_firmware_version(
        &self,
        _index: u32,
        _version: &mut FirmwareVersion,
    ) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_id(&self, _device_id: &mut DeviceId) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_info(&self, _index: u32, _info: &mut DeviceInfo) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn get_device_capabilities(
        &self,
        _capabilities: &mut DeviceCapabilities,
    ) -> CaliptraCmdResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    async fn export_attested_csr(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let algo =
            AsymAlgo::try_from_u32(algorithm).ok_or(CaliptraCompletionCode::InvalidParameter)?;

        let mut cert_ctx = CertContext::new();

        let len = cert_ctx
            .get_attested_csr(algo, device_key_id, nonce, csr_buf)
            .await
            .map_err(|e| match e {
                CaliptraApiError::MailboxBusy => CaliptraCompletionCode::CaliptraMailboxBusy,
                CaliptraApiError::InvalidArgument(_) => CaliptraCompletionCode::InvalidParameter,
                CaliptraApiError::AsymAlgoUnsupported => {
                    CaliptraCompletionCode::UnsupportedOperation
                }
                CaliptraApiError::BufferTooSmall => CaliptraCompletionCode::CaliptraBufferTooSmall,
                _ => CaliptraCompletionCode::GeneralError,
            })?;

        Ok(len)
    }

    async fn export_idevid_csr(
        &self,
        algorithm: u32,
        csr_buf: &mut [u8],
    ) -> CaliptraCmdResult<usize> {
        let algo =
            AsymAlgo::try_from_u32(algorithm).ok_or(CaliptraCompletionCode::InvalidParameter)?;

        let mut cert_ctx = CertContext::new();

        match algo {
            AsymAlgo::EccP384 => {
                let mut csr_der = [0u8; IDEV_ECC_CSR_MAX_SIZE];
                let len = cert_ctx
                    .get_idev_csr(&mut csr_der)
                    .await
                    .map_err(|e| match e {
                        CaliptraApiError::MailboxBusy => {
                            CaliptraCompletionCode::CaliptraMailboxBusy
                        }
                        CaliptraApiError::UnprovisionedCsr => CaliptraCompletionCode::InvalidState,
                        CaliptraApiError::BufferTooSmall => {
                            CaliptraCompletionCode::CaliptraBufferTooSmall
                        }
                        _ => CaliptraCompletionCode::GeneralError,
                    })?;
                if len > csr_buf.len() {
                    return Err(CaliptraCompletionCode::CaliptraBufferTooSmall);
                }
                csr_buf[..len].copy_from_slice(&csr_der[..len]);
                Ok(len)
            }
            AsymAlgo::MlDsa87 => {
                // MLDSA IDevID CSR not yet supported at the mailbox level
                Err(CaliptraCompletionCode::UnsupportedOperation)
            }
        }
    }
}
