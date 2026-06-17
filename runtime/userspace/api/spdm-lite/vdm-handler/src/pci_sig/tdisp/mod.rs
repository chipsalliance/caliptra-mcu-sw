// Licensed under the Apache-2.0 license

//! TDISP protocol responder for PCI-SIG VDMs.
//!
//! This module implements a fixed-storage TDISP responder using static command
//! dispatch, no boxed futures, and no heap-backed handler tables. Request
//! decoding and response generation are handled command-by-command.

mod commands;
mod driver;
mod protocol;
mod state;

use mcu_spdm_lite_codec::errors::{SPDM_INVALID_REQUEST, SPDM_VERSION_MISMATCH};
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc, SpdmPalIo, VdmResponse};

pub use driver::{TdispDriver, TdispDriverError, TdispDriverResult};
pub use protocol::{
    FunctionId, InterfaceId, TdiStatus, TdispCommand, TdispErrorCode, TdispLockInterfaceFlags,
    TdispLockInterfaceParam, TdispReqCapabilities, TdispRespCapabilities, TdispVersion,
    START_INTERFACE_NONCE_SIZE, TDISP_ERROR_BUSY, TDISP_ERROR_INSUFFICIENT_ENTROPY,
    TDISP_ERROR_INVALID_DEVICE_CONFIGURATION, TDISP_ERROR_INVALID_INTERFACE,
    TDISP_ERROR_INVALID_INTERFACE_STATE, TDISP_ERROR_INVALID_NONCE, TDISP_ERROR_INVALID_REQUEST,
    TDISP_ERROR_UNSPECIFIED, TDISP_ERROR_UNSUPPORTED_REQUEST, TDISP_ERROR_VENDOR_SPECIFIC_ERROR,
    TDISP_ERROR_VERSION_MISMATCH, TDISP_VERSION_1_0,
};
pub use state::MAX_TDISP_INTERFACES;

use protocol::{TdispMessageHeader, TDISP_HEADER_LEN};
use state::TdispState;

/// TDISP responder with fixed-size state storage.
pub struct TdispResponder<D> {
    pub(crate) supported_versions: &'static [TdispVersion],
    pub(crate) driver: D,
    pub(crate) state: TdispState,
}

impl<D> TdispResponder<D> {
    /// Creates a TDISP responder.
    pub fn new(supported_versions: &'static [TdispVersion], driver: D) -> Option<Self> {
        if supported_versions.is_empty() {
            return None;
        }
        Some(Self {
            supported_versions,
            driver,
            state: TdispState::new(),
        })
    }

    /// Returns the inner driver.
    pub fn driver(&self) -> &D {
        &self.driver
    }
}

impl<D> TdispResponder<D>
where
    D: TdispDriver,
{
    /// Handles a TDISP payload excluding the PCI-SIG protocol id byte.
    pub async fn handle_tdisp_payload<Alloc, Io>(
        &self,
        payload: &[u8],
        scratch: &Alloc,
        io: &Io,
        out: &mut [u8],
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        let (req_hdr, req_payload) = TdispMessageHeader::decode(payload)?;

        if TdispVersion::try_from(req_hdr.version).is_err() {
            return Err(SPDM_VERSION_MISMATCH);
        }

        let req_code = match TdispCommand::try_from(req_hdr.message_type) {
            Ok(command) => command,
            Err(_) => {
                return commands::error_rsp::write_error(
                    req_hdr.version,
                    req_hdr.interface_id,
                    TDISP_ERROR_UNSUPPORTED_REQUEST,
                    req_hdr.message_type as u32,
                    out,
                );
            }
        };

        if req_payload.len() != req_code.payload_len() {
            return commands::error_rsp::write_error(
                req_hdr.version,
                req_hdr.interface_id,
                TDISP_ERROR_INVALID_REQUEST,
                0,
                out,
            );
        }

        let result = match req_code {
            TdispCommand::GetTdispVersion => {
                commands::get_tdisp_version::handle(self, req_hdr, out)
            }
            TdispCommand::GetTdispCapabilities => {
                commands::get_tdisp_capabilities::handle(
                    self,
                    req_hdr,
                    req_payload,
                    scratch,
                    io,
                    out,
                )
                .await
            }
            TdispCommand::LockInterface => {
                commands::lock_interface::handle(self, req_hdr, req_payload, scratch, io, out).await
            }
            TdispCommand::GetDeviceInterfaceReport => {
                commands::device_interface_report::handle(
                    self,
                    req_hdr,
                    req_payload,
                    scratch,
                    io,
                    out,
                )
                .await
            }
            TdispCommand::GetDeviceInterfaceState => {
                commands::device_interface_state::handle(self, req_hdr, scratch, io, out).await
            }
            TdispCommand::StartInterfaceRequest => {
                commands::start_interface::handle(self, req_hdr, req_payload, scratch, io).await
            }
            TdispCommand::StopInterfaceRequest => {
                commands::stop_interface::handle(self, req_hdr, scratch, io).await
            }
            TdispCommand::BindP2PStreamRequest
            | TdispCommand::UnbindP2PStreamRequest
            | TdispCommand::SetMmioAttributeRequest
            | TdispCommand::VdmRequest => Ok(TdispHandlerResult::Error(
                TDISP_ERROR_UNSUPPORTED_REQUEST,
                req_hdr.message_type as u32,
            )),
            _ => Err(SPDM_INVALID_REQUEST),
        }?;

        match result {
            TdispHandlerResult::Response(payload_len) => {
                let Some(response_code) = req_code.response() else {
                    return Err(SPDM_INVALID_REQUEST);
                };
                TdispMessageHeader::new(req_hdr.version, response_code, req_hdr.interface_id)
                    .encode(out)?;
                Ok(VdmResponse::Inline(TDISP_HEADER_LEN + payload_len))
            }
            TdispHandlerResult::Error(error, data) => commands::error_rsp::write_error(
                req_hdr.version,
                req_hdr.interface_id,
                error,
                data,
                out,
            ),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TdispHandlerResult {
    Response(usize),
    Error(TdispErrorCode, u32),
}
