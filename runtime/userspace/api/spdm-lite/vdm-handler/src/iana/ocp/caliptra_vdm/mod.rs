// Licensed under the Apache-2.0 license

//! Caliptra VENDOR_DEFINED Message (VDM) backend.
//!
//! Implements [`SpdmVdmBackend`] for the Caliptra VDM protocol (IANA standards
//! body, vendor id [`protocol::CALIPTRA_VENDOR_ID`]). The backend decodes the
//! Caliptra VDM message header, dispatches the command, and frames the response.
//! Per-command device operations are provided by the platform through the
//! [`CaliptraVdmCommands`] PAL hook — the protocol/dispatch stays in this lib,
//! only the device work crosses to the platform.

mod commands;
pub mod protocol;

use mcu_error::codes::INVARIANT;
use mcu_spdm_lite_codec::StandardsBodyId;
use mcu_spdm_lite_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};

pub use protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmCommand, CaliptraVdmResult,
    CALIPTRA_VDM_COMMAND_VERSION, CALIPTRA_VENDOR_ID,
};

/// Caliptra VDM message header length: `[command_version, command_code]`.
const VDM_HEADER_LEN: usize = 2;

/// Platform hook for executing Caliptra VDM commands ("device operations").
///
/// The protocol and dispatch layers live in this crate; the platform implements
/// this trait to perform the actual device work (e.g. Caliptra mailbox calls).
/// Each method writes its command-specific response data into `out` and returns
/// the number of bytes written, or a [`CaliptraCompletionCode`] on failure
/// (surfaced as a VDM error completion, not an SPDM error).
///
/// `scratch`/`io` give each device op the request-scoped scratch allocator (and
/// the I/O handle that scopes it) so it can stage device interactions — e.g.
/// building a Caliptra mailbox request and receiving its response — without
/// owning persistent buffers.
pub trait CaliptraVdmCommands {
    /// Retrieves the firmware version string for `area_index` into `out`.
    async fn firmware_version<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        area_index: u32,
        scratch: &A,
        io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;

    /// Exports an attested CSR for `device_key_id` using `algorithm` and `nonce`,
    /// writing the raw CSR bytes into `out` and returning their length.
    ///
    /// This is the largest Caliptra VDM response, which is why the backend sets
    /// `USES_LARGE_RESPONSE`; the lib decides inline vs chunked framing from the
    /// returned length.
    async fn export_attested_csr<A: SpdmPalAlloc, I: SpdmPalIo>(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        scratch: &A,
        io: &I,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;
}

/// Caliptra VDM backend, parameterized over a platform [`CaliptraVdmCommands`] hook.
pub struct CaliptraVdm<'a, H: CaliptraVdmCommands> {
    cmds: &'a H,
}

impl<'a, H: CaliptraVdmCommands> CaliptraVdm<'a, H> {
    /// Creates a backend that dispatches commands to `cmds`.
    pub fn new(cmds: &'a H) -> Self {
        Self { cmds }
    }
}

impl<H: CaliptraVdmCommands> SpdmVdmBackend for CaliptraVdm<'_, H> {
    // Caliptra VDM can emit responses (CSRs, logs) larger than one transport
    // frame. TODO(stack-vdm-large): the large path is stubbed in the stack until
    // the chunking work in increment 6.
    const USES_LARGE_RESPONSE: bool = true;

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        registry.standard_id == StandardsBodyId::Iana.as_u16()
            && registry.vendor_id == CALIPTRA_VENDOR_ID.to_le_bytes()
    }

    async fn handle_request<Alloc, Io>(
        &self,
        req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        // Decode the Caliptra VDM header `[command_version, command_code]`. A
        // truncated header leaves no command code to echo, so no vendor-defined
        // response can be formed; the handler returns a plain McuError and the
        // stack classifies it into an SPDM ERROR PDU.
        if req.len() < VDM_HEADER_LEN {
            return Err(INVARIANT);
        }
        let command_version = req[0];
        let command_code = req[1];
        let cmd_req = &req[VDM_HEADER_LEN..];

        let VdmResponseBuffer {
            inline: out,
            large,
            alloc,
            io,
        } = rsp;
        // No room for even the response header + completion code → no
        // vendor-defined response can be formed; surfaced as an SPDM error by
        // the stack.
        if out.len() < VDM_HEADER_LEN + 1 {
            return Err(INVARIANT);
        }
        // Echo the response header (version + command code).
        out[0] = CALIPTRA_VDM_COMMAND_VERSION;
        out[1] = command_code;
        let payload = &mut out[VDM_HEADER_LEN..];

        // A mismatched command version is reported as a VDM completion, not an
        // SPDM error (the envelope itself is well-formed).
        if command_version != CALIPTRA_VDM_COMMAND_VERSION {
            payload[0] = CaliptraCompletionCode::InvalidCommandVersion as u8;
            return Ok(VdmResponse::Inline(VDM_HEADER_LEN + 1));
        }

        let result = match CaliptraVdmCommand::try_from(command_code) {
            Ok(CaliptraVdmCommand::FirmwareVersion) => {
                commands::firmware_version::handle(self.cmds, cmd_req, alloc, io, payload).await
            }
            Ok(CaliptraVdmCommand::ExportAttestedCsr) => {
                commands::export_attested_csr::handle(
                    self.cmds,
                    cmd_req,
                    command_code,
                    payload,
                    large,
                    alloc,
                    io,
                )
                .await
            }
            // Recognized-but-unimplemented and unknown command codes both map to
            // an UnsupportedOperation completion.
            _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::UnsupportedOperation),
        };

        match result {
            CaliptraVdmCmdResult::Response(n) => Ok(VdmResponse::Inline(VDM_HEADER_LEN + n)),
            // The command wrote the complete VDM payload (header + data) into `large`.
            CaliptraVdmCmdResult::Large(n) => Ok(VdmResponse::Large(n)),
            CaliptraVdmCmdResult::Error(code) => {
                payload[0] = code as u8;
                Ok(VdmResponse::Inline(VDM_HEADER_LEN + 1))
            }
        }
    }
}
