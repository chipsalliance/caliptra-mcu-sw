// Licensed under the Apache-2.0 license

//! FIRMWARE_VERSION (0x01): returns the firmware version string for an area.

use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};

use crate::iana::ocp::caliptra_vdm::protocol::{CaliptraCompletionCode, CaliptraVdmCmdResult};
use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;

/// Request payload length: `area_index` (u32, little-endian).
const AREA_INDEX_LEN: usize = 4;

/// Handles a FIRMWARE_VERSION command.
///
/// `req` is the command-specific request (after the VDM header); `scratch`/`io`
/// give the device op request-scoped scratch; `out` receives the response
/// payload `[completion_code, version_bytes..]`.
pub(crate) async fn handle<H, A, I>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    io: &I,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
    I: SpdmPalIo,
{
    let area_index = match req.len() {
        0 => 0,
        AREA_INDEX_LEN => u32::from_le_bytes([req[0], req[1], req[2], req[3]]),
        _ => return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize),
    };

    // out[0] = completion code, out[1..] = version string.
    if out.is_empty() {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    }
    match cmds
        .firmware_version(area_index, scratch, io, &mut out[1..])
        .await
    {
        Ok(n) => {
            out[0] = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1 + n)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
