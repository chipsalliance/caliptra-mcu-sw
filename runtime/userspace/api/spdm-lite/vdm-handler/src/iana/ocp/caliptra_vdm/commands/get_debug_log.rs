// Licensed under the Apache-2.0 license

//! GET_DEBUG_LOG (0x05): drains debug-log bytes.

use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};

use crate::iana::ocp::caliptra_vdm::protocol::CaliptraVdmCmdResult;
use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;

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
    handle_log(cmds, super::LOG_TYPE_DEBUG, req, scratch, io, out).await
}

pub(crate) async fn handle_log<H, A, I>(
    cmds: &H,
    log_type: u32,
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
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    if data.len() < 5 {
        return CaliptraVdmCmdResult::Error(
            crate::iana::ocp::caliptra_vdm::CaliptraCompletionCode::InsufficientResources,
        );
    }
    let log_buf = &mut data[5..];
    match cmds.get_log(log_type, scratch, io, log_buf).await {
        Ok(result) => {
            if result.bytes_written > log_buf.len() {
                return CaliptraVdmCmdResult::Error(
                    crate::iana::ocp::caliptra_vdm::CaliptraCompletionCode::InsufficientResources,
                );
            }
            data[0] = if result.more_data { 1 } else { 0 };
            data[1..5].copy_from_slice(&(result.bytes_written as u32).to_le_bytes());
            CaliptraVdmCmdResult::Response(1 + 1 + 4 + result.bytes_written)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
