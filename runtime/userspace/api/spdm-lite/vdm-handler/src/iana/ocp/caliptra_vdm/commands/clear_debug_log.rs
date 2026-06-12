// Licensed under the Apache-2.0 license

//! CLEAR_DEBUG_LOG (0x06): clears the debug log.

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
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    match cmds.clear_log(super::LOG_TYPE_DEBUG, scratch, io).await {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
