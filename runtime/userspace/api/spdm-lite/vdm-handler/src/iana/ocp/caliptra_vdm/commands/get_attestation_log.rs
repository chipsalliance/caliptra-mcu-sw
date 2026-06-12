// Licensed under the Apache-2.0 license

//! GET_ATTESTATION_LOG (0x07): drains attestation-log bytes.

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
    super::get_debug_log::handle_log(cmds, super::LOG_TYPE_ATTESTATION, req, scratch, io, out).await
}
