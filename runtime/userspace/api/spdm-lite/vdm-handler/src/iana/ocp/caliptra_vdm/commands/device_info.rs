// Licensed under the Apache-2.0 license

//! DEVICE_INFO (0x04): returns an indexed device-information blob.

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
    let info_index = match super::read_optional_u32_le(req) {
        Ok(index) => index,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    match cmds.device_info(info_index, scratch, io, data).await {
        Ok(n) => CaliptraVdmCmdResult::Response(1 + n),
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
