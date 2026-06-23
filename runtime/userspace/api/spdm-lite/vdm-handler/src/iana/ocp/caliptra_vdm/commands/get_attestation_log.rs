// Licensed under the Apache-2.0 license

//! GET_ATTESTATION_LOG (0x07): drains attestation-log bytes.

use mcu_spdm_lite_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;
use mcu_spdm_lite_codec::vendor_defined::iana::ocp::caliptra::CaliptraVdmCmdResult;

pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
{
    super::get_debug_log::handle_log(cmds, super::LOG_TYPE_ATTESTATION, req, scratch, out).await
}
