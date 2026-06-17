// Licensed under the Apache-2.0 license

//! CLEAR_ATTESTATION_LOG (0x08): clears the attestation log.

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
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    match cmds.clear_log(super::LOG_TYPE_ATTESTATION, scratch).await {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
