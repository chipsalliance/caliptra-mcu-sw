// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_mbox_common::messages::CommandId;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

pub const DOT_LOCK_CMD_ID: u32 = CommandId::MC_DOT_LOCK.0;

pub(crate) async fn handle<H, A>(
    _commands: &H,
    request: &[u8],
    _scratch: &A,
    _output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    A: SpdmPalAlloc,
{
    let Some(subcommand) = request.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let subcommand =
        u32::from_le_bytes([subcommand[0], subcommand[1], subcommand[2], subcommand[3]]);

    match subcommand {
        DOT_LOCK_CMD_ID => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::AccessDenied),
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}
