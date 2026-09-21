// Licensed under the Apache-2.0 license

use caliptra_mcu_mbox_common::messages::CommandId;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};

pub const OCP_LOCK_ROTATE_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_ROTATE_HEK.0;
pub const OCP_LOCK_SET_PERMA_HEK_CMD_ID: u32 = CommandId::MC_OCP_LOCK_SET_PERMA_HEK.0;

pub(crate) fn handle(request: &[u8]) -> CaliptraVdmCmdResult {
    let Some(subcommand) = request.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let subcommand =
        u32::from_le_bytes([subcommand[0], subcommand[1], subcommand[2], subcommand[3]]);

    // Protected commands must arrive as AuthorizedCommand(0x12) -> family
    // 0x13. Rejecting them on this native 0x13 path prevents authorization
    // bypass.
    match subcommand {
        OCP_LOCK_ROTATE_HEK_CMD_ID | OCP_LOCK_SET_PERMA_HEK_CMD_ID => {
            CaliptraVdmCmdResult::Error(CaliptraCompletionCode::AccessDenied)
        }
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}
