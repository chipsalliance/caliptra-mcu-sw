// Licensed under the Apache-2.0 license

use caliptra_mcu_common_commands::command::{execute_ocp_lock, CommandPolicy, CommandResponse};
use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use caliptra_mcu_spdm_traits::SpdmPalAlloc;

pub(crate) async fn handle<H, Alloc>(
    commands: &H,
    request: &[u8],
    scratch: &Alloc,
    output: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraCmdHandler,
    Alloc: SpdmPalAlloc,
{
    let Some((completion, response)) = output.split_first_mut() else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    match execute_ocp_lock(
        commands,
        scratch.allocator(),
        request,
        response,
        CommandPolicy::SPDM,
    )
    .await
    {
        Ok(CommandResponse::Data(len)) => {
            *completion = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1 + len)
        }
        Ok(CommandResponse::Empty | CommandResponse::ResetRequired) => {
            *completion = CaliptraCompletionCode::Success as u8;
            CaliptraVdmCmdResult::Response(1)
        }
        Err(error) => CaliptraVdmCmdResult::Error(super::map_common_completion(error)),
    }
}
