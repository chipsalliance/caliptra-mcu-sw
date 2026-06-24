// Licensed under the Apache-2.0 license

//! GET_DEBUG_LOG (0x05): drains debug-log bytes.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::CaliptraVdmCmdResult;

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
    handle_log(cmds, super::LOG_TYPE_DEBUG, req, scratch, out).await
}

pub(crate) async fn handle_log<H, A>(
    cmds: &H,
    log_type: u32,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
{
    use crate::iana::ocp::caliptra_vdm::CaliptraCompletionCode;

    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };

    // Carve out [more_data(1) | data_size(4) | log_buf(rest)] without
    // bounds-checked indexing. split_first_mut / split_at_mut_checked /
    // try_into are all panic-free; `data_size_arr` becomes a typed
    // &mut [u8; 4] so the later assignment is a direct array store
    // (no copy_from_slice length panic).
    let (more_data_byte, after_md) = match data.split_first_mut() {
        Some(parts) => parts,
        None => return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources),
    };
    let Some((data_size_bytes, log_buf)) = after_md.split_at_mut_checked(4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
    };
    let data_size_arr: &mut [u8; 4] = match data_size_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources)
        }
    };

    match cmds.get_log(log_type, scratch, log_buf).await {
        Ok(result) => {
            if result.bytes_written > log_buf.len() {
                return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
            }
            *more_data_byte = if result.more_data { 1 } else { 0 };
            *data_size_arr = (result.bytes_written as u32).to_le_bytes();
            CaliptraVdmCmdResult::Response(1 + 4 + result.bytes_written)
        }
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
