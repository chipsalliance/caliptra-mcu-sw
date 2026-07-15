// Licensed under the Apache-2.0 license

//! Device log API functions
//!
//! High-level functions for retrieving device logs from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    device_log::{
        DebugClearLogRequest, DebugClearLogResponse, DebugGetLogRequest, DebugGetLogResponse,
    },
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Retrieve a single page of the debug log.
///
/// The returned response carries `more_data` (non-zero when additional pages
/// remain), `data_len` (number of valid bytes in `data`), and the raw log
/// `data` for this page. Callers issue this repeatedly until `more_data` is 0
/// to drain the full log, concatenating the `data` bytes in order.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// # Returns
///
/// - `Ok(DebugGetLogResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_debug_log_page(
    session: &mut CaliptraSession,
) -> CaliptraResult<DebugGetLogResponse> {
    let request = DebugGetLogRequest {};
    session
        .execute_command_with_id(CaliptraCommandId::DebugGetLog, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}

/// Clear the debug log.
pub fn caliptra_cmd_clear_debug_log(
    session: &mut CaliptraSession,
) -> CaliptraResult<DebugClearLogResponse> {
    let request = DebugClearLogRequest {};
    session
        .execute_command_with_id(CaliptraCommandId::DebugClearLog, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}
