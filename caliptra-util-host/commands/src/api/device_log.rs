// Licensed under the Apache-2.0 license

//! Device log API functions
//!
//! High-level functions for retrieving device logs from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    device_log::{DebugGetLogRequest, DebugGetLogResponse, LOG_TYPE_DEBUG},
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Retrieve a single page of a device log.
///
/// The returned response carries `more_data` (non-zero when additional pages
/// remain), `data_len` (number of valid bytes in `data`), and the raw log
/// `data` for this page. Callers issue this repeatedly until `more_data` is 0
/// to drain the full log, concatenating the `data` bytes in order.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `log_type`: Log type to retrieve (0 = debug log, 1 = attestation log)
///
/// # Returns
///
/// - `Ok(DebugGetLogResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_log_page(
    session: &mut CaliptraSession,
    log_type: u32,
) -> CaliptraResult<DebugGetLogResponse> {
    let request = DebugGetLogRequest { log_type };
    session
        .execute_command_with_id(CaliptraCommandId::DebugGetLog, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}

/// Retrieve a single page of the debug log (log type 0).
pub fn caliptra_cmd_get_debug_log_page(
    session: &mut CaliptraSession,
) -> CaliptraResult<DebugGetLogResponse> {
    caliptra_cmd_get_log_page(session, LOG_TYPE_DEBUG)
}
