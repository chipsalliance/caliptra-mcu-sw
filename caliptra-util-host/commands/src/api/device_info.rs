// Licensed under the Apache-2.0 license

//! Device information API functions
//!
//! High-level functions for retrieving device information from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::{
    device_info::{GetDeviceIdRequest, GetDeviceIdResponse},
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Get device identification information (Rust version)
///
/// This is the main Rust API for getting device ID information.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
///
/// # Returns
///
/// - `Ok(GetDeviceIdResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_device_id(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetDeviceIdResponse> {
    caliptra_cmd_get_device_id_impl(session)
}

/// Internal implementation of get_device_id
fn caliptra_cmd_get_device_id_impl(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetDeviceIdResponse> {
    let request = GetDeviceIdRequest {};
    session
        .execute_command_with_id(CaliptraCommandId::GetDeviceId, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}
