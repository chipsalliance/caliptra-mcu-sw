// Licensed under the Apache-2.0 license

//! Device information API functions
//!
//! High-level functions for retrieving device information from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_mcu_core_util_host_command_types::{
    device_info::{
        GetDeviceCapabilitiesRequest, GetDeviceCapabilitiesResponse, GetFirmwareVersionRequest,
        GetFirmwareVersionResponse,
    },
    CaliptraCommandId,
};
use caliptra_util_host_session::CaliptraSession;

/// Get device capabilities (Rust version)
///
/// This is the main Rust API for getting device capabilities.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
///
/// # Returns
///
/// - `Ok(GetDeviceCapabilitiesResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_device_capabilities(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetDeviceCapabilitiesResponse> {
    caliptra_cmd_get_device_capabilities_impl(session)
}

/// Internal implementation of get_device_capabilities
fn caliptra_cmd_get_device_capabilities_impl(
    session: &mut CaliptraSession,
) -> CaliptraResult<GetDeviceCapabilitiesResponse> {
    let request = GetDeviceCapabilitiesRequest {};
    session
        .execute_command_with_id(CaliptraCommandId::GetDeviceCapabilities, &request)
        .map_err(|_| {
            CaliptraApiError::SessionError("GetDeviceCapabilities command execution failed")
        })
}

/// Get firmware version (Rust version)
///
/// This is the main Rust API for getting firmware version.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `index`: Firmware index (0 = ROM, 1 = Runtime)
///
/// # Returns
///
/// - `Ok(GetFirmwareVersionResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_firmware_version(
    session: &mut CaliptraSession,
    index: u32,
) -> CaliptraResult<GetFirmwareVersionResponse> {
    caliptra_cmd_get_firmware_version_impl(session, index)
}

/// Internal implementation of get_firmware_version
fn caliptra_cmd_get_firmware_version_impl(
    session: &mut CaliptraSession,
    index: u32,
) -> CaliptraResult<GetFirmwareVersionResponse> {
    let request = GetFirmwareVersionRequest { index };
    session
        .execute_command_with_id(CaliptraCommandId::GetFirmwareVersion, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}
