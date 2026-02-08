// Licensed under the Apache-2.0 license

//! Device information API functions
//!
//! High-level functions for retrieving device information from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_command_types::{
    device_info::{
        GetDeviceCapabilitiesRequest, GetDeviceCapabilitiesResponse, GetDeviceIdRequest,
        GetDeviceIdResponse, GetDeviceInfoRequest, GetDeviceInfoResponse,
        GetFirmwareVersionRequest, GetFirmwareVersionResponse,
    },
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

/// Get device information (Rust version)
///
/// This is the main Rust API for getting device information.
///
/// # Parameters
///
/// - `session`: Mutable reference to CaliptraSession
/// - `info_type`: Type of information to retrieve
///
/// # Returns
///
/// - `Ok(GetDeviceInfoResponse)` on success
/// - `Err(CaliptraApiError)` on failure
pub fn caliptra_cmd_get_device_info(
    session: &mut CaliptraSession,
    info_type: u32,
) -> CaliptraResult<GetDeviceInfoResponse> {
    caliptra_cmd_get_device_info_impl(session, info_type)
}

/// Internal implementation of get_device_info
fn caliptra_cmd_get_device_info_impl(
    session: &mut CaliptraSession,
    info_type: u32,
) -> CaliptraResult<GetDeviceInfoResponse> {
    let request = GetDeviceInfoRequest { info_type };
    session
        .execute_command_with_id(CaliptraCommandId::GetDeviceInfo, &request)
        .map_err(|_| CaliptraApiError::SessionError("Command execution failed"))
}

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
