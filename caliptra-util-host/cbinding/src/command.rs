// Licensed under the Apache-2.0 license

//! C-compatible command implementations
//!
//! This module contains C-exportable wrapper functions for Caliptra commands.

use crate::error::CaliptraError;
use caliptra_util_host_command_types::device_info::{
    GetDeviceCapabilitiesResponse, GetDeviceIdResponse, GetDeviceInfoResponse,
    GetFirmwareVersionResponse,
};
use caliptra_util_host_session::CaliptraSession;

/// Get device identification information (C-exportable version)
///
/// This function can be called from C code and takes a direct session pointer.
///
/// # Parameters
///
/// - `session_ptr`: Direct pointer to CaliptraSession
/// - `device_id`: Pointer to store the device ID response
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
///
/// # Safety
///
/// This function is unsafe because it works with raw pointers.
/// The caller must ensure both pointers are valid.
#[no_mangle]
pub extern "C" fn caliptra_cmd_get_device_id_c_impl(
    session_ptr: *mut CaliptraSession<'static>,
    device_id: *mut GetDeviceIdResponse,
) -> CaliptraError {
    if session_ptr.is_null() || device_id.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let session = &mut *session_ptr;

        // Call the actual implementation
        match caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_id(session) {
            Ok(response) => {
                *device_id = response;
                CaliptraError::Success
            }
            Err(_) => CaliptraError::Device,
        }
    }
}

/// Get device information (C-exportable version)
///
/// This function can be called from C code and takes a direct session pointer.
///
/// # Parameters
///
/// - `session_ptr`: Direct pointer to CaliptraSession
/// - `info_type`: Type of information to retrieve
/// - `device_info`: Pointer to store the device info response
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
///
/// # Safety
///
/// This function is unsafe because it works with raw pointers.
/// The caller must ensure both pointers are valid.
#[no_mangle]
pub extern "C" fn caliptra_cmd_get_device_info_c_impl(
    session_ptr: *mut CaliptraSession<'static>,
    info_type: u32,
    device_info: *mut GetDeviceInfoResponse,
) -> CaliptraError {
    if session_ptr.is_null() || device_info.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let session = &mut *session_ptr;

        // Call the actual implementation
        match caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_info(
            session, info_type,
        ) {
            Ok(response) => {
                *device_info = response;
                CaliptraError::Success
            }
            Err(_) => CaliptraError::Device,
        }
    }
}

/// Get device capabilities (C-exportable version)
///
/// This function can be called from C code and takes a direct session pointer.
///
/// # Parameters
///
/// - `session_ptr`: Direct pointer to CaliptraSession
/// - `capabilities`: Pointer to store the capabilities response
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
///
/// # Safety
///
/// This function is unsafe because it works with raw pointers.
/// The caller must ensure both pointers are valid.
#[no_mangle]
pub extern "C" fn caliptra_cmd_get_device_capabilities_c_impl(
    session_ptr: *mut CaliptraSession<'static>,
    capabilities: *mut GetDeviceCapabilitiesResponse,
) -> CaliptraError {
    if session_ptr.is_null() || capabilities.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let session = &mut *session_ptr;

        // Call the actual implementation
        match caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_capabilities(
            session,
        ) {
            Ok(response) => {
                *capabilities = response;
                CaliptraError::Success
            }
            Err(_) => CaliptraError::Device,
        }
    }
}

/// Get firmware version (C-exportable version)
///
/// This function can be called from C code and takes a direct session pointer.
///
/// # Parameters
///
/// - `session_ptr`: Direct pointer to CaliptraSession
/// - `index`: Firmware index (0 = ROM, 1 = Runtime)
/// - `firmware_version`: Pointer to store the firmware version response
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
///
/// # Safety
///
/// This function is unsafe because it works with raw pointers.
/// The caller must ensure both pointers are valid.
#[no_mangle]
pub extern "C" fn caliptra_cmd_get_firmware_version_c_impl(
    session_ptr: *mut CaliptraSession<'static>,
    index: u32,
    firmware_version: *mut GetFirmwareVersionResponse,
) -> CaliptraError {
    if session_ptr.is_null() || firmware_version.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let session = &mut *session_ptr;

        // Call the actual implementation
        match caliptra_util_host_commands::api::device_info::caliptra_cmd_get_firmware_version(
            session, index,
        ) {
            Ok(response) => {
                *firmware_version = response;
                CaliptraError::Success
            }
            Err(_) => CaliptraError::Device,
        }
    }
}
