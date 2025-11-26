// Licensed under the Apache-2.0 license

//! C-compatible command implementations
//!
//! This module contains C-exportable wrapper functions for Caliptra commands.

use crate::error::CaliptraError;
use caliptra_util_host_command_types::device_info::GetDeviceIdResponse;
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
