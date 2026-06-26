// Licensed under the Apache-2.0 license

//! Command dispatch for MCTP VDM transport
//!
//! Maps internal `CaliptraCommandId` values to the VDM command
//! handler functions defined in the `encode` module.

use super::encode;

/// Type alias for VDM command handler functions.
pub type VdmCommandHandlerFn = fn(
    &[u8],
    &mut dyn super::transport::MctpVdmDriver,
    &mut [u8],
) -> Result<usize, crate::TransportError>;

/// Look up the VDM command handler for a given internal command ID.
///
/// Returns `Some(handler)` for supported commands, `None` otherwise.
pub fn get_command_handler(command_id: u32) -> Option<VdmCommandHandlerFn> {
    match command_id {
        // Device Info Commands (matching CaliptraCommandId values)
        1 => Some(encode::handle_firmware_version), // GetFirmwareVersion
        2 => Some(encode::handle_device_capabilities), // GetDeviceCapabilities
        3 => Some(encode::handle_device_id),        // GetDeviceId
        4 => Some(encode::handle_device_info),      // GetDeviceInfo
        0x7005 => Some(encode::handle_get_debug_log), // DebugGetLog
        0x9001 => Some(encode::handle_get_dot_backup_blob), // GetDotBackupBlob
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;

    #[test]
    fn get_dot_backup_blob_dispatch_is_registered() {
        assert!(get_command_handler(CaliptraCommandId::GetDotBackupBlob as u32).is_some());
    }
}
