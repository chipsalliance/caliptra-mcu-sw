// Licensed under the Apache-2.0 license

//! Command dispatch for SPDM VDM transport
//!
//! Maps internal `CaliptraCommandId` values to the VDM command
//! handler functions defined in the `commands` module.

use super::commands;

/// Type alias for VDM command handler functions.
pub type VdmCommandHandlerFn = fn(
    &[u8],
    &mut dyn super::transport::SpdmVdmDriver,
    &mut [u8],
) -> Result<usize, crate::TransportError>;

/// Look up the VDM command handler for a given internal command ID.
///
/// Returns `Some(handler)` for supported commands, `None` otherwise.
pub fn get_command_handler(command_id: u32) -> Option<VdmCommandHandlerFn> {
    use caliptra_mcu_core_util_host_command_types::CaliptraCommandId;
    match command_id {
        x if x == CaliptraCommandId::GetFirmwareVersion as u32 => {
            Some(commands::handle_firmware_version)
        }
        x if x == CaliptraCommandId::GetDeviceCapabilities as u32 => {
            Some(commands::handle_device_capabilities)
        }
        x if x == CaliptraCommandId::GetDeviceId as u32 => Some(commands::handle_device_id),
        x if x == CaliptraCommandId::GetDeviceInfo as u32 => Some(commands::handle_device_info),
        x if x == CaliptraCommandId::ExportAttestedCsr as u32 => {
            Some(commands::handle_export_attested_csr)
        }
        _ => None,
    }
}
