// Licensed under the Apache-2.0 license

//! Command dispatch module for mailbox transport
//!
//! This module provides centralized command routing for all mailbox commands.
//! It maps internal command IDs to their handlers and external command codes.

use super::command_traits::process_command_with_metadata;

// Import command metadata types from each command module
use super::device_info::{
    GetDeviceCapabilitiesCmd, GetDeviceIdCmd, GetDeviceInfoCmd, GetFirmwareVersionCmd,
};
use super::sha::{ShaFinalCmd, ShaInitCmd, ShaUpdateCmd};

/// Type alias for command handler function to reduce complexity
pub type CommandHandlerFn = fn(
    &[u8],
    &mut dyn crate::transports::mailbox::transport::MailboxDriver,
    &mut [u8],
) -> Result<usize, crate::TransportError>;

/// Get the command handler function for a given internal command ID.
///
/// # Arguments
/// * `command_id` - The internal command identifier
///
/// # Returns
/// * `Some(handler)` - The handler function for the command
/// * `None` - If the command ID is not recognized
pub fn get_command_handler(command_id: u32) -> Option<CommandHandlerFn> {
    match command_id {
        // Device Info Commands
        1 => Some(process_command_with_metadata::<GetFirmwareVersionCmd>), // GetFirmwareVersion
        2 => Some(process_command_with_metadata::<GetDeviceCapabilitiesCmd>), // GetDeviceCapabilities
        3 => Some(process_command_with_metadata::<GetDeviceIdCmd>),           // GetDeviceId
        4 => Some(process_command_with_metadata::<GetDeviceInfoCmd>),         // GetDeviceInfo
        // SHA Commands (0x2001-0x2003)
        0x2001 => Some(process_command_with_metadata::<ShaInitCmd>), // HashInit
        0x2002 => Some(process_command_with_metadata::<ShaUpdateCmd>), // HashUpdate
        0x2003 => Some(process_command_with_metadata::<ShaFinalCmd>), // HashFinalize
        _ => None,
    }
}

/// Get the external mailbox command code for a given internal command ID.
///
/// # Arguments
/// * `command_id` - The internal command identifier
///
/// # Returns
/// * `Some(code)` - The external mailbox command code (4-byte ASCII)
/// * `None` - If the command ID is not recognized
pub fn get_external_cmd_code(command_id: u32) -> Option<u32> {
    match command_id {
        // Device Info Commands
        1 => Some(0x4D46_5756), // GetFirmwareVersion -> MC_FIRMWARE_VERSION ("MFWV")
        2 => Some(0x4D43_4150), // GetDeviceCapabilities -> MC_DEVICE_CAPABILITIES ("MCAP")
        3 => Some(0x4D44_4944), // GetDeviceId -> MC_DEVICE_ID ("MDID")
        4 => Some(0x4D44_494E), // GetDeviceInfo -> MC_DEVICE_INFO ("MDIN")
        // SHA Commands
        0x2001 => Some(0x4D43_5349), // HashInit -> MC_SHA_INIT ("MCSI")
        0x2002 => Some(0x4D43_5355), // HashUpdate -> MC_SHA_UPDATE ("MCSU")
        0x2003 => Some(0x4D43_5346), // HashFinalize -> MC_SHA_FINAL ("MCSF")
        _ => None,
    }
}
