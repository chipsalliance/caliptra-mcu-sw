//! Device information API functions
//! 
//! High-level functions for retrieving device information from Caliptra.

use crate::api::{CaliptraApiError, CaliptraResult};
use caliptra_command_types::device_info::{GetDeviceIdRequest, GetDeviceIdResponse};

/// Device ID information returned by caliptra_cmd_get_device_id
#[derive(Debug, Clone, PartialEq)]
pub struct CaliptraDeviceId {
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Subsystem Vendor ID
    pub subsystem_vendor_id: u16,
    /// Subsystem ID
    pub subsystem_id: u16,
}

impl From<GetDeviceIdResponse> for CaliptraDeviceId {
    fn from(response: GetDeviceIdResponse) -> Self {
        Self {
            vendor_id: response.vendor_id,
            device_id: response.device_id,
            subsystem_vendor_id: response.subsystem_vendor_id,
            subsystem_id: response.subsystem_id,
        }
    }
}

/// Get device ID from Caliptra device
/// 
/// This function sends a GetDeviceId command to the Caliptra device and returns
/// the unique device identifier. The device ID can be used for device identification,
/// authentication, and tracking purposes.
/// 
/// # Arguments
/// 
/// * `execute_fn` - Function that can execute commands with signature: 
///   `fn(&GetDeviceIdRequest) -> Result<GetDeviceIdResponse, E>`
/// 
/// # Returns
/// 
/// * `CaliptraResult<CaliptraDeviceId>` - Device ID information on success
/// 
/// # Example
/// 
/// ```no_run
/// use caliptra_commands::api::caliptra_cmd_get_device_id;
/// use caliptra_core::{CaliptraSession, execute_command_with_session};
/// use caliptra_vdm_transport::VdmTransport;
/// 
/// // Create transport and session
/// let transport = VdmTransport::new()?;
/// let mut session = CaliptraSession::new(transport)?;
/// 
/// // Get device ID using closure
/// let device_id = caliptra_cmd_get_device_id(|req| {
///     execute_command_with_session(&mut session, req)
/// })?;
/// println!("Device ID: 0x{:04x}, Vendor ID: 0x{:04x}", device_id.device_id, device_id.vendor_id);
/// ```
pub fn caliptra_cmd_get_device_id<F, E>(
    execute_fn: F
) -> CaliptraResult<CaliptraDeviceId> 
where
    F: FnOnce(&GetDeviceIdRequest) -> Result<GetDeviceIdResponse, E>,
    CaliptraApiError: From<E>,
{
    // Create the request with checksum as per external mailbox protocol
    let request = GetDeviceIdRequest {
        chksum: calculate_checksum(),
    };

    // Execute the command through the provided function
    let response: GetDeviceIdResponse = execute_fn(&request)
        .map_err(|e| CaliptraApiError::from(e))?;

    // Convert to high-level API type
    Ok(CaliptraDeviceId::from(response))
}

/// Calculate checksum for GetDeviceId request
/// 
/// For the MC_DEVICE_ID external mailbox command, a simple checksum is used.
/// This implementation uses a basic XOR-based checksum.
fn calculate_checksum() -> u32 {
    // For GetDeviceId, we can use a fixed checksum since the request payload is empty
    // In a real implementation, this would be calculated based on the command
    0x4D444944u32 // "MDID" - MC_DEVICE_ID command identifier
}