// Licensed under the Apache-2.0 license

//! C-compatible type definitions

use caliptra_util_host_command_types::device_info::GetDeviceIdResponse;

/// Device ID information structure
///
/// This structure contains device identification information retrieved from
/// a Caliptra device. All fields use little-endian byte order.
///
/// This type is memory-layout compatible with GetDeviceIdResponse for zero-cost conversion.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

// Zero-cost conversion using transmute since both types have identical #[repr(C)] layout
impl From<GetDeviceIdResponse> for CaliptraDeviceId {
    fn from(response: GetDeviceIdResponse) -> Self {
        // Safe because both types have identical #[repr(C)] memory layout
        unsafe { std::mem::transmute(response) }
    }
}

impl From<CaliptraDeviceId> for GetDeviceIdResponse {
    fn from(device_id: CaliptraDeviceId) -> Self {
        // Safe because both types have identical #[repr(C)] memory layout
        unsafe { std::mem::transmute(device_id) }
    }
}
