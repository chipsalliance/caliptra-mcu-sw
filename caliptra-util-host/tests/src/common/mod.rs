// Licensed under the Apache-2.0 license

//! Common test utilities and mock implementations
//!
//! This module provides shared test infrastructure including mock mailbox
//! implementations and common test data structures.

use caliptra_util_host_transport::{MailboxDriver, MailboxError};
use zerocopy::{FromBytes, Immutable, IntoBytes};

// Buffer length constants
const RESPONSE_BUFFER_SIZE: usize = 128;
const CAPABILITIES_ARRAY_SIZE: usize = 32;
const DEVICE_INFO_DATA_SIZE: usize = 64;

/// Calculate checksum for external mailbox commands
/// Formula: 0 - (SUM(command code bytes) + SUM(response bytes))
fn calc_checksum(cmd: u32, data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as u32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as u32);
    }
    0u32.wrapping_sub(checksum)
}

/// External command response format for testing (matches ExtCmdGetDeviceIdResponse)
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct TestExtCmdGetDeviceIdResponse {
    /// Checksum field
    pub chksum: u32,
    /// FIPS approved or an error
    pub fips_status: u32,
    /// Vendor ID; LSB
    pub vendor_id: u16,
    /// Device ID; LSB
    pub device_id: u16,
    /// Subsystem Vendor ID; LSB
    pub subsystem_vendor_id: u16,
    /// Subsystem ID; LSB
    pub subsystem_id: u16,
}

/// Mock mailbox implementation for testing
pub struct MockMailbox {
    connected: bool,
    ready: bool,
    device_id: u16, // Changed to u16 to match GetDeviceIdResponse
    vendor_id: u16,
    subsystem_vendor_id: u16,
    subsystem_id: u16,
    response_buffer: [u8; RESPONSE_BUFFER_SIZE], // Buffer to store response data
}

impl MockMailbox {
    /// Create a new MockMailbox with specified device characteristics
    pub fn new(device_id: u16) -> Self {
        Self {
            connected: false,
            ready: true,
            device_id,
            vendor_id: 0x1234, // Default vendor ID
            subsystem_vendor_id: 0x5678,
            subsystem_id: 0x9ABC,
            response_buffer: [0; RESPONSE_BUFFER_SIZE],
        }
    }

    /// Create a MockMailbox with default device ID for convenience
    pub fn new_default() -> Self {
        Self::new(0x1234)
    }

    /// Set the ready state of the mailbox (useful for error testing)
    pub fn set_ready(&mut self, ready: bool) {
        self.ready = ready;
    }

    /// Get the configured device ID
    pub fn get_device_id(&self) -> u16 {
        self.device_id
    }

    fn process_command(
        &mut self,
        external_cmd: u32,
        _payload: &[u8],
    ) -> Result<&[u8], MailboxError> {
        // Mock responses for external mailbox commands using command codes from external_mailbox_cmds.md
        match external_cmd {
            0x4D44_4944 => {
                // MC_DEVICE_ID ("MDID")
                // For test simplification, return the external format that the transport layer can convert
                // Build response payload without checksum first
                let mut payload = Vec::new();
                payload.extend_from_slice(&0x00000001u32.to_le_bytes()); // fips_status
                payload.extend_from_slice(&self.vendor_id.to_le_bytes());
                payload.extend_from_slice(&self.device_id.to_le_bytes());
                payload.extend_from_slice(&self.subsystem_vendor_id.to_le_bytes());
                payload.extend_from_slice(&self.subsystem_id.to_le_bytes());

                // Calculate checksum over the payload data (for responses, cmd should be 0)
                let chksum = calc_checksum(0, &payload);

                // Create complete response with calculated checksum
                let response = TestExtCmdGetDeviceIdResponse {
                    chksum,
                    fips_status: 0x00000001, // Mock FIPS approved status
                    vendor_id: self.vendor_id,
                    device_id: self.device_id,
                    subsystem_vendor_id: self.subsystem_vendor_id,
                    subsystem_id: self.subsystem_id,
                };

                // Convert to bytes using zerocopy for proper serialization
                let response_bytes = response.as_bytes();
                let response_len = response_bytes.len();
                self.response_buffer[0..response_len].copy_from_slice(response_bytes);
                Ok(&self.response_buffer[0..response_len])
            }
            0x4D43_4150 => {
                // MC_DEVICE_CAPABILITIES ("MCAP")
                // Mock capabilities response with proper external structure (32-byte caps array)
                let mut payload = Vec::new();
                payload.extend_from_slice(&0x00000001u32.to_le_bytes()); // fips_status
                
                // Build capabilities array
                let mut caps = [0u8; CAPABILITIES_ARRAY_SIZE];
                // capabilities (bytes 0-3)
                caps[0..4].copy_from_slice(&0x000001F3u32.to_le_bytes());
                // max_cert_size (bytes 4-7)  
                caps[4..8].copy_from_slice(&4096u32.to_le_bytes());
                // max_csr_size (bytes 8-11)
                caps[8..12].copy_from_slice(&2048u32.to_le_bytes());
                // device_lifecycle (bytes 12-15)
                caps[12..16].copy_from_slice(&1u32.to_le_bytes());
                // Remaining bytes stay 0
                
                payload.extend_from_slice(&caps);

                let chksum = calc_checksum(0, &payload);
                // Complete response with checksum
                let mut response = Vec::new();
                response.extend_from_slice(&chksum.to_le_bytes());
                response.extend_from_slice(&payload);

                let response_len = response.len();
                self.response_buffer[0..response_len].copy_from_slice(&response);
                Ok(&self.response_buffer[0..response_len])
            }
            0x4D44_494E => {
                // MC_DEVICE_INFO ("MDIN")
                // Mock device info response with proper external structure
                let mut payload = Vec::new();
                payload.extend_from_slice(&0x00000001u32.to_le_bytes()); // fips_status
                payload.extend_from_slice(&16u32.to_le_bytes());          // data_size
                
                // Device info data field
                let mut data = [0u8; DEVICE_INFO_DATA_SIZE];
                data[0..16].copy_from_slice(b"Mock Device Info");
                payload.extend_from_slice(&data);

                let chksum = calc_checksum(0, &payload);
                // Complete response with checksum
                let mut response = Vec::new();
                response.extend_from_slice(&chksum.to_le_bytes());
                response.extend_from_slice(&payload);

                let response_len = response.len();
                self.response_buffer[0..response_len].copy_from_slice(&response);
                Ok(&self.response_buffer[0..response_len])
            }
            0x4D46_5756 => {
                // MC_FIRMWARE_VERSION ("MFWV")
                // Mock firmware version response with proper external structure  
                let mut payload = Vec::new();
                payload.extend_from_slice(&0x00000001u32.to_le_bytes()); // fips_status
                
                // Version string in ASCII format
                let version_str = b"1.2.3.4-mock_git_commit_sha";
                let data_len = version_str.len() as u32;
                payload.extend_from_slice(&data_len.to_le_bytes()); // data_len
                payload.extend_from_slice(version_str); // version data
                
                let chksum = calc_checksum(0, &payload);
                // Complete response with checksum
                let mut response = Vec::new();
                response.extend_from_slice(&chksum.to_le_bytes());
                response.extend_from_slice(&payload);

                let response_len = response.len();
                self.response_buffer[0..response_len].copy_from_slice(&response);
                Ok(&self.response_buffer[0..response_len])
            }
            _ => Err(MailboxError::InvalidCommand),
        }
    }
}

impl MailboxDriver for MockMailbox {
    fn send_command(&mut self, external_cmd: u32, payload: &[u8]) -> Result<&[u8], MailboxError> {
        if !self.ready {
            return Err(MailboxError::NotReady);
        }

        if !self.connected {
            return Err(MailboxError::CommunicationError);
        }

        self.process_command(external_cmd, payload)
    }

    fn is_ready(&self) -> bool {
        self.ready
    }

    fn connect(&mut self) -> Result<(), MailboxError> {
        if !self.ready {
            return Err(MailboxError::CommunicationError);
        }
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), MailboxError> {
        self.connected = false;
        Ok(())
    }
}

/// Test constants
pub mod test_constants {
    pub const DEFAULT_VENDOR_ID: u16 = 0x1234;
    pub const DEFAULT_SUBSYSTEM_VENDOR_ID: u16 = 0x5678;
    pub const DEFAULT_SUBSYSTEM_ID: u16 = 0x9ABC;
    pub const TEST_DEVICE_ID_1: u16 = 0x1234;
    pub const TEST_DEVICE_ID_2: u16 = 0x4321;
}
