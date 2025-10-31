//! Integration tests for Caliptra Utility Host Library
//! 
//! These tests focus on the new modular architecture with session-transport integration.
//! 
//! ## Architecture Overview
//! 
//! The tests use the new no_std modular architecture:
//! - `caliptra-transport`: Transport trait definitions (no_std)
//! - `caliptra-session`: Session management with transport integration (no_std)  
//! - `caliptra-command-types`: Command structures with zerocopy serialization (no_std)
//! - `caliptra-commands`: Command packing/unpacking utilities (no_std)
//! - `caliptra-osal`: OS abstraction layer (only module with std access)
//!
//! ## Tests
//! 
//! - `test_get_device_id_vdm_style_transport`: End-to-end test of GetDeviceId command
//!   using a mock VDM (Vendor Defined Message) transport that simulates the external
//!   mailbox protocol for MC_DEVICE_ID commands.

/// Integration test for get_device_id using mock VDM-style transport
/// 
/// This test demonstrates the session-transport integration using a mock
/// VDM-style transport that simulates the VDM external mailbox protocol
/// to execute a GetDeviceId command through the new modular architecture.
#[test]
fn test_get_device_id_vdm_style_transport() {
    use caliptra_transport::{Transport, TransportError};
    use caliptra_session::CaliptraSession;
    use caliptra_command_types::device_info::{GetDeviceIdRequest, GetDeviceIdResponse};
    
    /// Mock VDM-style transport for testing
    struct MockVdmTransport {
        connected: bool,
    }
    
    impl MockVdmTransport {
        fn new() -> Self {
            Self { connected: false }
        }
    }
    
    impl Transport for MockVdmTransport {
        fn connect(&mut self) -> Result<(), TransportError> {
            println!("MockVdmTransport: Connecting to VDM channel...");
            self.connected = true;
            Ok(())
        }
        
        fn disconnect(&mut self) -> Result<(), TransportError> {
            println!("MockVdmTransport: Disconnecting from VDM channel...");
            self.connected = false;
            Ok(())
        }
        
        fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
            if !self.connected {
                return Err(TransportError::ConnectionError("VDM not connected"));
            }
            
            println!("MockVdmTransport: Sending VDM message {} bytes: {:02x?}", 
                data.len(), &data[..data.len().min(16)]);
            
            // Simulate VDM external mailbox processing
            println!("MockVdmTransport: Processing MC_DEVICE_ID command...");
            Ok(())
        }
        
        fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
            if !self.connected {
                return Err(TransportError::ConnectionError("VDM not connected"));
            }
            
            // Simulate VDM MC_DEVICE_ID response (matching GetDeviceIdResponse structure)
            // Create response as individual bytes to avoid zerocopy import issues
            let mut response_bytes = [0u8; 16];
            let mut offset = 0;
            
            // chksum (u32)
            response_bytes[offset..offset+4].copy_from_slice(&0x12345678u32.to_le_bytes());
            offset += 4;
            
            // fips_status (u32) 
            response_bytes[offset..offset+4].copy_from_slice(&0x00000001u32.to_le_bytes());
            offset += 4;
            
            // vendor_id (u16)
            response_bytes[offset..offset+2].copy_from_slice(&0x1234u16.to_le_bytes());
            offset += 2;
            
            // device_id (u16)
            response_bytes[offset..offset+2].copy_from_slice(&0x5678u16.to_le_bytes());
            offset += 2;
            
            // subsystem_vendor_id (u16)
            response_bytes[offset..offset+2].copy_from_slice(&0x9ABCu16.to_le_bytes());
            offset += 2;
            
            // subsystem_id (u16)
            response_bytes[offset..offset+2].copy_from_slice(&0xDEF0u16.to_le_bytes());
            offset += 2;
            
            let len = offset.min(buffer.len());
            buffer[..len].copy_from_slice(&response_bytes[..len]);
            
            println!("MockVdmTransport: Returning VDM response {} bytes: device_id=0x5678, vendor_id=0x1234", len);
            
            Ok(len)
        }
    }
    
    // Create VDM-style transport
    let transport = MockVdmTransport::new();
    
    // Create session with VDM transport
    let mut session = CaliptraSession::new(1, transport)
        .expect("Failed to create session");
    
    // Connect to device
    session.connect()
        .expect("Failed to connect to device");
    
    assert!(session.is_ready(), "Session should be ready after connection");
    println!("Session connected and ready");
    
    // Create GetDeviceId request
    let request = GetDeviceIdRequest {
        chksum: 0, // Checksum will be calculated by transport
    };
    
    // Execute the command through session-transport integration
    let response: GetDeviceIdResponse = session.execute_command(&request)
        .expect("Failed to execute GetDeviceId command");
    
    // Verify response structure (VDM transport provides simulated response)
    println!("Device ID: 0x{:04x}", response.device_id);
    println!("Vendor ID: 0x{:04x}", response.vendor_id);
    println!("Subsystem Vendor ID: 0x{:04x}", response.subsystem_vendor_id);
    println!("Subsystem ID: 0x{:04x}", response.subsystem_id);
    println!("FIPS Status: 0x{:08x}", response.fips_status);
    println!("Checksum: 0x{:08x}", response.chksum);
    
    // Expected values from VDM transport simulation
    assert_eq!(response.device_id, 0x5678, "Device ID should match VDM simulation");
    assert_eq!(response.vendor_id, 0x1234, "Vendor ID should match VDM simulation");
    assert_eq!(response.subsystem_vendor_id, 0x9ABC, "Subsystem Vendor ID should match");
    assert_eq!(response.subsystem_id, 0xDEF0, "Subsystem ID should match");
    assert_eq!(response.fips_status, 0x00000001, "FIPS status should indicate approved");
    assert_eq!(response.chksum, 0x12345678, "Checksum should match VDM simulation");
    
    // Verify session statistics were updated
    let info = session.get_info();
    assert_eq!(info.stats.commands_sent, 1, "Should have sent 1 command");
    assert!(info.stats.bytes_sent > 0, "Should have sent some bytes");
    assert!(info.stats.bytes_received > 0, "Should have received some bytes");
    
    println!("Session stats: commands={}, bytes_sent={}, bytes_received={}", 
        info.stats.commands_sent, info.stats.bytes_sent, info.stats.bytes_received);
    
    // Disconnect
    session.disconnect()
        .expect("Failed to disconnect");
    
    println!("VDM-style Transport integration test completed successfully!");
}