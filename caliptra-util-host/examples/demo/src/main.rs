//! Session-Transport Integration Demo
//!
//! Demonstrates how the session uses transport to send commands and receive responses

use caliptra_transport::Transport;
use caliptra_session::{CaliptraSession, SessionResult, SessionError};
use caliptra_command_types::{CommandRequest, CommandResponse};

/// Mock transport implementation for demonstration
pub struct MockTransport {
    connected: bool,
}

impl MockTransport {
    pub fn new() -> Self {
        Self { connected: false }
    }
}

impl Transport for MockTransport {
    type Error = &'static str;
    
    fn connect(&mut self) -> Result<(), Self::Error> {
        println!("MockTransport: Connecting to device...");
        self.connected = true;
        Ok(())
    }
    
    fn disconnect(&mut self) -> Result<(), Self::Error> {
        println!("MockTransport: Disconnecting from device...");
        self.connected = false;
        Ok(())
    }
    
    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if !self.connected {
            return Err("Not connected");
        }
        println!("MockTransport: Sending {} bytes: {:02x?}", data.len(), &data[..data.len().min(8)]);
        Ok(())
    }
    
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.connected {
            return Err("Not connected");
        }
        
        // Simulate a simple response (device ID response)
        let response_data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let len = response_data.len().min(buffer.len());
        buffer[..len].copy_from_slice(&response_data[..len]);
        
        println!("MockTransport: Received {} bytes: {:02x?}", len, &buffer[..len]);
        Ok(len)
    }
}

fn main() -> SessionResult<()> {
    println!("=== Session-Transport Integration Demo ===\n");
    
    // Create transport and session
    let transport = MockTransport::new();
    let mut session = CaliptraSession::new(1, transport)?;
    
    println!("1. Initial session state:");
    let info = session.get_info();
    println!("   Session ID: {}", info.session_id);
    println!("   State: {:?}", info.state);
    println!("   Commands sent: {}\n", info.stats.commands_sent);
    
    // Connect to device
    println!("2. Connecting to device:");
    session.connect()?;
    let info = session.get_info();
    println!("   State: {:?}", info.state);
    println!("   Ready: {}\n", session.is_ready());
    
    // Execute raw command
    println!("3. Executing raw command:");
    let request_data = [0x10, 0x20, 0x30, 0x40];
    let response_len = session.execute_command_raw(&request_data)?;
    println!("   Sent {} bytes, received {} bytes\n", request_data.len(), response_len);
    
    // Show updated statistics
    println!("4. Session statistics:");
    let info = session.get_info();
    println!("   Commands sent: {}", info.stats.commands_sent);
    println!("   Bytes sent: {}", info.stats.bytes_sent);
    println!("   Bytes received: {}\n", info.stats.bytes_received);
    
    // Disconnect
    println!("5. Disconnecting:");
    session.disconnect()?;
    let info = session.get_info();
    println!("   State: {:?}", info.state);
    
    println!("\n=== Demo completed successfully! ===");
    Ok(())
}