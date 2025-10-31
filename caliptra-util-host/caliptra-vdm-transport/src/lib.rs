//! VDM (Vendor Defined Message) Transport
//!
//! Transport implementation for external mailbox commands using mpsc channels.
//! Translates internal CaliptraCommandId to external mailbox protocol codes.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
use std::{
    vec,
    vec::Vec,
    string::{String, ToString},
    format,
    sync::{Arc, mpsc::{self, Receiver, Sender}, Mutex},
    println,
};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{
    vec,
    vec::Vec,
    string::{String, ToString},
    format,
};

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

use caliptra_commands::CaliptraCommandId;
use caliptra_core::{Transport, TransportError};

/// VDM Transport error types
#[derive(Debug, Clone)]
pub enum VdmError {
    /// Channel send error
    SendError(String),
    
    /// Channel receive error  
    ReceiveError(String),
    
    /// Timeout waiting for response
    Timeout,
    
    /// Invalid command for VDM transport
    UnsupportedCommand(CaliptraCommandId),
    
    /// Protocol error
    ProtocolError(String),
    
    /// Not connected
    NotConnected,
    
    /// I/O error
    IoError(String),
}

impl core::fmt::Display for VdmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VdmError::SendError(msg) => write!(f, "Send error: {}", msg),
            VdmError::ReceiveError(msg) => write!(f, "Receive error: {}", msg),
            VdmError::Timeout => write!(f, "Operation timeout"),
            VdmError::UnsupportedCommand(cmd) => write!(f, "Unsupported command: {:?}", cmd),
            VdmError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            VdmError::NotConnected => write!(f, "Not connected"),
            VdmError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

/// External Mailbox Command Codes (from external_mailbox_cmds.md)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalMailboxCode {
    /// MC_DEVICE_ID - Retrieves the device ID  
    McDeviceId = 0x4D44_4944, // "MDID"
    
    /// MC_FIRMWARE_VERSION - Retrieves firmware version
    McFirmwareVersion = 0x4D46_5756, // "MFWV"
    
    /// MC_DEVICE_CAPABILITIES - Retrieve device capabilities
    McDeviceCapabilities = 0x4D43_4150, // "MCAP"
    
    /// MC_DEVICE_INFO - Retrieve device information
    McDeviceInfo = 0x4D44_494E, // "MDIN"
}

/// VDM Message structure for external mailbox protocol
#[derive(Debug, Clone)]
pub struct VdmMessage {
    /// External mailbox command code
    pub command_code: u32,
    
    /// Message payload data
    pub payload: Vec<u8>,
}

/// VDM Transport configuration
#[derive(Debug, Clone)]
pub struct VdmConfig {
    /// Response timeout in milliseconds
    pub timeout_ms: u64,
    
    /// Maximum message size
    pub max_message_size: usize,
    
    /// Enable debug logging
    pub debug: bool,
}

impl Default for VdmConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000, // 5 second timeout
            max_message_size: 4096,
            debug: false,
        }
    }
}

/// VDM Transport implementation using mpsc channels
#[cfg(feature = "std")]
pub struct VdmTransport {
    /// Configuration
    config: VdmConfig,
    
    /// Sender for outgoing messages
    tx: Option<Sender<VdmMessage>>,
    
    /// Receiver for incoming responses
    rx: Option<Arc<Mutex<Receiver<VdmMessage>>>>,
    
    /// Connection state
    connected: bool,
}

// Stub implementation for no_std environments
#[cfg(not(feature = "std"))]
pub struct VdmTransport {
    _phantom: core::marker::PhantomData<()>,
}

#[cfg(feature = "std")]
impl VdmTransport {
    /// Create new VDM transport with default configuration
    pub fn new() -> Self {
        Self::with_config(VdmConfig::default())
    }
    
    /// Create new VDM transport with custom configuration
    pub fn with_config(config: VdmConfig) -> Self {
        Self {
            config,
            tx: None,
            rx: None,
            connected: false,
        }
    }
    
    /// Map CaliptraCommandId to external mailbox command code
    fn map_command_id(command_id: CaliptraCommandId) -> Result<ExternalMailboxCode, VdmError> {
        match command_id {
            CaliptraCommandId::GetDeviceId => Ok(ExternalMailboxCode::McDeviceId),
            CaliptraCommandId::GetFirmwareVersion => Ok(ExternalMailboxCode::McFirmwareVersion), 
            CaliptraCommandId::GetDeviceCapabilities => Ok(ExternalMailboxCode::McDeviceCapabilities),
            CaliptraCommandId::GetDeviceInfo => Ok(ExternalMailboxCode::McDeviceInfo),
            _ => Err(VdmError::UnsupportedCommand(command_id)),
        }
    }
    
    /// Create external mailbox message from internal command
    fn create_external_message(command_id: CaliptraCommandId, payload: &[u8]) -> Result<VdmMessage, VdmError> {
        let command_code = Self::map_command_id(command_id)? as u32;
        
        Ok(VdmMessage {
            command_code,
            payload: payload.to_vec(),
        })
    }
    
    /// Simulate external mailbox response for GetDeviceId
    fn simulate_response(&self, request: &VdmMessage) -> Result<VdmMessage, VdmError> {
        match request.command_code {
            // MC_DEVICE_ID response simulation
            0x4D44_4944 => {
                if self.config.debug {
                    #[cfg(feature = "std")]
                    println!("VDM: Processing MC_DEVICE_ID request");
                }
                
                // Simulate a device response with sample data
                let mut response_payload = Vec::with_capacity(16);
                response_payload.extend_from_slice(&0u32.to_le_bytes()); // chksum  
                response_payload.extend_from_slice(&0x00000001u32.to_le_bytes()); // fips_status (approved)
                response_payload.extend_from_slice(&0x1234u16.to_le_bytes()); // vendor_id
                response_payload.extend_from_slice(&0x5678u16.to_le_bytes()); // device_id  
                response_payload.extend_from_slice(&0x9ABCu16.to_le_bytes()); // subsystem_vendor_id
                response_payload.extend_from_slice(&0xDEF0u16.to_le_bytes()); // subsystem_id
                
                Ok(VdmMessage {
                    command_code: request.command_code,
                    payload: response_payload,
                })
            }
            _ => Err(VdmError::UnsupportedCommand(CaliptraCommandId::GetDeviceId)), // Placeholder
        }
    }
}

#[cfg(feature = "std")]
impl Transport for VdmTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionError("VDM not connected".to_string()));
        }
        
        if let Some(tx) = &self.tx {
            // For simulation, we assume the data contains the command ID in the first 4 bytes
            if data.len() < 4 {
                return Err(TransportError::IoError("Data too short for command ID".to_string()));
            }
            
            // Extract command ID (assuming first 4 bytes for now)
            // In a real implementation, this would be passed differently
            let command_id = CaliptraCommandId::GetDeviceId; // Hardcoded for now
            let payload = &data[4..]; // Skip command ID bytes
            
            let message = Self::create_external_message(command_id, payload)
                .map_err(|e| TransportError::IoError(format!("Failed to create message: {}", e)))?;
            
            tx.send(message)
                .map_err(|e| TransportError::IoError(format!("Send failed: {}", e)))?;
            
            if self.config.debug {
                #[cfg(feature = "std")]
                println!("VDM: Sent message with command code: 0x{:08X}", 
                    Self::map_command_id(command_id).unwrap() as u32);
            }
            
            Ok(())
        } else {
            Err(TransportError::ConnectionError("No sender available".to_string()))
        }
    }
    
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionError("VDM not connected".to_string()));
        }
        
        if let Some(_rx) = &self.rx {
            // Simulate response generation (in real implementation, this would come from the device)
            let dummy_request = VdmMessage {
                command_code: 0x4D44_4944, // MC_DEVICE_ID
                payload: vec![0, 0, 0, 0], // dummy chksum
            };
            
            let response = self.simulate_response(&dummy_request)
                .map_err(|e| TransportError::IoError(format!("Failed to generate response: {}", e)))?;
            
            let response_data = &response.payload;
            let copy_size = core::cmp::min(buffer.len(), response_data.len());
            buffer[..copy_size].copy_from_slice(&response_data[..copy_size]);
            
            if self.config.debug {
                #[cfg(feature = "std")]
                println!("VDM: Received response, {} bytes", copy_size);
            }
            
            Ok(copy_size)
        } else {
            Err(TransportError::ConnectionError("No receiver available".to_string()))
        }
    }
    
    fn connect(&mut self) -> Result<(), TransportError> {
        if self.connected {
            return Ok(());
        }
        
        // Create mpsc channel pair  
        let (tx, rx) = mpsc::channel::<VdmMessage>();
        
        self.tx = Some(tx);
        self.rx = Some(Arc::new(Mutex::new(rx)));
        self.connected = true;
        
        if self.config.debug {
            #[cfg(feature = "std")]
            println!("VDM: Connected successfully");
        }
        
        Ok(())
    }
    
    fn disconnect(&mut self) -> Result<(), TransportError> {
        if !self.connected {
            return Ok(());
        }
        
        self.tx = None;
        self.rx = None; 
        self.connected = false;
        
        if self.config.debug {
            #[cfg(feature = "std")]
            println!("VDM: Disconnected");
        }
        
        Ok(())
    }
}

// Stub implementations for no_std environments
#[cfg(not(feature = "std"))]
impl VdmTransport {
    pub fn new() -> Self {
        Self { _phantom: core::marker::PhantomData }
    }
    
    pub fn with_config(_config: VdmConfig) -> Self {
        Self { _phantom: core::marker::PhantomData }
    }
}

#[cfg(not(feature = "std"))]
impl Transport for VdmTransport {
    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotConnected)
    }
    
    fn receive(&mut self, _buffer: &mut [u8], _timeout_ms: u32) -> Result<usize, TransportError> {
        Err(TransportError::NotConnected)
    }
    
    fn connect(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotConnected)
    }
    
    fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}