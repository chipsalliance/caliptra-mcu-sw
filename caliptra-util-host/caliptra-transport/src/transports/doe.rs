//! DOE (Data Object Exchange) transport implementation

use crate::{Transport, TransportConfig, TransportError, TransportResult, registry::TransportFactory};
use caliptra_osal::{memory::Buffer, sync::{Mutex, Arc}, io::SeekFrom};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec, string::String};

#[cfg(feature = "std")]
use std::{fs::File, io::{Read, Write, Seek}};

/// DOE transport configuration
#[derive(Debug, Clone)]
pub struct DoeConfig {
    pub vendor_id: u16,
    pub data_object_type: u8,
    pub max_request_size: usize,
    pub max_response_size: usize,
    pub timeout_ms: u32,
    #[cfg(feature = "std")]
    pub device_path: Option<String>,
}

impl Default for DoeConfig {
    fn default() -> Self {
        Self {
            vendor_id: 0x1AF4,  // Example vendor ID
            data_object_type: 0x01,
            max_request_size: 1024,
            max_response_size: 4096,
            timeout_ms: 5000,
            #[cfg(feature = "std")]
            device_path: None,
        }
    }
}

/// DOE capability structure
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct DoeCapability {
    pub cap_id: u16,        // Extended Capability ID (0x002E for DOE)
    pub next_cap: u16,      // Next capability offset
    pub cap_header: u32,    // DOE capability header
    pub control: u32,       // DOE control register  
    pub status: u32,        // DOE status register
    pub write_mailbox: u32, // DOE write data mailbox
    pub read_mailbox: u32,  // DOE read data mailbox
}

/// DOE protocol message header
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct DoeHeader {
    pub vendor_id: u16,
    pub data_object_type: u8,
    pub reserved: u8,
    pub length: u32,  // Length in DW (4-byte words)
}

impl DoeHeader {
    pub fn new(vendor_id: u16, data_object_type: u8, payload_length: usize) -> Self {
        let total_length = (core::mem::size_of::<Self>() + payload_length + 3) / 4; // Round up to DW
        Self {
            vendor_id,
            data_object_type,
            reserved: 0,
            length: total_length as u32,
        }
    }
    
    pub fn payload_length(&self) -> usize {
        (self.length as usize * 4) - core::mem::size_of::<Self>()
    }
}

/// DOE transport implementation
pub struct DoeTransport {
    config: DoeConfig,
    #[cfg(feature = "std")]
    device: Arc<Mutex<Option<File>>>,
    is_connected: Arc<Mutex<bool>>,
    sequence_number: Arc<Mutex<u32>>,
}

impl DoeTransport {
    pub fn new(config: DoeConfig) -> TransportResult<Self> {
        if config.max_request_size > 1024 * 1024 {  // 1MB limit
            return Err(TransportError::ConfigurationError("Max request size too large"));
        }
        
        if config.max_response_size > 1024 * 1024 {  // 1MB limit
            return Err(TransportError::ConfigurationError("Max response size too large"));
        }
        
        Ok(Self {
            config,
            #[cfg(feature = "std")]
            device: Arc::new(Mutex::new(None)),
            is_connected: Arc::new(Mutex::new(false)),
            sequence_number: Arc::new(Mutex::new(0)),
        })
    }
    
    fn create_doe_message(&self, payload: &[u8]) -> TransportResult<Vec<u8>> {
        let header = DoeHeader::new(
            self.config.vendor_id,
            self.config.data_object_type,
            payload.len(),
        );
        
        let mut message = Vec::with_capacity(core::mem::size_of::<DoeHeader>() + payload.len());
        
        // Serialize header
        unsafe {
            let header_bytes = core::slice::from_raw_parts(
                &header as *const _ as *const u8,
                core::mem::size_of::<DoeHeader>()
            );
            message.extend_from_slice(header_bytes);
        }
        
        // Add payload
        message.extend_from_slice(payload);
        
        // Pad to 4-byte boundary
        while message.len() % 4 != 0 {
            message.push(0);
        }
        
        Ok(message)
    }
    
    fn parse_doe_response(&self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if data.len() < core::mem::size_of::<DoeHeader>() {
            return Err(TransportError::ParseError("Response too small for DOE header"));
        }
        
        let header = unsafe {
            &*(data.as_ptr() as *const DoeHeader)
        };
        
        if header.vendor_id != self.config.vendor_id {
            return Err(TransportError::ParseError("Vendor ID mismatch"));
        }
        
        let expected_length = header.length as usize * 4;
        if data.len() < expected_length {
            return Err(TransportError::ParseError("Response shorter than expected"));
        }
        
        let payload_start = core::mem::size_of::<DoeHeader>();
        let payload_length = header.payload_length();
        
        if payload_start + payload_length > data.len() {
            return Err(TransportError::ParseError("Invalid payload length"));
        }
        
        Ok(data[payload_start..payload_start + payload_length].to_vec())
    }
    
    #[cfg(feature = "std")]
    fn write_doe_mailbox(&self, data: &[u8]) -> TransportResult<()> {
        let mut device = self.device.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire device lock"))?;
        
        if let Some(ref mut file) = *device {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| TransportError::IoError(format!("Seek failed: {}", e)))?;
            
            file.write_all(data)
                .map_err(|e| TransportError::IoError(format!("Write failed: {}", e)))?;
            
            file.flush()
                .map_err(|e| TransportError::IoError(format!("Flush failed: {}", e)))?;
            
            Ok(())
        } else {
            Err(TransportError::ConnectionError("Device not open"))
        }
    }
    
    #[cfg(feature = "std")]
    fn read_doe_mailbox(&self, buffer: &mut [u8]) -> TransportResult<usize> {
        let mut device = self.device.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire device lock"))?;
        
        if let Some(ref mut file) = *device {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| TransportError::IoError(format!("Seek failed: {}", e)))?;
            
            let bytes_read = file.read(buffer)
                .map_err(|e| TransportError::IoError(format!("Read failed: {}", e)))?;
            
            Ok(bytes_read)
        } else {
            Err(TransportError::ConnectionError("Device not open"))
        }
    }
    
    fn get_next_sequence(&self) -> TransportResult<u32> {
        let mut seq = self.sequence_number.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire sequence lock"))?;
        
        let current = *seq;
        *seq = seq.wrapping_add(1);
        Ok(current)
    }
}

impl Transport for DoeTransport {
    fn send(&self, data: &Buffer) -> TransportResult<usize> {
        let payload = data.as_slice();
        
        if payload.len() > self.config.max_request_size {
            return Err(TransportError::MessageTooLarge("Payload exceeds max request size"));
        }
        
        let message = self.create_doe_message(payload)?;
        
        #[cfg(feature = "std")]
        {
            self.write_doe_mailbox(&message)?;
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, simulate sending
            // This would typically involve writing to hardware registers
        }
        
        Ok(message.len())
    }
    
    fn receive(&self, buffer: &mut Buffer) -> TransportResult<usize> {
        #[cfg(feature = "std")]
        {
            let mut temp_buffer = vec![0u8; self.config.max_response_size];
            let bytes_read = self.read_doe_mailbox(&mut temp_buffer)?;
            
            if bytes_read == 0 {
                return Ok(0);
            }
            
            let payload = self.parse_doe_response(&temp_buffer[..bytes_read])?;
            
            if payload.len() > buffer.capacity() {
                return Err(TransportError::BufferError("Response too large for buffer"));
            }
            
            buffer.clear();
            buffer.extend_from_slice(&payload)
                .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
            
            Ok(payload.len())
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, read from hardware registers
            // This is a placeholder implementation
            Ok(0)
        }
    }
    
    fn connect(&self) -> TransportResult<()> {
        #[cfg(feature = "std")]
        {
            let device_path = self.config.device_path
                .as_ref()
                .ok_or_else(|| TransportError::ConfigurationError("No device path provided"))?;
            
            let file = File::options()
                .read(true)
                .write(true)
                .open(device_path)
                .map_err(|e| TransportError::ConnectionError(&format!("Failed to open device: {}", e)))?;
            
            let mut device = self.device.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire device lock"))?;
            *device = Some(file);
        }
        
        let mut is_connected = self.is_connected.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire connection status lock"))?;
        *is_connected = true;
        
        Ok(())
    }
    
    fn disconnect(&self) -> TransportResult<()> {
        #[cfg(feature = "std")]
        {
            let mut device = self.device.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire device lock"))?;
            *device = None;
        }
        
        let mut is_connected = self.is_connected.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire connection status lock"))?;
        *is_connected = false;
        
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.is_connected.lock()
            .map(|status| *status)
            .unwrap_or(false)
    }
    
    fn configure(&mut self, config: TransportConfig) -> TransportResult<()> {
        if let Some(vendor_id) = config.get_u16("vendor_id") {
            self.config.vendor_id = vendor_id;
        }
        
        if let Some(data_object_type) = config.get_u8("data_object_type") {
            self.config.data_object_type = data_object_type;
        }
        
        if let Some(max_request) = config.get_usize("max_request_size") {
            if max_request > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max request size too large"));
            }
            self.config.max_request_size = max_request;
        }
        
        if let Some(max_response) = config.get_usize("max_response_size") {
            if max_response > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max response size too large"));
            }
            self.config.max_response_size = max_response;
        }
        
        if let Some(timeout) = config.get_u32("timeout_ms") {
            self.config.timeout_ms = timeout;
        }
        
        #[cfg(feature = "std")]
        if let Some(device_path) = config.get_string("device_path") {
            self.config.device_path = Some(device_path);
        }
        
        Ok(())
    }
    
    fn get_info(&self) -> crate::TransportInfo {
        crate::TransportInfo {
            name: "DOE",
            version: "1.0.0",
            description: "Data Object Exchange over PCIe",
            max_message_size: core::cmp::min(self.config.max_request_size, self.config.max_response_size),
            supports_fragmentation: false,
            is_reliable: true,
        }
    }
}

/// DOE transport factory
pub struct DoeTransportFactory;

impl TransportFactory for DoeTransportFactory {
    fn create_transport(&self, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let doe_config = DoeConfig {
            vendor_id: config.get_u16("vendor_id").unwrap_or(0x1AF4),
            data_object_type: config.get_u8("data_object_type").unwrap_or(0x01),
            max_request_size: config.get_usize("max_request_size").unwrap_or(1024),
            max_response_size: config.get_usize("max_response_size").unwrap_or(4096),
            timeout_ms: config.get_u32("timeout_ms").unwrap_or(5000),
            #[cfg(feature = "std")]
            device_path: config.get_string("device_path"),
        };
        
        let transport = DoeTransport::new(doe_config)?;
        Ok(Box::new(transport))
    }
    
    fn name(&self) -> &'static str {
        "doe"
    }
    
    fn supported_params(&self) -> &[&'static str] {
        &[
            "vendor_id",
            "data_object_type",
            "max_request_size",
            "max_response_size", 
            "timeout_ms",
            "device_path",
        ]
    }
    
    fn validate_config(&self, config: &TransportConfig) -> TransportResult<()> {
        if let Some(max_request) = config.get_usize("max_request_size") {
            if max_request > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max request size too large"));
            }
        }
        
        if let Some(max_response) = config.get_usize("max_response_size") {
            if max_response > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max response size too large"));
            }
        }
        
        Ok(())
    }
}