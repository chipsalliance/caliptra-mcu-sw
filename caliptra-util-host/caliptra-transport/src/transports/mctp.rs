//! MCTP (Management Component Transport Protocol) transport implementation

use crate::{Transport, TransportConfig, TransportError, TransportResult, registry::TransportFactory};
use caliptra_osal::{memory::Buffer, sync::{Mutex, Arc}, thread::spawn, time::sleep_ms};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec, collections::VecDeque, string::String};

#[cfg(feature = "std")]
use std::{io::{Read, Write}, net::TcpStream, os::unix::net::UnixStream};

/// MCTP transport configuration parameters
#[derive(Debug, Clone)]
pub struct MctpConfig {
    pub endpoint_id: u8,
    pub target_eid: u8,
    pub message_tag: u8,
    pub max_message_size: usize,
    pub connection_string: Option<String>,
}

impl Default for MctpConfig {
    fn default() -> Self {
        Self {
            endpoint_id: 0x10,
            target_eid: 0x20,
            message_tag: 0x01,
            max_message_size: 4096,
            connection_string: None,
        }
    }
}

/// MCTP message types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum MctpMessageType {
    MctpControl = 0x00,
    Pldm = 0x01,
    Ncsi = 0x02,
    Ethernet = 0x03,
    NvmeMgmt = 0x04,
    Spdm = 0x05,
    SecurePldm = 0x06,
    Vendor = 0x7E,
}

/// MCTP packet header
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct MctpHeader {
    pub header_version: u8,  // bits [7:4] = version, bits [3:0] = reserved
    pub dest_eid: u8,
    pub source_eid: u8,
    pub msg_tag: u8,         // bits [7:3] = tag, bit [2] = tag_owner, bit [1] = packet_seq, bit [0] = eom
}

impl MctpHeader {
    pub fn new(dest_eid: u8, source_eid: u8, msg_tag: u8, som: bool, eom: bool, packet_seq: u8) -> Self {
        let mut tag_field = (msg_tag & 0x1F) << 3;
        if som { tag_field |= 0x04; }  // Set TO bit for SOM
        tag_field |= (packet_seq & 0x03) << 1;
        if eom { tag_field |= 0x01; }
        
        Self {
            header_version: 0x01,  // Version 1
            dest_eid,
            source_eid,
            msg_tag: tag_field,
        }
    }
    
    pub fn is_som(&self) -> bool {
        (self.msg_tag & 0x04) != 0
    }
    
    pub fn is_eom(&self) -> bool {
        (self.msg_tag & 0x01) != 0
    }
    
    pub fn packet_seq(&self) -> u8 {
        (self.msg_tag >> 1) & 0x03
    }
    
    pub fn tag(&self) -> u8 {
        (self.msg_tag >> 3) & 0x1F
    }
}

/// MCTP transport implementation
pub struct MctpTransport {
    config: MctpConfig,
    #[cfg(feature = "std")]
    connection: Arc<Mutex<Option<Box<dyn MctpConnection>>>>,
    message_buffer: Arc<Mutex<VecDeque<Vec<u8>>>>,
    is_connected: Arc<Mutex<bool>>,
}

#[cfg(feature = "std")]
trait MctpConnection: Send + Sync {
    fn send(&mut self, data: &[u8]) -> TransportResult<usize>;
    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize>;
    fn is_connected(&self) -> bool;
    fn connect(&mut self) -> TransportResult<()>;
    fn disconnect(&mut self) -> TransportResult<()>;
}

#[cfg(feature = "std")]
struct TcpMctpConnection {
    stream: Option<TcpStream>,
    address: String,
}

#[cfg(feature = "std")]
impl MctpConnection for TcpMctpConnection {
    fn send(&mut self, data: &[u8]) -> TransportResult<usize> {
        if let Some(ref mut stream) = self.stream {
            stream.write(data)
                .map_err(|e| TransportError::IoError(format!("TCP send failed: {}", e)))
        } else {
            Err(TransportError::ConnectionError("Not connected"))
        }
    }
    
    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize> {
        if let Some(ref mut stream) = self.stream {
            stream.read(buffer)
                .map_err(|e| TransportError::IoError(format!("TCP receive failed: {}", e)))
        } else {
            Err(TransportError::ConnectionError("Not connected"))
        }
    }
    
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
    
    fn connect(&mut self) -> TransportResult<()> {
        if self.stream.is_some() {
            return Ok(());
        }
        
        let stream = TcpStream::connect(&self.address)
            .map_err(|e| TransportError::ConnectionError(&format!("Failed to connect: {}", e)))?;
        
        self.stream = Some(stream);
        Ok(())
    }
    
    fn disconnect(&mut self) -> TransportResult<()> {
        self.stream = None;
        Ok(())
    }
}

impl MctpTransport {
    pub fn new(config: MctpConfig) -> TransportResult<Self> {
        if config.max_message_size > 65535 {
            return Err(TransportError::ConfigurationError("Max message size too large"));
        }
        
        Ok(Self {
            config,
            #[cfg(feature = "std")]
            connection: Arc::new(Mutex::new(None)),
            message_buffer: Arc::new(Mutex::new(VecDeque::new())),
            is_connected: Arc::new(Mutex::new(false)),
        })
    }
    
    fn fragment_message(&self, message_type: MctpMessageType, payload: &[u8]) -> TransportResult<Vec<Vec<u8>>> {
        const MAX_PAYLOAD_SIZE: usize = 64; // Typical MCTP payload size
        const MCTP_HEADER_SIZE: usize = core::mem::size_of::<MctpHeader>();
        
        let mut fragments = Vec::new();
        let mut offset = 0;
        let mut packet_seq = 0u8;
        
        while offset < payload.len() {
            let remaining = payload.len() - offset;
            let fragment_size = core::cmp::min(remaining, MAX_PAYLOAD_SIZE);
            let som = offset == 0;
            let eom = offset + fragment_size >= payload.len();
            
            let header = MctpHeader::new(
                self.config.target_eid,
                self.config.endpoint_id,
                self.config.message_tag,
                som,
                eom,
                packet_seq & 0x03,
            );
            
            let mut packet = Vec::with_capacity(MCTP_HEADER_SIZE + 1 + fragment_size);
            
            // Serialize header
            unsafe {
                let header_bytes = core::slice::from_raw_parts(
                    &header as *const _ as *const u8,
                    MCTP_HEADER_SIZE
                );
                packet.extend_from_slice(header_bytes);
            }
            
            // Add message type (only for SOM)
            if som {
                packet.push(message_type as u8);
            }
            
            // Add payload fragment
            packet.extend_from_slice(&payload[offset..offset + fragment_size]);
            
            fragments.push(packet);
            offset += fragment_size;
            packet_seq += 1;
        }
        
        Ok(fragments)
    }
    
    fn reassemble_message(&self, packets: &[Vec<u8>]) -> TransportResult<(MctpMessageType, Vec<u8>)> {
        if packets.is_empty() {
            return Err(TransportError::ParseError("No packets to reassemble"));
        }
        
        let mut message = Vec::new();
        let mut message_type = None;
        
        for (i, packet) in packets.iter().enumerate() {
            if packet.len() < core::mem::size_of::<MctpHeader>() {
                return Err(TransportError::ParseError("Packet too small"));
            }
            
            let header = unsafe {
                &*(packet.as_ptr() as *const MctpHeader)
            };
            
            let mut payload_start = core::mem::size_of::<MctpHeader>();
            
            // Extract message type from SOM packet
            if header.is_som() {
                if packet.len() <= payload_start {
                    return Err(TransportError::ParseError("SOM packet missing message type"));
                }
                
                let msg_type = packet[payload_start];
                message_type = Some(match msg_type {
                    0x00 => MctpMessageType::MctpControl,
                    0x01 => MctpMessageType::Pldm,
                    0x02 => MctpMessageType::Ncsi,
                    0x03 => MctpMessageType::Ethernet,
                    0x04 => MctpMessageType::NvmeMgmt,
                    0x05 => MctpMessageType::Spdm,
                    0x06 => MctpMessageType::SecurePldm,
                    0x7E => MctpMessageType::Vendor,
                    _ => return Err(TransportError::ParseError("Unknown message type")),
                });
                
                payload_start += 1;
            }
            
            // Add payload to message
            if packet.len() > payload_start {
                message.extend_from_slice(&packet[payload_start..]);
            }
        }
        
        let msg_type = message_type
            .ok_or_else(|| TransportError::ParseError("No SOM packet found"))?;
        
        Ok((msg_type, message))
    }
}

impl Transport for MctpTransport {
    fn send(&self, data: &Buffer) -> TransportResult<usize> {
        let payload = data.as_slice();
        
        // Default to PLDM message type if not specified
        let message_type = MctpMessageType::Pldm;
        
        let fragments = self.fragment_message(message_type, payload)?;
        let mut total_sent = 0;
        
        #[cfg(feature = "std")]
        {
            let mut connection = self.connection.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire connection lock"))?;
            
            if let Some(ref mut conn) = *connection {
                for fragment in fragments {
                    let sent = conn.send(&fragment)?;
                    total_sent += sent;
                }
            } else {
                return Err(TransportError::ConnectionError("Not connected"));
            }
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, just simulate sending
            for fragment in fragments {
                total_sent += fragment.len();
            }
        }
        
        Ok(total_sent)
    }
    
    fn receive(&self, buffer: &mut Buffer) -> TransportResult<usize> {
        #[cfg(feature = "std")]
        {
            let mut connection = self.connection.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire connection lock"))?;
            
            if let Some(ref mut conn) = *connection {
                let mut temp_buffer = vec![0u8; self.config.max_message_size];
                let received = conn.receive(&mut temp_buffer)?;
                
                if received > 0 {
                    let copy_size = core::cmp::min(received, buffer.capacity());
                    buffer.clear();
                    buffer.extend_from_slice(&temp_buffer[..copy_size])
                        .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
                    Ok(copy_size)
                } else {
                    Ok(0)
                }
            } else {
                Err(TransportError::ConnectionError("Not connected"))
            }
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, check message buffer
            let mut msg_buffer = self.message_buffer.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire buffer lock"))?;
            
            if let Some(message) = msg_buffer.pop_front() {
                let copy_size = core::cmp::min(message.len(), buffer.capacity());
                buffer.clear();
                buffer.extend_from_slice(&message[..copy_size])
                    .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
                Ok(copy_size)
            } else {
                Ok(0)
            }
        }
    }
    
    fn connect(&self) -> TransportResult<()> {
        #[cfg(feature = "std")]
        {
            let mut connection = self.connection.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire connection lock"))?;
            
            if connection.is_none() {
                let conn_str = self.config.connection_string
                    .as_ref()
                    .ok_or_else(|| TransportError::ConfigurationError("No connection string provided"))?;
                
                if conn_str.starts_with("tcp://") {
                    let address = &conn_str[6..];  // Remove "tcp://" prefix
                    let tcp_conn = TcpMctpConnection {
                        stream: None,
                        address: address.to_string(),
                    };
                    *connection = Some(Box::new(tcp_conn));
                } else {
                    return Err(TransportError::ConfigurationError("Unsupported connection type"));
                }
            }
            
            if let Some(ref mut conn) = *connection {
                conn.connect()?;
            }
        }
        
        let mut is_connected = self.is_connected.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire connection status lock"))?;
        *is_connected = true;
        
        Ok(())
    }
    
    fn disconnect(&self) -> TransportResult<()> {
        #[cfg(feature = "std")]
        {
            let mut connection = self.connection.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire connection lock"))?;
            
            if let Some(ref mut conn) = *connection {
                conn.disconnect()?;
            }
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
        if let Some(endpoint_id) = config.get_u8("endpoint_id") {
            self.config.endpoint_id = endpoint_id;
        }
        
        if let Some(target_eid) = config.get_u8("target_eid") {
            self.config.target_eid = target_eid;
        }
        
        if let Some(message_tag) = config.get_u8("message_tag") {
            self.config.message_tag = message_tag;
        }
        
        if let Some(max_size) = config.get_usize("max_message_size") {
            if max_size > 65535 {
                return Err(TransportError::ConfigurationError("Max message size too large"));
            }
            self.config.max_message_size = max_size;
        }
        
        #[cfg(feature = "std")]
        if let Some(conn_str) = config.get_string("connection_string") {
            self.config.connection_string = Some(conn_str);
        }
        
        Ok(())
    }
    
    fn get_info(&self) -> crate::TransportInfo {
        crate::TransportInfo {
            name: "MCTP",
            version: "1.0.0",
            description: "Management Component Transport Protocol",
            max_message_size: self.config.max_message_size,
            supports_fragmentation: true,
            is_reliable: true,
        }
    }
}

/// MCTP transport factory
pub struct MctpTransportFactory;

impl TransportFactory for MctpTransportFactory {
    fn create_transport(&self, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let mctp_config = MctpConfig {
            endpoint_id: config.get_u8("endpoint_id").unwrap_or(0x10),
            target_eid: config.get_u8("target_eid").unwrap_or(0x20),
            message_tag: config.get_u8("message_tag").unwrap_or(0x01),
            max_message_size: config.get_usize("max_message_size").unwrap_or(4096),
            #[cfg(feature = "std")]
            connection_string: config.get_string("connection_string"),
            #[cfg(not(feature = "std"))]
            connection_string: None,
        };
        
        let transport = MctpTransport::new(mctp_config)?;
        Ok(Box::new(transport))
    }
    
    fn name(&self) -> &'static str {
        "mctp"
    }
    
    fn supported_params(&self) -> &[&'static str] {
        &[
            "endpoint_id",
            "target_eid", 
            "message_tag",
            "max_message_size",
            "connection_string",
        ]
    }
    
    fn validate_config(&self, config: &TransportConfig) -> TransportResult<()> {
        if let Some(max_size) = config.get_usize("max_message_size") {
            if max_size > 65535 {
                return Err(TransportError::ConfigurationError("Max message size too large"));
            }
        }
        
        if let Some(endpoint_id) = config.get_u8("endpoint_id") {
            if endpoint_id == 0 || endpoint_id == 0xFF {
                return Err(TransportError::ConfigurationError("Invalid endpoint ID"));
            }
        }
        
        if let Some(target_eid) = config.get_u8("target_eid") {
            if target_eid == 0 || target_eid == 0xFF {
                return Err(TransportError::ConfigurationError("Invalid target EID"));
            }
        }
        
        Ok(())
    }
}