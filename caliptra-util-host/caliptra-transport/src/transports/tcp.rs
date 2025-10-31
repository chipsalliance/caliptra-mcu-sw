//! TCP transport implementation for testing and development

use crate::{Transport, TransportConfig, TransportError, TransportResult, registry::TransportFactory};
use caliptra_osal::{memory::Buffer, sync::{Mutex, Arc}};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{net::{TcpStream, TcpListener, SocketAddr}, io::{Read, Write}, time::Duration};

/// TCP transport configuration
#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub address: String,
    pub port: u16,
    pub connect_timeout_ms: u32,
    pub read_timeout_ms: u32,
    pub write_timeout_ms: u32,
    pub is_server: bool,
    pub max_message_size: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".to_string(),
            port: 8080,
            connect_timeout_ms: 5000,
            read_timeout_ms: 5000,
            write_timeout_ms: 5000,
            is_server: false,
            max_message_size: 64 * 1024,  // 64KB
        }
    }
}

/// TCP transport implementation  
pub struct TcpTransport {
    config: TcpConfig,
    #[cfg(feature = "std")]
    stream: Arc<Mutex<Option<TcpStream>>>,
    #[cfg(feature = "std")]
    listener: Arc<Mutex<Option<TcpListener>>>,
    is_connected: Arc<Mutex<bool>>,
}

impl TcpTransport {
    pub fn new(config: TcpConfig) -> TransportResult<Self> {
        if config.max_message_size > 1024 * 1024 {  // 1MB limit
            return Err(TransportError::ConfigurationError("Max message size too large"));
        }
        
        if config.port == 0 {
            return Err(TransportError::ConfigurationError("Invalid port number"));
        }
        
        Ok(Self {
            config,
            #[cfg(feature = "std")]
            stream: Arc::new(Mutex::new(None)),
            #[cfg(feature = "std")]
            listener: Arc::new(Mutex::new(None)),
            is_connected: Arc::new(Mutex::new(false)),
        })
    }
    
    #[cfg(feature = "std")]
    fn connect_client(&self) -> TransportResult<()> {
        let address = format!("{}:{}", self.config.address, self.config.port);
        let socket_addr: SocketAddr = address.parse()
            .map_err(|_| TransportError::ConfigurationError("Invalid address format"))?;
        
        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(self.config.connect_timeout_ms as u64))
            .map_err(|e| TransportError::ConnectionError(&format!("Failed to connect: {}", e)))?;
        
        // Set timeouts
        stream.set_read_timeout(Some(Duration::from_millis(self.config.read_timeout_ms as u64)))
            .map_err(|e| TransportError::ConfigurationError(&format!("Failed to set read timeout: {}", e)))?;
        
        stream.set_write_timeout(Some(Duration::from_millis(self.config.write_timeout_ms as u64)))
            .map_err(|e| TransportError::ConfigurationError(&format!("Failed to set write timeout: {}", e)))?;
        
        let mut stream_guard = self.stream.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire stream lock"))?;
        *stream_guard = Some(stream);
        
        Ok(())
    }
    
    #[cfg(feature = "std")]
    fn start_server(&self) -> TransportResult<()> {
        let address = format!("{}:{}", self.config.address, self.config.port);
        let socket_addr: SocketAddr = address.parse()
            .map_err(|_| TransportError::ConfigurationError("Invalid address format"))?;
        
        let listener = TcpListener::bind(socket_addr)
            .map_err(|e| TransportError::ConnectionError(&format!("Failed to bind server: {}", e)))?;
        
        let mut listener_guard = self.listener.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire listener lock"))?;
        *listener_guard = Some(listener);
        
        Ok(())
    }
    
    #[cfg(feature = "std")]
    fn accept_connection(&self) -> TransportResult<()> {
        let listener_guard = self.listener.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire listener lock"))?;
        
        if let Some(ref listener) = *listener_guard {
            let (stream, _addr) = listener.accept()
                .map_err(|e| TransportError::ConnectionError(&format!("Failed to accept connection: {}", e)))?;
            
            // Set timeouts
            stream.set_read_timeout(Some(Duration::from_millis(self.config.read_timeout_ms as u64)))
                .map_err(|e| TransportError::ConfigurationError(&format!("Failed to set read timeout: {}", e)))?;
            
            stream.set_write_timeout(Some(Duration::from_millis(self.config.write_timeout_ms as u64)))
                .map_err(|e| TransportError::ConfigurationError(&format!("Failed to set write timeout: {}", e)))?;
            
            drop(listener_guard);  // Release listener lock
            
            let mut stream_guard = self.stream.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire stream lock"))?;
            *stream_guard = Some(stream);
            
            Ok(())
        } else {
            Err(TransportError::ConnectionError("Server not started"))
        }
    }
    
    #[cfg(feature = "std")]
    fn send_message(&self, data: &[u8]) -> TransportResult<usize> {
        let mut stream_guard = self.stream.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire stream lock"))?;
        
        if let Some(ref mut stream) = *stream_guard {
            // Send message length first (4 bytes, big-endian)
            let len_bytes = (data.len() as u32).to_be_bytes();
            stream.write_all(&len_bytes)
                .map_err(|e| TransportError::IoError(format!("Failed to send length: {}", e)))?;
            
            // Send message data
            stream.write_all(data)
                .map_err(|e| TransportError::IoError(format!("Failed to send data: {}", e)))?;
            
            stream.flush()
                .map_err(|e| TransportError::IoError(format!("Failed to flush: {}", e)))?;
            
            Ok(4 + data.len())  // Length prefix + data
        } else {
            Err(TransportError::ConnectionError("Not connected"))
        }
    }
    
    #[cfg(feature = "std")]
    fn receive_message(&self, buffer: &mut [u8]) -> TransportResult<usize> {
        let mut stream_guard = self.stream.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire stream lock"))?;
        
        if let Some(ref mut stream) = *stream_guard {
            // Read message length first (4 bytes, big-endian)
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes)
                .map_err(|e| TransportError::IoError(format!("Failed to read length: {}", e)))?;
            
            let message_len = u32::from_be_bytes(len_bytes) as usize;
            
            if message_len > self.config.max_message_size {
                return Err(TransportError::MessageTooLarge("Message exceeds max size"));
            }
            
            if message_len > buffer.len() {
                return Err(TransportError::BufferError("Buffer too small for message"));
            }
            
            // Read message data
            stream.read_exact(&mut buffer[..message_len])
                .map_err(|e| TransportError::IoError(format!("Failed to read data: {}", e)))?;
            
            Ok(message_len)
        } else {
            Err(TransportError::ConnectionError("Not connected"))
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, data: &Buffer) -> TransportResult<usize> {
        let payload = data.as_slice();
        
        if payload.len() > self.config.max_message_size {
            return Err(TransportError::MessageTooLarge("Message exceeds max size"));
        }
        
        #[cfg(feature = "std")]
        {
            self.send_message(payload)
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, simulate sending
            Ok(payload.len())
        }
    }
    
    fn receive(&self, buffer: &mut Buffer) -> TransportResult<usize> {
        #[cfg(feature = "std")]
        {
            let mut temp_buffer = vec![0u8; self.config.max_message_size];
            let received = self.receive_message(&mut temp_buffer)?;
            
            if received > 0 {
                buffer.clear();
                buffer.extend_from_slice(&temp_buffer[..received])
                    .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
            }
            
            Ok(received)
        }
        
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, simulate receiving
            Ok(0)
        }
    }
    
    fn connect(&self) -> TransportResult<()> {
        #[cfg(feature = "std")]
        {
            if self.config.is_server {
                self.start_server()?;
                self.accept_connection()?;
            } else {
                self.connect_client()?;
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
            let mut stream_guard = self.stream.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire stream lock"))?;
            *stream_guard = None;
            
            let mut listener_guard = self.listener.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire listener lock"))?;
            *listener_guard = None;
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
        if let Some(address) = config.get_string("address") {
            self.config.address = address;
        }
        
        if let Some(port) = config.get_u16("port") {
            if port == 0 {
                return Err(TransportError::ConfigurationError("Invalid port number"));
            }
            self.config.port = port;
        }
        
        if let Some(timeout) = config.get_u32("connect_timeout_ms") {
            self.config.connect_timeout_ms = timeout;
        }
        
        if let Some(timeout) = config.get_u32("read_timeout_ms") {
            self.config.read_timeout_ms = timeout;
        }
        
        if let Some(timeout) = config.get_u32("write_timeout_ms") {
            self.config.write_timeout_ms = timeout;
        }
        
        if let Some(is_server) = config.get_bool("is_server") {
            self.config.is_server = is_server;
        }
        
        if let Some(max_size) = config.get_usize("max_message_size") {
            if max_size > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max message size too large"));
            }
            self.config.max_message_size = max_size;
        }
        
        Ok(())
    }
    
    fn get_info(&self) -> crate::TransportInfo {
        crate::TransportInfo {
            name: "TCP",
            version: "1.0.0",
            description: "TCP/IP network transport",
            max_message_size: self.config.max_message_size,
            supports_fragmentation: false,
            is_reliable: true,
        }
    }
}

/// TCP transport factory
pub struct TcpTransportFactory;

impl TransportFactory for TcpTransportFactory {
    fn create_transport(&self, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let tcp_config = TcpConfig {
            address: config.get_string("address").unwrap_or_else(|| "127.0.0.1".to_string()),
            port: config.get_u16("port").unwrap_or(8080),
            connect_timeout_ms: config.get_u32("connect_timeout_ms").unwrap_or(5000),
            read_timeout_ms: config.get_u32("read_timeout_ms").unwrap_or(5000),
            write_timeout_ms: config.get_u32("write_timeout_ms").unwrap_or(5000),
            is_server: config.get_bool("is_server").unwrap_or(false),
            max_message_size: config.get_usize("max_message_size").unwrap_or(64 * 1024),
        };
        
        let transport = TcpTransport::new(tcp_config)?;
        Ok(Box::new(transport))
    }
    
    fn name(&self) -> &'static str {
        "tcp"
    }
    
    fn supported_params(&self) -> &[&'static str] {
        &[
            "address",
            "port",
            "connect_timeout_ms",
            "read_timeout_ms",
            "write_timeout_ms",
            "is_server",
            "max_message_size",
        ]
    }
    
    fn validate_config(&self, config: &TransportConfig) -> TransportResult<()> {
        if let Some(port) = config.get_u16("port") {
            if port == 0 {
                return Err(TransportError::ConfigurationError("Invalid port number"));
            }
        }
        
        if let Some(max_size) = config.get_usize("max_message_size") {
            if max_size > 1024 * 1024 {
                return Err(TransportError::ConfigurationError("Max message size too large"));
            }
        }
        
        Ok(())
    }
}