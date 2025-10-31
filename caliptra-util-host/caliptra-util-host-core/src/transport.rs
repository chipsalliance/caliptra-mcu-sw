//! Transport layer abstraction for different communication protocols

use async_trait::async_trait;
use thiserror::Error;

pub type TransportResult<T> = std::result::Result<T, TransportError>;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Send failed: {0}")]
    SendFailed(String),
    
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    
    #[error("Timeout occurred")]
    Timeout,
    
    #[error("Transport not supported: {0}")]
    NotSupported(String),
    
    #[error("Invalid message format")]
    InvalidMessage,
    
    #[error("Transport disconnected")]
    Disconnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Mctp,
    Doe,
    Tcp,
    Custom,
}

/// Generic transport trait for different communication protocols
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get the transport type
    fn transport_type(&self) -> TransportType;
    
    /// Send data and receive response
    async fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>>;
    
    /// Send data without expecting a response
    async fn send_no_response(&mut self, data: &[u8]) -> TransportResult<()>;
    
    /// Receive data (for listening mode)
    async fn receive(&mut self) -> TransportResult<Vec<u8>>;
    
    /// Connect to the target device
    async fn connect(&mut self) -> TransportResult<()>;
    
    /// Disconnect from the target device
    async fn disconnect(&mut self) -> TransportResult<()>;
    
    /// Check if connected
    fn is_connected(&self) -> bool;
    
    /// Get maximum message size
    fn max_message_size(&self) -> usize;
    
    /// Get transport-specific configuration
    fn get_config(&self) -> TransportConfig;
}

/// Transport configuration
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub max_retries: u32,
    pub timeout_ms: u64,
    pub buffer_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            timeout_ms: 5000,
            buffer_size: 4096,
        }
    }
}

/// MCTP transport implementation
pub struct MctpTransport {
    endpoint_id: u8,
    connected: bool,
    config: TransportConfig,
}

impl MctpTransport {
    pub fn new(endpoint_id: u8) -> Self {
        Self {
            endpoint_id,
            connected: false,
            config: TransportConfig::default(),
        }
    }
    
    pub fn with_config(endpoint_id: u8, config: TransportConfig) -> Self {
        Self {
            endpoint_id,
            connected: false,
            config,
        }
    }
}

#[async_trait]
impl Transport for MctpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Mctp
    }
    
    async fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if !self.is_connected() {
            return Err(TransportError::ConnectionFailed("Not connected".to_string()));
        }
        
        // TODO: Implement MCTP specific logic
        // This would integrate with libmctp or similar
        log::info!("Sending MCTP message to endpoint 0x{:02X}: {} bytes", self.endpoint_id, data.len());
        
        // Validate message size
        if data.len() > self.max_message_size() {
            return Err(TransportError::InvalidMessage);
        }
        
        // Placeholder implementation - would be replaced with actual MCTP calls
        #[cfg(feature = "async")]
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Simulate response
        Ok(vec![0x00, 0x01, 0x02])
    }
    
    async fn send_no_response(&mut self, data: &[u8]) -> TransportResult<()> {
        self.send(data).await.map(|_| ())
    }
    
    async fn receive(&mut self) -> TransportResult<Vec<u8>> {
        if !self.is_connected() {
            return Err(TransportError::Disconnected);
        }
        
        // TODO: Implement MCTP receive logic
        Err(TransportError::NotSupported("Receive not implemented".to_string()))
    }
    
    async fn connect(&mut self) -> TransportResult<()> {
        log::info!("Connecting to MCTP endpoint 0x{:02X}", self.endpoint_id);
        
        // TODO: Implement actual MCTP connection logic
        // This would involve:
        // - Opening MCTP socket or device
        // - Performing MCTP discovery
        // - Establishing connection to endpoint
        
        self.connected = true;
        log::info!("Successfully connected to MCTP endpoint");
        Ok(())
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        log::info!("Disconnecting from MCTP endpoint 0x{:02X}", self.endpoint_id);
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn max_message_size(&self) -> usize {
        4096 // MCTP typical max payload size
    }
    
    fn get_config(&self) -> TransportConfig {
        self.config.clone()
    }
}

/// DOE (Data Object Exchange) transport implementation
pub struct DoeTransport {
    connected: bool,
    config: TransportConfig,
    device_path: Option<String>,
}

impl DoeTransport {
    pub fn new() -> Self {
        Self { 
            connected: false,
            config: TransportConfig::default(),
            device_path: None,
        }
    }
    
    pub fn with_device(device_path: String) -> Self {
        Self {
            connected: false,
            config: TransportConfig::default(),
            device_path: Some(device_path),
        }
    }
}

#[async_trait]
impl Transport for DoeTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Doe
    }
    
    async fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if !self.is_connected() {
            return Err(TransportError::ConnectionFailed("Not connected".to_string()));
        }
        
        log::info!("Sending DOE message: {} bytes", data.len());
        
        // Validate message size
        if data.len() > self.max_message_size() {
            return Err(TransportError::InvalidMessage);
        }
        
        // TODO: Implement DOE specific logic
        // This would involve:
        // - Writing to DOE capability registers
        // - Polling for completion
        // - Reading response data
        
        #[cfg(feature = "async")]
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        
        // Simulate response
        Ok(vec![0x10, 0x11, 0x12])
    }
    
    async fn send_no_response(&mut self, data: &[u8]) -> TransportResult<()> {
        self.send(data).await.map(|_| ())
    }
    
    async fn receive(&mut self) -> TransportResult<Vec<u8>> {
        Err(TransportError::NotSupported("DOE is request-response only".to_string()))
    }
    
    async fn connect(&mut self) -> TransportResult<()> {
        log::info!("Connecting to DOE interface");
        
        // TODO: Implement DOE connection logic
        // This would involve:
        // - Opening PCIe device
        // - Finding DOE capability
        // - Initializing DOE interface
        
        self.connected = true;
        log::info!("Successfully connected to DOE interface");
        Ok(())
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        log::info!("Disconnecting from DOE interface");
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn max_message_size(&self) -> usize {
        2048 // DOE typical max data object size
    }
    
    fn get_config(&self) -> TransportConfig {
        self.config.clone()
    }
}

impl Default for DoeTransport {
    fn default() -> Self {
        Self::new()
    }
}