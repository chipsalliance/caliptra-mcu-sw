//! TCP transport implementation for testing and development

use caliptra_util_host_core::transport::{Transport, TransportError, TransportResult, TransportType, TransportConfig};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::net::SocketAddr;

pub struct TcpTransport {
    host: String,
    port: u16,
    stream: Option<TcpStream>,
    config: TransportConfig,
}

impl TcpTransport {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            stream: None,
            config: TransportConfig::default(),
        }
    }
    
    pub fn with_config(host: String, port: u16, config: TransportConfig) -> Self {
        Self {
            host,
            port,
            stream: None,
            config,
        }
    }
    
    pub fn from_addr(addr: SocketAddr) -> Self {
        Self::new(addr.ip().to_string(), addr.port())
    }
    
    async fn with_timeout<F, T>(&self, operation: F) -> TransportResult<T>
    where
        F: std::future::Future<Output = TransportResult<T>>,
    {
        timeout(Duration::from_millis(self.config.timeout_ms), operation)
            .await
            .map_err(|_| TransportError::Timeout)?
    }
    
    async fn send_with_retry<F, T>(&mut self, mut operation: F) -> TransportResult<T>
    where
        F: FnMut(&mut Self) -> std::pin::Pin<Box<dyn std::future::Future<Output = TransportResult<T>> + '_>>,
    {
        let mut last_error = TransportError::ConnectionFailed("No attempts made".to_string());
        
        for attempt in 0..=self.config.max_retries {
            match operation(self).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e;
                    
                    if attempt < self.config.max_retries {
                        log::debug!("TCP transport attempt {} failed, retrying...", attempt + 1);
                        
                        // Disconnect and reconnect on retry
                        self.stream = None;
                        if self.connect().await.is_err() {
                            continue;
                        }
                    }
                }
            }
        }
        
        Err(last_error)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Tcp
    }
    
    async fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        self.send_with_retry(|transport| {
            Box::pin(async move {
                transport.with_timeout(async {
                    transport.send_internal(data).await
                }).await
            })
        }).await
    }
    
    async fn send_no_response(&mut self, data: &[u8]) -> TransportResult<()> {
        self.send_with_retry(|transport| {
            Box::pin(async move {
                transport.with_timeout(async {
                    transport.send_no_response_internal(data).await
                }).await
            })
        }).await
    }
    
    async fn receive(&mut self) -> TransportResult<Vec<u8>> {
        self.with_timeout(async {
            if let Some(ref mut stream) = self.stream {
                let len = stream.read_u32().await
                    .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
                    
                if len > self.max_message_size() as u32 {
                    return Err(TransportError::InvalidMessage);
                }
                
                let mut data = vec![0u8; len as usize];
                stream.read_exact(&mut data).await
                    .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
                
                log::debug!("TCP received {} bytes", data.len());
                Ok(data)
            } else {
                Err(TransportError::Disconnected)
            }
        }).await
    }
    
    async fn connect(&mut self) -> TransportResult<()> {
        log::info!("Connecting to TCP {}:{}", self.host, self.port);
        
        let addr = format!("{}:{}", self.host, self.port);
        let stream = self.with_timeout(async {
            TcpStream::connect(&addr).await
                .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
        }).await?;
        
        // Set TCP options for better performance
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("Failed to set TCP_NODELAY: {}", e);
        }
        
        self.stream = Some(stream);
        log::info!("Successfully connected to TCP {}:{}", self.host, self.port);
        Ok(())
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        if let Some(mut stream) = self.stream.take() {
            log::info!("Disconnecting from TCP {}:{}", self.host, self.port);
            
            // Graceful shutdown
            if let Err(e) = stream.shutdown().await {
                log::warn!("Error during TCP shutdown: {}", e);
            }
        }
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
    
    fn max_message_size(&self) -> usize {
        self.config.buffer_size.min(65536) // Cap at 64KB for TCP
    }
    
    fn get_config(&self) -> TransportConfig {
        self.config.clone()
    }
}

impl TcpTransport {
    async fn send_internal(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            // Validate message size
            if data.len() > self.max_message_size() {
                return Err(TransportError::InvalidMessage);
            }
            
            log::debug!("TCP sending {} bytes", data.len());
            
            // Send length first, then data
            let len = data.len() as u32;
            stream.write_u32(len).await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            stream.write_all(data).await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            stream.flush().await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            // Read response length, then response data
            let response_len = stream.read_u32().await
                .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
                
            if response_len > self.max_message_size() as u32 {
                return Err(TransportError::InvalidMessage);
            }
            
            let mut response = vec![0u8; response_len as usize];
            stream.read_exact(&mut response).await
                .map_err(|e| TransportError::ReceiveFailed(e.to_string()))?;
            
            log::debug!("TCP received {} bytes", response.len());
            Ok(response)
        } else {
            Err(TransportError::Disconnected)
        }
    }
    
    async fn send_no_response_internal(&mut self, data: &[u8]) -> TransportResult<()> {
        if let Some(ref mut stream) = self.stream {
            if data.len() > self.max_message_size() {
                return Err(TransportError::InvalidMessage);
            }
            
            log::debug!("TCP sending {} bytes (no response)", data.len());
            
            // Send length first, then data
            let len = data.len() as u32;
            stream.write_u32(len).await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            stream.write_all(data).await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            stream.flush().await
                .map_err(|e| TransportError::SendFailed(e.to_string()))?;
            
            Ok(())
        } else {
            Err(TransportError::Disconnected)
        }
    }
}

/// TCP Server for testing purposes
pub struct TcpTestServer {
    port: u16,
    response_handler: Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>,
}

impl TcpTestServer {
    pub fn new<F>(port: u16, handler: F) -> Self
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        Self {
            port,
            response_handler: Box::new(handler),
        }
    }
    
    pub async fn start(&self) -> TransportResult<()> {
        use tokio::net::TcpListener;
        
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        
        log::info!("TCP test server listening on {}", addr);
        
        loop {
            match listener.accept().await {
                Ok((mut socket, peer_addr)) => {
                    log::info!("TCP test server: new connection from {}", peer_addr);
                    
                    let handler = self.response_handler.as_ref();
                    
                    tokio::spawn(async move {
                        loop {
                            match socket.read_u32().await {
                                Ok(len) => {
                                    if len > 65536 {
                                        log::error!("Message too large: {} bytes", len);
                                        break;
                                    }
                                    
                                    let mut data = vec![0u8; len as usize];
                                    if socket.read_exact(&mut data).await.is_err() {
                                        break;
                                    }
                                    
                                    log::debug!("TCP server received {} bytes", data.len());
                                    
                                    // Generate response
                                    let response = handler(&data);
                                    
                                    // Send response
                                    let response_len = response.len() as u32;
                                    if socket.write_u32(response_len).await.is_err() {
                                        break;
                                    }
                                    if socket.write_all(&response).await.is_err() {
                                        break;
                                    }
                                    if socket.flush().await.is_err() {
                                        break;
                                    }
                                    
                                    log::debug!("TCP server sent {} bytes", response.len());
                                },
                                Err(_) => {
                                    log::info!("TCP test server: client disconnected");
                                    break;
                                }
                            }
                        }
                    });
                },
                Err(e) => {
                    log::error!("TCP test server accept error: {}", e);
                }
            }
        }
    }
}