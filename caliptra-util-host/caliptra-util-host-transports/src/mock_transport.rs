//! Mock transport for testing and development

use caliptra_util_host_core::transport::{Transport, TransportError, TransportResult, TransportType, TransportConfig};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MockBehavior {
    /// Always return success with specified response
    Success(Vec<u8>),
    /// Always return the specified error
    Error(String),
    /// Return responses in sequence, cycling when exhausted
    Sequence(Vec<Vec<u8>>),
    /// Echo the request data back as response
    Echo,
    /// Return empty response
    Empty,
    /// Simulate timeout
    Timeout,
    /// Custom behavior with delay
    DelayedResponse { response: Vec<u8>, delay_ms: u64 },
}

pub struct MockTransport {
    behavior: MockBehavior,
    connected: bool,
    config: TransportConfig,
    call_history: Arc<Mutex<Vec<Vec<u8>>>>,
    sequence_index: Arc<Mutex<usize>>,
    statistics: Arc<Mutex<MockTransportStats>>,
}

#[derive(Debug, Clone, Default)]
pub struct MockTransportStats {
    pub send_count: usize,
    pub receive_count: usize,
    pub connect_count: usize,
    pub disconnect_count: usize,
    pub error_count: usize,
    pub total_bytes_sent: usize,
    pub total_bytes_received: usize,
}

impl MockTransport {
    pub fn new(behavior: MockBehavior) -> Self {
        Self {
            behavior,
            connected: false,
            config: TransportConfig::default(),
            call_history: Arc::new(Mutex::new(Vec::new())),
            sequence_index: Arc::new(Mutex::new(0)),
            statistics: Arc::new(Mutex::new(MockTransportStats::default())),
        }
    }
    
    pub fn with_config(behavior: MockBehavior, config: TransportConfig) -> Self {
        Self {
            behavior,
            connected: false,
            config,
            call_history: Arc::new(Mutex::new(Vec::new())),
            sequence_index: Arc::new(Mutex::new(0)),
            statistics: Arc::new(Mutex::new(MockTransportStats::default())),
        }
    }
    
    /// Create a mock transport that echoes requests
    pub fn echo() -> Self {
        Self::new(MockBehavior::Echo)
    }
    
    /// Create a mock transport that returns a fixed response
    pub fn fixed_response(response: Vec<u8>) -> Self {
        Self::new(MockBehavior::Success(response))
    }
    
    /// Create a mock transport that returns different responses in sequence
    pub fn sequence_responses(responses: Vec<Vec<u8>>) -> Self {
        Self::new(MockBehavior::Sequence(responses))
    }
    
    /// Create a mock transport that always fails
    pub fn always_error(error_message: String) -> Self {
        Self::new(MockBehavior::Error(error_message))
    }
    
    /// Create a mock transport that simulates timeouts
    pub fn timeout() -> Self {
        Self::new(MockBehavior::Timeout)
    }
    
    /// Get the history of all send calls
    pub fn get_call_history(&self) -> Vec<Vec<u8>> {
        self.call_history.lock().unwrap().clone()
    }
    
    /// Clear call history
    pub fn clear_history(&mut self) {
        self.call_history.lock().unwrap().clear();
        *self.sequence_index.lock().unwrap() = 0;
    }
    
    /// Get transport statistics
    pub fn get_statistics(&self) -> MockTransportStats {
        self.statistics.lock().unwrap().clone()
    }
    
    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        *self.statistics.lock().unwrap() = MockTransportStats::default();
    }
    
    /// Update behavior at runtime
    pub fn set_behavior(&mut self, behavior: MockBehavior) {
        self.behavior = behavior;
        *self.sequence_index.lock().unwrap() = 0;
    }
    
    fn record_call(&self, data: &[u8]) {
        self.call_history.lock().unwrap().push(data.to_vec());
    }
    
    fn increment_send_stats(&self, bytes: usize) {
        let mut stats = self.statistics.lock().unwrap();
        stats.send_count += 1;
        stats.total_bytes_sent += bytes;
    }
    
    fn increment_receive_stats(&self, bytes: usize) {
        let mut stats = self.statistics.lock().unwrap();
        stats.receive_count += 1;
        stats.total_bytes_received += bytes;
    }
    
    fn increment_error_stats(&self) {
        self.statistics.lock().unwrap().error_count += 1;
    }
}

#[async_trait]
impl Transport for MockTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Custom
    }
    
    async fn send(&mut self, data: &[u8]) -> TransportResult<Vec<u8>> {
        if !self.is_connected() {
            self.increment_error_stats();
            return Err(TransportError::Disconnected);
        }
        
        self.record_call(data);
        self.increment_send_stats(data.len());
        
        let response = match &self.behavior {
            MockBehavior::Success(response) => response.clone(),
            
            MockBehavior::Error(error_msg) => {
                self.increment_error_stats();
                return Err(TransportError::SendFailed(error_msg.clone()));
            },
            
            MockBehavior::Sequence(responses) => {
                if responses.is_empty() {
                    Vec::new()
                } else {
                    let mut index = self.sequence_index.lock().unwrap();
                    let response = responses[*index % responses.len()].clone();
                    *index += 1;
                    response
                }
            },
            
            MockBehavior::Echo => data.to_vec(),
            
            MockBehavior::Empty => Vec::new(),
            
            MockBehavior::Timeout => {
                self.increment_error_stats();
                return Err(TransportError::Timeout);
            },
            
            MockBehavior::DelayedResponse { response, delay_ms } => {
                tokio::time::sleep(tokio::time::Duration::from_millis(*delay_ms)).await;
                response.clone()
            },
        };
        
        self.increment_receive_stats(response.len());
        Ok(response)
    }
    
    async fn send_no_response(&mut self, data: &[u8]) -> TransportResult<()> {
        if !self.is_connected() {
            self.increment_error_stats();
            return Err(TransportError::Disconnected);
        }
        
        self.record_call(data);
        self.increment_send_stats(data.len());
        
        match &self.behavior {
            MockBehavior::Error(error_msg) => {
                self.increment_error_stats();
                Err(TransportError::SendFailed(error_msg.clone()))
            },
            MockBehavior::Timeout => {
                self.increment_error_stats();
                Err(TransportError::Timeout)
            },
            MockBehavior::DelayedResponse { delay_ms, .. } => {
                tokio::time::sleep(tokio::time::Duration::from_millis(*delay_ms)).await;
                Ok(())
            },
            _ => Ok(()),
        }
    }
    
    async fn receive(&mut self) -> TransportResult<Vec<u8>> {
        if !self.is_connected() {
            self.increment_error_stats();
            return Err(TransportError::Disconnected);
        }
        
        match &self.behavior {
            MockBehavior::Success(response) => {
                self.increment_receive_stats(response.len());
                Ok(response.clone())
            },
            MockBehavior::Error(error_msg) => {
                self.increment_error_stats();
                Err(TransportError::ReceiveFailed(error_msg.clone()))
            },
            MockBehavior::Timeout => {
                self.increment_error_stats();
                Err(TransportError::Timeout)
            },
            _ => {
                // Most behaviors don't support receive-only
                self.increment_error_stats();
                Err(TransportError::NotSupported("Receive not supported for this behavior".to_string()))
            }
        }
    }
    
    async fn connect(&mut self) -> TransportResult<()> {
        self.statistics.lock().unwrap().connect_count += 1;
        
        match &self.behavior {
            MockBehavior::Error(error_msg) if error_msg.contains("connect") => {
                self.increment_error_stats();
                Err(TransportError::ConnectionFailed(error_msg.clone()))
            },
            MockBehavior::Timeout => {
                self.increment_error_stats();
                Err(TransportError::Timeout)
            },
            MockBehavior::DelayedResponse { delay_ms, .. } => {
                tokio::time::sleep(tokio::time::Duration::from_millis(*delay_ms)).await;
                self.connected = true;
                Ok(())
            },
            _ => {
                self.connected = true;
                Ok(())
            }
        }
    }
    
    async fn disconnect(&mut self) -> TransportResult<()> {
        self.statistics.lock().unwrap().disconnect_count += 1;
        self.connected = false;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn max_message_size(&self) -> usize {
        self.config.buffer_size
    }
    
    fn get_config(&self) -> TransportConfig {
        self.config.clone()
    }
}

/// Builder for creating complex mock transport scenarios
pub struct MockTransportBuilder {
    behaviors: VecDeque<MockBehavior>,
    config: TransportConfig,
}

impl MockTransportBuilder {
    pub fn new() -> Self {
        Self {
            behaviors: VecDeque::new(),
            config: TransportConfig::default(),
        }
    }
    
    pub fn with_config(config: TransportConfig) -> Self {
        Self {
            behaviors: VecDeque::new(),
            config,
        }
    }
    
    pub fn then_respond(mut self, response: Vec<u8>) -> Self {
        self.behaviors.push_back(MockBehavior::Success(response));
        self
    }
    
    pub fn then_echo(mut self) -> Self {
        self.behaviors.push_back(MockBehavior::Echo);
        self
    }
    
    pub fn then_error(mut self, error: String) -> Self {
        self.behaviors.push_back(MockBehavior::Error(error));
        self
    }
    
    pub fn then_timeout(mut self) -> Self {
        self.behaviors.push_back(MockBehavior::Timeout);
        self
    }
    
    pub fn then_delay(mut self, response: Vec<u8>, delay_ms: u64) -> Self {
        self.behaviors.push_back(MockBehavior::DelayedResponse { response, delay_ms });
        self
    }
    
    pub fn build(self) -> MockTransport {
        if self.behaviors.is_empty() {
            MockTransport::with_config(MockBehavior::Echo, self.config)
        } else {
            let responses: Vec<Vec<u8>> = self.behaviors.into_iter()
                .filter_map(|b| match b {
                    MockBehavior::Success(data) => Some(data),
                    MockBehavior::Echo => Some(b"echo".to_vec()),
                    MockBehavior::Empty => Some(Vec::new()),
                    _ => None,
                })
                .collect();
            
            MockTransport::with_config(MockBehavior::Sequence(responses), self.config)
        }
    }
}

impl Default for MockTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mock_echo_transport() {
        let mut transport = MockTransport::echo();
        assert!(!transport.is_connected());
        
        transport.connect().await.unwrap();
        assert!(transport.is_connected());
        
        let test_data = b"hello world";
        let response = transport.send(test_data).await.unwrap();
        assert_eq!(response, test_data);
        
        let history = transport.get_call_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], test_data);
        
        let stats = transport.get_statistics();
        assert_eq!(stats.send_count, 1);
        assert_eq!(stats.total_bytes_sent, test_data.len());
    }
    
    #[tokio::test]
    async fn test_mock_sequence_transport() {
        let responses = vec![
            b"response1".to_vec(),
            b"response2".to_vec(),
            b"response3".to_vec(),
        ];
        
        let mut transport = MockTransport::sequence_responses(responses.clone());
        transport.connect().await.unwrap();
        
        // Test sequence
        for expected in &responses {
            let response = transport.send(b"request").await.unwrap();
            assert_eq!(&response, expected);
        }
        
        // Test cycling
        let response = transport.send(b"request").await.unwrap();
        assert_eq!(response, responses[0]);
    }
}