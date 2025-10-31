//! Mock transport implementation for testing

use crate::{Transport, TransportConfig, TransportError, TransportResult, registry::TransportFactory};
use caliptra_osal::{memory::Buffer, sync::{Mutex, Arc}};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec, collections::VecDeque, string::String};

/// Mock transport configuration
#[derive(Debug, Clone)]
pub struct MockConfig {
    pub simulate_errors: bool,
    pub error_rate: f32,  // 0.0 to 1.0
    pub latency_ms: u32,
    pub max_message_size: usize,
    pub drop_rate: f32,   // 0.0 to 1.0, for simulating packet loss
    pub duplicate_rate: f32, // 0.0 to 1.0, for simulating duplicates
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            simulate_errors: false,
            error_rate: 0.0,
            latency_ms: 0,
            max_message_size: 64 * 1024,
            drop_rate: 0.0,
            duplicate_rate: 0.0,
        }
    }
}

/// Mock transport for testing and simulation
pub struct MockTransport {
    config: MockConfig,
    send_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    receive_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
    is_connected: Arc<Mutex<bool>>,
    message_counter: Arc<Mutex<u64>>,
    error_counter: Arc<Mutex<u64>>,
}

impl MockTransport {
    pub fn new(config: MockConfig) -> TransportResult<Self> {
        if config.error_rate < 0.0 || config.error_rate > 1.0 {
            return Err(TransportError::ConfigurationError("Error rate must be between 0.0 and 1.0"));
        }
        
        if config.drop_rate < 0.0 || config.drop_rate > 1.0 {
            return Err(TransportError::ConfigurationError("Drop rate must be between 0.0 and 1.0"));
        }
        
        if config.duplicate_rate < 0.0 || config.duplicate_rate > 1.0 {
            return Err(TransportError::ConfigurationError("Duplicate rate must be between 0.0 and 1.0"));
        }
        
        Ok(Self {
            config,
            send_queue: Arc::new(Mutex::new(VecDeque::new())),
            receive_queue: Arc::new(Mutex::new(VecDeque::new())),
            is_connected: Arc::new(Mutex::new(false)),
            message_counter: Arc::new(Mutex::new(0)),
            error_counter: Arc::new(Mutex::new(0)),
        })
    }
    
    /// Create a pair of connected mock transports for testing
    pub fn create_pair() -> TransportResult<(Self, Self)> {
        let config = MockConfig::default();
        let transport1 = Self::new(config.clone())?;
        let transport2 = Self::new(config)?;
        
        // Connect the transports by sharing queues
        let send_queue1 = transport1.send_queue.clone();
        let receive_queue1 = transport1.receive_queue.clone();
        let send_queue2 = transport2.send_queue.clone();  
        let receive_queue2 = transport2.receive_queue.clone();
        
        // Cross-connect: transport1's send queue is transport2's receive queue
        std::mem::swap(&mut *send_queue1.lock().unwrap(), &mut *receive_queue2.lock().unwrap());
        std::mem::swap(&mut *send_queue2.lock().unwrap(), &mut *receive_queue1.lock().unwrap());
        
        Ok((transport1, transport2))
    }
    
    fn should_simulate_error(&self) -> bool {
        if !self.config.simulate_errors {
            return false;
        }
        
        // Simple pseudo-random based on message counter
        let counter = self.message_counter.lock().unwrap();
        let pseudo_random = ((*counter * 1664525 + 1013904223) % 2147483647) as f32 / 2147483647.0;
        pseudo_random < self.config.error_rate
    }
    
    fn should_drop_message(&self) -> bool {
        let counter = self.message_counter.lock().unwrap();
        let pseudo_random = ((*counter * 22695477 + 1) % 2147483647) as f32 / 2147483647.0;
        pseudo_random < self.config.drop_rate
    }
    
    fn should_duplicate_message(&self) -> bool {
        let counter = self.message_counter.lock().unwrap();
        let pseudo_random = ((*counter * 1103515245 + 12345) % 2147483647) as f32 / 2147483647.0;
        pseudo_random < self.config.duplicate_rate
    }
    
    fn simulate_latency(&self) {
        if self.config.latency_ms > 0 {
            caliptra_osal::time::sleep_ms(self.config.latency_ms);
        }
    }
    
    pub fn inject_message(&self, data: Vec<u8>) -> TransportResult<()> {
        let mut receive_queue = self.receive_queue.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire receive queue lock"))?;
        
        receive_queue.push_back(data);
        Ok(())
    }
    
    pub fn get_sent_messages(&self) -> TransportResult<Vec<Vec<u8>>> {
        let send_queue = self.send_queue.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire send queue lock"))?;
        
        Ok(send_queue.iter().cloned().collect())
    }
    
    pub fn clear_queues(&self) -> TransportResult<()> {
        let mut send_queue = self.send_queue.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire send queue lock"))?;
        let mut receive_queue = self.receive_queue.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire receive queue lock"))?;
        
        send_queue.clear();
        receive_queue.clear();
        
        Ok(())
    }
    
    pub fn get_statistics(&self) -> TransportResult<MockStatistics> {
        let message_count = self.message_counter.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire message counter lock"))?;
        let error_count = self.error_counter.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire error counter lock"))?;
        
        Ok(MockStatistics {
            messages_sent: *message_count,
            errors_simulated: *error_count,
            error_rate: self.config.error_rate,
            drop_rate: self.config.drop_rate,
            duplicate_rate: self.config.duplicate_rate,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MockStatistics {
    pub messages_sent: u64,
    pub errors_simulated: u64,
    pub error_rate: f32,
    pub drop_rate: f32,
    pub duplicate_rate: f32,
}

impl Transport for MockTransport {
    fn send(&self, data: &Buffer) -> TransportResult<usize> {
        let payload = data.as_slice();
        
        if payload.len() > self.config.max_message_size {
            return Err(TransportError::MessageTooLarge("Message exceeds max size"));
        }
        
        // Increment message counter
        {
            let mut counter = self.message_counter.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire message counter lock"))?;
            *counter += 1;
        }
        
        // Simulate latency
        self.simulate_latency();
        
        // Check if we should simulate an error
        if self.should_simulate_error() {
            let mut error_count = self.error_counter.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire error counter lock"))?;
            *error_count += 1;
            
            return Err(TransportError::Custom("Simulated error"));
        }
        
        // Check if we should drop the message
        if self.should_drop_message() {
            return Ok(payload.len()); // Pretend it was sent successfully
        }
        
        let message = payload.to_vec();
        
        // Add to send queue
        {
            let mut send_queue = self.send_queue.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire send queue lock"))?;
            send_queue.push_back(message.clone());
        }
        
        // Check if we should duplicate the message
        if self.should_duplicate_message() {
            let mut send_queue = self.send_queue.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire send queue lock"))?;
            send_queue.push_back(message);
        }
        
        Ok(payload.len())
    }
    
    fn receive(&self, buffer: &mut Buffer) -> TransportResult<usize> {
        // Simulate latency
        self.simulate_latency();
        
        // Check if we should simulate an error  
        if self.should_simulate_error() {
            let mut error_count = self.error_counter.lock()
                .map_err(|_| TransportError::Custom("Failed to acquire error counter lock"))?;
            *error_count += 1;
            
            return Err(TransportError::Custom("Simulated error"));
        }
        
        let mut receive_queue = self.receive_queue.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire receive queue lock"))?;
        
        if let Some(message) = receive_queue.pop_front() {
            let copy_size = core::cmp::min(message.len(), buffer.capacity());
            buffer.clear();
            buffer.extend_from_slice(&message[..copy_size])
                .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
            
            Ok(copy_size)
        } else {
            Ok(0)  // No message available
        }
    }
    
    fn connect(&self) -> TransportResult<()> {
        let mut is_connected = self.is_connected.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire connection status lock"))?;
        *is_connected = true;
        
        Ok(())
    }
    
    fn disconnect(&self) -> TransportResult<()> {
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
        if let Some(simulate_errors) = config.get_bool("simulate_errors") {
            self.config.simulate_errors = simulate_errors;
        }
        
        if let Some(error_rate) = config.get_f32("error_rate") {
            if error_rate < 0.0 || error_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Error rate must be between 0.0 and 1.0"));
            }
            self.config.error_rate = error_rate;
        }
        
        if let Some(latency) = config.get_u32("latency_ms") {
            self.config.latency_ms = latency;
        }
        
        if let Some(max_size) = config.get_usize("max_message_size") {
            self.config.max_message_size = max_size;
        }
        
        if let Some(drop_rate) = config.get_f32("drop_rate") {
            if drop_rate < 0.0 || drop_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Drop rate must be between 0.0 and 1.0"));
            }
            self.config.drop_rate = drop_rate;
        }
        
        if let Some(duplicate_rate) = config.get_f32("duplicate_rate") {
            if duplicate_rate < 0.0 || duplicate_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Duplicate rate must be between 0.0 and 1.0"));
            }
            self.config.duplicate_rate = duplicate_rate;
        }
        
        Ok(())
    }
    
    fn get_info(&self) -> crate::TransportInfo {
        crate::TransportInfo {
            name: "Mock",
            version: "1.0.0", 
            description: "Mock transport for testing",
            max_message_size: self.config.max_message_size,
            supports_fragmentation: false,
            is_reliable: !self.config.simulate_errors && self.config.drop_rate == 0.0,
        }
    }
}

/// Mock transport factory
pub struct MockTransportFactory;

impl TransportFactory for MockTransportFactory {
    fn create_transport(&self, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let mock_config = MockConfig {
            simulate_errors: config.get_bool("simulate_errors").unwrap_or(false),
            error_rate: config.get_f32("error_rate").unwrap_or(0.0),
            latency_ms: config.get_u32("latency_ms").unwrap_or(0),
            max_message_size: config.get_usize("max_message_size").unwrap_or(64 * 1024),
            drop_rate: config.get_f32("drop_rate").unwrap_or(0.0),
            duplicate_rate: config.get_f32("duplicate_rate").unwrap_or(0.0),
        };
        
        let transport = MockTransport::new(mock_config)?;
        Ok(Box::new(transport))
    }
    
    fn name(&self) -> &'static str {
        "mock"
    }
    
    fn supported_params(&self) -> &[&'static str] {
        &[
            "simulate_errors",
            "error_rate",
            "latency_ms",
            "max_message_size",
            "drop_rate",
            "duplicate_rate",
        ]
    }
    
    fn validate_config(&self, config: &TransportConfig) -> TransportResult<()> {
        if let Some(error_rate) = config.get_f32("error_rate") {
            if error_rate < 0.0 || error_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Error rate must be between 0.0 and 1.0"));
            }
        }
        
        if let Some(drop_rate) = config.get_f32("drop_rate") {
            if drop_rate < 0.0 || drop_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Drop rate must be between 0.0 and 1.0"));
            }
        }
        
        if let Some(duplicate_rate) = config.get_f32("duplicate_rate") {
            if duplicate_rate < 0.0 || duplicate_rate > 1.0 {
                return Err(TransportError::ConfigurationError("Duplicate rate must be between 0.0 and 1.0"));
            }
        }
        
        Ok(())
    }
}