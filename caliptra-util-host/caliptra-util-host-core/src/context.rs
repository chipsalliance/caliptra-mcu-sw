//! Context for maintaining state during command execution

use std::collections::HashMap;
use crate::transport::Transport;

/// Context object that maintains state during command execution
pub struct CaliptraContext {
    transport: Box<dyn Transport>,
    session_data: HashMap<String, Vec<u8>>,
    properties: HashMap<String, String>,
    sequence_number: u32,
}

impl CaliptraContext {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            transport,
            session_data: HashMap::new(),
            properties: HashMap::new(),
            sequence_number: 0,
        }
    }
    
    /// Get mutable reference to transport
    pub fn transport_mut(&mut self) -> &mut dyn Transport {
        self.transport.as_mut()
    }
    
    /// Get reference to transport
    pub fn transport(&self) -> &dyn Transport {
        self.transport.as_ref()
    }
    
    /// Store session data
    pub fn set_session_data(&mut self, key: String, data: Vec<u8>) {
        log::debug!("Setting session data for key: {}", key);
        self.session_data.insert(key, data);
    }
    
    /// Retrieve session data
    pub fn get_session_data(&self, key: &str) -> Option<&[u8]> {
        self.session_data.get(key).map(|v| v.as_slice())
    }
    
    /// Remove session data
    pub fn remove_session_data(&mut self, key: &str) -> Option<Vec<u8>> {
        self.session_data.remove(key)
    }
    
    /// Clear all session data
    pub fn clear_session_data(&mut self) {
        log::debug!("Clearing all session data");
        self.session_data.clear();
    }
    
    /// Set a context property
    pub fn set_property(&mut self, key: String, value: String) {
        log::debug!("Setting property: {} = {}", key, value);
        self.properties.insert(key, value);
    }
    
    /// Get a context property
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }
    
    /// Remove a context property
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.properties.remove(key)
    }
    
    /// Get all properties
    pub fn get_all_properties(&self) -> &HashMap<String, String> {
        &self.properties
    }
    
    /// Generate next sequence number
    pub fn next_sequence_number(&mut self) -> u32 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.sequence_number
    }
    
    /// Get current sequence number
    pub fn current_sequence_number(&self) -> u32 {
        self.sequence_number
    }
    
    /// Check if transport is connected
    pub fn is_connected(&self) -> bool {
        self.transport.is_connected()
    }
    
    /// Get transport type
    pub fn transport_type(&self) -> crate::transport::TransportType {
        self.transport.transport_type()
    }
    
    /// Get transport configuration
    pub fn transport_config(&self) -> crate::transport::TransportConfig {
        self.transport.get_config()
    }
}