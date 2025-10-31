//! Transport registry and factory system

use crate::{Transport, TransportConfig, TransportError, TransportResult};
use caliptra_osal::{sync::Mutex, memory::Buffer};

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeMap, boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Factory trait for creating transports
pub trait TransportFactory: Send + Sync {
    /// Create a new transport instance
    fn create_transport(&self, config: TransportConfig) -> TransportResult<Box<dyn Transport>>;
    
    /// Get factory name
    fn name(&self) -> &'static str;
    
    /// Get supported configuration parameters
    fn supported_params(&self) -> &[&'static str] {
        &[]
    }
    
    /// Validate configuration
    fn validate_config(&self, _config: &TransportConfig) -> TransportResult<()> {
        Ok(())
    }
}

/// Transport registry for managing available transports
pub struct TransportRegistry {
    #[cfg(feature = "std")]
    factories: Mutex<HashMap<String, Box<dyn TransportFactory>>>,
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    factories: Mutex<BTreeMap<&'static str, Box<dyn TransportFactory>>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            factories: Mutex::new(HashMap::new()),
            #[cfg(all(feature = "alloc", not(feature = "std")))]
            factories: Mutex::new(BTreeMap::new()),
        }
    }
    
    /// Register a transport factory
    #[cfg(feature = "std")]
    pub fn register(&self, name: String, factory: Box<dyn TransportFactory>) -> TransportResult<()> {
        let mut factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        if factories.contains_key(&name) {
            return Err(TransportError::FactoryError("Transport already registered"));
        }
        
        factories.insert(name, factory);
        Ok(())
    }
    
    #[cfg(not(feature = "std"))]
    pub fn register(&self, name: &'static str, factory: Box<dyn TransportFactory>) -> TransportResult<()> {
        let mut factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        if factories.contains_key(name) {
            return Err(TransportError::FactoryError("Transport already registered"));
        }
        
        factories.insert(name, factory);
        Ok(())
    }
    
    /// Create a transport by name
    #[cfg(feature = "std")]
    pub fn create_transport(&self, name: &str, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        let factory = factories.get(name)
            .ok_or_else(|| TransportError::TransportNotFound("Unknown transport"))?;
        
        factory.validate_config(&config)?;
        factory.create_transport(config)
    }
    
    #[cfg(not(feature = "std"))]
    pub fn create_transport(&self, name: &str, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
        let factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        let factory = factories.get(name)
            .ok_or_else(|| TransportError::TransportNotFound("Unknown transport"))?;
        
        factory.validate_config(&config)?;
        factory.create_transport(config)
    }
    
    /// List available transport names
    #[cfg(feature = "std")]
    pub fn list_transports(&self) -> TransportResult<Vec<String>> {
        let factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        Ok(factories.keys().cloned().collect())
    }
    
    #[cfg(not(feature = "std"))]
    pub fn list_transports(&self) -> TransportResult<Vec<&'static str>> {
        let factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        Ok(factories.keys().cloned().collect())
    }
    
    /// Unregister a transport factory
    #[cfg(feature = "std")]
    pub fn unregister(&self, name: &str) -> TransportResult<()> {
        let mut factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        factories.remove(name)
            .ok_or_else(|| TransportError::TransportNotFound("Transport not registered"))?;
        
        Ok(())
    }
    
    #[cfg(not(feature = "std"))]
    pub fn unregister(&self, name: &str) -> TransportResult<()> {
        let mut factories = self.factories.lock()
            .map_err(|_| TransportError::Custom("Failed to acquire registry lock"))?;
        
        factories.remove(name)
            .ok_or_else(|| TransportError::TransportNotFound("Transport not registered"))?;
        
        Ok(())
    }
}

static mut GLOBAL_REGISTRY: Option<TransportRegistry> = None;

/// Initialize the global transport registry
pub fn init() -> TransportResult<()> {
    unsafe {
        if GLOBAL_REGISTRY.is_some() {
            return Err(TransportError::ConfigurationError("Registry already initialized"));
        }
        GLOBAL_REGISTRY = Some(TransportRegistry::new());
    }
    Ok(())
}

/// Cleanup the global transport registry
pub fn cleanup() -> TransportResult<()> {
    unsafe {
        GLOBAL_REGISTRY = None;
    }
    Ok(())
}

/// Get the global transport registry
fn get_registry() -> &'static TransportRegistry {
    unsafe {
        GLOBAL_REGISTRY.as_ref()
            .expect("Transport registry not initialized")
    }
}

/// Register a transport factory globally
#[cfg(feature = "std")]
pub fn register_factory(name: &str, factory: Box<dyn TransportFactory>) -> TransportResult<()> {
    get_registry().register(name.to_string(), factory)
}

#[cfg(not(feature = "std"))]
pub fn register_factory(name: &'static str, factory: Box<dyn TransportFactory>) -> TransportResult<()> {
    get_registry().register(name, factory)
}

/// Create a transport globally
pub fn create_transport(name: &str, config: TransportConfig) -> TransportResult<Box<dyn Transport>> {
    get_registry().create_transport(name, config)
}

/// List available transports globally
#[cfg(feature = "std")]
pub fn list_transports() -> TransportResult<Vec<String>> {
    get_registry().list_transports()
}

#[cfg(not(feature = "std"))]
pub fn list_transports() -> TransportResult<Vec<&'static str>> {
    get_registry().list_transports()
}

/// Unregister a transport factory globally
pub fn unregister_factory(name: &str) -> TransportResult<()> {
    get_registry().unregister(name)
}