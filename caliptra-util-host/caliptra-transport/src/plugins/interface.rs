//! Plugin interface definitions

use crate::{TransportFactory, TransportResult};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Plugin interface for transport plugins
pub trait TransportPlugin: Send + Sync {
    /// Get plugin name
    fn name(&self) -> &str;
    
    /// Get plugin version  
    fn version(&self) -> &str;
    
    /// Get plugin description
    fn description(&self) -> &str;
    
    /// Get supported transport types
    fn supported_transports(&self) -> &[&str];
    
    /// Create a factory for the specified transport type
    fn create_factory(&self, transport_type: &str) -> TransportResult<Box<dyn TransportFactory>>;
    
    /// Initialize the plugin
    fn initialize(&mut self) -> TransportResult<()> {
        Ok(())
    }
    
    /// Cleanup the plugin
    fn cleanup(&mut self) -> TransportResult<()> {
        Ok(())
    }
}

/// Plugin registry entry
#[derive(Debug, Clone)]
pub struct PluginEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_transports: Vec<String>,
    pub loaded: bool,
}

/// Plugin capability flags
#[derive(Debug, Clone, Copy)]
pub struct PluginCapabilities {
    pub supports_config_validation: bool,
    pub supports_hot_reload: bool,
    pub supports_multiple_instances: bool,
    pub requires_cleanup: bool,
}

impl Default for PluginCapabilities {
    fn default() -> Self {
        Self {
            supports_config_validation: false,
            supports_hot_reload: false,
            supports_multiple_instances: true,
            requires_cleanup: false,
        }
    }
}

/// Extended plugin interface with additional capabilities
pub trait ExtendedTransportPlugin: TransportPlugin {
    /// Get plugin capabilities
    fn capabilities(&self) -> PluginCapabilities {
        PluginCapabilities::default()
    }
    
    /// Validate plugin configuration
    fn validate_config(&self, _transport_type: &str, _config: &crate::TransportConfig) -> TransportResult<()> {
        Ok(())
    }
    
    /// Hot reload the plugin (if supported)
    fn hot_reload(&mut self) -> TransportResult<()> {
        Err(crate::TransportError::NotSupported("Hot reload not supported"))
    }
    
    /// Get plugin dependencies
    fn dependencies(&self) -> &[&str] {
        &[]
    }
    
    /// Check if plugin is compatible with system
    fn is_compatible(&self) -> bool {
        true
    }
}

/// Simple macro for implementing the basic TransportPlugin trait
#[macro_export]
macro_rules! impl_transport_plugin {
    (
        $plugin_type:ty,
        name: $name:expr,
        version: $version:expr,
        description: $description:expr,
        transports: [$($transport:expr),*],
        factory_fn: $factory_fn:expr
    ) => {
        impl $crate::plugins::TransportPlugin for $plugin_type {
            fn name(&self) -> &str {
                $name
            }
            
            fn version(&self) -> &str {
                $version
            }
            
            fn description(&self) -> &str {
                $description
            }
            
            fn supported_transports(&self) -> &[&str] {
                &[$($transport),*]
            }
            
            fn create_factory(&self, transport_type: &str) -> $crate::TransportResult<Box<dyn $crate::TransportFactory>> {
                $factory_fn(self, transport_type)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockTransportFactory, TransportError};
    
    struct TestPlugin;
    
    impl_transport_plugin!(
        TestPlugin,
        name: "Test Plugin",
        version: "1.0.0", 
        description: "A test transport plugin",
        transports: ["mock", "test"],
        factory_fn: |_plugin: &TestPlugin, transport_type: &str| {
            match transport_type {
                "mock" | "test" => Ok(Box::new(MockTransportFactory)),
                _ => Err(TransportError::TransportNotFound("Unsupported transport type")),
            }
        }
    );
    
    #[test]
    fn test_plugin_interface() {
        let plugin = TestPlugin;
        
        assert_eq!(plugin.name(), "Test Plugin");
        assert_eq!(plugin.version(), "1.0.0");
        assert_eq!(plugin.description(), "A test transport plugin");
        
        let transports = plugin.supported_transports();
        assert_eq!(transports.len(), 2);
        assert!(transports.contains(&"mock"));
        assert!(transports.contains(&"test"));
        
        // Test factory creation
        assert!(plugin.create_factory("mock").is_ok());
        assert!(plugin.create_factory("test").is_ok());
        assert!(plugin.create_factory("unknown").is_err());
    }
}