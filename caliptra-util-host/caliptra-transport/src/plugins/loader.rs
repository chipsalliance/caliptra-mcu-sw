//! Plugin loader for dynamic transport loading

use crate::{TransportFactory, TransportResult, TransportError, registry::register_factory};

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::path::Path;

#[cfg(all(feature = "std", feature = "plugins"))]
use libloading::{Library, Symbol};

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub transport_types: Vec<String>,
}

/// Plugin trait for Rust plugins
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> PluginMetadata;
    
    /// Create transport factories provided by this plugin
    fn create_factories(&self) -> TransportResult<Vec<(String, Box<dyn TransportFactory>)>>;
    
    /// Initialize the plugin
    fn initialize(&mut self) -> TransportResult<()>;
    
    /// Cleanup the plugin
    fn cleanup(&mut self) -> TransportResult<()>;
}

/// Plugin loader for dynamic loading
pub struct PluginLoader {
    #[cfg(all(feature = "std", feature = "plugins"))]
    loaded_libraries: Vec<Library>,
    loaded_plugins: Vec<Box<dyn Plugin>>,
}

impl PluginLoader {
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "std", feature = "plugins"))]
            loaded_libraries: Vec::new(),
            loaded_plugins: Vec::new(),
        }
    }
    
    /// Load a plugin from a dynamic library
    #[cfg(all(feature = "std", feature = "plugins"))]
    pub fn load_plugin<P: AsRef<Path>>(&mut self, path: P) -> TransportResult<()> {
        unsafe {
            let lib = Library::new(path.as_ref())
                .map_err(|e| TransportError::PluginError(&format!("Failed to load library: {}", e)))?;
            
            // Look for the plugin creation function
            let create_plugin: Symbol<unsafe extern fn() -> *mut dyn Plugin> = lib.get(b"create_plugin")
                .map_err(|e| TransportError::PluginError(&format!("Plugin missing create_plugin function: {}", e)))?;
            
            let plugin_ptr = create_plugin();
            if plugin_ptr.is_null() {
                return Err(TransportError::PluginError("Plugin creation returned null"));
            }
            
            let mut plugin = Box::from_raw(plugin_ptr);
            plugin.initialize()?;
            
            // Register the plugin's transport factories
            let factories = plugin.create_factories()?;
            for (name, factory) in factories {
                register_factory(&name, factory)?;
            }
            
            self.loaded_plugins.push(plugin);
            self.loaded_libraries.push(lib);
            
            Ok(())
        }
    }
    
    /// Load a plugin from source (for testing)
    pub fn load_plugin_direct(&mut self, mut plugin: Box<dyn Plugin>) -> TransportResult<()> {
        plugin.initialize()?;
        
        // Register the plugin's transport factories
        let factories = plugin.create_factories()?;
        for (name, factory) in factories {
            register_factory(&name, factory)?;
        }
        
        self.loaded_plugins.push(plugin);
        Ok(())
    }
    
    /// Unload all plugins
    pub fn unload_all(&mut self) -> TransportResult<()> {
        // Cleanup plugins in reverse order
        while let Some(mut plugin) = self.loaded_plugins.pop() {
            if let Err(e) = plugin.cleanup() {
                // Log error but continue cleanup
                #[cfg(feature = "std")]
                eprintln!("Warning: Plugin cleanup failed: {:?}", e);
            }
        }
        
        #[cfg(all(feature = "std", feature = "plugins"))]
        {
            // Drop libraries
            self.loaded_libraries.clear();
        }
        
        Ok(())
    }
    
    /// Get list of loaded plugins
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.loaded_plugins.iter()
            .map(|plugin| plugin.metadata())
            .collect()
    }
}

impl Drop for PluginLoader {
    fn drop(&mut self) {
        if let Err(e) = self.unload_all() {
            #[cfg(feature = "std")]
            eprintln!("Warning: Failed to unload plugins during cleanup: {:?}", e);
        }
    }
}

/// Macro for easier plugin creation
#[macro_export]
macro_rules! plugin_main {
    ($plugin_type:ty) => {
        #[no_mangle]
        pub extern "C" fn create_plugin() -> *mut dyn $crate::plugins::Plugin {
            let plugin: Box<dyn $crate::plugins::Plugin> = Box::new(<$plugin_type>::new());
            Box::into_raw(plugin)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockTransportFactory, TransportConfig};
    
    struct TestPlugin;
    
    impl Plugin for TestPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                name: "Test Plugin".to_string(),
                version: "1.0.0".to_string(),
                description: "Test transport plugin".to_string(),
                author: "Test Author".to_string(),
                transport_types: vec!["test".to_string()],
            }
        }
        
        fn create_factories(&self) -> TransportResult<Vec<(String, Box<dyn TransportFactory>)>> {
            let factory: Box<dyn TransportFactory> = Box::new(MockTransportFactory);
            Ok(vec![("test".to_string(), factory)])
        }
        
        fn initialize(&mut self) -> TransportResult<()> {
            Ok(())
        }
        
        fn cleanup(&mut self) -> TransportResult<()> {
            Ok(())
        }
    }
    
    #[test]
    fn test_plugin_loading() {
        let mut loader = PluginLoader::new();
        let plugin = Box::new(TestPlugin);
        
        assert!(loader.load_plugin_direct(plugin).is_ok());
        
        let plugins = loader.list_plugins();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "Test Plugin");
    }
}