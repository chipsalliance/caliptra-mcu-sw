//! Plugin system extensions and dynamic loading

pub mod dynamic_loader;
pub mod c_plugin_interface;
pub mod discovery;

pub use caliptra_util_host_core::plugin::*;
pub use dynamic_loader::DynamicPluginLoader;
pub use c_plugin_interface::{CPluginInterface, CPluginVTable};
pub use discovery::PluginDiscovery;

use caliptra_util_host_core::command::{CommandHandler, CommandType};
use caliptra_util_host_core::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

/// Enhanced plugin manager with dynamic loading capabilities
pub struct EnhancedPluginManager {
    base_manager: PluginManager,
    dynamic_loader: Option<DynamicPluginLoader>,
    plugin_discovery: PluginDiscovery,
}

impl EnhancedPluginManager {
    pub fn new() -> Self {
        Self {
            base_manager: PluginManager::new(),
            dynamic_loader: None,
            plugin_discovery: PluginDiscovery::new(),
        }
    }
    
    #[cfg(feature = "dynamic-loading")]
    pub fn with_dynamic_loading(mut self, plugin_dirs: Vec<String>) -> Self {
        self.dynamic_loader = Some(DynamicPluginLoader::new(plugin_dirs));
        self
    }
    
    pub fn load_static_plugin(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        self.base_manager.load(plugin)
    }
    
    #[cfg(feature = "dynamic-loading")]
    pub fn load_dynamic_plugin(&mut self, path: &str) -> Result<Uuid> {
        if let Some(ref mut loader) = self.dynamic_loader {
            loader.load_plugin(path)
        } else {
            Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                "Dynamic loading not enabled".to_string()
            ))
        }
    }
    
    pub fn discover_plugins(&mut self, directory: &str) -> Result<Vec<PluginMetadata>> {
        self.plugin_discovery.discover_plugins(directory)
    }
    
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        let mut plugins = self.base_manager.list_plugins();
        
        #[cfg(feature = "dynamic-loading")]
        if let Some(ref loader) = self.dynamic_loader {
            plugins.extend(loader.list_loaded_plugins());
        }
        
        plugins
    }
    
    pub fn unload_plugin(&mut self, plugin_id: Uuid) -> Result<()> {
        // Try unloading from base manager first
        if self.base_manager.list_plugins().iter().any(|p| p.id == plugin_id) {
            return self.base_manager.unload(plugin_id);
        }
        
        #[cfg(feature = "dynamic-loading")]
        if let Some(ref mut loader) = self.dynamic_loader {
            return loader.unload_plugin(plugin_id);
        }
        
        Err(caliptra_util_host_core::error::CaliptraUtilError::PluginNotFound(
            plugin_id.to_string()
        ))
    }
}

impl Default for EnhancedPluginManager {
    fn default() -> Self {
        Self::new()
    }
}