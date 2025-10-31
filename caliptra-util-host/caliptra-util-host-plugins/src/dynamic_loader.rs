//! Dynamic plugin loading functionality

use caliptra_util_host_core::plugin::{Plugin, PluginMetadata};
use caliptra_util_host_core::Result;
use std::collections::HashMap;
use uuid::Uuid;
use std::path::Path;

#[cfg(feature = "dynamic-loading")]
use libloading::{Library, Symbol};

pub struct DynamicPluginLoader {
    plugin_dirs: Vec<String>,
    loaded_libraries: HashMap<Uuid, LoadedPlugin>,
}

struct LoadedPlugin {
    #[cfg(feature = "dynamic-loading")]
    library: Library,
    metadata: PluginMetadata,
    #[cfg(not(feature = "dynamic-loading"))]
    _phantom: std::marker::PhantomData<()>,
}

impl DynamicPluginLoader {
    pub fn new(plugin_dirs: Vec<String>) -> Self {
        Self {
            plugin_dirs,
            loaded_libraries: HashMap::new(),
        }
    }
    
    #[cfg(feature = "dynamic-loading")]
    pub fn load_plugin(&mut self, plugin_path: &str) -> Result<Uuid> {
        log::info!("Loading dynamic plugin from: {}", plugin_path);
        
        // Load the library
        let library = unsafe { Library::new(plugin_path) }
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Failed to load library: {}", e)
            ))?;
        
        // Get the plugin creation function
        let create_plugin: Symbol<unsafe extern "C" fn() -> *mut std::ffi::c_void> = unsafe {
            library.get(b"create_plugin")
                .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    format!("Plugin missing create_plugin function: {}", e)
                ))?
        };
        
        // Create the plugin instance (this is a simplified example)
        let plugin_ptr = unsafe { create_plugin() };
        if plugin_ptr.is_null() {
            return Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                "Plugin creation failed".to_string()
            ));
        }
        
        // Get plugin metadata (this would need proper C interface)
        let metadata = self.get_plugin_metadata(&library)?;
        let plugin_id = metadata.id;
        
        let loaded_plugin = LoadedPlugin {
            library,
            metadata,
        };
        
        self.loaded_libraries.insert(plugin_id, loaded_plugin);
        
        log::info!("Successfully loaded dynamic plugin: {}", plugin_id);
        Ok(plugin_id)
    }
    
    #[cfg(not(feature = "dynamic-loading"))]
    pub fn load_plugin(&mut self, _plugin_path: &str) -> Result<Uuid> {
        Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
            "Dynamic loading not supported in this build".to_string()
        ))
    }
    
    #[cfg(feature = "dynamic-loading")]
    fn get_plugin_metadata(&self, library: &Library) -> Result<PluginMetadata> {
        // Get metadata from the plugin library
        let get_metadata: Symbol<unsafe extern "C" fn() -> *const std::ffi::c_char> = unsafe {
            library.get(b"get_plugin_metadata")
                .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    format!("Plugin missing get_plugin_metadata function: {}", e)
                ))?
        };
        
        let metadata_json = unsafe {
            let ptr = get_metadata();
            if ptr.is_null() {
                return Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    "Plugin returned null metadata".to_string()
                ));
            }
            
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    format!("Invalid metadata string: {}", e)
                ))?
        };
        
        // Parse JSON metadata (this is a simplified example)
        let metadata: serde_json::Value = serde_json::from_str(metadata_json)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Invalid metadata JSON: {}", e)
            ))?;
        
        Ok(PluginMetadata {
            id: Uuid::new_v4(), // In real implementation, this would come from metadata
            name: metadata.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            version: metadata.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string(),
            description: metadata.get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            author: metadata.get("author")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string(),
            license: metadata.get("license")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            homepage: metadata.get("homepage")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }
    
    pub fn unload_plugin(&mut self, plugin_id: Uuid) -> Result<()> {
        if let Some(loaded_plugin) = self.loaded_libraries.remove(&plugin_id) {
            log::info!("Unloading dynamic plugin: {}", plugin_id);
            
            #[cfg(feature = "dynamic-loading")]
            {
                // Call plugin cleanup if available
                if let Ok(cleanup) = unsafe { 
                    loaded_plugin.library.get::<Symbol<unsafe extern "C" fn()>>(b"cleanup_plugin") 
                } {
                    unsafe { cleanup() };
                }
                // Library will be automatically unloaded when dropped
            }
            
            Ok(())
        } else {
            Err(caliptra_util_host_core::error::CaliptraUtilError::PluginNotFound(
                plugin_id.to_string()
            ))
        }
    }
    
    pub fn list_loaded_plugins(&self) -> Vec<PluginMetadata> {
        self.loaded_libraries.values()
            .map(|p| p.metadata.clone())
            .collect()
    }
    
    pub fn discover_plugins_in_dirs(&self) -> Result<Vec<String>> {
        let mut plugin_files = Vec::new();
        
        for dir in &self.plugin_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let path = entry.path();
                        if self.is_plugin_file(&path) {
                            if let Some(path_str) = path.to_str() {
                                plugin_files.push(path_str.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        Ok(plugin_files)
    }
    
    fn is_plugin_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            
            #[cfg(target_os = "windows")]
            return ext == "dll";
            
            #[cfg(target_os = "macos")]
            return ext == "dylib";
            
            #[cfg(target_os = "linux")]
            return ext == "so";
            
            #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
            return false;
        }
        
        false
    }
}