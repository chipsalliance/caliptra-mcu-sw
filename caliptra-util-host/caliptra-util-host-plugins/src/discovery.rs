//! Plugin discovery and management

use caliptra_util_host_core::plugin::PluginMetadata;
use caliptra_util_host_core::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginInfo,
    pub dependencies: Option<Vec<Dependency>>,
    pub capabilities: Option<Vec<String>>,
    pub config_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: Option<String>,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub library_path: String,
    pub entry_point: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub optional: Option<bool>,
}

pub struct PluginDiscovery {
    search_paths: Vec<PathBuf>,
}

impl PluginDiscovery {
    pub fn new() -> Self {
        Self {
            search_paths: Vec::new(),
        }
    }
    
    pub fn add_search_path<P: AsRef<Path>>(&mut self, path: P) {
        self.search_paths.push(path.as_ref().to_path_buf());
    }
    
    pub fn discover_plugins(&mut self, directory: &str) -> Result<Vec<PluginMetadata>> {
        let dir_path = Path::new(directory);
        if !dir_path.exists() {
            log::warn!("Plugin directory does not exist: {}", directory);
            return Ok(Vec::new());
        }
        
        let mut discovered_plugins = Vec::new();
        
        // Look for plugin manifest files (plugin.toml, plugin.json)
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    
                    if path.is_dir() {
                        // Look for manifest in subdirectory
                        if let Some(manifest) = self.find_manifest_in_dir(&path)? {
                            if let Ok(metadata) = self.manifest_to_metadata(manifest, &path) {
                                discovered_plugins.push(metadata);
                            }
                        }
                    } else if let Some(manifest) = self.try_parse_manifest(&path)? {
                        let parent_dir = path.parent().unwrap_or(&path);
                        if let Ok(metadata) = self.manifest_to_metadata(manifest, parent_dir) {
                            discovered_plugins.push(metadata);
                        }
                    }
                }
            }
        }
        
        log::info!("Discovered {} plugins in {}", discovered_plugins.len(), directory);
        Ok(discovered_plugins)
    }
    
    fn find_manifest_in_dir(&self, dir: &Path) -> Result<Option<PluginManifest>> {
        let manifest_files = ["plugin.toml", "plugin.json", "Cargo.toml"];
        
        for manifest_file in &manifest_files {
            let manifest_path = dir.join(manifest_file);
            if manifest_path.exists() {
                if let Some(manifest) = self.try_parse_manifest(&manifest_path)? {
                    return Ok(Some(manifest));
                }
            }
        }
        
        Ok(None)
    }
    
    fn try_parse_manifest(&self, path: &Path) -> Result<Option<PluginManifest>> {
        if let Some(file_name) = path.file_name() {
            let file_name = file_name.to_string_lossy();
            
            match file_name.as_ref() {
                "plugin.toml" => self.parse_toml_manifest(path),
                "plugin.json" => self.parse_json_manifest(path),
                "Cargo.toml" => self.parse_cargo_toml(path),
                _ => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
    
    fn parse_toml_manifest(&self, path: &Path) -> Result<Option<PluginManifest>> {
        let content = fs::read_to_string(path)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Io(e))?;
        
        // Use basic TOML parsing (would need toml crate in real implementation)
        // For now, just return None as we don't have toml dependency
        log::debug!("Found TOML manifest at {}, but TOML parsing not implemented", path.display());
        Ok(None)
    }
    
    fn parse_json_manifest(&self, path: &Path) -> Result<Option<PluginManifest>> {
        let content = fs::read_to_string(path)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Io(e))?;
        
        let manifest: PluginManifest = serde_json::from_str(&content)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Serialization(e))?;
        
        log::debug!("Parsed JSON plugin manifest: {}", manifest.plugin.name);
        Ok(Some(manifest))
    }
    
    fn parse_cargo_toml(&self, path: &Path) -> Result<Option<PluginManifest>> {
        let content = fs::read_to_string(path)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Io(e))?;
        
        // Simple check for Caliptra plugin marker in Cargo.toml
        if content.contains("[caliptra-plugin]") || content.contains("caliptra-util-host-core") {
            log::debug!("Found potential Caliptra plugin Cargo.toml at {}", path.display());
            
            // Extract basic information (would need proper TOML parsing)
            let plugin_name = path.parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            
            let manifest = PluginManifest {
                plugin: PluginInfo {
                    id: None,
                    name: plugin_name.clone(),
                    version: "0.1.0".to_string(),
                    description: format!("Rust plugin: {}", plugin_name),
                    author: "Unknown".to_string(),
                    license: Some("Apache-2.0".to_string()),
                    homepage: None,
                    library_path: format!("target/release/lib{}.so", plugin_name),
                    entry_point: Some("create_plugin".to_string()),
                },
                dependencies: None,
                capabilities: None,
                config_schema: None,
            };
            
            Ok(Some(manifest))
        } else {
            Ok(None)
        }
    }
    
    fn manifest_to_metadata(&self, manifest: PluginManifest, base_path: &Path) -> Result<PluginMetadata> {
        let id = if let Some(id_str) = manifest.plugin.id {
            Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };
        
        Ok(PluginMetadata {
            id,
            name: manifest.plugin.name,
            version: manifest.plugin.version,
            description: manifest.plugin.description,
            author: manifest.plugin.author,
            license: manifest.plugin.license,
            homepage: manifest.plugin.homepage,
        })
    }
    
    pub fn validate_plugin_dependencies(&self, manifest: &PluginManifest) -> Result<bool> {
        if let Some(ref dependencies) = manifest.dependencies {
            for dep in dependencies {
                if dep.optional.unwrap_or(false) {
                    continue;
                }
                
                // Check if dependency is available
                // This would involve checking system libraries, other plugins, etc.
                log::debug!("Checking dependency: {} v{}", dep.name, dep.version);
                
                // For now, just assume all dependencies are satisfied
            }
        }
        
        Ok(true)
    }
    
    pub fn get_plugin_load_order(&self, plugins: &[PluginManifest]) -> Vec<usize> {
        // Simple topological sort based on dependencies
        // For now, just return plugins in original order
        // In a real implementation, this would resolve dependency order
        (0..plugins.len()).collect()
    }
}

impl Default for PluginDiscovery {
    fn default() -> Self {
        let mut discovery = Self::new();
        
        // Add default search paths
        if let Ok(current_dir) = std::env::current_dir() {
            discovery.add_search_path(current_dir.join("plugins"));
        }
        
        // Add system plugin directories
        #[cfg(target_os = "linux")]
        {
            discovery.add_search_path("/usr/lib/caliptra-plugins");
            discovery.add_search_path("/usr/local/lib/caliptra-plugins");
        }
        
        #[cfg(target_os = "windows")]
        {
            if let Ok(program_files) = std::env::var("PROGRAMFILES") {
                discovery.add_search_path(Path::new(&program_files).join("Caliptra").join("plugins"));
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            discovery.add_search_path("/usr/local/lib/caliptra-plugins");
            discovery.add_search_path("/opt/caliptra/plugins");
        }
        
        discovery
    }
}