//! Plugin system for extending functionality

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{command::{Command, CommandHandler, CommandResult, CommandType}, context::CaliptraContext, error::Result};

/// Plugin trait for extending library functionality
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> PluginMetadata;
    
    /// Initialize the plugin
    async fn initialize(&mut self) -> Result<()>;
    
    /// Get command handlers provided by this plugin
    fn get_command_handlers(&self) -> Vec<Box<dyn CommandHandler>>;
    
    /// Plugin-specific configuration
    fn configure(&mut self, config: HashMap<String, String>) -> Result<()>;
    
    /// Shutdown the plugin
    async fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
    
    /// Get plugin capabilities
    fn capabilities(&self) -> Vec<PluginCapability> {
        Vec::new()
    }
}

/// Plugin metadata
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: Option<String>,
    pub homepage: Option<String>,
}

/// Plugin capabilities
#[derive(Debug, Clone)]
pub enum PluginCapability {
    CommandHandler(CommandType),
    TransportProvider,
    MessageFilter,
    Logger,
    Custom(String),
}

/// Plugin manager for loading and managing plugins
pub struct PluginManager {
    plugins: HashMap<Uuid, Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }
    
    pub fn load(&mut self, mut plugin: Box<dyn Plugin>) -> Result<()> {
        let metadata = plugin.metadata();
        let plugin_id = metadata.id;
        
        log::info!("Loading plugin: {} v{}", metadata.name, metadata.version);
        
        // TODO: Add plugin validation and sandboxing
        // - Verify plugin signature
        // - Check version compatibility
        // - Validate capabilities
        
        self.plugins.insert(plugin_id, plugin);
        log::info!("Plugin loaded successfully: {}", metadata.name);
        Ok(())
    }
    
    pub fn unload(&mut self, plugin_id: Uuid) -> Result<()> {
        if let Some(mut plugin) = self.plugins.remove(&plugin_id) {
            let metadata = plugin.metadata();
            log::info!("Unloading plugin: {}", metadata.name);
            
            // Shutdown plugin in async context if needed
            // In a real implementation, this would need proper async handling
            
            Ok(())
        } else {
            Err(crate::error::CaliptraUtilError::Plugin("Plugin not found".to_string()))
        }
    }
    
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|p| p.metadata()).collect()
    }
    
    pub fn get_plugin(&self, plugin_id: Uuid) -> Option<&dyn Plugin> {
        self.plugins.get(&plugin_id).map(|p| p.as_ref())
    }
    
    pub fn find_plugins_by_capability(&self, capability: &PluginCapability) -> Vec<Uuid> {
        self.plugins.iter()
            .filter(|(_, plugin)| {
                plugin.capabilities().iter().any(|cap| {
                    match (cap, capability) {
                        (PluginCapability::CommandHandler(a), PluginCapability::CommandHandler(b)) => a == b,
                        (PluginCapability::TransportProvider, PluginCapability::TransportProvider) => true,
                        (PluginCapability::MessageFilter, PluginCapability::MessageFilter) => true,
                        (PluginCapability::Logger, PluginCapability::Logger) => true,
                        (PluginCapability::Custom(a), PluginCapability::Custom(b)) => a == b,
                        _ => false,
                    }
                })
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry for plugins (can be used for dynamic loading)
pub struct PluginRegistry {
    available_plugins: Vec<PluginMetadata>,
    plugin_paths: HashMap<Uuid, String>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            available_plugins: Vec::new(),
            plugin_paths: HashMap::new(),
        }
    }
    
    pub fn register_plugin(&mut self, metadata: PluginMetadata, path: String) {
        log::info!("Registering plugin: {} at {}", metadata.name, path);
        let id = metadata.id;
        self.available_plugins.push(metadata);
        self.plugin_paths.insert(id, path);
    }
    
    pub fn list_available(&self) -> &[PluginMetadata] {
        &self.available_plugins
    }
    
    pub fn get_plugin_path(&self, plugin_id: Uuid) -> Option<&str> {
        self.plugin_paths.get(&plugin_id).map(|s| s.as_str())
    }
    
    // TODO: Add methods for discovering and loading plugins from filesystem
    // pub fn discover_plugins(&mut self, directory: &str) -> Result<()>
    // pub fn load_plugin(&self, plugin_id: Uuid) -> Result<Box<dyn Plugin>>
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Example custom command handler that could be provided by a plugin
pub struct CustomCommandHandler {
    command_type: CommandType,
    name: String,
    supported_opcodes: Vec<u32>,
}

impl CustomCommandHandler {
    pub fn new(custom_id: u32, name: String) -> Self {
        Self {
            command_type: CommandType::Custom(custom_id),
            name,
            supported_opcodes: Vec::new(),
        }
    }
    
    pub fn with_opcodes(mut self, opcodes: Vec<u32>) -> Self {
        self.supported_opcodes = opcodes;
        self
    }
}

#[async_trait]
impl CommandHandler for CustomCommandHandler {
    fn command_type(&self) -> CommandType {
        self.command_type
    }
    
    async fn execute(&self, context: &mut CaliptraContext, command: Command) -> Result<CommandResult> {
        let start_time = std::time::Instant::now();
        
        self.validate(&command)?;
        
        log::info!("Executing custom command: {} with opcode: 0x{:02X}", self.name, command.opcode);
        
        // Custom command logic here
        // This is a placeholder implementation
        let mut response = Vec::new();
        response.extend_from_slice(&command.opcode.to_le_bytes());
        response.push(0x00); // Success status
        response.extend_from_slice(b"Custom response");
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        Ok(CommandResult::success(command.id, response, execution_time)
            .with_metadata("handler".to_string(), self.name.clone())
            .with_metadata("custom_id".to_string(), 
                if let CommandType::Custom(id) = self.command_type { id.to_string() } else { "unknown".to_string() }))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn supported_opcodes(&self) -> Vec<u32> {
        self.supported_opcodes.clone()
    }
}

/// Example Rust plugin implementation
pub struct ExampleRustPlugin {
    metadata: PluginMetadata,
    handlers: Vec<Box<dyn CommandHandler>>,
    initialized: bool,
}

impl ExampleRustPlugin {
    pub fn new() -> Self {
        let metadata = PluginMetadata {
            id: Uuid::new_v4(),
            name: "Example Rust Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "An example plugin written in Rust".to_string(),
            author: "Caliptra Team".to_string(),
            license: Some("Apache-2.0".to_string()),
            homepage: Some("https://github.com/chipsalliance/caliptra-mcu-sw".to_string()),
        };
        
        Self {
            metadata,
            handlers: Vec::new(),
            initialized: false,
        }
    }
}

impl Default for ExampleRustPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for ExampleRustPlugin {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }
    
    async fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        
        log::info!("Initializing Example Rust Plugin");
        
        // Add custom command handlers
        let custom_handler = CustomCommandHandler::new(1, "Example Custom Command".to_string())
            .with_opcodes(vec![0x01, 0x02, 0x03]);
        
        // Note: In a real implementation, we'd need to handle the ownership differently
        // since we can't return owned CommandHandlers from get_command_handlers
        // This would likely require Arc<dyn CommandHandler> or similar
        
        self.initialized = true;
        log::info!("Example Rust Plugin initialized successfully");
        Ok(())
    }
    
    fn get_command_handlers(&self) -> Vec<Box<dyn CommandHandler>> {
        // This is a limitation of the current design - we can't return owned handlers
        // In a real implementation, this would need to return references or use Arc
        // For now, return empty vec
        Vec::new()
    }
    
    fn configure(&mut self, config: HashMap<String, String>) -> Result<()> {
        log::info!("Configuring Example Rust Plugin with {} settings", config.len());
        
        for (key, value) in &config {
            log::debug!("Plugin config: {} = {}", key, value);
        }
        
        Ok(())
    }
    
    fn capabilities(&self) -> Vec<PluginCapability> {
        vec![
            PluginCapability::CommandHandler(CommandType::Custom(1)),
            PluginCapability::MessageFilter,
        ]
    }
}