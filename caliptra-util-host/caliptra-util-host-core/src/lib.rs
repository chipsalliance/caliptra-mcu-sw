//! Caliptra Utility Host Library Core
//! 
//! This library provides a flexible framework for communicating with Caliptra devices
//! through various transports (MCTP, DOE, etc.) with pluggable command handlers.

pub mod command;
pub mod transport;
pub mod plugin;
pub mod error;
pub mod context;

use async_trait::async_trait;
pub use command::{Command, CommandHandler, CommandRegistry, CommandResult, CommandType};
pub use transport::{Transport, TransportError, TransportType};
pub use plugin::{Plugin, PluginManager, PluginRegistry};
pub use error::{CaliptraUtilError, Result};
pub use context::CaliptraContext;

/// Main library interface
pub struct CaliptraUtilHost {
    context: CaliptraContext,
    command_registry: CommandRegistry,
    plugin_manager: PluginManager,
}

impl CaliptraUtilHost {
    /// Create a new instance with specified transport
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self {
            context: CaliptraContext::new(transport),
            command_registry: CommandRegistry::new(),
            plugin_manager: PluginManager::new(),
        }
    }

    /// Register a command handler
    pub fn register_command_handler(&mut self, handler: Box<dyn CommandHandler>) -> Result<()> {
        self.command_registry.register(handler)
    }

    /// Load a plugin
    pub fn load_plugin(&mut self, plugin: Box<dyn Plugin>) -> Result<()> {
        self.plugin_manager.load(plugin)
    }

    /// Execute a command
    pub async fn execute_command(&mut self, command: Command) -> Result<CommandResult> {
        let handler = self.command_registry
            .get_handler(command.command_type())
            .ok_or(CaliptraUtilError::CommandNotFound)?;

        handler.execute(&mut self.context, command).await
    }

    /// Send raw data through transport
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.context.transport_mut().send(data).await
            .map_err(CaliptraUtilError::from)
    }

    /// Get list of registered command handlers
    pub fn list_handlers(&self) -> Vec<CommandType> {
        self.command_registry.list_handlers()
    }
}