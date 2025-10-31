//! Command abstraction and registry for Caliptra operations

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{context::CaliptraContext, error::Result};

/// Command types supported by the library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommandType {
    /// SPDM related commands
    Spdm,
    /// PLDM related commands
    Pldm,
    /// Mailbox operations
    Mailbox,
    /// Certificate operations
    Certificate,
    /// Custom plugin commands
    Custom(u32),
}

/// Generic command structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: Uuid,
    pub command_type: CommandType,
    pub opcode: u32,
    pub payload: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

impl Command {
    pub fn new(command_type: CommandType, opcode: u32, payload: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            command_type,
            opcode,
            payload,
            metadata: HashMap::new(),
        }
    }
    
    pub fn command_type(&self) -> CommandType {
        self.command_type
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Command execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: Uuid,
    pub success: bool,
    pub response_data: Vec<u8>,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
    pub metadata: HashMap<String, String>,
}

impl CommandResult {
    pub fn success(command_id: Uuid, response_data: Vec<u8>, execution_time_ms: u64) -> Self {
        Self {
            command_id,
            success: true,
            response_data,
            error_message: None,
            execution_time_ms,
            metadata: HashMap::new(),
        }
    }
    
    pub fn error(command_id: Uuid, error_message: String, execution_time_ms: u64) -> Self {
        Self {
            command_id,
            success: false,
            response_data: Vec::new(),
            error_message: Some(error_message),
            execution_time_ms,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Trait for command handlers
#[async_trait]
pub trait CommandHandler: Send + Sync {
    /// Get the command type this handler supports
    fn command_type(&self) -> CommandType;
    
    /// Execute the command
    async fn execute(&self, context: &mut CaliptraContext, command: Command) -> Result<CommandResult>;
    
    /// Get handler name/description
    fn name(&self) -> &str;
    
    /// Get supported opcodes (empty means all opcodes supported)
    fn supported_opcodes(&self) -> Vec<u32> {
        Vec::new()
    }
    
    /// Validate command before execution
    fn validate(&self, command: &Command) -> Result<()> {
        if command.command_type != self.command_type() {
            return Err(crate::error::CaliptraUtilError::InvalidCommand(
                "Command type mismatch".to_string()
            ));
        }
        
        let supported_opcodes = self.supported_opcodes();
        if !supported_opcodes.is_empty() && !supported_opcodes.contains(&command.opcode) {
            return Err(crate::error::CaliptraUtilError::InvalidCommand(
                format!("Unsupported opcode: 0x{:02X}", command.opcode)
            ));
        }
        
        Ok(())
    }
}

/// Registry for command handlers
pub struct CommandRegistry {
    handlers: HashMap<CommandType, Box<dyn CommandHandler>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }
    
    pub fn register(&mut self, handler: Box<dyn CommandHandler>) -> Result<()> {
        let command_type = handler.command_type();
        if self.handlers.contains_key(&command_type) {
            log::warn!("Replacing existing handler for {:?}", command_type);
        }
        
        log::info!("Registering command handler: {} for {:?}", handler.name(), command_type);
        self.handlers.insert(command_type, handler);
        Ok(())
    }
    
    pub fn unregister(&mut self, command_type: CommandType) -> Result<()> {
        self.handlers.remove(&command_type)
            .ok_or_else(|| crate::error::CaliptraUtilError::CommandNotFound)?;
        Ok(())
    }
    
    pub fn get_handler(&self, command_type: CommandType) -> Option<&dyn CommandHandler> {
        self.handlers.get(&command_type).map(|h| h.as_ref())
    }
    
    pub fn list_handlers(&self) -> Vec<CommandType> {
        self.handlers.keys().cloned().collect()
    }
    
    pub fn get_handler_info(&self, command_type: CommandType) -> Option<String> {
        self.handlers.get(&command_type).map(|h| h.name().to_string())
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in SPDM command handler
pub struct SpdmCommandHandler;

impl SpdmCommandHandler {
    pub const GET_VERSION: u32 = 0x84;
    pub const GET_CAPABILITIES: u32 = 0x81;
    pub const NEGOTIATE_ALGORITHMS: u32 = 0x83;
    pub const GET_DIGESTS: u32 = 0x01;
    pub const GET_CERTIFICATE: u32 = 0x02;
}

#[async_trait]
impl CommandHandler for SpdmCommandHandler {
    fn command_type(&self) -> CommandType {
        CommandType::Spdm
    }
    
    async fn execute(&self, context: &mut CaliptraContext, command: Command) -> Result<CommandResult> {
        let start_time = std::time::Instant::now();
        
        self.validate(&command)?;
        
        log::info!("Executing SPDM command with opcode: 0x{:02X}", command.opcode);
        
        // Add SPDM header to payload if needed
        let mut spdm_message = Vec::new();
        spdm_message.push(0x10); // SPDM version 1.0
        spdm_message.push(command.opcode as u8);
        spdm_message.extend_from_slice(&command.payload);
        
        let response = context.transport_mut().send(&spdm_message).await
            .map_err(|e| crate::error::CaliptraUtilError::Transport(e))?;
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        // Parse SPDM response and validate
        if response.len() >= 2 {
            let version = response[0];
            let response_code = response[1];
            
            if version != 0x10 {
                return Ok(CommandResult::error(
                    command.id,
                    format!("Invalid SPDM version: 0x{:02X}", version),
                    execution_time
                ));
            }
            
            if response_code == 0x7F {
                // SPDM error response
                let error_code = if response.len() > 2 { response[2] } else { 0 };
                return Ok(CommandResult::error(
                    command.id,
                    format!("SPDM error: 0x{:02X}", error_code),
                    execution_time
                ));
            }
        }
        
        Ok(CommandResult::success(command.id, response, execution_time)
            .with_metadata("protocol".to_string(), "SPDM".to_string()))
    }
    
    fn name(&self) -> &str {
        "SPDM Command Handler"
    }
    
    fn supported_opcodes(&self) -> Vec<u32> {
        vec![
            Self::GET_VERSION,
            Self::GET_CAPABILITIES,
            Self::NEGOTIATE_ALGORITHMS,
            Self::GET_DIGESTS,
            Self::GET_CERTIFICATE,
        ]
    }
}

/// Built-in PLDM command handler
pub struct PldmCommandHandler;

impl PldmCommandHandler {
    pub const GET_TID: u32 = 0x02;
    pub const GET_PLDM_VERSION: u32 = 0x03;
    pub const GET_PLDM_TYPES: u32 = 0x04;
    pub const GET_PLDM_COMMANDS: u32 = 0x05;
}

#[async_trait]
impl CommandHandler for PldmCommandHandler {
    fn command_type(&self) -> CommandType {
        CommandType::Pldm
    }
    
    async fn execute(&self, context: &mut CaliptraContext, command: Command) -> Result<CommandResult> {
        let start_time = std::time::Instant::now();
        
        self.validate(&command)?;
        
        log::info!("Executing PLDM command with opcode: 0x{:02X}", command.opcode);
        
        // Add PLDM header to payload
        let mut pldm_message = Vec::new();
        pldm_message.push(0x00); // Instance ID
        pldm_message.push(0x80); // Header version and type
        pldm_message.push(command.opcode as u8);
        pldm_message.extend_from_slice(&command.payload);
        
        let response = context.transport_mut().send(&pldm_message).await
            .map_err(|e| crate::error::CaliptraUtilError::Transport(e))?;
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        // Parse PLDM response
        if response.len() >= 4 {
            let completion_code = response[3];
            
            if completion_code != 0x00 {
                return Ok(CommandResult::error(
                    command.id,
                    format!("PLDM completion code error: 0x{:02X}", completion_code),
                    execution_time
                ));
            }
        }
        
        Ok(CommandResult::success(command.id, response, execution_time)
            .with_metadata("protocol".to_string(), "PLDM".to_string()))
    }
    
    fn name(&self) -> &str {
        "PLDM Command Handler"
    }
    
    fn supported_opcodes(&self) -> Vec<u32> {
        vec![
            Self::GET_TID,
            Self::GET_PLDM_VERSION,
            Self::GET_PLDM_TYPES,
            Self::GET_PLDM_COMMANDS,
        ]
    }
}

/// Built-in Mailbox command handler
pub struct MailboxCommandHandler;

impl MailboxCommandHandler {
    pub const GET_IDEV_CSR: u32 = 0x5003_0000;
    pub const GET_IDEV_CERT: u32 = 0x5003_0001;
    pub const GET_LDEV_CERT: u32 = 0x5003_0002;
}

#[async_trait]
impl CommandHandler for MailboxCommandHandler {
    fn command_type(&self) -> CommandType {
        CommandType::Mailbox
    }
    
    async fn execute(&self, context: &mut CaliptraContext, command: Command) -> Result<CommandResult> {
        let start_time = std::time::Instant::now();
        
        self.validate(&command)?;
        
        log::info!("Executing Mailbox command with opcode: 0x{:08X}", command.opcode);
        
        // Format mailbox message
        let mut mailbox_message = Vec::new();
        mailbox_message.extend_from_slice(&command.opcode.to_le_bytes());
        mailbox_message.extend_from_slice(&command.payload);
        
        let response = context.transport_mut().send(&mailbox_message).await
            .map_err(|e| crate::error::CaliptraUtilError::Transport(e))?;
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        Ok(CommandResult::success(command.id, response, execution_time)
            .with_metadata("protocol".to_string(), "Mailbox".to_string()))
    }
    
    fn name(&self) -> &str {
        "Mailbox Command Handler"
    }
    
    fn supported_opcodes(&self) -> Vec<u32> {
        vec![
            Self::GET_IDEV_CSR,
            Self::GET_IDEV_CERT,
            Self::GET_LDEV_CERT,
        ]
    }
}