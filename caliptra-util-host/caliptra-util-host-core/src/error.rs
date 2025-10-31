//! Error types for the Caliptra Utility Host Library

use thiserror::Error;

pub type Result<T> = std::result::Result<T, CaliptraUtilError>;

#[derive(Error, Debug)]
pub enum CaliptraUtilError {
    #[error("Transport error: {0}")]
    Transport(#[from] crate::transport::TransportError),
    
    #[error("Command not found")]
    CommandNotFound,
    
    #[error("Plugin error: {0}")]
    Plugin(String),
    
    #[error("Command execution failed: {0}")]
    CommandExecution(String),
    
    #[error("Invalid command format: {0}")]
    InvalidCommand(String),
    
    #[error("Context error: {0}")]
    Context(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    
    #[error("Handler already registered for command type")]
    HandlerAlreadyRegistered,
}