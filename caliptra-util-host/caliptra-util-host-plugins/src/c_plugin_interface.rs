//! C plugin interface for dynamic loading

use caliptra_util_host_core::plugin::{Plugin, PluginMetadata, PluginCapability};
use caliptra_util_host_core::command::{Command, CommandHandler, CommandResult, CommandType};
use caliptra_util_host_core::context::CaliptraContext;
use caliptra_util_host_core::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use libc::{c_char, c_int, c_uint, c_void, size_t};
use uuid::Uuid;

/// C plugin vtable for dynamic plugins
#[repr(C)]
pub struct CPluginVTable {
    pub get_metadata: unsafe extern "C" fn() -> *const c_char,
    pub initialize: unsafe extern "C" fn() -> c_int,
    pub shutdown: unsafe extern "C" fn() -> c_int,
    pub configure: unsafe extern "C" fn(*const c_char) -> c_int,
    pub execute_command: unsafe extern "C" fn(
        command_type: c_uint,
        opcode: c_uint,
        payload: *const u8,
        payload_size: size_t,
        response: *mut *mut u8,
        response_size: *mut size_t,
    ) -> c_int,
    pub get_supported_commands: unsafe extern "C" fn(
        commands: *mut *mut c_uint,
        count: *mut size_t,
    ) -> c_int,
}

/// C plugin interface wrapper
pub struct CPluginInterface {
    vtable: CPluginVTable,
    metadata: PluginMetadata,
    initialized: bool,
}

impl CPluginInterface {
    pub fn new(vtable: CPluginVTable) -> Result<Self> {
        // Get metadata from the C plugin
        let metadata_json = unsafe {
            let ptr = (vtable.get_metadata)();
            if ptr.is_null() {
                return Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    "Plugin returned null metadata".to_string()
                ));
            }
            
            CStr::from_ptr(ptr)
                .to_str()
                .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                    format!("Invalid metadata string: {}", e)
                ))?
        };
        
        let metadata = parse_plugin_metadata(metadata_json)?;
        
        Ok(Self {
            vtable,
            metadata,
            initialized: false,
        })
    }
}

#[async_trait]
impl Plugin for CPluginInterface {
    fn metadata(&self) -> PluginMetadata {
        self.metadata.clone()
    }
    
    async fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        
        let result = unsafe { (self.vtable.initialize)() };
        if result == 0 {
            self.initialized = true;
            Ok(())
        } else {
            Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Plugin initialization failed with code: {}", result)
            ))
        }
    }
    
    fn get_command_handlers(&self) -> Vec<Box<dyn CommandHandler>> {
        // Create a C plugin command handler
        if self.initialized {
            vec![Box::new(CPluginCommandHandler {
                vtable: self.vtable,
                plugin_name: self.metadata.name.clone(),
            })]
        } else {
            Vec::new()
        }
    }
    
    fn configure(&mut self, config: HashMap<String, String>) -> Result<()> {
        let config_json = serde_json::to_string(&config)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Serialization(e))?;
        
        let config_cstring = CString::new(config_json)
            .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Invalid config string: {}", e)
            ))?;
        
        let result = unsafe { (self.vtable.configure)(config_cstring.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Plugin configuration failed with code: {}", result)
            ))
        }
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        if !self.initialized {
            return Ok(());
        }
        
        let result = unsafe { (self.vtable.shutdown)() };
        if result == 0 {
            self.initialized = false;
            Ok(())
        } else {
            Err(caliptra_util_host_core::error::CaliptraUtilError::Plugin(
                format!("Plugin shutdown failed with code: {}", result)
            ))
        }
    }
    
    fn capabilities(&self) -> Vec<PluginCapability> {
        // Get supported commands from C plugin
        let mut commands_ptr: *mut c_uint = std::ptr::null_mut();
        let mut count: size_t = 0;
        
        let result = unsafe {
            (self.vtable.get_supported_commands)(&mut commands_ptr, &mut count)
        };
        
        if result != 0 || commands_ptr.is_null() {
            return Vec::new();
        }
        
        let commands = unsafe {
            std::slice::from_raw_parts(commands_ptr, count)
        };
        
        let mut capabilities = Vec::new();
        for &command in commands {
            let command_type = match command {
                0 => CommandType::Spdm,
                1 => CommandType::Pldm,
                2 => CommandType::Mailbox,
                3 => CommandType::Certificate,
                _ => CommandType::Custom(command),
            };
            capabilities.push(PluginCapability::CommandHandler(command_type));
        }
        
        // Free the memory allocated by the C plugin
        unsafe {
            libc::free(commands_ptr as *mut c_void);
        }
        
        capabilities
    }
}

/// Command handler for C plugins
struct CPluginCommandHandler {
    vtable: CPluginVTable,
    plugin_name: String,
}

#[async_trait]
impl CommandHandler for CPluginCommandHandler {
    fn command_type(&self) -> CommandType {
        CommandType::Custom(0) // C plugins can handle any custom command
    }
    
    async fn execute(&self, _context: &mut CaliptraContext, command: Command) -> Result<CommandResult> {
        let start_time = std::time::Instant::now();
        
        let command_type_id = match command.command_type {
            CommandType::Spdm => 0,
            CommandType::Pldm => 1,
            CommandType::Mailbox => 2,
            CommandType::Certificate => 3,
            CommandType::Custom(id) => id,
        };
        
        let mut response_ptr: *mut u8 = std::ptr::null_mut();
        let mut response_size: size_t = 0;
        
        let result = unsafe {
            (self.vtable.execute_command)(
                command_type_id,
                command.opcode,
                command.payload.as_ptr(),
                command.payload.len(),
                &mut response_ptr,
                &mut response_size,
            )
        };
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        if result == 0 {
            let response_data = if !response_ptr.is_null() && response_size > 0 {
                unsafe {
                    let data = std::slice::from_raw_parts(response_ptr, response_size).to_vec();
                    libc::free(response_ptr as *mut c_void);
                    data
                }
            } else {
                Vec::new()
            };
            
            Ok(CommandResult::success(command.id, response_data, execution_time)
                .with_metadata("plugin".to_string(), self.plugin_name.clone()))
        } else {
            Ok(CommandResult::error(
                command.id,
                format!("C plugin execution failed with code: {}", result),
                execution_time,
            ))
        }
    }
    
    fn name(&self) -> &str {
        &self.plugin_name
    }
}

fn parse_plugin_metadata(json_str: &str) -> Result<PluginMetadata> {
    let metadata: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| caliptra_util_host_core::error::CaliptraUtilError::Serialization(e))?;
    
    let id_str = metadata.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    
    let id = if id_str.is_empty() {
        Uuid::new_v4()
    } else {
        Uuid::parse_str(id_str)
            .unwrap_or_else(|_| Uuid::new_v4())
    };
    
    Ok(PluginMetadata {
        id,
        name: metadata.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown C Plugin")
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

/// C API for plugins to implement

/// Plugin metadata structure for C plugins
#[repr(C)]
pub struct CPluginMetadata {
    pub name: *const c_char,
    pub version: *const c_char,
    pub description: *const c_char,
    pub author: *const c_char,
}

/// Command structure for C plugins
#[repr(C)]
pub struct CPluginCommand {
    pub command_type: c_uint,
    pub opcode: c_uint,
    pub payload: *const u8,
    pub payload_size: size_t,
}

/// Standard plugin entry points that C plugins should implement:
/// 
/// ```c
/// // Plugin metadata (must return valid JSON string)
/// const char* get_plugin_metadata(void);
/// 
/// // Initialize the plugin
/// int initialize_plugin(void);
/// 
/// // Shutdown the plugin  
/// int shutdown_plugin(void);
/// 
/// // Configure the plugin with JSON config string
/// int configure_plugin(const char* config_json);
/// 
/// // Execute a command
/// int execute_command(
///     uint32_t command_type,
///     uint32_t opcode, 
///     const uint8_t* payload,
///     size_t payload_size,
///     uint8_t** response,
///     size_t* response_size
/// );
/// 
/// // Get supported command types
/// int get_supported_commands(uint32_t** commands, size_t* count);
/// ```