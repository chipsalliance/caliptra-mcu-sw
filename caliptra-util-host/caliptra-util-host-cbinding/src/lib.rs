//! C bindings for the Caliptra Utility Host Library

use caliptra_util_host_core::*;
use libc::{c_char, c_int, c_uint, c_void, size_t};
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;
use std::collections::HashMap;
use tokio::runtime::Runtime;

/// Opaque handle for CaliptraUtilHost
pub struct CaliptraUtilHostHandle {
    inner: Mutex<CaliptraUtilHost>,
    runtime: Runtime,
}

/// C-compatible error codes
#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum CaliptraUtilResult {
    Success = 0,
    Error = -1,
    InvalidParam = -2,
    TransportError = -3,
    CommandNotFound = -4,
    PluginError = -5,
    TimeoutError = -6,
    NotConnected = -7,
}

/// C-compatible transport types
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CTransportType {
    Mctp = 0,
    Doe = 1,
    Tcp = 2,
    Custom = 3,
}

/// C-compatible command types
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum CCommandType {
    Spdm = 0,
    Pldm = 1,
    Mailbox = 2,
    Certificate = 3,
    Custom = 4,
}

/// C-compatible command structure
#[repr(C)]
pub struct CCommand {
    pub command_type: CCommandType,
    pub opcode: c_uint,
    pub payload_data: *const u8,
    pub payload_size: size_t,
}

/// C-compatible command result
#[repr(C)]
pub struct CCommandResult {
    pub success: c_int,
    pub response_data: *mut u8,
    pub response_size: size_t,
    pub error_message: *mut c_char,
    pub execution_time_ms: c_uint,
}

/// Transport configuration for C API
#[repr(C)]
pub struct CTransportConfig {
    pub max_retries: c_uint,
    pub timeout_ms: c_uint,
    pub buffer_size: size_t,
}

impl Default for CTransportConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            timeout_ms: 5000,
            buffer_size: 4096,
        }
    }
}

/// Initialize the library (must be called before any other functions)
#[no_mangle]
pub extern "C" fn caliptra_util_host_init() -> CaliptraUtilResult {
    // Initialize logging if not already done
    let _ = env_logger::try_init();
    CaliptraUtilResult::Success
}

/// Create a new CaliptraUtilHost instance with MCTP transport
#[no_mangle]
pub extern "C" fn caliptra_util_host_create_mctp(
    endpoint_id: c_uint,
) -> *mut CaliptraUtilHostHandle {
    create_mctp_with_config(endpoint_id, CTransportConfig::default())
}

/// Create a new CaliptraUtilHost instance with MCTP transport and custom config
#[no_mangle]
pub extern "C" fn caliptra_util_host_create_mctp_with_config(
    endpoint_id: c_uint,
    config: CTransportConfig,
) -> *mut CaliptraUtilHostHandle {
    create_mctp_with_config(endpoint_id, config)
}

fn create_mctp_with_config(
    endpoint_id: c_uint, 
    config: CTransportConfig
) -> *mut CaliptraUtilHostHandle {
    let transport_config = transport::TransportConfig {
        max_retries: config.max_retries,
        timeout_ms: config.timeout_ms as u64,
        buffer_size: config.buffer_size,
    };
    
    let transport = Box::new(transport::MctpTransport::with_config(
        endpoint_id as u8, 
        transport_config
    ));
    let host = CaliptraUtilHost::new(transport);
    
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    
    Box::into_raw(Box::new(CaliptraUtilHostHandle {
        inner: Mutex::new(host),
        runtime,
    }))
}

/// Create a new CaliptraUtilHost instance with DOE transport
#[no_mangle]
pub extern "C" fn caliptra_util_host_create_doe() -> *mut CaliptraUtilHostHandle {
    create_doe_with_config(CTransportConfig::default())
}

/// Create a new CaliptraUtilHost instance with DOE transport and custom config
#[no_mangle]
pub extern "C" fn caliptra_util_host_create_doe_with_config(
    config: CTransportConfig,
) -> *mut CaliptraUtilHostHandle {
    create_doe_with_config(config)
}

fn create_doe_with_config(config: CTransportConfig) -> *mut CaliptraUtilHostHandle {
    let transport_config = transport::TransportConfig {
        max_retries: config.max_retries,
        timeout_ms: config.timeout_ms as u64,
        buffer_size: config.buffer_size,
    };
    
    let transport = Box::new(transport::DoeTransport::new());
    let host = CaliptraUtilHost::new(transport);
    
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    
    Box::into_raw(Box::new(CaliptraUtilHostHandle {
        inner: Mutex::new(host),
        runtime,
    }))
}

/// Destroy a CaliptraUtilHost instance
#[no_mangle]
pub extern "C" fn caliptra_util_host_destroy(handle: *mut CaliptraUtilHostHandle) {
    if !handle.is_null() {
        unsafe {
            let handle = Box::from_raw(handle);
            // Runtime and host will be automatically dropped
            drop(handle);
        }
    }
}

/// Connect the transport
#[no_mangle]
pub extern "C" fn caliptra_util_host_connect(
    handle: *mut CaliptraUtilHostHandle,
) -> CaliptraUtilResult {
    if handle.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let mut host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    match handle.runtime.block_on(host.context.transport_mut().connect()) {
        Ok(_) => CaliptraUtilResult::Success,
        Err(_) => CaliptraUtilResult::TransportError,
    }
}

/// Disconnect the transport
#[no_mangle]
pub extern "C" fn caliptra_util_host_disconnect(
    handle: *mut CaliptraUtilHostHandle,
) -> CaliptraUtilResult {
    if handle.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let mut host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    match handle.runtime.block_on(host.context.transport_mut().disconnect()) {
        Ok(_) => CaliptraUtilResult::Success,
        Err(_) => CaliptraUtilResult::TransportError,
    }
}

/// Check if transport is connected
#[no_mangle]
pub extern "C" fn caliptra_util_host_is_connected(
    handle: *mut CaliptraUtilHostHandle,
) -> c_int {
    if handle.is_null() {
        return 0;
    }
    
    let handle = unsafe { &*handle };
    let host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return 0,
    };
    
    if host.context.is_connected() { 1 } else { 0 }
}

/// Execute a command
#[no_mangle]
pub extern "C" fn caliptra_util_host_execute_command(
    handle: *mut CaliptraUtilHostHandle,
    command: *const CCommand,
    result: *mut CCommandResult,
) -> CaliptraUtilResult {
    if handle.is_null() || command.is_null() || result.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let command = unsafe { &*command };
    
    let mut host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    // Convert C command to Rust command
    let command_type = match command.command_type {
        CCommandType::Spdm => command::CommandType::Spdm,
        CCommandType::Pldm => command::CommandType::Pldm,
        CCommandType::Mailbox => command::CommandType::Mailbox,
        CCommandType::Certificate => command::CommandType::Certificate,
        CCommandType::Custom => command::CommandType::Custom(0), // Default custom type
    };
    
    let payload = if command.payload_data.is_null() || command.payload_size == 0 {
        Vec::new()
    } else {
        unsafe {
            std::slice::from_raw_parts(command.payload_data, command.payload_size).to_vec()
        }
    };
    
    let rust_command = command::Command::new(command_type, command.opcode, payload);
    
    // Execute command
    let command_result = handle.runtime.block_on(host.execute_command(rust_command));
    
    match command_result {
        Ok(cmd_result) => {
            unsafe {
                (*result).success = if cmd_result.success { 1 } else { 0 };
                (*result).execution_time_ms = cmd_result.execution_time_ms as c_uint;
                
                // Allocate and copy response data
                if !cmd_result.response_data.is_empty() {
                    let response_ptr = libc::malloc(cmd_result.response_data.len());
                    if !response_ptr.is_null() {
                        ptr::copy_nonoverlapping(
                            cmd_result.response_data.as_ptr(),
                            response_ptr as *mut u8,
                            cmd_result.response_data.len(),
                        );
                        (*result).response_data = response_ptr as *mut u8;
                        (*result).response_size = cmd_result.response_data.len();
                    } else {
                        (*result).response_data = ptr::null_mut();
                        (*result).response_size = 0;
                    }
                } else {
                    (*result).response_data = ptr::null_mut();
                    (*result).response_size = 0;
                }
                
                // Handle error message
                if let Some(error_msg) = cmd_result.error_message {
                    if let Ok(c_str) = CString::new(error_msg) {
                        (*result).error_message = c_str.into_raw();
                    } else {
                        (*result).error_message = ptr::null_mut();
                    }
                } else {
                    (*result).error_message = ptr::null_mut();
                }
            }
            CaliptraUtilResult::Success
        },
        Err(e) => {
            unsafe {
                (*result).success = 0;
                (*result).response_data = ptr::null_mut();
                (*result).response_size = 0;
                (*result).execution_time_ms = 0;
                
                let error_msg = format!("{}", e);
                if let Ok(c_str) = CString::new(error_msg) {
                    (*result).error_message = c_str.into_raw();
                } else {
                    (*result).error_message = ptr::null_mut();
                }
            }
            
            match e {
                CaliptraUtilError::Transport(_) => CaliptraUtilResult::TransportError,
                CaliptraUtilError::CommandNotFound => CaliptraUtilResult::CommandNotFound,
                CaliptraUtilError::Plugin(_) => CaliptraUtilResult::PluginError,
                _ => CaliptraUtilResult::Error,
            }
        }
    }
}

/// Send raw data through transport
#[no_mangle]
pub extern "C" fn caliptra_util_host_send_raw(
    handle: *mut CaliptraUtilHostHandle,
    data: *const u8,
    data_size: size_t,
    response_data: *mut *mut u8,
    response_size: *mut size_t,
) -> CaliptraUtilResult {
    if handle.is_null() || data.is_null() || response_data.is_null() || response_size.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let input_data = unsafe { std::slice::from_raw_parts(data, data_size) };
    
    let mut host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    match handle.runtime.block_on(host.send_raw(input_data)) {
        Ok(response) => {
            unsafe {
                if !response.is_empty() {
                    let response_ptr = libc::malloc(response.len());
                    if !response_ptr.is_null() {
                        ptr::copy_nonoverlapping(
                            response.as_ptr(),
                            response_ptr as *mut u8,
                            response.len(),
                        );
                        *response_data = response_ptr as *mut u8;
                        *response_size = response.len();
                    } else {
                        *response_data = ptr::null_mut();
                        *response_size = 0;
                        return CaliptraUtilResult::Error;
                    }
                } else {
                    *response_data = ptr::null_mut();
                    *response_size = 0;
                }
            }
            CaliptraUtilResult::Success
        },
        Err(_) => CaliptraUtilResult::TransportError,
    }
}

/// Free memory allocated by the library
#[no_mangle]
pub extern "C" fn caliptra_util_host_free_result(result: *mut CCommandResult) {
    if !result.is_null() {
        unsafe {
            if !(*result).response_data.is_null() {
                libc::free((*result).response_data as *mut c_void);
                (*result).response_data = ptr::null_mut();
                (*result).response_size = 0;
            }
            
            if !(*result).error_message.is_null() {
                let _ = CString::from_raw((*result).error_message);
                (*result).error_message = ptr::null_mut();
            }
        }
    }
}

/// Free memory allocated for raw send response
#[no_mangle]
pub extern "C" fn caliptra_util_host_free_data(data: *mut u8) {
    if !data.is_null() {
        unsafe {
            libc::free(data as *mut c_void);
        }
    }
}

/// Register built-in command handlers
#[no_mangle]
pub extern "C" fn caliptra_util_host_register_builtin_handlers(
    handle: *mut CaliptraUtilHostHandle,
) -> CaliptraUtilResult {
    if handle.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let mut host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    // Register built-in handlers
    if host.register_command_handler(Box::new(command::SpdmCommandHandler)).is_err() {
        return CaliptraUtilResult::Error;
    }
    
    if host.register_command_handler(Box::new(command::PldmCommandHandler)).is_err() {
        return CaliptraUtilResult::Error;
    }
    
    if host.register_command_handler(Box::new(command::MailboxCommandHandler)).is_err() {
        return CaliptraUtilResult::Error;
    }
    
    CaliptraUtilResult::Success
}

/// Get list of registered command handlers
#[no_mangle]
pub extern "C" fn caliptra_util_host_list_handlers(
    handle: *mut CaliptraUtilHostHandle,
    handlers: *mut *mut CCommandType,
    count: *mut size_t,
) -> CaliptraUtilResult {
    if handle.is_null() || handlers.is_null() || count.is_null() {
        return CaliptraUtilResult::InvalidParam;
    }
    
    let handle = unsafe { &*handle };
    let host = match handle.inner.lock() {
        Ok(host) => host,
        Err(_) => return CaliptraUtilResult::Error,
    };
    
    let handler_list = host.list_handlers();
    
    unsafe {
        if handler_list.is_empty() {
            *handlers = ptr::null_mut();
            *count = 0;
            return CaliptraUtilResult::Success;
        }
        
        let handlers_ptr = libc::malloc(handler_list.len() * std::mem::size_of::<CCommandType>()) as *mut CCommandType;
        if handlers_ptr.is_null() {
            return CaliptraUtilResult::Error;
        }
        
        for (i, &handler_type) in handler_list.iter().enumerate() {
            let c_type = match handler_type {
                CommandType::Spdm => CCommandType::Spdm,
                CommandType::Pldm => CCommandType::Pldm,
                CommandType::Mailbox => CCommandType::Mailbox,
                CommandType::Certificate => CCommandType::Certificate,
                CommandType::Custom(_) => CCommandType::Custom,
            };
            *handlers_ptr.add(i) = c_type;
        }
        
        *handlers = handlers_ptr;
        *count = handler_list.len();
    }
    
    CaliptraUtilResult::Success
}

/// Free memory allocated for handler list
#[no_mangle]
pub extern "C" fn caliptra_util_host_free_handlers(handlers: *mut CCommandType) {
    if !handlers.is_null() {
        unsafe {
            libc::free(handlers as *mut c_void);
        }
    }
}

/// Get library version string
#[no_mangle]
pub extern "C" fn caliptra_util_host_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}