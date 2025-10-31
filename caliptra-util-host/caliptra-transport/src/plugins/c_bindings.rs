//! C bindings for transport plugin system

use crate::{Transport, TransportConfig, TransportError, TransportResult, TransportInfo};
use caliptra_osal::memory::Buffer;

use core::ffi::{c_char, c_void};
use core::ptr;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, ffi::CString, string::String};

/// C-compatible transport handle
pub type CTransportHandle = *mut c_void;

/// C-compatible buffer structure  
#[repr(C)]
pub struct CBuffer {
    data: *mut u8,
    length: usize,
    capacity: usize,
}

/// C-compatible transport info
#[repr(C)]
pub struct CTransportInfo {
    name: *const c_char,
    version: *const c_char, 
    description: *const c_char,
    max_message_size: usize,
    supports_fragmentation: bool,
    is_reliable: bool,
}

/// C-compatible result type
#[repr(C)]
pub struct CResult {
    success: bool,
    error_code: i32,
    error_message: *const c_char,
}

/// Error codes for C API
#[repr(i32)]
pub enum CErrorCode {
    Success = 0,
    InvalidParameter = -1,
    ConnectionError = -2,
    IoError = -3,
    BufferError = -4,
    ConfigurationError = -5,
    TransportNotFound = -6,
    MessageTooLarge = -7,
    ParseError = -8,
    FactoryError = -9,
    PluginError = -10,
    NotSupported = -11,
    Custom = -100,
}

impl From<TransportError> for CErrorCode {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::ConnectionError(_) => CErrorCode::ConnectionError,
            TransportError::IoError(_) => CErrorCode::IoError,
            TransportError::BufferError(_) => CErrorCode::BufferError,
            TransportError::ConfigurationError(_) => CErrorCode::ConfigurationError,
            TransportError::TransportNotFound(_) => CErrorCode::TransportNotFound,
            TransportError::MessageTooLarge(_) => CErrorCode::MessageTooLarge,
            TransportError::ParseError(_) => CErrorCode::ParseError,
            TransportError::FactoryError(_) => CErrorCode::FactoryError,
            TransportError::PluginError(_) => CErrorCode::PluginError,
            TransportError::NotSupported(_) => CErrorCode::NotSupported,
            TransportError::Custom(_) => CErrorCode::Custom,
        }
    }
}

/// C plugin function signatures
pub type CPluginInitFn = unsafe extern "C" fn() -> CResult;
pub type CPluginCleanupFn = unsafe extern "C" fn() -> CResult;
pub type CPluginCreateTransportFn = unsafe extern "C" fn(transport_type: *const c_char) -> CTransportHandle;
pub type CPluginGetInfoFn = unsafe extern "C" fn() -> *const c_char;

/// C plugin structure
#[repr(C)]
pub struct CPlugin {
    init: CPluginInitFn,
    cleanup: CPluginCleanupFn,
    create_transport: CPluginCreateTransportFn,
    get_info: CPluginGetInfoFn,
}

/// C transport function pointers
#[repr(C)]
pub struct CTransportVTable {
    send: unsafe extern "C" fn(handle: CTransportHandle, buffer: *const CBuffer) -> CResult,
    receive: unsafe extern "C" fn(handle: CTransportHandle, buffer: *mut CBuffer) -> CResult,
    connect: unsafe extern "C" fn(handle: CTransportHandle) -> CResult,
    disconnect: unsafe extern "C" fn(handle: CTransportHandle) -> CResult,
    is_connected: unsafe extern "C" fn(handle: CTransportHandle) -> bool,
    configure: unsafe extern "C" fn(handle: CTransportHandle, config: *const c_char) -> CResult,
    get_info: unsafe extern "C" fn(handle: CTransportHandle) -> CTransportInfo,
    destroy: unsafe extern "C" fn(handle: CTransportHandle),
}

/// Wrapper for C transport implementations
pub struct CTransportWrapper {
    handle: CTransportHandle,
    vtable: CTransportVTable,
}

impl CTransportWrapper {
    pub fn new(handle: CTransportHandle, vtable: CTransportVTable) -> Self {
        Self { handle, vtable }
    }
    
    fn convert_buffer_to_c(buffer: &Buffer) -> CBuffer {
        CBuffer {
            data: buffer.as_slice().as_ptr() as *mut u8,
            length: buffer.len(),
            capacity: buffer.capacity(),
        }
    }
    
    fn convert_buffer_from_c(cbuffer: &mut CBuffer, buffer: &mut Buffer) -> TransportResult<()> {
        if cbuffer.length > cbuffer.capacity {
            return Err(TransportError::BufferError("Invalid C buffer length"));
        }
        
        unsafe {
            let slice = core::slice::from_raw_parts(cbuffer.data, cbuffer.length);
            buffer.clear();
            buffer.extend_from_slice(slice)
                .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
        }
        
        Ok(())
    }
}

impl Transport for CTransportWrapper {
    fn send(&self, data: &Buffer) -> TransportResult<usize> {
        let cbuffer = Self::convert_buffer_to_c(data);
        
        unsafe {
            let result = (self.vtable.send)(self.handle, &cbuffer);
            if result.success {
                Ok(data.len())
            } else {
                let error = match result.error_code {
                    -1 => TransportError::Custom("Invalid parameter"),
                    -2 => TransportError::ConnectionError("Connection error"),
                    -3 => TransportError::IoError("IO error".to_string()),
                    _ => TransportError::Custom("Unknown C transport error"),
                };
                Err(error)
            }
        }
    }
    
    fn receive(&self, buffer: &mut Buffer) -> TransportResult<usize> {
        let mut cbuffer = CBuffer {
            data: buffer.as_mut_slice().as_mut_ptr(),
            length: 0,
            capacity: buffer.capacity(),
        };
        
        unsafe {
            let result = (self.vtable.receive)(self.handle, &mut cbuffer);
            if result.success {
                buffer.clear();
                if cbuffer.length > 0 {
                    let slice = core::slice::from_raw_parts(cbuffer.data, cbuffer.length);
                    buffer.extend_from_slice(slice)
                        .map_err(|_| TransportError::BufferError("Buffer overflow"))?;
                }
                Ok(cbuffer.length)
            } else {
                let error = match result.error_code {
                    -2 => TransportError::ConnectionError("Connection error"),
                    -3 => TransportError::IoError("IO error".to_string()),
                    -4 => TransportError::BufferError("Buffer error"),
                    _ => TransportError::Custom("Unknown C transport error"),
                };
                Err(error)
            }
        }
    }
    
    fn connect(&self) -> TransportResult<()> {
        unsafe {
            let result = (self.vtable.connect)(self.handle);
            if result.success {
                Ok(())
            } else {
                Err(TransportError::ConnectionError("Failed to connect"))
            }
        }
    }
    
    fn disconnect(&self) -> TransportResult<()> {
        unsafe {
            let result = (self.vtable.disconnect)(self.handle);
            if result.success {
                Ok(())
            } else {
                Err(TransportError::ConnectionError("Failed to disconnect"))
            }
        }
    }
    
    fn is_connected(&self) -> bool {
        unsafe {
            (self.vtable.is_connected)(self.handle)
        }
    }
    
    fn configure(&mut self, _config: TransportConfig) -> TransportResult<()> {
        // For now, skip configuration of C transports
        // TODO: Implement JSON serialization of config
        Ok(())
    }
    
    fn get_info(&self) -> TransportInfo {
        unsafe {
            let cinfo = (self.vtable.get_info)(self.handle);
            
            // Convert C strings to Rust strings (unsafe, assumes null-terminated)
            let name = if cinfo.name.is_null() {
                "Unknown"
            } else {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(
                        cinfo.name as *const u8,
                        libc::strlen(cinfo.name)
                    )
                )
            };
            
            let version = if cinfo.version.is_null() {
                "0.0.0"
            } else {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(
                        cinfo.version as *const u8,
                        libc::strlen(cinfo.version)
                    )
                )
            };
            
            let description = if cinfo.description.is_null() {
                "No description"
            } else {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(
                        cinfo.description as *const u8,
                        libc::strlen(cinfo.description)
                    )
                )
            };
            
            TransportInfo {
                name,
                version,
                description,
                max_message_size: cinfo.max_message_size,
                supports_fragmentation: cinfo.supports_fragmentation,
                is_reliable: cinfo.is_reliable,
            }
        }
    }
}

impl Drop for CTransportWrapper {
    fn drop(&mut self) {
        unsafe {
            (self.vtable.destroy)(self.handle);
        }
    }
}

/// Helper functions for C integration
impl CResult {
    pub fn success() -> Self {
        Self {
            success: true,
            error_code: 0,
            error_message: ptr::null(),
        }
    }
    
    pub fn error(code: CErrorCode, message: *const c_char) -> Self {
        Self {
            success: false,
            error_code: code as i32,
            error_message: message,
        }
    }
}

/// C API exports
#[no_mangle]
pub unsafe extern "C" fn caliptra_transport_create_buffer(capacity: usize) -> *mut CBuffer {
    let buffer = Box::new(CBuffer {
        data: libc::malloc(capacity) as *mut u8,
        length: 0,
        capacity,
    });
    Box::into_raw(buffer)
}

#[no_mangle]
pub unsafe extern "C" fn caliptra_transport_destroy_buffer(buffer: *mut CBuffer) {
    if !buffer.is_null() {
        let buffer = Box::from_raw(buffer);
        libc::free(buffer.data as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "C" fn caliptra_transport_register_plugin(plugin: *const CPlugin) -> CResult {
    if plugin.is_null() {
        return CResult::error(CErrorCode::InvalidParameter, ptr::null());
    }
    
    // Initialize the plugin
    let init_result = ((*plugin).init)();
    if !init_result.success {
        return init_result;
    }
    
    CResult::success()
}

// External C library functions we depend on
extern "C" {
    fn strlen(s: *const c_char) -> usize;
}

// Link with libc for malloc/free
#[cfg(feature = "std")]
extern crate libc;