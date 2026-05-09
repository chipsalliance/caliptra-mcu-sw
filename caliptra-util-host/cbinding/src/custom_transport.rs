// Licensed under the Apache-2.0 license

//! Custom transport support for C-defined transports

use crate::error::CaliptraError::{self, Success};
use crate::transport::CaliptraTransport;
use caliptra_util_host_transport::{Transport, TransportError, TransportResult};
use std::ffi::c_void;

/// C function pointer types for custom transport implementation
pub type CTransportSendFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    command_id: u32,
    data: *const u8,
    len: usize,
) -> CaliptraError;

pub type CTransportReceiveFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    buffer: *mut u8,
    buffer_len: usize,
    received_len: *mut usize,
) -> CaliptraError;

pub type CTransportConnectFn = unsafe extern "C" fn(ctx: *mut c_void) -> CaliptraError;
pub type CTransportDisconnectFn = unsafe extern "C" fn(ctx: *mut c_void) -> CaliptraError;
pub type CTransportIsConnectedFn = unsafe extern "C" fn(ctx: *mut c_void) -> bool;
pub type CTransportDestroyFn = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

/// C Transport vtable - function pointers for transport operations
#[repr(C)]
pub struct CTransportVTable {
    pub send: CTransportSendFn,
    pub receive: CTransportReceiveFn,
    pub connect: CTransportConnectFn,
    pub disconnect: CTransportDisconnectFn,
    pub is_connected: CTransportIsConnectedFn,
    pub destroy: CTransportDestroyFn, // Optional destructor
}

/// Rust wrapper for C-defined transport
pub struct CTransportWrapper {
    vtable: CTransportVTable,
    context: *mut c_void,
}

// SAFETY: The C transport implementation is responsible for thread safety
// We assume the C code properly handles concurrent access to the context
unsafe impl Send for CTransportWrapper {}
unsafe impl Sync for CTransportWrapper {}

impl CTransportWrapper {
    /// Create a new C transport wrapper
    pub fn new(vtable: CTransportVTable, context: *mut c_void) -> Self {
        Self { vtable, context }
    }
}

impl Transport for CTransportWrapper {
    fn connect(&mut self) -> TransportResult<()> {
        unsafe {
            match (self.vtable.connect)(self.context) {
                Success => Ok(()),
                _error => Err(TransportError::Custom("C transport connect failed")),
            }
        }
    }

    fn disconnect(&mut self) -> TransportResult<()> {
        unsafe {
            match (self.vtable.disconnect)(self.context) {
                Success => Ok(()),
                _error => Err(TransportError::Custom("C transport disconnect failed")),
            }
        }
    }

    fn send(&mut self, command_id: u32, data: &[u8]) -> TransportResult<()> {
        unsafe {
            match (self.vtable.send)(self.context, command_id, data.as_ptr(), data.len()) {
                CaliptraError::Success => Ok(()),
                _error => Err(TransportError::Custom("C transport send failed")),
            }
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> TransportResult<usize> {
        let mut received_len = 0usize;
        unsafe {
            match (self.vtable.receive)(
                self.context,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut received_len as *mut usize,
            ) {
                CaliptraError::Success => Ok(received_len),
                _error => Err(TransportError::Custom("C transport receive failed")),
            }
        }
    }

    fn is_connected(&self) -> bool {
        unsafe { (self.vtable.is_connected)(self.context) }
    }
}

impl Drop for CTransportWrapper {
    fn drop(&mut self) {
        // Check if destroy function is provided (Some)
        if let Some(destroy_fn) = self.vtable.destroy {
            unsafe {
                destroy_fn(self.context);
            }
        }
    }
}

/// Create a transport from C function pointers (C-exportable)
#[no_mangle]
pub extern "C" fn caliptra_transport_create_from_c_vtable(
    vtable: *const CTransportVTable,
    context: *mut c_void,
    transport: *mut *mut CaliptraTransport,
) -> CaliptraError {
    if vtable.is_null() || transport.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let vtable_copy = (*vtable).clone();
        let wrapper = CTransportWrapper::new(vtable_copy, context);
        let boxed_transport = Box::new(wrapper);
        let raw_transport = Box::into_raw(boxed_transport);

        // Cast to CaliptraTransport pointer
        *transport = raw_transport as *mut CaliptraTransport;
    }

    CaliptraError::Success
}

// Need to implement Clone for CTransportVTable
impl Clone for CTransportVTable {
    fn clone(&self) -> Self {
        *self
    }
}

// Need to implement Copy for CTransportVTable
impl Copy for CTransportVTable {}
