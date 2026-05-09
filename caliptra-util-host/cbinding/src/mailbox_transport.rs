// Licensed under the Apache-2.0 license

//! Mock transport implementations for testing
//!
//! This module contains mock transport implementations used only for testing.
//! These are not part of the production API.

use crate::error::CaliptraError;
use crate::transport::CaliptraTransport;
use caliptra_util_host_transport::transports::mailbox::transport::Mailbox;
use caliptra_util_host_transport::transports::mailbox::MailboxDriver;
use caliptra_util_host_transport::transports::mailbox::MailboxError;
use std::boxed::Box;

/// Function pointer types for MailboxDriver implementation in C
#[repr(C)]
pub struct CMailboxDriverVTable {
    pub send_command: extern "C" fn(
        driver: *mut CMailboxDriver,
        external_cmd: u32,
        payload: *const u8,
        payload_len: usize,
        response: *mut *const u8,
        response_len: *mut usize,
    ) -> CaliptraError,
    pub is_ready: extern "C" fn(driver: *mut CMailboxDriver) -> bool,
    pub connect: extern "C" fn(driver: *mut CMailboxDriver) -> CaliptraError,
    pub disconnect: extern "C" fn(driver: *mut CMailboxDriver) -> CaliptraError,
}

/// Complete C MailboxDriver implementation
#[repr(C)]
pub struct CMailboxDriver {
    pub vtable: *mut CMailboxDriverVTable,
    pub device_id: u16,
    pub vendor_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub ready: bool,
    pub connected: bool,
    pub response_buffer: [u8; 32],
}

/// Rust wrapper that implements MailboxDriver trait for CMailboxDriver
pub struct CMailboxDriverWrapper {
    c_driver: *mut CMailboxDriver,
}

// SAFETY: This is for testing only and we control the C driver lifecycle
unsafe impl Send for CMailboxDriverWrapper {}
unsafe impl Sync for CMailboxDriverWrapper {}

impl CMailboxDriverWrapper {
    pub fn new(c_driver: *mut CMailboxDriver) -> Self {
        Self { c_driver }
    }
}

impl MailboxDriver for CMailboxDriverWrapper {
    fn send_command(&mut self, external_cmd: u32, payload: &[u8]) -> Result<&[u8], MailboxError> {
        unsafe {
            let vtable = (*self.c_driver).vtable;
            let mut response_ptr: *const u8 = std::ptr::null();
            let mut response_len: usize = 0;

            let result = ((*vtable).send_command)(
                self.c_driver,
                external_cmd,
                payload.as_ptr(),
                payload.len(),
                &mut response_ptr,
                &mut response_len,
            );

            match result {
                CaliptraError::Success => {
                    if response_ptr.is_null() || response_len == 0 {
                        Err(MailboxError::CommunicationError)
                    } else {
                        Ok(std::slice::from_raw_parts(response_ptr, response_len))
                    }
                }
                CaliptraError::NotSupported => Err(MailboxError::InvalidCommand),
                CaliptraError::Timeout => Err(MailboxError::Timeout),
                _ => Err(MailboxError::CommunicationError),
            }
        }
    }

    fn is_ready(&self) -> bool {
        unsafe {
            let vtable = (*self.c_driver).vtable;
            ((*vtable).is_ready)(self.c_driver)
        }
    }

    fn connect(&mut self) -> Result<(), MailboxError> {
        unsafe {
            let vtable = (*self.c_driver).vtable;
            let result = ((*vtable).connect)(self.c_driver);
            match result {
                CaliptraError::Success => Ok(()),
                _ => Err(MailboxError::CommunicationError),
            }
        }
    }

    fn disconnect(&mut self) -> Result<(), MailboxError> {
        unsafe {
            let vtable = (*self.c_driver).vtable;
            let result = ((*vtable).disconnect)(self.c_driver);
            match result {
                CaliptraError::Success => Ok(()),
                _ => Err(MailboxError::CommunicationError),
            }
        }
    }
}

/// Create a transport from a C MailboxDriver
#[no_mangle]
pub extern "C" fn caliptra_transport_create_from_c_mailbox_driver(
    c_driver: *mut CMailboxDriver,
    transport: *mut *mut CaliptraTransport,
) -> CaliptraError {
    if c_driver.is_null() || transport.is_null() {
        return CaliptraError::InvalidArgument;
    }

    // Create a wrapper that implements MailboxDriver
    let wrapper = CMailboxDriverWrapper::new(c_driver);

    // Create a boxed mailbox driver for dynamic dispatch
    let boxed_mailbox = Box::new(wrapper) as Box<dyn MailboxDriver>;

    // Leak the box to get a static reference (this is for testing only)
    let leaked_mailbox: &'static mut dyn MailboxDriver = Box::leak(boxed_mailbox);
    let mailbox_transport = Mailbox::new(leaked_mailbox);
    let transport_box = Box::new(mailbox_transport);

    unsafe {
        *transport = Box::into_raw(transport_box) as *mut CaliptraTransport;
    }

    CaliptraError::Success
}
