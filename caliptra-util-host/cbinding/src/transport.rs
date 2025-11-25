// Licensed under the Apache-2.0 license

//! Transport abstraction layer for Caliptra C bindings
//!
//! This module implements the transport abstraction layer as defined in the design document.

use crate::error::CaliptraError;

/// Opaque transport handle (from design document)
#[repr(C)]
pub struct CaliptraTransport {
    _private: [u8; 0],
}

/// Destroy transport instance (from design document)
#[no_mangle]
pub extern "C" fn caliptra_transport_destroy(transport: *mut CaliptraTransport) -> CaliptraError {
    if transport.is_null() {
        return CaliptraError::InvalidArgument;
    }

    // For now, try to destroy as a mock transport (used in testing)
    // Transport cleanup is handled by the C MailboxDriver implementation
    // The transport wrapper will be automatically cleaned up when dropped
    if !transport.is_null() {
        unsafe {
            let _ = Box::from_raw(transport); // Convert back to Box to drop it
        }
    }
    CaliptraError::Success
}
