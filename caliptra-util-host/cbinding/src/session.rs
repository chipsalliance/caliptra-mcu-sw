// Licensed under the Apache-2.0 license

//! Session management C bindings

use std::boxed::Box;

use caliptra_util_host_session::CaliptraSession;
use caliptra_util_host_transport::{Mailbox, Transport};

use crate::{CaliptraError, CaliptraTransport};

// Session extractor callback no longer needed - we pass CaliptraSession pointers directly

/// Convert SessionError to CaliptraError
fn session_error_to_caliptra_error(err: caliptra_util_host_session::SessionError) -> CaliptraError {
    match err {
        caliptra_util_host_session::SessionError::TransportError(_) => CaliptraError::Transport,
        caliptra_util_host_session::SessionError::OsalError(_) => CaliptraError::Unknown,
        caliptra_util_host_session::SessionError::ConfigurationError(_) => {
            CaliptraError::InvalidArgument
        }
        caliptra_util_host_session::SessionError::InvalidState { .. } => CaliptraError::State,
        caliptra_util_host_session::SessionError::SessionNotFound(_) => CaliptraError::State,
        _ => CaliptraError::Unknown,
    }
}

/// Protocol types supported by the core layer (from design document)
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum CaliptraProtocolType {
    Mailbox = 0,
    MctpVdm = 1,
    Custom = 2,
}

/// Convert a C transport pointer to a boxed Transport with explicit protocol type
///
/// This function interprets the transport based on the specified protocol type.
unsafe fn transport_from_c_pointer_with_protocol(
    transport_ptr: *mut CaliptraTransport,
    protocol_type: CaliptraProtocolType,
) -> Result<Box<dyn Transport>, CaliptraError> {
    if transport_ptr.is_null() {
        return Err(CaliptraError::InvalidArgument);
    }

    match protocol_type {
        CaliptraProtocolType::Mailbox => {
            // For mailbox protocol, cast to mailbox transport
            // NOTE: This takes ownership of the transport. Each transport should only be used for one session.
            let mailbox_transport = *Box::from_raw(transport_ptr as *mut Mailbox<'static>);
            let boxed_transport = Box::new(mailbox_transport) as Box<dyn Transport>;

            Ok(boxed_transport)
        }
        CaliptraProtocolType::MctpVdm => {
            // Future: cast to MCTP VDM transport
            Err(CaliptraError::NotSupported)
        }
        CaliptraProtocolType::Custom => {
            // For custom protocol, cast back to CTransportWrapper and box it as Transport trait object
            let custom_transport =
                *Box::from_raw(transport_ptr as *mut crate::custom_transport::CTransportWrapper);
            let boxed_transport = Box::new(custom_transport) as Box<dyn Transport>;
            Ok(boxed_transport)
        }
    }
}

/// Create a new Caliptra session with transport
///
/// # Parameters
///
/// - `transport`: Transport instance to use for communication
/// - `session_handle`: Pointer to store the created session handle
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
///
/// Create a new Caliptra session with explicit protocol type
///
/// # Parameters
///
/// - `transport`: Transport instance to use for communication
/// - `protocol_type`: Protocol type that determines how to interpret the transport
/// - `session_handle`: Pointer to store the created session handle
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
#[no_mangle]
pub extern "C" fn caliptra_session_create_with_protocol(
    transport: *mut CaliptraTransport,
    protocol_type: CaliptraProtocolType,
    session: *mut *mut CaliptraSession<'static>,
) -> CaliptraError {
    if transport.is_null() || session.is_null() {
        return CaliptraError::InvalidArgument;
    }

    // Convert the C transport pointer to a boxed Transport with explicit protocol type
    let boxed_transport =
        match unsafe { transport_from_c_pointer_with_protocol(transport, protocol_type) } {
            Ok(bt) => bt,
            Err(err) => return err,
        };

    let transport_ref: &'static mut dyn Transport =
        unsafe { core::mem::transmute(boxed_transport) };
    let caliptra_session = match CaliptraSession::new(1, transport_ref) {
        Ok(s) => s,
        Err(_) => return CaliptraError::Transport,
    };

    unsafe { *session = Box::into_raw(Box::new(caliptra_session)) };
    CaliptraError::Success
}

/// Connect to the Caliptra device
///
/// # Parameters
///
/// - `session_handle`: Session handle obtained from `caliptra_session_create`
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
#[no_mangle]
pub extern "C" fn caliptra_session_connect(
    session: *mut CaliptraSession<'static>,
) -> CaliptraError {
    if session.is_null() {
        return CaliptraError::InvalidArgument;
    }

    let session_ref = unsafe { &mut *(session as *mut CaliptraSession<'static>) };

    match session_ref.connect() {
        Ok(_) => CaliptraError::Success,
        Err(err) => session_error_to_caliptra_error(err),
    }
}

/// Disconnect from the Caliptra device
///
/// # Parameters
///
/// - `session_handle`: Session handle
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
#[no_mangle]
pub extern "C" fn caliptra_session_disconnect(
    session: *mut CaliptraSession<'static>,
) -> CaliptraError {
    if session.is_null() {
        return CaliptraError::InvalidArgument;
    }

    let session_ref = unsafe { &mut *(session as *mut CaliptraSession<'static>) };

    match session_ref.disconnect() {
        Ok(_) => CaliptraError::Success,
        Err(err) => session_error_to_caliptra_error(err),
    }
}

/// Destroy a Caliptra session and free associated resources
///
/// # Parameters
///
/// - `session_handle`: Session handle to destroy
///
/// # Returns
///
/// - `CaliptraError::Success` on success
/// - Error code on failure
#[no_mangle]
pub extern "C" fn caliptra_session_destroy(
    session: *mut CaliptraSession<'static>,
) -> CaliptraError {
    if session.is_null() {
        return CaliptraError::InvalidArgument;
    }

    unsafe {
        let session_ref = &mut *(session as *mut CaliptraSession<'static>);
        // Convert back to ManagedSession and drop it
        let _ = Box::from_raw(session_ref);
    }

    CaliptraError::Success
}
