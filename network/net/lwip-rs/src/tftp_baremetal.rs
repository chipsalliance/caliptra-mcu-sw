// Licensed under the Apache-2.0 license

//! Bare-metal TFTP client for lwIP (`no_std`, single-threaded).
//!
//! The caller provides callbacks to handle received data chunks,
//! enabling streaming verification without buffering the entire file.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::slice;

use crate::error::{check_err, LwipError, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;
#[cfg(feature = "baremetal-ipv6")]
use crate::ip::Ipv6Addr;

const TFTP_PORT: u16 = 69;

/// Callbacks for bare-metal TFTP file handling.
#[derive(Clone, Copy)]
pub struct BaremetalTftpOps {
    /// Called for each chunk of received data. Return `true` to continue.
    pub write: fn(data: &[u8]) -> bool,
    /// Called when the TFTP server reports an error.
    pub error: fn(err: i32, msg: &[u8]),
}

/// Internal state for the bare-metal TFTP client.
struct TftpState {
    ops: BaremetalTftpOps,
    bytes_received: usize,
    has_error: bool,
    complete: bool,
}

/// Sentinel value used as the TFTP "file handle" (lwIP requires non-null).
static HANDLE_SENTINEL: u8 = 0xAA;

/// Global TFTP state. Safe because bare-metal is single-threaded.
static mut STATE: Option<TftpState> = None;

/// Open callback — lwIP calls this when starting a transfer.
unsafe extern "C" fn tftp_open_cb(
    _fname: *const c_char,
    _mode: *const c_char,
    is_write: u8,
) -> *mut c_void {
    if is_write == 0 {
        return ptr::null_mut();
    }

    if let Some(ref mut s) = STATE {
        s.bytes_received = 0;
        s.has_error = false;
        s.complete = false;
        return (&HANDLE_SENTINEL as *const u8) as *mut c_void;
    }
    ptr::null_mut()
}

/// Close callback — transfer complete.
unsafe extern "C" fn tftp_close_cb(_handle: *mut c_void) {
    if let Some(ref mut s) = STATE {
        s.complete = true;
    }
}

/// Read callback — unused for GET operations.
unsafe extern "C" fn tftp_read_cb(_handle: *mut c_void, _buf: *mut c_void, _bytes: c_int) -> c_int {
    -1
}

/// Write callback — called for each received data block.
unsafe extern "C" fn tftp_write_cb(_handle: *mut c_void, p: *mut ffi::pbuf) -> c_int {
    if let Some(ref mut s) = STATE {
        let mut current = p;
        while !current.is_null() {
            let pbuf_ref = &*current;
            let data = slice::from_raw_parts(pbuf_ref.payload as *const u8, pbuf_ref.len as usize);

            if !(s.ops.write)(data) {
                s.has_error = true;
                return -1;
            }
            s.bytes_received += data.len();
            current = pbuf_ref.next;
        }
        return 0;
    }
    -1
}

/// Error callback — called when the server sends an error.
unsafe extern "C" fn tftp_error_cb(
    _handle: *mut c_void,
    err: c_int,
    msg: *const c_char,
    size: c_int,
) {
    if let Some(ref mut s) = STATE {
        let msg_bytes = if msg.is_null() || size <= 0 {
            &[] as &[u8]
        } else {
            slice::from_raw_parts(msg as *const u8, size as usize)
        };
        (s.ops.error)(err as i32, msg_bytes);
        s.has_error = true;
        s.complete = true;
    }
}

/// Static TFTP context struct passed to `tftp_init_client`.
static TFTP_CONTEXT: ffi::tftp_context = ffi::tftp_context {
    open: Some(tftp_open_cb),
    close: Some(tftp_close_cb),
    read: Some(tftp_read_cb),
    write: Some(tftp_write_cb),
    error: Some(tftp_error_cb),
};

/// Bare-metal TFTP client.
///
/// Place in a `static mut`; call `init()` then `get()` to download.
pub struct BaremetalTftpClient {
    initialized: bool,
}

impl BaremetalTftpClient {
    /// Create an uninitialized TFTP client.
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the TFTP client with lwIP. Must be called after `lwip_rs::init()`.
    pub fn init(&mut self, ops: BaremetalTftpOps) -> Result<()> {
        unsafe {
            STATE = Some(TftpState {
                ops,
                bytes_received: 0,
                has_error: false,
                complete: false,
            });
        }

        let err = unsafe { ffi::tftp_init_client(&TFTP_CONTEXT) };
        check_err(err)?;
        self.initialized = true;
        Ok(())
    }

    /// Initiate a TFTP GET over IPv4.
    ///
    /// `filename` must be null-terminated. Poll lwIP until `is_complete()`.
    pub fn get(&mut self, server: Ipv4Addr, filename: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(LwipError::NotConnected);
        }

        // Verify filename is null-terminated
        if filename.is_empty() || filename[filename.len() - 1] != 0 {
            return Err(LwipError::IllegalArgument);
        }

        // Reset transfer state
        unsafe {
            if let Some(ref mut s) = STATE {
                s.bytes_received = 0;
                s.has_error = false;
                s.complete = false;
            }
        }

        // Call open to get the handle
        let fname_ptr = filename.as_ptr() as *const c_char;
        let mode_ptr = b"octet\0".as_ptr() as *const c_char;
        let handle = unsafe { tftp_open_cb(fname_ptr, mode_ptr, 1) };
        if handle.is_null() {
            return Err(LwipError::OutOfMemory);
        }

        let mut server_addr: ffi::ip_addr_t = unsafe { core::mem::zeroed() };
        #[cfg(not(feature = "baremetal-ipv6"))]
        {
            server_addr.addr = server.0.addr;
        }
        #[cfg(feature = "baremetal-ipv6")]
        {
            server_addr.u_addr.ip4 = server.0;
            server_addr.type_ = 0; // IPADDR_TYPE_V4
        }

        let err = unsafe {
            ffi::tftp_get(
                handle,
                &server_addr,
                TFTP_PORT,
                fname_ptr,
                ffi::tftp_transfer_mode_TFTP_MODE_OCTET,
            )
        };

        if err != 0 {
            unsafe { tftp_close_cb(handle) };
        }

        check_err(err)
    }

    /// Initiate a TFTP GET over IPv6.
    ///
    /// `filename` must be null-terminated. Poll lwIP until `is_complete()`.
    #[cfg(feature = "baremetal-ipv6")]
    pub fn get_v6(&mut self, server: Ipv6Addr, filename: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(LwipError::NotConnected);
        }

        if filename.is_empty() || filename[filename.len() - 1] != 0 {
            return Err(LwipError::IllegalArgument);
        }

        unsafe {
            if let Some(ref mut s) = STATE {
                s.bytes_received = 0;
                s.has_error = false;
                s.complete = false;
            }
        }

        // Call open to get the handle
        let fname_ptr = filename.as_ptr() as *const c_char;
        let mode_ptr = b"octet\0".as_ptr() as *const c_char;
        let handle = unsafe { tftp_open_cb(fname_ptr, mode_ptr, 1) };
        if handle.is_null() {
            return Err(LwipError::OutOfMemory);
        }

        let mut server_addr: ffi::ip_addr_t = unsafe { core::mem::zeroed() };
        server_addr.u_addr.ip6 = server.0;
        server_addr.type_ = 6;

        let err = unsafe {
            ffi::tftp_get(
                handle,
                &server_addr,
                TFTP_PORT,
                fname_ptr,
                ffi::tftp_transfer_mode_TFTP_MODE_OCTET,
            )
        };

        if err != 0 {
            unsafe { tftp_close_cb(handle) };
        }

        check_err(err)
    }

    /// Check if the transfer is complete (success or error).
    pub fn is_complete(&self) -> bool {
        unsafe {
            let ptr = ptr::addr_of!(STATE);
            (*ptr).as_ref().map(|s| s.complete).unwrap_or(false)
        }
    }

    /// Check if the transfer ended with an error.
    pub fn has_error(&self) -> bool {
        unsafe {
            let ptr = ptr::addr_of!(STATE);
            (*ptr).as_ref().map(|s| s.has_error).unwrap_or(false)
        }
    }

    /// Get the total number of bytes received so far.
    pub fn bytes_received(&self) -> usize {
        unsafe {
            let ptr = ptr::addr_of!(STATE);
            (*ptr).as_ref().map(|s| s.bytes_received).unwrap_or(0)
        }
    }

    /// Clean up the TFTP client resources.
    pub fn cleanup(&mut self) {
        if self.initialized {
            unsafe {
                ffi::tftp_cleanup();
                STATE = None;
            }
            self.initialized = false;
        }
    }
}
