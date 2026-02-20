// Licensed under the Apache-2.0 license

//! Bare-metal TFTP client for lwIP (no alloc, no spin).
//!
//! Designed for single-threaded firmware on bare-metal RISC-V.
//! The caller provides callbacks to handle received data chunks,
//! enabling streaming verification without buffering the entire file.
//!
//! # Usage
//!
//! ```ignore
//! use lwip_rs::tftp_baremetal::{BaremetalTftpClient, BaremetalTftpOps};
//!
//! static mut TFTP: BaremetalTftpClient = BaremetalTftpClient::new();
//!
//! unsafe {
//!     TFTP.init(BaremetalTftpOps {
//!         write: my_write_callback,
//!         error: my_error_callback,
//!     }).unwrap();
//!     TFTP.get(server_ip, b"bootfile.bin\0").unwrap();
//!     // ... poll lwIP until is_complete() ...
//! }
//! ```

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::slice;

use crate::error::{check_err, LwipError, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;

const TFTP_PORT: u16 = 69;

/// Callbacks for bare-metal TFTP file handling.
///
/// These function pointers are called by lwIP during a TFTP transfer.
/// Since there is no heap, filenames and errors are passed as byte slices.
#[derive(Clone, Copy)]
pub struct BaremetalTftpOps {
    /// Called for each chunk of data received from the TFTP server.
    ///
    /// `data` contains the bytes for this chunk. Chunks arrive in order.
    /// Return `true` to continue the transfer, `false` to abort.
    pub write: fn(data: &[u8]) -> bool,

    /// Called when the TFTP server reports an error.
    ///
    /// `err` is the TFTP error code, `msg` is the error message (if any).
    pub error: fn(err: i32, msg: &[u8]),
}

/// Internal state for the bare-metal TFTP client.
///
/// Uses a simple sentinel pointer as the "file handle" since we don't need
/// actual file I/O — data is streamed to the write callback.
struct TftpState {
    ops: BaremetalTftpOps,
    bytes_received: usize,
    has_error: bool,
    complete: bool,
}

/// Sentinel value used as the TFTP "file handle".
///
/// lwIP requires a non-null handle from the open callback; we use the address
/// of this static as a dummy handle since we don't do actual file I/O.
static HANDLE_SENTINEL: u8 = 0xAA;

/// Global TFTP state. Safe because bare-metal is single-threaded.
static mut STATE: Option<TftpState> = None;

// ============================================================================
// extern "C" callbacks for lwIP TFTP
// ============================================================================

/// Open callback. lwIP calls this when starting a transfer.
/// For a GET (client download), `is_write` is 1 (server writes to us).
unsafe extern "C" fn tftp_open_cb(
    _fname: *const c_char,
    _mode: *const c_char,
    is_write: u8,
) -> *mut c_void {
    if is_write == 0 {
        // We only support receiving (GET), not sending (PUT)
        return ptr::null_mut();
    }

    if let Some(ref mut s) = STATE {
        s.bytes_received = 0;
        s.has_error = false;
        s.complete = false;
        // Return our sentinel as the "file handle"
        return (&HANDLE_SENTINEL as *const u8) as *mut c_void;
    }
    ptr::null_mut()
}

/// Close callback. lwIP calls this when the transfer is complete.
unsafe extern "C" fn tftp_close_cb(_handle: *mut c_void) {
    if let Some(ref mut s) = STATE {
        s.complete = true;
    }
}

/// Read callback. Not used for GET operations (we only download).
unsafe extern "C" fn tftp_read_cb(
    _handle: *mut c_void,
    _buf: *mut c_void,
    _bytes: c_int,
) -> c_int {
    -1
}

/// Write callback. lwIP calls this for each received data block.
/// The data arrives in a pbuf chain; we walk it and call the user's write callback.
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

/// Error callback. lwIP calls this when the server sends an error.
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

/// Static TFTP context struct — passed to `tftp_init_client`.
static TFTP_CONTEXT: ffi::tftp_context = ffi::tftp_context {
    open: Some(tftp_open_cb),
    close: Some(tftp_close_cb),
    read: Some(tftp_read_cb),
    write: Some(tftp_write_cb),
    error: Some(tftp_error_cb),
};

// ============================================================================
// Public API
// ============================================================================

/// Bare-metal TFTP client.
///
/// Place this in a `static mut` since lwIP's TFTP API uses global state.
/// Call `init()` to register callbacks, then `get()` to initiate a download.
pub struct BaremetalTftpClient {
    initialized: bool,
}

impl BaremetalTftpClient {
    /// Create an uninitialized TFTP client.
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the TFTP client and register it with lwIP.
    ///
    /// Must be called after `lwip_rs::init()`.
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

    /// Initiate a TFTP GET request.
    ///
    /// `server` is the TFTP server IPv4 address.
    /// `filename` must be a null-terminated byte string (e.g., `b"boot.bin\0"`).
    ///
    /// After calling this, poll lwIP (via `netif.poll()`) until `is_complete()`
    /// returns true.
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

        // Build server address
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
