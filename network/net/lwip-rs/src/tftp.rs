// Licensed under the Apache-2.0 license

//! TFTP client wrapper (no_std compatible)
//!
//! Users must provide storage callbacks to handle file I/O operations.

use alloc::ffi::CString;
use alloc::string::String;
use spin::Mutex;

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use core::slice;

use crate::error::{check_err, LwipError, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;

const TFTP_PORT: u16 = 69;
const TFTP_MODE_OCTET: u32 = 0;

/// Storage operations for TFTP file handling.
/// Implement these callbacks to handle file transfers in your environment.
#[derive(Clone, Copy)]
pub struct TftpStorageOps {
    /// Open a file for writing. Returns opaque handle (non-null on success).
    pub open: fn(filename: &str) -> *mut c_void,
    /// Write data to file. Returns true on success.
    pub write: fn(handle: *mut c_void, data: &[u8]) -> bool,
    /// Close the file.
    pub close: fn(handle: *mut c_void),
}

struct TftpState {
    ops: TftpStorageOps,
    handle: *mut c_void,
    bytes_received: usize,
    error: Option<(i32, String)>,
    complete: bool,
}

unsafe impl Send for TftpState {}

static TFTP_STATE: Mutex<Option<TftpState>> = Mutex::new(None);

extern "C" fn tftp_open_callback(
    fname: *const c_char,
    _mode: *const c_char,
    is_write: u8,
) -> *mut c_void {
    if is_write == 0 {
        return ptr::null_mut();
    }

    let filename = if fname.is_null() {
        return ptr::null_mut();
    } else {
        match unsafe { CStr::from_ptr(fname).to_str() } {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let mut state = TFTP_STATE.lock();
    if let Some(ref mut s) = *state {
        let handle = (s.ops.open)(filename);
        if !handle.is_null() {
            s.handle = handle;
            s.bytes_received = 0;
            s.error = None;
            s.complete = false;
            return handle;
        }
    }
    ptr::null_mut()
}

extern "C" fn tftp_close_callback(handle: *mut c_void) {
    let mut state = TFTP_STATE.lock();
    if let Some(ref mut s) = *state {
        if !s.handle.is_null() {
            (s.ops.close)(handle);
            s.handle = ptr::null_mut();
        }
        s.complete = true;
    }
}

extern "C" fn tftp_read_callback(_handle: *mut c_void, _buf: *mut c_void, _bytes: c_int) -> c_int {
    -1
}

extern "C" fn tftp_write_callback(_handle: *mut c_void, p: *mut ffi::pbuf) -> c_int {
    let mut state = TFTP_STATE.lock();
    if let Some(ref mut s) = *state {
        if s.handle.is_null() {
            return -1;
        }

        let mut current = p;
        while !current.is_null() {
            let (payload, len, next) = unsafe {
                let pbuf_ref = &*current;
                (pbuf_ref.payload, pbuf_ref.len, pbuf_ref.next)
            };

            let data = unsafe { slice::from_raw_parts(payload as *const u8, len as usize) };

            if !(s.ops.write)(s.handle, data) {
                return -1;
            }
            s.bytes_received += data.len();
            current = next;
        }
        return 0;
    }
    -1
}

extern "C" fn tftp_error_callback(
    _handle: *mut c_void,
    err: c_int,
    msg: *const c_char,
    size: c_int,
) {
    let error_msg = if msg.is_null() || size <= 0 {
        String::new()
    } else {
        let data = unsafe { slice::from_raw_parts(msg as *const u8, size as usize) };
        String::from_utf8_lossy(data).into_owned()
    };

    let mut state = TFTP_STATE.lock();
    if let Some(ref mut s) = *state {
        s.error = Some((err, error_msg));
        s.complete = true;
    }
}

static TFTP_CONTEXT: ffi::tftp_context = ffi::tftp_context {
    open: Some(tftp_open_callback),
    close: Some(tftp_close_callback),
    read: Some(tftp_read_callback),
    write: Some(tftp_write_callback),
    error: Some(tftp_error_callback),
};

/// TFTP client for downloading files
pub struct TftpClient {
    initialized: bool,
}

impl TftpClient {
    pub fn new(ops: &TftpStorageOps) -> Result<Self> {
        {
            let mut state = TFTP_STATE.lock();
            *state = Some(TftpState {
                ops: *ops,
                handle: ptr::null_mut(),
                bytes_received: 0,
                error: None,
                complete: false,
            });
        }

        let err = unsafe { ffi::tftp_init_client(&TFTP_CONTEXT) };
        check_err(err)?;

        Ok(TftpClient { initialized: true })
    }

    /// Initiate a TFTP GET request. Use is_complete() to check when done.
    pub fn get(&mut self, server: Ipv4Addr, filename: &str) -> Result<()> {
        {
            let mut state = TFTP_STATE.lock();
            if let Some(ref mut s) = *state {
                s.handle = ptr::null_mut();
                s.bytes_received = 0;
                s.error = None;
                s.complete = false;
            }
        }

        let c_filename = CString::new(filename).map_err(|_| LwipError::IllegalArgument)?;
        let c_mode = CString::new("octet").map_err(|_| LwipError::IllegalArgument)?;

        let handle = tftp_open_callback(c_filename.as_ptr(), c_mode.as_ptr(), 1);
        if handle.is_null() {
            return Err(LwipError::OutOfMemory);
        }

        let mut server_addr: ffi::ip_addr_t = unsafe { core::mem::zeroed() };
        server_addr.u_addr.ip4 = server.0;
        server_addr.type_ = 0;

        let err = unsafe {
            ffi::tftp_get(
                handle,
                &server_addr,
                TFTP_PORT,
                c_filename.as_ptr(),
                TFTP_MODE_OCTET,
            )
        };

        if err != 0 {
            tftp_close_callback(handle);
        }

        check_err(err)
    }

    pub fn is_complete(&self) -> bool {
        let state = TFTP_STATE.lock();
        state.as_ref().map(|s| s.complete).unwrap_or(false)
    }

    pub fn has_error(&self) -> bool {
        let state = TFTP_STATE.lock();
        state.as_ref().map(|s| s.error.is_some()).unwrap_or(false)
    }

    pub fn error(&self) -> Option<(i32, String)> {
        let state = TFTP_STATE.lock();
        state.as_ref().and_then(|s| s.error.clone())
    }

    pub fn bytes_received(&self) -> usize {
        let state = TFTP_STATE.lock();
        state.as_ref().map(|s| s.bytes_received).unwrap_or(0)
    }
}

impl Drop for TftpClient {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                ffi::tftp_cleanup();
            }
            let mut state = TFTP_STATE.lock();
            *state = None;
        }
    }
}
