// Licensed under the Apache-2.0 license

//! SPDM device I/O transport abstraction.
//!
//! Provides a trait for pluggable MCTP transports and the `extern "C"` callback
//! bridge that libspdm invokes for sending/receiving messages.

use core::ffi::c_void;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Mutex;
use std::time::Duration;

use libspdm::libspdm_rs;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

/// Trait for pluggable SPDM device I/O backends.
///
/// Implementors provide the raw byte-level send/receive over the physical
/// transport (TCP socket, AF_MCTP, etc.).
pub trait SpdmDeviceIo: Send {
    fn send(&mut self, data: &[u8]) -> anyhow::Result<()>;
    fn receive(&mut self, buf: &mut [u8]) -> anyhow::Result<usize>;
}

// Global registry keyed by spdm_context pointer to support multiple contexts.
static DEVICE_IO_REGISTRY: Mutex<Option<HashMap<usize, Box<dyn SpdmDeviceIo>>>> = Mutex::new(None);

/// Register a device I/O backend for a given SPDM context.
pub(crate) fn register_device_io(context: *mut c_void, io: Box<dyn SpdmDeviceIo>) {
    let mut registry = DEVICE_IO_REGISTRY.lock().unwrap();
    let map = registry.get_or_insert_with(HashMap::new);
    map.insert(context as usize, io);
}

/// Unregister the device I/O backend for a given SPDM context.
pub(crate) fn unregister_device_io(context: *mut c_void) {
    let mut registry = DEVICE_IO_REGISTRY.lock().unwrap();
    if let Some(map) = registry.as_mut() {
        map.remove(&(context as usize));
    }
}

fn with_device_io<F, R>(context: *mut c_void, f: F) -> R
where
    F: FnOnce(&mut dyn SpdmDeviceIo) -> R,
{
    let mut registry = DEVICE_IO_REGISTRY.lock().unwrap();
    let map = registry
        .as_mut()
        .expect("Device IO registry not initialized");
    let io = map
        .get_mut(&(context as usize))
        .expect("No device IO registered for this context");
    f(io.as_mut())
}

/// C callback for libspdm to send messages.
///
/// # Safety
/// Called by libspdm with valid context and message buffer.
#[no_mangle]
unsafe extern "C" fn spdm_requester_send_message(
    context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    _timeout: u64,
) -> u32 {
    let msg = unsafe { from_raw_parts(message_ptr as *const u8, message_size) };
    match with_device_io(context, |io| io.send(msg)) {
        Ok(()) => 0,
        Err(e) => {
            log::error!("spdm send failed: {e}");
            1
        }
    }
}

/// C callback for libspdm to receive messages.
///
/// # Safety
/// Called by libspdm with valid context and buffer pointers.
#[no_mangle]
unsafe extern "C" fn spdm_requester_receive_message(
    context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let buf = unsafe { from_raw_parts_mut(*msg_buf_ptr as *mut u8, SEND_RECEIVE_BUFFER_LEN) };
    match with_device_io(context, |io| io.receive(buf)) {
        Ok(n) => {
            unsafe { *message_size = n };
            0
        }
        Err(e) => {
            log::error!("spdm receive failed: {e}");
            1
        }
    }
}

// --- IO buffer management ---
// libspdm requires acquire/release buffer callbacks for sender and receiver.
// These are process-global buffers (matching spdm-utils pattern).

static IO_SEND_BUFFER: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static IO_RECEIVE_BUFFER: Mutex<Option<Vec<u8>>> = Mutex::new(None);

#[no_mangle]
unsafe extern "C" fn spdm_acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let guard = IO_SEND_BUFFER.lock().unwrap();
    if let Some(ref buffer) = *guard {
        unsafe { *msg_buf_ptr = buffer.as_ptr() as *mut c_void };
        return 0;
    }
    log::error!("Sender buffer not initialized");
    1
}

#[no_mangle]
unsafe extern "C" fn spdm_release_sender_buffer(
    _context: *mut c_void,
    _msg_buf_ptr: *const c_void,
) {
    // No-op: we only pass references to heap-allocated memory.
}

#[no_mangle]
unsafe extern "C" fn spdm_acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let guard = IO_RECEIVE_BUFFER.lock().unwrap();
    if let Some(ref buffer) = *guard {
        unsafe { *msg_buf_ptr = buffer.as_ptr() as *mut c_void };
        return 0;
    }
    log::error!("Receiver buffer not initialized");
    1
}

#[no_mangle]
unsafe extern "C" fn spdm_release_receiver_buffer(
    _context: *mut c_void,
    _msg_buf_ptr: *const c_void,
) {
    // No-op: we only pass references to heap-allocated memory.
}

fn setup_io_buffers(context: *mut c_void, buffer_size: usize) -> anyhow::Result<()> {
    {
        let mut send = IO_SEND_BUFFER.lock().unwrap();
        *send = Some(vec![0u8; buffer_size]);
    }
    {
        let mut recv = IO_RECEIVE_BUFFER.lock().unwrap();
        *recv = Some(vec![0u8; buffer_size]);
    }

    unsafe {
        libspdm_rs::libspdm_register_device_buffer_func(
            context,
            buffer_size as u32,
            buffer_size as u32,
            Some(spdm_acquire_sender_buffer),
            Some(spdm_release_sender_buffer),
            Some(spdm_acquire_receiver_buffer),
            Some(spdm_release_receiver_buffer),
        );
    }
    Ok(())
}

/// Register the device I/O callbacks and IO buffers with libspdm.
///
/// # Safety
/// `context` must be a valid libspdm context pointer.
pub(crate) unsafe fn register_device_io_callbacks(context: *mut c_void) -> anyhow::Result<()> {
    unsafe {
        libspdm_rs::libspdm_register_device_io_func(
            context,
            Some(spdm_requester_send_message),
            Some(spdm_requester_receive_message),
        );
    }
    setup_io_buffers(context, SEND_RECEIVE_BUFFER_LEN)
}

// --- Concrete implementations ---

/// TCP socket-based SPDM device I/O (for emulator testing).
pub struct TcpSpdmDeviceIo {
    stream: TcpStream,
}

impl TcpSpdmDeviceIo {
    pub fn connect(addr: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self { stream })
    }
}

impl SpdmDeviceIo for TcpSpdmDeviceIo {
    fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.stream.write_all(data)?;
        self.stream.flush()?;
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let n = self.stream.read(buf)?;
        if n == 0 {
            return Err(anyhow::anyhow!("Connection closed"));
        }
        Ok(n)
    }
}

// --- Socket-framed SPDM Device I/O ---

/// Socket header length (command + transport_type + payload_size, all u32 BE).
const SOCKET_HEADER_LEN: usize = 12;
/// Normal SPDM message command.
const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x0001;
/// Stop command to terminate the bridge.
const SOCKET_SPDM_COMMAND_STOP: u32 = 0xFFFE;
/// Test/hello command for initial handshake.
const SOCKET_SPDM_COMMAND_TEST: u32 = 0xDEAD;
/// MCTP transport type identifier.
pub const SOCKET_TRANSPORT_TYPE_MCTP: u32 = 0x01;

/// Socket-framed SPDM device I/O for use with `SpdmValidatorRunner` bridge.
///
/// Each message is framed with a 12-byte header (matching the libspdm
/// emulator socket protocol used by `qemu_server` in spdm-utils):
///
/// ```text
/// [command: u32 BE | transport_type: u32 BE | payload_size: u32 BE] [payload...]
/// ```
pub struct SpdmSocketDeviceIo {
    stream: TcpStream,
    transport_type: u32,
}

impl SpdmSocketDeviceIo {
    /// Connect to the SPDM bridge socket with a specified transport type.
    pub fn connect(addr: &str, transport_type: u32) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream,
            transport_type,
        })
    }

    /// Connect using MCTP transport type.
    pub fn connect_mctp(addr: &str) -> anyhow::Result<Self> {
        Self::connect(addr, SOCKET_TRANSPORT_TYPE_MCTP)
    }

    /// Clone this device I/O handle (for sending STOP after the original is consumed).
    ///
    /// The cloned handle shares the same underlying TCP connection.
    pub fn try_clone(&self) -> anyhow::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            transport_type: self.transport_type,
        })
    }

    /// Perform the initial TEST/hello handshake with the bridge.
    ///
    /// Sends a TEST command with "Client Hello!" and expects a
    /// TEST response with "Server Hello!".
    pub fn handshake(&mut self) -> anyhow::Result<()> {
        let hello = b"Client Hello!\0";
        self.send_framed(SOCKET_SPDM_COMMAND_TEST, hello)?;

        let mut buf = [0u8; 64];
        let (command, size) = self.receive_framed(&mut buf)?;
        if command != SOCKET_SPDM_COMMAND_TEST {
            return Err(anyhow::anyhow!(
                "Expected TEST response, got command {:#x}",
                command
            ));
        }
        log::debug!(
            "Bridge handshake OK: {:?}",
            std::str::from_utf8(&buf[..size]).unwrap_or("<invalid utf8>")
        );
        Ok(())
    }

    /// Send the STOP command to gracefully shut down the bridge.
    pub fn send_stop(&mut self) -> anyhow::Result<()> {
        self.send_framed(SOCKET_SPDM_COMMAND_STOP, &[])
    }

    fn send_framed(&mut self, command: u32, payload: &[u8]) -> anyhow::Result<()> {
        let mut header = [0u8; SOCKET_HEADER_LEN];
        header[0..4].copy_from_slice(&command.to_be_bytes());
        header[4..8].copy_from_slice(&self.transport_type.to_be_bytes());
        header[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        self.stream.write_all(&header)?;
        if !payload.is_empty() {
            self.stream.write_all(payload)?;
        }
        self.stream.flush()?;
        Ok(())
    }

    fn receive_framed(&mut self, buf: &mut [u8]) -> anyhow::Result<(u32, usize)> {
        let mut header = [0u8; SOCKET_HEADER_LEN];
        self.stream.read_exact(&mut header)?;

        let command = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let payload_size =
            u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

        if payload_size == 0 {
            return Ok((command, 0));
        }

        if payload_size > buf.len() {
            return Err(anyhow::anyhow!(
                "Socket payload size ({}) exceeds buffer ({})",
                payload_size,
                buf.len()
            ));
        }

        self.stream.read_exact(&mut buf[..payload_size])?;
        Ok((command, payload_size))
    }
}

impl SpdmDeviceIo for SpdmSocketDeviceIo {
    fn send(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.send_framed(SOCKET_SPDM_COMMAND_NORMAL, data)
    }

    fn receive(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let (command, size) = self.receive_framed(buf)?;
        if command == SOCKET_SPDM_COMMAND_STOP {
            return Err(anyhow::anyhow!("Received STOP command from bridge"));
        }
        Ok(size)
    }
}
