// Licensed under the Apache-2.0 license

//! USB device driver trait for OCP Recovery over EP0.
//!
//! Provides a recovery-command-level abstraction for embedded ROM firmware.
//! Implementors handle all hardware setup, buffer management, USB
//! enumeration, and protocol details internally.

use crate::error::OcpError;
use crate::protocol::RecoveryCommand;

/// Errors from USB driver operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UsbDriverError {
    /// No OCP recovery command pending (non-blocking poll returned empty).
    NoPendingCommand = Self::NO_PENDING_COMMAND,
    /// The provided buffer is too small for the received data.
    BufferTooSmall = Self::BUFFER_TOO_SMALL,
    /// The payload exceeds the maximum transfer size declared in the functional descriptor.
    TransferTooLarge = Self::TRANSFER_TOO_LARGE,
    /// A previous [`RecoveryRequest::Read`] was not completed with
    /// [`UsbDeviceDriver::send`] or [`UsbDeviceDriver::stall_endpoint`]
    /// before the next [`UsbDeviceDriver::recv`] call.
    SendRequired = Self::SEND_REQUIRED,
    /// [`UsbDeviceDriver::send`] or [`UsbDeviceDriver::stall_endpoint`]
    /// was called without a preceding [`RecoveryRequest::Read`] from
    /// [`UsbDeviceDriver::recv`].
    NoPendingRead = Self::NO_PENDING_READ,
    /// Hardware-level error (timeout, CRC, bit-stuffing, etc.).
    HardwareError = Self::HARDWARE_ERROR,
    /// The closure passed to [`UsbDeviceDriver::send`] returned an
    /// [`OcpError`] while populating the response buffer.
    OcpError(OcpError) = Self::OCP_ERROR,
}

impl UsbDriverError {
    const NO_PENDING_COMMAND: u8 = 0;
    const BUFFER_TOO_SMALL: u8 = 1;
    const TRANSFER_TOO_LARGE: u8 = 2;
    const SEND_REQUIRED: u8 = 3;
    const NO_PENDING_READ: u8 = 4;
    const HARDWARE_ERROR: u8 = 5;
    const OCP_ERROR: u8 = 6;
}

impl From<UsbDriverError> for u8 {
    fn from(e: UsbDriverError) -> u8 {
        match e {
            UsbDriverError::NoPendingCommand => UsbDriverError::NO_PENDING_COMMAND,
            UsbDriverError::BufferTooSmall => UsbDriverError::BUFFER_TOO_SMALL,
            UsbDriverError::TransferTooLarge => UsbDriverError::TRANSFER_TOO_LARGE,
            UsbDriverError::SendRequired => UsbDriverError::SEND_REQUIRED,
            UsbDriverError::NoPendingRead => UsbDriverError::NO_PENDING_READ,
            UsbDriverError::HardwareError => UsbDriverError::HARDWARE_ERROR,
            UsbDriverError::OcpError(_) => UsbDriverError::OCP_ERROR,
        }
    }
}

/// The transfer direction and associated payload for an OCP recovery command.
///
/// Paired with a [`RecoveryCommand`] by [`UsbDeviceDriver::recv`].
#[derive(Debug)]
pub enum RecoveryRequest<'a> {
    /// Host is reading from the device.
    ///
    /// `len` is the requested byte count (from `wLength`). The caller
    /// should respond with [`UsbDeviceDriver::send`] or
    /// [`UsbDeviceDriver::stall_endpoint`].
    Read { len: u16 },

    /// Host wrote data to the device.
    ///
    /// `data` contains the received payload. The IN status stage has
    /// already been completed by the driver.
    Write { data: &'a [u8] },
}

/// OCP Recovery USB device driver.
///
/// Operates at the recovery-command level. Implementors handle all
/// register, buffer, FIFO, and USB protocol details internally.
///
/// # Initialization
///
/// [`init`](Self::init) performs hardware configuration and completes
/// the full USB bus enumeration sequence -- bus reset, descriptor
/// exchanges, `SET_ADDRESS`, `SET_CONFIGURATION`. On success the device
/// is in the USB Configured state and ready for OCP recovery commands.
///
/// # Post-Enumeration Usage
///
/// ```text
/// loop {
///     let (cmd, req) = driver.recv()?;
///     match (cmd, req) {
///         (ProtCap, Read { .. }) => driver.send(&mut |buf| {
///             buf[..prot_cap.len()].copy_from_slice(&prot_cap);
///             Ok(prot_cap.len())
///         })?,
///         (RecoveryCtrl, Write { data })  => process(data),
///         (_, Read { .. })               => driver.stall_endpoint()?,
///         (_, Write { .. })              => { /* unsupported, already acked */ },
///     }
/// }
/// ```
///
/// Any post-enumeration standard USB requests (e.g. re-enumeration)
/// are handled internally by [`recv`](Self::recv) and never surfaced
/// to the caller.
pub trait UsbDeviceDriver {
    /// Initialize USB hardware and complete bus enumeration.
    ///
    /// Drives the full sequence to reach the USB Configured state:
    ///
    /// 1. Configure PHY, enable EP0, supply receive buffers.
    /// 2. Assert the D+ pull-up (device becomes visible to the host).
    /// 3. Handle the host-initiated bus reset.
    /// 4. Respond to all standard enumeration requests including
    ///    `SET_ADDRESS` and `SET_CONFIGURATION`.
    ///
    /// On success the device is fully enumerated and the caller may
    /// begin calling [`recv`](Self::recv) immediately.
    fn init(&mut self) -> Result<(), UsbDriverError>;

    /// Poll for the next OCP recovery command (non-blocking).
    ///
    /// Returns `(RecoveryCommand, RecoveryRequest)` when an OCP command
    /// has been received, or `Err(UsbDriverError::NoPendingCommand)`
    /// when the receive FIFO is empty.
    ///
    /// For **write** commands the driver completes the entire USB
    /// control transfer (SETUP + OUT data + IN status ZLP) before
    /// returning, so the caller receives the data ready to process.
    ///
    /// For **read** commands the driver reads the SETUP packet and
    /// returns immediately -- the caller must follow up with
    /// [`send`](Self::send) or [`stall_endpoint`](Self::stall_endpoint)
    /// before calling `recv` again.  Calling `recv` while a read
    /// response is still outstanding returns
    /// [`UsbDriverError::SendRequired`].
    ///
    /// Standard USB requests arriving after enumeration are handled
    /// and stalled internally; only OCP recovery commands are surfaced.
    fn recv(&mut self) -> Result<(RecoveryCommand, RecoveryRequest<'_>), UsbDriverError>;

    /// Send response data to the host (for read commands).
    ///
    /// Must be called exactly once after [`recv`](Self::recv) returns a
    /// [`RecoveryRequest::Read`].  The driver provides an internal
    /// buffer to `populate_buffer`; the closure writes response data
    /// into the buffer and returns the number of bytes written.  The
    /// driver then handles multi-packet segmentation for payloads
    /// exceeding the 64-byte max packet size.  When the response is
    /// shorter than the `wLength` requested by the host and the last
    /// data packet is exactly `MaxPacketSize`, a zero-length packet is
    /// appended to signal end-of-data per USB 2.0 §5.5.3.  The OUT
    /// status stage is completed before returning.
    fn send(
        &mut self,
        populate_buffer: &mut dyn FnMut(&mut [u8]) -> Result<usize, OcpError>,
    ) -> Result<(), UsbDriverError>;

    /// Stall EP0 to reject a read command the device does not support.
    ///
    /// Must be called exactly once after [`recv`](Self::recv) returns a
    /// [`RecoveryRequest::Read`] that the device cannot service.
    /// Clears the pending read state so that [`recv`](Self::recv) may
    /// be called again.  Hardware automatically clears the stall
    /// condition when the next SETUP packet arrives.
    fn stall_endpoint(&mut self) -> Result<(), UsbDriverError>;
}
