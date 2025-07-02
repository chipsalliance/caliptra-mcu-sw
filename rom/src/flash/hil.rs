// Licensed under the Apache-2.0 license

//! Generic interface for flash storage access.

use core::result::Result;

/// Simple interface for reading, writing and erasing the arbitrary length of data on flash storage. It is expected
/// that drivers for the flash storage access would implement this trait.
pub trait FlashStorage {
    /// Read from the flash storage, filling the provided buffer with data
    fn read(&self, buffer: &mut [u8], address: usize) -> Result<(), FlashDrvError>;

    /// Write to the flash storage with the full contents of the buffer, starting at the specified address
    fn write(&self, buffer: &[u8], address: usize) -> Result<(), FlashDrvError>;

    /// Erase `length` bytes starting at address `address`. The address must be
    /// in the address space of the physical storage.
    fn erase(&self, address: usize, length: usize) -> Result<(), FlashDrvError>;

    /// Returns the size of the flash storage in bytes.
    fn capacity(&self) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum FlashDrvError {
    // Reserved value, for when "no error" / "success" should be
    // encoded in the same numeric representation as FlashDrvError
    //
    // Ok(()) = 0,
    /// Generic failure condition
    FAIL = 1,
    /// Underlying system is busy; retry
    BUSY = 2,
    /// The state requested is already set
    ALREADY = 3,
    /// The component is powered down
    OFF = 4,
    /// Reservation required before use
    RESERVE = 5,
    /// An invalid parameter was passed
    INVAL = 6,
    /// Parameter passed was too large
    SIZE = 7,
    /// Operation canceled by a call
    CANCEL = 8,
    /// Memory required not available
    NOMEM = 9,
    /// Operation is not supported
    NOSUPPORT = 10,
    /// Device is not available
    NODEVICE = 11,
    /// Device is not physically installed
    UNINSTALLED = 12,
    /// Packet transmission not acknowledged
    NOACK = 13,
}

impl From<FlashDrvError> for usize {
    fn from(err: FlashDrvError) -> usize {
        err as usize
    }
}

impl TryFrom<Result<(), FlashDrvError>> for FlashDrvError {
    type Error = ();

    fn try_from(rc: Result<(), FlashDrvError>) -> Result<Self, Self::Error> {
        match rc {
            Ok(()) => Err(()),
            Err(FlashDrvError::FAIL) => Ok(FlashDrvError::FAIL),
            Err(FlashDrvError::BUSY) => Ok(FlashDrvError::BUSY),
            Err(FlashDrvError::ALREADY) => Ok(FlashDrvError::ALREADY),
            Err(FlashDrvError::OFF) => Ok(FlashDrvError::OFF),
            Err(FlashDrvError::RESERVE) => Ok(FlashDrvError::RESERVE),
            Err(FlashDrvError::INVAL) => Ok(FlashDrvError::INVAL),
            Err(FlashDrvError::SIZE) => Ok(FlashDrvError::SIZE),
            Err(FlashDrvError::CANCEL) => Ok(FlashDrvError::CANCEL),
            Err(FlashDrvError::NOMEM) => Ok(FlashDrvError::NOMEM),
            Err(FlashDrvError::NOSUPPORT) => Ok(FlashDrvError::NOSUPPORT),
            Err(FlashDrvError::NODEVICE) => Ok(FlashDrvError::NODEVICE),
            Err(FlashDrvError::UNINSTALLED) => Ok(FlashDrvError::UNINSTALLED),
            Err(FlashDrvError::NOACK) => Ok(FlashDrvError::NOACK),
        }
    }
}

impl From<FlashDrvError> for Result<(), FlashDrvError> {
    fn from(ec: FlashDrvError) -> Self {
        match ec {
            FlashDrvError::FAIL => Err(FlashDrvError::FAIL),
            FlashDrvError::BUSY => Err(FlashDrvError::BUSY),
            FlashDrvError::ALREADY => Err(FlashDrvError::ALREADY),
            FlashDrvError::OFF => Err(FlashDrvError::OFF),
            FlashDrvError::RESERVE => Err(FlashDrvError::RESERVE),
            FlashDrvError::INVAL => Err(FlashDrvError::INVAL),
            FlashDrvError::SIZE => Err(FlashDrvError::SIZE),
            FlashDrvError::CANCEL => Err(FlashDrvError::CANCEL),
            FlashDrvError::NOMEM => Err(FlashDrvError::NOMEM),
            FlashDrvError::NOSUPPORT => Err(FlashDrvError::NOSUPPORT),
            FlashDrvError::NODEVICE => Err(FlashDrvError::NODEVICE),
            FlashDrvError::UNINSTALLED => Err(FlashDrvError::UNINSTALLED),
            FlashDrvError::NOACK => Err(FlashDrvError::NOACK),
        }
    }
}
