// Licensed under the Apache-2.0 license

//! Shared large message buffer for SPDM responders.
//!
//! MCTP and DOE responders share a single static buffer for large message
//! operations (CHUNK_SEND reassembly and CHUNK_GET response chunking).

use caliptra_mcu_spdm_lib::chunk_ctx::LargeMsgBufProvider;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use static_cell::StaticCell;

/// Buffer size for large SPDM messages.
/// TODO: Increase to ~14 KB for ML-DSA support.
pub const LARGE_MSG_BUF_SIZE: usize = 4096;

/// Backing storage (allocated once in `.bss`).
static LARGE_MSG_BUF_STORAGE: StaticCell<[u8; LARGE_MSG_BUF_SIZE]> = StaticCell::new();

/// Holds the buffer when it is not checked out by a responder.
/// `Some(buf)` = available, `None` = in use by a responder.
static SHARED_BUF: Mutex<CriticalSectionRawMutex, core::cell::RefCell<Option<&'static mut [u8]>>> =
    Mutex::new(core::cell::RefCell::new(None));

/// Initialize the shared buffer. Must be called once before spawning responders.
pub fn init() {
    let buf = LARGE_MSG_BUF_STORAGE.init([0u8; LARGE_MSG_BUF_SIZE]);
    SHARED_BUF.lock(|cell| {
        *cell.borrow_mut() = Some(buf);
    });
}

/// Zero-size wrapper that implements `LargeMsgBufProvider` by delegating
/// to the module-level static mutex. Follows the same pattern as `SharedCertStore`.
pub struct SharedLargeMsgBuf;

impl SharedLargeMsgBuf {
    pub fn new() -> Self {
        Self
    }
}

impl LargeMsgBufProvider for SharedLargeMsgBuf {
    fn acquire(&self) -> Option<&'static mut [u8]> {
        SHARED_BUF.lock(|cell| cell.borrow_mut().take())
    }

    fn release(&self, buf: &'static mut [u8]) {
        SHARED_BUF.lock(|cell| {
            *cell.borrow_mut() = Some(buf);
        });
    }

    fn capacity(&self) -> usize {
        LARGE_MSG_BUF_SIZE
    }
}
