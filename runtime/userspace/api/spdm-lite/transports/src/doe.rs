// Licensed under the Apache-2.0 license

//! PCIe DOE (Data Object Exchange) transport for SPDM-Lite.
//!
//! Implements [`SpdmPalTransport`] over the MCU DOE syscall driver.
//!
//! # Wire format
//!
//! Each DOE data object has an 8-byte header:
//!
//! ```text
//!  bytes 0..1     byte 2            byte 3     bytes 4..7
//! ┌──────────────┬─────────────────┬──────────┬─────────────────────┐
//! │  vendor_id   │ data_object_type│ reserved │ length (DWORDs)     │
//! │  (LE u16)    │     (u8)        │          │ (18 bits, LE)       │
//! └──────────────┴─────────────────┴──────────┴─────────────────────┘
//! ```
//!
//! * `vendor_id` — `0x0001` (PCI-SIG)
//! * `data_object_type` — `1` = DOE SPDM, `2` = DOE Secure SPDM
//! * `length` — total data object size in DWORDs (including header)
//!
//! SPDM payload follows the header directly. On send, the payload is
//! padded to 4-byte (DWORD) alignment.

extern crate alloc;

use alloc::boxed::Box;

use async_trait::async_trait;
use caliptra_mcu_libsyscall_caliptra::doe::{driver_num, Doe};
use mcu_spdm_lite_traits::{McuResult, SpdmPalIoKind, SpdmPalTransport};

use crate::errors::doe as error_code;

/// DOE header size in bytes.
const DOE_HEADER_SIZE: usize = 8;

/// PCI-SIG vendor ID for DOE SPDM objects.
const DOE_PCI_SIG_VENDOR_ID: u16 = 0x0001;

/// Data object type for plain SPDM.
const DOE_TYPE_SPDM: u8 = 1;

/// Data object type for SPDM Secured Messages.
const DOE_TYPE_SECURE_SPDM: u8 = 2;

/// PCIe DOE-based SPDM PAL transport.
///
/// Wraps a single [`Doe`] syscall handle. Unlike MCTP, DOE supports
/// both plain SPDM and Secured SPDM on the same transport — the
/// `data_object_type` field in the header distinguishes them.
pub struct McuSpdmDoeTransport {
    doe: Doe,
}

impl McuSpdmDoeTransport {
    /// Creates a DOE transport bound to the given driver number.
    ///
    /// Use [`driver_num::DOE_SPDM`] for the standard DOE SPDM driver.
    pub fn new(driver_num: u32) -> Self {
        Self {
            doe: Doe::new(driver_num),
        }
    }

    /// Returns true if the DOE driver is available on this platform.
    pub fn exists(&self) -> bool {
        self.doe.exists()
    }
}

impl Default for McuSpdmDoeTransport {
    fn default() -> Self {
        Self::new(driver_num::DOE_SPDM)
    }
}

#[async_trait]
impl SpdmPalTransport for McuSpdmDoeTransport {
    fn secure_message_supported(&self) -> bool {
        true // DOE carries both plain and secured on same transport
    }

    fn mtu(&self) -> usize {
        let max = self.doe.max_message_size().unwrap_or(0) as usize;
        // Cap to the SPDM responder buffer size — same as spdm-lib's
        // MAX_SPDM_RESPONDER_BUF_SIZE. The PAL allocates header+mtu
        // from the BitmapAllocator per exchange.
        const MAX_SPDM_MTU: usize = 1024;
        max.saturating_sub(DOE_HEADER_SIZE).min(MAX_SPDM_MTU)
    }

    fn header_size(&self) -> usize {
        DOE_HEADER_SIZE
    }

    fn send_len_alignment(&self) -> usize {
        4 // DOE data objects must be DWORD-aligned
    }

    async fn recv_request(&mut self, buf: &mut [u8]) -> McuResult<(SpdmPalIoKind, usize)> {
        if buf.len() < DOE_HEADER_SIZE {
            return Err(error_code::BUFFER_TOO_SMALL);
        }

        let recv_len = self.doe.receive_message(buf).await? as usize;

        if recv_len < DOE_HEADER_SIZE || recv_len > buf.len() {
            return Err(error_code::INVALID_MESSAGE);
        }

        // Parse DOE header (little-endian)
        let vendor_id = u16::from_le_bytes([buf[0], buf[1]]);
        let data_object_type = buf[2];

        if vendor_id != DOE_PCI_SIG_VENDOR_ID {
            return Err(error_code::INVALID_MESSAGE);
        }

        let kind = match data_object_type {
            DOE_TYPE_SPDM => SpdmPalIoKind::Message,
            DOE_TYPE_SECURE_SPDM => SpdmPalIoKind::SecuredMessage,
            _ => return Err(error_code::UNEXPECTED_OBJECT_TYPE),
        };

        Ok((kind, recv_len))
    }

    async fn send_response(&mut self, kind: SpdmPalIoKind, msg: &mut [u8]) -> McuResult<()> {
        if msg.len() < DOE_HEADER_SIZE {
            return Err(error_code::INVALID_MESSAGE);
        }

        let data_object_type = match kind {
            SpdmPalIoKind::Message => DOE_TYPE_SPDM,
            SpdmPalIoKind::SecuredMessage => DOE_TYPE_SECURE_SPDM,
        };

        // Length in DWORDs — build_response pads to DWORD alignment.
        let length_dw = msg.len() / 4;

        // Write DOE header in-place
        buf_write_doe_header(msg, data_object_type, length_dw as u32);

        self.doe.send_message(msg).await?;
        Ok(())
    }
}

/// Write DOE header into the first 8 bytes of `buf`.
fn buf_write_doe_header(buf: &mut [u8], data_object_type: u8, length_dw: u32) {
    // bytes 0..1: vendor_id (LE)
    buf[0..2].copy_from_slice(&DOE_PCI_SIG_VENDOR_ID.to_le_bytes());
    // byte 2: data_object_type
    buf[2] = data_object_type;
    // byte 3: reserved
    buf[3] = 0;
    // bytes 4..7: length in DWORDs (18 bits, LE) + reserved (14 bits)
    // Low 18 bits = length_dw, upper 14 bits = 0
    let length_field = length_dw & 0x0003_FFFF;
    buf[4..8].copy_from_slice(&length_field.to_le_bytes());
}
