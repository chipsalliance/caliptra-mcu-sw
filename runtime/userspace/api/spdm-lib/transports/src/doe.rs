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
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalIoKind, SpdmPalTransport};

use crate::errors::doe as error_code;

/// DOE header size in bytes.
const DOE_HEADER_SIZE: usize = 8;

/// PCI-SIG vendor ID for DOE SPDM objects.
const DOE_PCI_SIG_VENDOR_ID: u16 = 0x0001;

/// Data object type for plain SPDM.
const DOE_TYPE_SPDM: u8 = 1;

/// Data object type for SPDM Secured Messages.
const DOE_TYPE_SECURE_SPDM: u8 = 2;

/// Default SPDM `DataTransferSize` (payload bytes) when a caller uses
/// [`McuSpdmDoeTransport::new`]. This is a transport convenience default,
/// **not** a profile policy: an OCP NVMe integration selects a larger value
/// (e.g. 4 KiB) via [`McuSpdmDoeTransport::with_transfer_size`] and validates
/// the OCP minimum once at initialization (the transport itself carries no OCP
/// rule). The generic default is kept small so a stock integration uses a
/// modest transfer buffer and chunks larger messages.
const DEFAULT_TRANSFER_SIZE: usize = 1024;

/// PCIe DOE-based SPDM PAL transport.
///
/// Wraps a single [`Doe`] syscall handle. Unlike MCTP, DOE supports
/// both plain SPDM and Secured SPDM on the same transport — the
/// `data_object_type` field in the header distinguishes them.
pub struct McuSpdmDoeTransport {
    doe: Doe,
    /// Integrator-configured SPDM `DataTransferSize` in payload bytes,
    /// reported by [`mtu`](SpdmPalTransport::mtu) after bounding by the
    /// driver-reported capacity.
    transfer_size: usize,
}

impl McuSpdmDoeTransport {
    /// Creates a DOE transport bound to the given driver number, using the
    /// [`DEFAULT_TRANSFER_SIZE`] `DataTransferSize`.
    ///
    /// Use [`driver_num::DOE_SPDM`] for the standard DOE SPDM driver.
    pub fn new(driver_num: u32) -> Self {
        Self::with_transfer_size(driver_num, DEFAULT_TRANSFER_SIZE)
    }

    /// Creates a DOE transport with an integrator-chosen `DataTransferSize`.
    ///
    /// `transfer_size` is the SPDM payload size (excluding the DOE header)
    /// this transport advertises; [`mtu`](SpdmPalTransport::mtu) bounds it by
    /// the driver-reported message capacity. Callers that must satisfy a
    /// profile minimum (e.g. OCP NVMe v2.7's 4 KiB `DataTransferSize`) select
    /// it here and validate the resulting `mtu()` once at initialization.
    pub fn with_transfer_size(driver_num: u32, transfer_size: usize) -> Self {
        Self {
            doe: Doe::new(driver_num),
            transfer_size,
        }
    }

    /// Returns true if the DOE driver is available on this platform.
    pub fn exists(&self) -> bool {
        self.doe.exists()
    }
}

/// Bounds the configured `transfer_size` by the driver-reported message
/// capacity, reserving the DOE header.
///
/// Returns the SPDM payload MTU: `min(transfer_size, driver_max - header)`.
/// A driver that reports 0 or a too-small `max_message_size` yields a smaller
/// (possibly 0) MTU rather than panicking — the integrator is responsible for
/// enforcing any profile minimum against the reported `mtu()` at init.
pub(crate) fn bound_mtu(driver_max: usize, transfer_size: usize) -> usize {
    transfer_size.min(driver_max.saturating_sub(DOE_HEADER_SIZE))
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

    /// Reports the SPDM payload `DataTransferSize`: the integrator-configured
    /// `transfer_size` bounded by the driver-reported message capacity (less
    /// the DOE header). The stack advertises `MaxSPDMmsgSize` independently and
    /// chunks messages larger than this MTU via CHUNK_SEND/CHUNK_GET, so a
    /// smaller transfer buffer is a valid integration. Any profile minimum
    /// (e.g. OCP 2.7 SPDM-14's 4 KiB) is enforced by the integrator against
    /// this value at init — the transport never panics on a small driver MTU.
    fn mtu(&self) -> usize {
        let max = self.doe.max_message_size().unwrap_or(0) as usize;
        bound_mtu(max, self.transfer_size)
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
    let Some(hdr) = buf.first_chunk_mut::<8>() else {
        return;
    };
    // bytes 0..1: vendor_id (LE)
    hdr[0..2].copy_from_slice(&DOE_PCI_SIG_VENDOR_ID.to_le_bytes());
    // byte 2: data_object_type
    hdr[2] = data_object_type;
    // byte 3: reserved
    hdr[3] = 0;
    // bytes 4..7: length in DWORDs (18 bits, LE) + reserved (14 bits)
    // Low 18 bits = length_dw, upper 14 bits = 0
    let length_field = length_dw & 0x0003_FFFF;
    hdr[4..8].copy_from_slice(&length_field.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::{bound_mtu, DOE_HEADER_SIZE};

    #[test]
    fn small_driver_max_does_not_panic() {
        // A driver reporting far below the configured transfer size must yield
        // a smaller MTU, never a release panic (the regression this fixes).
        assert_eq!(bound_mtu(64, 4096), 64 - DOE_HEADER_SIZE);
    }

    #[test]
    fn failed_syscall_max_is_zero() {
        // max_message_size() error -> unwrap_or(0) -> mtu 0, no underflow panic.
        assert_eq!(bound_mtu(0, 4096), 0);
    }

    #[test]
    fn configured_transfer_size_caps_large_driver_max() {
        assert_eq!(bound_mtu(65536, 4096), 4096);
    }

    #[test]
    fn exact_floor_reports_full_transfer_size() {
        assert_eq!(bound_mtu(4096 + DOE_HEADER_SIZE, 4096), 4096);
    }
}
