// Licensed under the Apache-2.0 license

//! MCTP-based SPDM transport for MCU userspace.
//!
//! This module provides [`McuMctpTransport`], an implementation of the
//! [`SpdmPalTransport`] trait that carries SPDM traffic over the MCTP
//! (Management Component Transport Protocol) syscall driver exposed by
//! the MCU Tock kernel.
//!
//! # Wire format
//!
//! Each MCTP message exchanged with the peer is prefixed by a single
//! "MCTP transport message header" byte. The byte is bit-packed as
//! follows (high bit first):
//!
//! ```text
//!  bit 7         bits 6..0
//! ┌──────┬───────────────────────────┐
//! │  IC  │       message type        │
//! └──────┴───────────────────────────┘
//! ```
//!
//! * `IC`  — Integrity Check bit (always `0` for this transport).
//! * `message type` — A 7-bit MCTP message type. For SPDM this is
//!   `0x05`; the value used on the wire is whatever
//!   [`Mctp::msg_type`](caliptra_mcu_libsyscall_caliptra::mctp::Mctp::msg_type)
//!   returns for the bound driver number.
//!
//! On receive, the transport validates the header byte, captures the
//! source endpoint / tag in a [`MessageInfo`], strips the header, and
//! hands the caller only the SPDM payload. On send, it prepends the
//! header byte to the caller-supplied payload before handing the bytes
//! to the MCTP driver.
//!
//! # Request / response correlation
//!
//! Between [`SpdmPalTransport::recv_request`] and the matching
//! [`SpdmPalTransport::send_response`], the transport caches the
//! [`MessageInfo`] returned by the MCTP driver. Calling `send_response`
//! without a prior `recv_request` returns
//! [`error_code::NO_REQUEST_IN_FLIGHT`].
//!
//! # Secured messages
//!
//! A single MCTP driver handle is bound to a single MCTP message type,
//! so this transport cannot multiplex plain SPDM (`0x05`) and SPDM
//! Secured Messages (`0x06`) on its own. Accordingly,
//! [`SpdmPalTransport::secure_message_supported`] returns `false` and
//! calling `send_response` with `secure = true` returns
//! [`error_code::OPERATION_NOT_SUPPORTED`].
//!
//! Higher layers that need both transports can instantiate two
//! [`McuMctpTransport`] objects bound to the corresponding driver
//! numbers and route between them.
//!
//! This implementation operates on raw byte buffers as required by the
//! SPDM-Lite PAL trait.

extern crate alloc;

use alloc::boxed::Box;

use async_trait::async_trait;
use caliptra_mcu_libsyscall_caliptra::mctp::{driver_num, Mctp, MessageInfo};
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalIoKind, SpdmPalTransport};

/// MCTP transport message header size in bytes.
const MCTP_MSG_HEADER_SIZE: usize = 1;

/// Bit mask for the MCTP message type field in the transport header.
const MCTP_MSG_TYPE_MASK: u8 = 0x7F;

/// MCTP message-type byte for an MCTP-framed plain SPDM message.
pub const MCTP_MSG_TYPE_SPDM: u8 = 0x05;
/// MCTP message-type byte for an MCTP-framed SPDM Secured Message.
pub const MCTP_MSG_TYPE_SECURED_SPDM: u8 = 0x06;

// Error codes for this transport live in [`crate::errors::mctp`];
// internally we alias the module so existing call sites keep working.
use crate::errors::mctp as error_code;

/// MCTP-based SPDM PAL transport.
///
/// Wraps a single [`Mctp`] syscall handle bound to a specific driver
/// number (e.g.,
/// [`MCTP_SPDM`](caliptra_mcu_libsyscall_caliptra::mctp::driver_num::MCTP_SPDM)).
/// Each `recv_request` / `send_response` pair is correlated by the
/// [`MessageInfo`] captured on receive and stored in
/// [`cur_resp_ctx`](Self::cur_resp_ctx).
pub struct McuSpdmMctpTransport {
    mctp: Mctp,
    cur_resp_ctx: Option<MessageInfo>,
    /// MCTP message-type byte this transport is bound to (`0x05`
    /// for plain SPDM, `0x06` for Secured SPDM). Set by [`new`] from
    /// the caller-supplied `msg_type`, after validating it against
    /// `driver_num`.
    msg_type: u8,
}

impl McuSpdmMctpTransport {
    /// Creates an MCTP transport bound to `driver_num` and configured
    /// to send/receive frames with MCTP message-type `msg_type`.
    ///
    /// `msg_type` must be one of:
    /// * [`MCTP_MSG_TYPE_SPDM`] (`0x05`) — plain SPDM, on
    ///   [`driver_num::MCTP_SPDM`].
    /// * [`MCTP_MSG_TYPE_SECURED_SPDM`] (`0x06`) — SPDM Secured
    ///   Message, on [`driver_num::MCTP_SECURE`].
    ///
    /// # Errors
    ///
    /// Returns [`error_code::UNEXPECTED_MESSAGE_TYPE`] if `msg_type`
    /// is unknown, or if it does not match the message type the MCTP
    /// driver bound to `driver_num` will actually emit on the wire
    /// (e.g. `MCTP_SPDM` driver with `msg_type = 0x06`).
    pub fn new(driver_num: u32, msg_type: u8) -> McuResult<Self> {
        // Reject anything other than the two SPDM-related message types.
        if msg_type != MCTP_MSG_TYPE_SPDM && msg_type != MCTP_MSG_TYPE_SECURED_SPDM {
            return Err(error_code::UNEXPECTED_MESSAGE_TYPE);
        }

        // Reject driver/msg_type pairings the kernel won't accept.
        let expected_driver = match msg_type {
            MCTP_MSG_TYPE_SPDM => driver_num::MCTP_SPDM,
            MCTP_MSG_TYPE_SECURED_SPDM => driver_num::MCTP_SECURE,
            _ => return Err(error_code::UNEXPECTED_MESSAGE_TYPE),
        };
        if driver_num != expected_driver {
            return Err(error_code::UNEXPECTED_MESSAGE_TYPE);
        }

        Ok(Self {
            mctp: Mctp::new(driver_num),
            cur_resp_ctx: None,
            msg_type,
        })
    }

    /// Returns the [`SpdmPalIoKind`] this transport carries, derived
    /// from the bound MCTP message type.
    #[inline]
    pub const fn kind(&self) -> SpdmPalIoKind {
        match self.msg_type {
            MCTP_MSG_TYPE_SECURED_SPDM => SpdmPalIoKind::SecuredMessage,
            _ => SpdmPalIoKind::Message,
        }
    }
}

#[async_trait]
impl SpdmPalTransport for McuSpdmMctpTransport {
    fn secure_message_supported(&self) -> bool {
        // A single instance is bound to exactly one MCTP message type,
        // so secured-message support is determined by which type the
        // transport was constructed for.
        self.msg_type == MCTP_MSG_TYPE_SECURED_SPDM
    }

    /// Maximum SPDM payload bytes the MCTP transport can carry,
    /// excluding the 1-byte MCTP header.
    fn mtu(&self) -> usize {
        let max = self.mctp.max_message_size().unwrap_or(0) as usize;
        max.saturating_sub(MCTP_MSG_HEADER_SIZE)
    }

    fn header_size(&self) -> usize {
        MCTP_MSG_HEADER_SIZE
    }

    /// Receives the next MCTP-framed SPDM request. After this call
    /// `buf[0]` is the MCTP transport header byte and
    /// `buf[1..len]` is the SPDM payload — no shifting performed.
    async fn recv_request(&mut self, buf: &mut [u8]) -> McuResult<(SpdmPalIoKind, usize)> {
        if buf.len() < MCTP_MSG_HEADER_SIZE {
            return Err(error_code::BUFFER_TOO_SMALL);
        }

        let (req_len, msg_info) = self.mctp.receive_request(buf).await?;

        let req_len = req_len as usize;
        if req_len < MCTP_MSG_HEADER_SIZE || req_len > buf.len() {
            return Err(error_code::INVALID_MESSAGE);
        }

        if (buf[0] & MCTP_MSG_TYPE_MASK) != self.msg_type {
            return Err(error_code::UNEXPECTED_MESSAGE_TYPE);
        }

        self.cur_resp_ctx = Some(msg_info);
        Ok((self.kind(), req_len))
    }

    /// Sends an MCTP-framed SPDM response. Caller must have written
    /// the SPDM payload into `msg[1..]`; the transport fills `msg[0]`
    /// with the MCTP message-type byte in place and forwards the full
    /// slice to the syscall — no extra allocation.
    async fn send_response(&mut self, kind: SpdmPalIoKind, msg: &mut [u8]) -> McuResult<()> {
        // The bound `msg_type` dictates what we send on the wire; the
        // caller must agree.
        if kind != self.kind() {
            return Err(error_code::OPERATION_NOT_SUPPORTED);
        }
        if msg.is_empty() {
            return Err(error_code::INVALID_MESSAGE);
        }

        let msg_info = self
            .cur_resp_ctx
            .take()
            .ok_or(error_code::NO_REQUEST_IN_FLIGHT)?;

        if let Some(first) = msg.first_mut() {
            *first = self.msg_type & MCTP_MSG_TYPE_MASK;
        }

        self.mctp.send_response(msg, msg_info).await?;
        Ok(())
    }
}
