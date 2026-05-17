// Licensed under the Apache-2.0 license

//! Low-level asynchronous transport trait used by the SPDM-Lite PAL.
//!
//! This module defines [`PalTransport`], an `async` byte-oriented interface
//! that platform implementations expose to the SPDM-Lite stack. Unlike the
//! higher-level [`SpdmIoTransport`](crate::SpdmIoTransport), which operates
//! on framed [`SpdmIo`](crate::SpdmIo) objects, `PalTransport` works
//! directly on raw byte buffers and is intended to wrap an underlying
//! transport (e.g., MCTP, PCIe DOE, I3C) at the PAL layer.
//!
//! Implementations also indicate whether the transport supports SPDM
//! Secured Messages and convey per-message security framing on each
//! exchange.

extern crate alloc;

use alloc::boxed::Box;

use async_trait::async_trait;

use super::*;

/// Asynchronous, byte-oriented transport interface for the SPDM-Lite PAL.
///
/// Implementors provide the platform-specific mechanism for exchanging
/// raw SPDM byte streams with a remote endpoint. The trait is `async`,
/// allowing implementations to suspend execution while waiting on I/O,
/// and includes a capability query plus a per-message "secured" flag so
/// the stack can distinguish plain SPDM messages from SPDM Secured
/// Messages on the wire.
#[async_trait]
pub trait SpdmPalTransport {
    /// Reports whether this transport supports SPDM Secured Messages.
    fn secure_message_supported(&self) -> bool;

    /// Maximum SPDM payload size (in bytes) the transport can carry in
    /// a single message, **excluding** the transport-framing header
    /// reported by [`header_size`](Self::header_size).
    fn mtu(&self) -> usize;

    /// Number of transport-framing header bytes the responder must
    /// reserve at the **start** of every send/receive buffer.
    ///
    /// On receive, the transport writes the framing bytes into
    /// `buf[0..header_size()]` and the SPDM payload into
    /// `buf[header_size()..len]`. On send, the caller writes the SPDM
    /// payload into `buf[header_size()..]` and the transport fills in
    /// `buf[0..header_size()]` in-place — no extra allocation or
    /// copy.
    ///
    /// Typical values: MCTP = 1 byte, PCIe DOE = 8 bytes.
    fn header_size(&self) -> usize;

    /// Receives the next SPDM message into `buf`.
    ///
    /// On success, `buf[0..len]` contains the raw transport frame:
    /// `buf[0..header_size()]` is the framing header, and
    /// `buf[header_size()..len]` is the SPDM payload — no shifting
    /// is performed.
    ///
    /// # Returns
    ///
    /// * `Ok((kind, len))` — `kind` indicates whether the frame was
    ///   plain SPDM or an SPDM Secured Message; `len` is the total
    ///   frame size including the transport header.
    async fn recv_request(&mut self, buf: &mut [u8]) -> McuResult<(SpdmPalIoKind, usize)>;

    /// Sends an SPDM message held in `msg`.
    ///
    /// The caller must have written the SPDM payload into
    /// `msg[header_size()..]`. The transport fills
    /// `msg[0..header_size()]` in place and forwards the full `&[u8]`
    /// to the underlying driver — no intermediate buffer, no copy.
    async fn send_response(&mut self, kind: SpdmPalIoKind, msg: &mut [u8]) -> McuResult<()>;
}
