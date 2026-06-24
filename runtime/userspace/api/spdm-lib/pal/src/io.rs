// Licensed under the Apache-2.0 license

//! MCU-side [`SpdmPalIo`] / [`SpdmPalIoTransport`] implementations.
//!
//! This module bridges the framed-request/response interface that the
//! SPDM-Lite stack drives
//! ([`SpdmPalIoTransport`](caliptra_mcu_spdm_traits::SpdmPalIoTransport))
//! onto the byte-oriented platform transport
//! ([`SpdmPalTransport`](caliptra_mcu_spdm_traits::SpdmPalTransport))
//! held inside [`McuSpdmPal`].
//!
//! # Buffer flow
//!
//! On every `recv_request`:
//!
//! 1. A single `header_size + mtu` buffer is allocated; the transport
//!    writes both its framing header *and* the SPDM payload into it
//!    (no shift / copy is performed afterwards).
//! 2. The buffer is shrunk to the actual frame length, releasing the
//!    trailing slots back to the pool.
//! 3. The resulting [`McuSpdmIo`] is returned to the stack and keeps
//!    the frame alive until it is dropped.
//!
//! On `send_response`, the caller-provided `msg` already has the
//! SPDM payload at offset `header_size()`; the transport fills
//! `msg[0..header_size()]` in place.
//!
//! # Soundness
//!
//! `McuSpdmPal::transport_mut` is the only `&mut` borrow of the
//! inner transport, and the SPDM responder is strictly single-task,
//! so the `UnsafeCell`-based interior mutability is never observed
//! concurrently. See [`McuSpdmPal::transport_mut`] for the contract.

use super::measurements::MeasurementProvider;
use super::*;

/// Per-IO handle returned by [`McuSpdmPal::recv_request`].
///
/// Holds the received SPDM frame (transport header + SPDM payload)
/// and its [`SpdmPalIoKind`] (plain vs. secured) as classified by
/// the underlying [`SpdmPalTransport`]. The transport-framing bytes
/// occupy the first `header_size` bytes of `frame`;
/// [`SpdmPalIo::request`] returns the SPDM-only suffix.
///
/// Sized to be small (`BitmapBytes` + `u8` + `SpdmPalIoKind`) so it
/// can live cheaply across `.await` points in the stack's run loop.
pub struct McuSpdmIo<'a> {
    /// RAII handle to the received frame. Borrows from the
    /// allocator on [`McuSpdmPal`]; the underlying slots are
    /// released when this `McuSpdmIo` is dropped.
    frame: BitmapBytes<'a>,
    /// Number of transport-framing bytes at the start of `frame`.
    /// Stored as `u8` because no real transport uses > 255 bytes of
    /// framing.
    header_size: u8,
    /// Whether the frame is plain SPDM or an SPDM Secured Message,
    /// as reported by the transport.
    kind: SpdmPalIoKind,
}

impl SpdmPalIo for McuSpdmIo<'_> {
    /// Returns the message kind classified by the transport.
    ///
    /// # Returns
    ///
    /// [`SpdmPalIoKind::Message`] for a plain SPDM frame or
    /// [`SpdmPalIoKind::SecuredMessage`] for a Secured Message.
    fn kind(&self) -> SpdmPalIoKind {
        self.kind
    }

    /// Returns the SPDM payload (transport header stripped).
    ///
    /// # Returns
    ///
    /// `frame[header_size..]` — the SPDM message bytes, ready to
    /// be decoded by the stack.
    fn request(&self) -> &[u8] {
        &self.frame[self.header_size as usize..]
    }
}

impl<M: MeasurementProvider> SpdmPalIoTransport for McuSpdmPal<M> {
    type Io<'a>
        = McuSpdmIo<'a>
    where
        Self: 'a;

    /// Reports whether the underlying transport supports SPDM
    /// Secured Messages.
    ///
    /// # Returns
    ///
    /// `true` if the transport can frame and deliver Secured
    /// Messages; `false` if only plain SPDM is supported.
    fn secure_message_supported(&self) -> bool {
        self.transport_secure_supported()
    }

    /// Number of transport-framing bytes reserved at the start of
    /// every send / receive buffer.
    ///
    /// # Returns
    ///
    /// Byte count to skip when reading an SPDM payload and to leave
    /// uninitialised when building a response (the transport fills
    /// those bytes in place inside [`Self::send_response`]).
    fn header_size(&self) -> usize {
        self.transport_header_size()
    }

    fn send_len_alignment(&self) -> usize {
        self.transport_send_len_alignment()
    }

    /// Maximum SPDM payload the transport will carry in a single
    /// message, excluding [`Self::header_size`].
    ///
    /// # Returns
    ///
    /// The transport MTU in bytes — used by the stack to populate
    /// `DataTransferSize` / `MaxSPDMmsgSize` in `CAPABILITIES`.
    fn mtu(&self) -> usize {
        self.transport_mtu()
    }

    /// Blocks until the next SPDM request arrives from the peer.
    ///
    /// Resets the per-IO allocator, reserves a single
    /// `header_size + mtu` scratch buffer, lets the transport fill
    /// it in place, and shrinks the buffer to the actual frame
    /// length. The returned [`McuSpdmIo`] owns the slots backing
    /// the frame for the duration of the exchange.
    ///
    /// # Returns
    ///
    /// * `Ok(McuSpdmIo)` — RAII handle to the received frame.
    ///
    /// # Errors
    ///
    /// * `OUT_OF_MEMORY` — the scratch region is too small for
    ///   `header_size + mtu` bytes (configuration error at
    ///   construction time).
    /// * Any [`McuErrorCode`] surfaced by the underlying
    ///   [`SpdmPalTransport::recv_request`].
    async fn recv_request(&self) -> McuResult<Self::Io<'_>> {
        // Transient allocations are released by RAII. The persistent large-message
        // buffer (if any) lives on ConnectionState and survives across cycles.

        // Need room for header + MTU; the transport writes both into the
        // same buffer (no shifting).
        let header = self.transport_header_size();
        let mtu = self.transport_mtu();
        let mut buf = self.allocator.alloc_bytes(header + mtu)?;

        // SAFETY: single-task responder; no other `&mut` borrow exists.
        let transport = unsafe { self.transport_mut() };
        let (kind, len) = transport.recv_request(buf.as_mut_slice()).await?;
        buf.shrink(len)?;

        Ok(McuSpdmIo {
            frame: buf,
            header_size: header as u8,
            kind,
        })
    }

    /// Sends an already-encoded SPDM response back to the peer.
    ///
    /// The caller must have written the SPDM payload into
    /// `msg[header_size()..]`; the transport fills
    /// `msg[0..header_size()]` in place before forwarding.
    ///
    /// # Parameters
    ///
    /// * `_io` — The handle returned by [`Self::recv_request`].
    ///   Borrowed (not consumed) so the stack can keep the request
    ///   buffer alive for transcript-hashing in parallel with the
    ///   response send. Not used directly here.
    /// * `kind` — Whether to frame as plain SPDM or as an SPDM
    ///   Secured Message.
    /// * `msg` — Full response buffer (transport header reserved at
    ///   the front, SPDM payload at offset `header_size()`).
    ///   Mutable so the transport can stamp its framing bytes in
    ///   place.
    ///
    /// # Returns
    ///
    /// * `Ok(())` — The frame was handed off to the transport.
    ///
    /// # Errors
    ///
    /// * Any [`McuErrorCode`] surfaced by the underlying
    ///   [`SpdmPalTransport::send_response`].
    async fn send_response(
        &self,
        _io: &Self::Io<'_>,
        kind: SpdmPalIoKind,
        msg: &mut [u8],
    ) -> McuResult<()> {
        // SAFETY: single-task responder; `recv_request` has returned
        // and no overlapping send is in flight.
        let transport = unsafe { self.transport_mut() };
        transport.send_response(kind, msg).await
    }
}
