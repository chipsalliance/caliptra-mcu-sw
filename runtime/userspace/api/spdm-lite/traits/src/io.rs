// Licensed under the Apache-2.0 license

//! SPDM I/O abstractions for transport-layer message exchange.
//!
//! This module defines the core traits and types used to send and receive
//! SPDM messages over a transport layer. It distinguishes between plain
//! SPDM messages and secured (encrypted/authenticated) messages, and
//! provides a transport abstraction that implementations can use to
//! integrate with different underlying communication mechanisms.

use super::*;

/// Describes the kind of SPDM message being transported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmPalIoKind {
    /// A plain, unsecured SPDM message.
    Message,
    /// An SPDM secured message (encrypted and/or authenticated).
    SecuredMessage,
}

/// Represents a single received SPDM request and its associated metadata.
///
/// Implementors provide access to the message kind and the raw request payload.
pub trait SpdmPalIo {
    /// Returns the kind of SPDM message this I/O object carries.
    ///
    /// # Returns
    ///
    /// An [`SpdmPalIoKind`] indicating whether this is a plain or secured message.
    fn kind(&self) -> SpdmPalIoKind;

    /// Returns the raw bytes of the SPDM request payload.
    ///
    /// # Returns
    ///
    /// A byte slice containing the request data.
    fn request(&self) -> &[u8];
}

/// Transport-layer abstraction for SPDM request/response exchange.
///
/// Implementations of this trait handle the mechanics of receiving SPDM
/// requests from a remote endpoint and sending back responses over a
/// specific transport (e.g., MCTP, PCIe DOE, etc.).
pub trait SpdmPalIoTransport {
    /// The concrete I/O type returned when a request is received.
    ///
    /// Must implement [`SpdmPalIo`] and is parameterized by the lifetime of
    /// the borrow on `self`, allowing the I/O object to reference
    /// transport-internal buffers.
    type Io<'a>: SpdmPalIo
    where
        Self: 'a;

    /// Indicates whether this transport supports secured SPDM messages.
    fn secure_message_supported(&self) -> bool;

    /// Number of transport-framing header bytes the responder must
    /// reserve at the start of each send buffer. Handlers should
    /// allocate `header_size() + spdm_payload_len` bytes, write the
    /// SPDM payload at offset `header_size()`, and pass the full
    /// `&mut [u8]` to [`Self::send_response`]; the transport fills
    /// `buf[0..header_size()]` in place.
    fn header_size(&self) -> usize;

    /// Required length-alignment for outbound message buffers.
    ///
    /// The response builder rounds up allocations to this multiple
    /// so the transport receives a correctly-sized buffer.
    /// DOE returns 4 (DWORD). Defaults to 1 (no padding).
    fn send_len_alignment(&self) -> usize {
        1
    }

    /// Maximum SPDM payload the underlying transport will carry in a
    /// single message, excluding [`Self::header_size`] framing.
    /// Used by the SPDM stack to populate the `DataTransferSize` /
    /// `MaxSpdmMsgSize` fields in `CAPABILITIES`.
    fn mtu(&self) -> usize;

    /// Blocks until the next SPDM request is received from the remote endpoint.
    ///
    /// # Returns
    ///
    /// * `Ok(Io)` — An I/O handle containing the received request. The handle
    ///   borrows from `self` and provides access to the request payload and kind.
    /// * `Err(McuErrorCode)` — A transport-level error if the receive failed.
    ///   Blocks until the next SPDM request is received from the remote endpoint.
    ///
    /// Takes `&self` rather than `&mut self` so subsequent
    /// [`Self::send_response`] and allocator calls can coexist with
    /// the returned [`Self::Io`] borrow. Implementations must provide
    /// their own interior mutability (e.g., `UnsafeCell`) for any
    /// transport-internal mutable state.
    ///
    /// # Returns
    ///
    /// * `Ok(Io)` — An I/O handle containing the received request. The
    ///   handle borrows from `self` and provides access to the request
    ///   payload and kind.
    /// * `Err(McuErrorCode)` — A transport-level error if the receive
    ///   failed.
    async fn recv_request(&self) -> McuResult<Self::Io<'_>>;

    /// Sends an SPDM response back to the remote endpoint.
    ///
    /// `msg[0..header_size()]` is reserved for the transport's
    /// framing header (filled by the implementation in place);
    /// `msg[header_size()..]` must contain the SPDM payload written
    /// by the caller. The whole `&mut [u8]` is forwarded to the
    /// underlying transport without any extra copies.
    async fn send_response(
        &self,
        io: &Self::Io<'_>,
        kind: SpdmPalIoKind,
        msg: &mut [u8],
    ) -> McuResult<()>;
}
