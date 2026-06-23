// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED extension points implemented by platform/user code.

use super::*;

/// Decoded VENDOR_DEFINED registry identity used to select a responder.
pub struct VdmRegistry<'a> {
    /// Standards body registry value decoded from the SPDM envelope.
    pub standard_id: u16,
    /// Vendor ID bytes decoded from the SPDM envelope.
    pub vendor_id: &'a [u8],
    /// True when the transport delivered this request as a secured message.
    pub secure_session: bool,
}

/// Outcome of a handled VDM request: which response buffer was written.
pub enum VdmResponse {
    /// Wrote N payload bytes into [`VdmResponseBuffer::inline`] (fits one frame).
    Inline(usize),
    /// Wrote N payload bytes into [`VdmResponseBuffer::large`] (sent via chunking).
    Large(usize),
}

/// Response buffers and scratch allocator provided to a VDM handler.
pub struct VdmResponseBuffer<'a, Alloc: SpdmPalAlloc, Io: SpdmPalIo> {
    /// Per-request payload buffer sized to fit a single transport frame.
    pub inline: &'a mut [u8],
    /// Buffer for responses that do not fit `inline`; when the handler returns
    /// [`VdmResponse::Large`], the stack transmits these bytes via chunking.
    /// Empty when chunking is unavailable or the backend indicates this request
    /// cannot produce a large response.
    ///
    /// The backing storage is chosen by the stack and may be the persistent
    /// large-message store directly, so handlers must only write the returned
    /// byte count and must not assume this is disposable scratch.
    pub large: &'a mut [u8],
    /// Allocator for per-request VDM working scratch (e.g. staging a mailbox call).
    pub alloc: &'a Alloc,
    /// I/O handle associated with the current request; scopes allocator usage.
    pub io: &'a Io,
}

/// Streaming metadata for a large VENDOR_DEFINED request that should be
/// consumed incrementally instead of reassembled in the SPDM large buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VdmLargeRequestStreamInfo {
    /// Offset within the vendor-defined payload where streamed bytes begin.
    pub stream_offset: usize,
    /// Total streamed payload bytes expected across all CHUNK_SEND chunks.
    pub stream_len: usize,
}

impl<'a, Alloc: SpdmPalAlloc, Io: SpdmPalIo> VdmResponseBuffer<'a, Alloc, Io> {
    /// Returns the request-scoped scratch allocator for platform hooks.
    pub fn scratch(&self) -> &'a Alloc {
        self.alloc
    }
}

/// Static-dispatch VDM backend used by the spdm-lite dispatcher.
#[allow(async_fn_in_trait)]
pub trait SpdmVdmBackend {
    /// True when this backend can emit a response that does not fit the inline
    /// transport frame and must use [`VdmResponseBuffer::large`]. Backends should
    /// keep this `false` unless at least one response can overflow one SPDM frame
    /// and should still choose [`VdmResponse::Inline`] whenever the actual
    /// response fits inline.
    const USES_LARGE_RESPONSE: bool = false;

    /// Maximum VDM payload bytes this backend needs for any large response.
    ///
    /// The stack still caps this by the negotiated maximum SPDM message size and
    /// PAL large-message capacity, but this backend-specific bound avoids
    /// reserving a worst-case SPDM-sized scratch buffer for small vendor command
    /// sets.
    const LARGE_RESPONSE_CAPACITY: usize = usize::MAX;

    /// True when this backend can consume a large request incrementally from
    /// CHUNK_SEND chunks.
    const USES_LARGE_REQUEST_STREAM: bool = false;

    /// Returns the large-response capacity needed for this request.
    ///
    /// Backends that can cheaply identify only some large-capable requests should
    /// override this to avoid reserving the persistent large-message buffer for
    /// requests that will stay inline.
    fn large_response_capacity(&self, _req: &[u8]) -> usize {
        if Self::USES_LARGE_RESPONSE {
            Self::LARGE_RESPONSE_CAPACITY
        } else {
            0
        }
    }

    /// Returns streaming metadata when this request prefix identifies a
    /// streamable large request owned by this backend.
    fn large_request_stream_info(
        &self,
        _req_prefix: &[u8],
        _req_payload_len: usize,
    ) -> Option<VdmLargeRequestStreamInfo> {
        None
    }

    /// Starts a streamed large request.
    async fn stream_large_request_begin<Alloc, Io>(
        &self,
        _stream_len: usize,
        _first_payload: &[u8],
        _alloc: &Alloc,
        _io: &Io,
    ) -> McuResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    /// Consumes a subsequent streamed large-request chunk.
    async fn stream_large_request_chunk<Alloc, Io>(
        &self,
        _payload: &[u8],
        _alloc: &Alloc,
        _io: &Io,
    ) -> McuResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    /// Finalizes a streamed large request and writes the VDM response payload.
    async fn stream_large_request_finish<Alloc, Io>(
        &self,
        _out: &mut [u8],
        _alloc: &Alloc,
        _io: &Io,
    ) -> McuResult<usize>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    /// Returns true when this backend owns the decoded VDM registry ID.
    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool;

    /// Handles a matched VDM request and writes only the VDM response payload.
    ///
    /// Called only after [`SpdmVdmBackend::match_id`] has selected this backend, so it
    /// already owns the request. Intra-backend routing (e.g. PCI-SIG IDE_KM vs TDISP
    /// by `protocol_id`, or an OCP command code) is decoded from `req`.
    ///
    /// Writes the payload into [`VdmResponseBuffer::inline`] when it fits, otherwise
    /// into [`VdmResponseBuffer::large`], and reports which via [`VdmResponse`].
    async fn handle_request<Alloc, Io>(
        &self,
        req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;
}

/// Default VDM backend used when no platform VDM support is registered.
///
/// [`match_id`](SpdmVdmBackend::match_id) always returns `false`, so the stack answers
/// every VENDOR_DEFINED request with `SPDM_UNSUPPORTED_REQUEST` before `handle_request`
/// is ever reached.
#[derive(Clone, Copy, Default)]
pub struct NoVdmBackend;

impl SpdmVdmBackend for NoVdmBackend {
    fn match_id(&self, _registry: &VdmRegistry<'_>) -> bool {
        false
    }

    async fn handle_request<Alloc, Io>(
        &self,
        _req: &[u8],
        _rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }
}
