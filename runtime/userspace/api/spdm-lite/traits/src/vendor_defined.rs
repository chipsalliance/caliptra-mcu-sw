// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED extension points implemented by platform/user code.

use super::*;
use mcu_error::domain;

const VDM_INVALID_PARAMS: McuErrorCode = McuErrorCode::new(domain::SPDM, 0x00, 0x0100);
const VDM_UNSUPPORTED: McuErrorCode = McuErrorCode::new(domain::SPDM, 0x00, 0x0101);

/// Decoded VENDOR_DEFINED request context passed to a backend.
pub struct VdmRequest<'a> {
    /// Standards body registry value decoded from the SPDM envelope.
    pub standard_id: u16,
    /// Vendor ID bytes decoded from the SPDM envelope.
    pub vendor_id: &'a [u8],
    /// True when the transport delivered this request as a secured message.
    pub secure_session: bool,
    /// Vendor-defined payload, excluding the SPDM VENDOR_DEFINED envelope.
    pub payload: &'a [u8],
}

/// Placeholder storage type for inline-only VDM responses.
pub struct NoLargeResponseStorage;

impl SpdmPalLargeMessage for NoLargeResponseStorage {
    fn capacity(&self) -> usize {
        0
    }

    fn write(&self, _offset: usize, _data: &[u8]) -> McuResult<()> {
        Err(VDM_INVALID_PARAMS)
    }

    fn read(&self, _offset: usize, _out: &mut [u8]) -> McuResult<()> {
        Err(VDM_INVALID_PARAMS)
    }
}

/// Writer for a large VDM response payload stored in PAL persistent storage.
pub struct VdmLargeResponseWriter<'a, Storage: SpdmPalLargeMessage> {
    storage: &'a Storage,
    payload_offset: usize,
    capacity: usize,
}

impl<'a, Storage: SpdmPalLargeMessage> VdmLargeResponseWriter<'a, Storage> {
    /// Creates a writer over `storage`, starting payload bytes at `payload_offset`.
    pub fn new(storage: &'a Storage, payload_offset: usize, capacity: usize) -> Self {
        Self {
            storage,
            payload_offset,
            capacity,
        }
    }

    /// Maximum payload bytes that can be written.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Copy `data` into the large response payload at `offset`.
    pub fn write(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let storage_offset = self.checked_storage_range(offset, data.len())?;
        self.storage.write(storage_offset, data)
    }

    fn checked_storage_range(&self, offset: usize, len: usize) -> McuResult<usize> {
        let end = offset.checked_add(len).ok_or(VDM_INVALID_PARAMS)?;
        if end > self.capacity {
            return Err(VDM_INVALID_PARAMS);
        }
        self.payload_offset
            .checked_add(offset)
            .ok_or(VDM_INVALID_PARAMS)
    }
}

/// Response payload buffers provided to a static-dispatch VDM backend.
pub struct VdmResponseBuffers<'a, Storage: SpdmPalLargeMessage = NoLargeResponseStorage> {
    /// Inline VDM response payload buffer.
    pub inline: &'a mut [u8],
    /// Optional large VDM response payload writer.
    pub large: Option<VdmLargeResponseWriter<'a, Storage>>,
}

/// VDM backend response location and payload length.
pub enum VdmResponseKind {
    /// Backend wrote this many bytes into [`VdmResponseBuffers::inline`].
    Inline(usize),
    /// Backend wrote this many bytes through [`VdmResponseBuffers::large`].
    Large(usize),
}

/// Static-dispatch VDM backend used by the spdm-lite dispatcher.
#[allow(async_fn_in_trait)]
pub trait SpdmVdmBackend: Sync {
    /// Error type returned by this backend.
    type Error;

    /// Returns true when this backend handles the decoded VDM request.
    fn match_request(&self, req: &VdmRequest<'_>) -> bool;

    /// Handles a matched VDM request and writes only the VDM response payload.
    async fn handle_request<Storage: SpdmPalLargeMessage>(
        &self,
        req: VdmRequest<'_>,
        rsp: VdmResponseBuffers<'_, Storage>,
    ) -> core::result::Result<VdmResponseKind, Self::Error>;
}

/// Default VDM backend used when no platform VDM support is registered.
#[derive(Clone, Copy, Default)]
pub struct NoVdmBackend;

impl SpdmVdmBackend for NoVdmBackend {
    type Error = McuErrorCode;

    fn match_request(&self, _req: &VdmRequest<'_>) -> bool {
        false
    }

    async fn handle_request<Storage: SpdmPalLargeMessage>(
        &self,
        _req: VdmRequest<'_>,
        _rsp: VdmResponseBuffers<'_, Storage>,
    ) -> McuResult<VdmResponseKind> {
        Err(VDM_UNSUPPORTED)
    }
}
