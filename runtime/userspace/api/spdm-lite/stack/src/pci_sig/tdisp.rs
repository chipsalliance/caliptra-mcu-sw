// Licensed under the Apache-2.0 license

//! TDISP protocol responder for SPDM-Lite PCI-SIG VDMs.
//!
//! This module ports the libspdm-compatible TDISP command set without the
//! `async_trait`, boxed-future, or heap-backed handler table used by the full
//! SPDM library.  All requests are decoded from borrowed slices and responses
//! are written into the caller-provided VDM buffer.

use core::cell::Cell;

use crate::{SpdmResult, VdmResponseKind, SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED};

/// TDISP version 1.0 wire value.
pub const TDISP_VERSION_1_0: u8 = 0x10;
/// Size of the START_INTERFACE nonce.
pub const START_INTERFACE_NONCE_SIZE: usize = 32;
/// Maximum number of TDISP interfaces tracked by the responder.
pub const MAX_TDISP_INTERFACES: usize = 64;

const TDISP_HEADER_LEN: usize = 16;
const TDISP_CAPS_REQ_LEN: usize = 4;
const TDISP_CAPS_RSP_LEN: usize = 28;
const LOCK_INTERFACE_PARAM_LEN: usize = 20;
const DEVICE_INTERFACE_REPORT_REQ_LEN: usize = 4;
const DEVICE_INTERFACE_REPORT_RSP_HDR_LEN: usize = 4;
const ERROR_RSP_LEN: usize = TDISP_HEADER_LEN + 8;

/// Supported TDISP protocol versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdispVersion {
    /// TDISP 1.0.
    V10 = TDISP_VERSION_1_0,
}

impl TdispVersion {
    /// Converts the version to the wire value.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TdispVersion {
    type Error = TdispError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TDISP_VERSION_1_0 => Ok(Self::V10),
            _ => Err(TdispError::VersionMismatch),
        }
    }
}

/// TDISP command and response codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdispCommand {
    GetTdispVersion = 0x81,
    TdispVersion = 0x01,
    GetTdispCapabilities = 0x82,
    TdispCapabilities = 0x02,
    LockInterface = 0x83,
    LockInterfaceResponse = 0x03,
    GetDeviceInterfaceReport = 0x84,
    DeviceInterfaceReport = 0x04,
    GetDeviceInterfaceState = 0x85,
    DeviceInterfaceState = 0x05,
    StartInterfaceRequest = 0x86,
    StartInterfaceResponse = 0x06,
    StopInterfaceRequest = 0x87,
    StopInterfaceResponse = 0x07,
    BindP2PStreamRequest = 0x88,
    BindP2PStreamResponse = 0x08,
    UnbindP2PStreamRequest = 0x89,
    UnbindP2PStreamResponse = 0x09,
    SetMmioAttributeRequest = 0x8A,
    SetMmioAttributeResponse = 0x0A,
    VdmRequest = 0x8B,
    VdmResponse = 0x0B,
    ErrorResponse = 0x7F,
}

impl TdispCommand {
    const fn response(self) -> Option<Self> {
        match self {
            Self::GetTdispVersion => Some(Self::TdispVersion),
            Self::GetTdispCapabilities => Some(Self::TdispCapabilities),
            Self::LockInterface => Some(Self::LockInterfaceResponse),
            Self::GetDeviceInterfaceReport => Some(Self::DeviceInterfaceReport),
            Self::GetDeviceInterfaceState => Some(Self::DeviceInterfaceState),
            Self::StartInterfaceRequest => Some(Self::StartInterfaceResponse),
            Self::StopInterfaceRequest => Some(Self::StopInterfaceResponse),
            Self::BindP2PStreamRequest => Some(Self::BindP2PStreamResponse),
            Self::UnbindP2PStreamRequest => Some(Self::UnbindP2PStreamResponse),
            Self::SetMmioAttributeRequest => Some(Self::SetMmioAttributeResponse),
            Self::VdmRequest => Some(Self::VdmResponse),
            _ => None,
        }
    }

    const fn payload_len(self) -> usize {
        match self {
            Self::GetTdispVersion => 0,
            Self::GetTdispCapabilities => TDISP_CAPS_REQ_LEN,
            Self::LockInterface => LOCK_INTERFACE_PARAM_LEN,
            Self::GetDeviceInterfaceReport => DEVICE_INTERFACE_REPORT_REQ_LEN,
            Self::GetDeviceInterfaceState => 0,
            Self::StartInterfaceRequest => START_INTERFACE_NONCE_SIZE,
            Self::StopInterfaceRequest => 0,
            Self::BindP2PStreamRequest
            | Self::UnbindP2PStreamRequest
            | Self::SetMmioAttributeRequest => 0,
            _ => 0,
        }
    }
}

impl TryFrom<u8> for TdispCommand {
    type Error = TdispError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x81 => Ok(Self::GetTdispVersion),
            0x01 => Ok(Self::TdispVersion),
            0x82 => Ok(Self::GetTdispCapabilities),
            0x02 => Ok(Self::TdispCapabilities),
            0x83 => Ok(Self::LockInterface),
            0x03 => Ok(Self::LockInterfaceResponse),
            0x84 => Ok(Self::GetDeviceInterfaceReport),
            0x04 => Ok(Self::DeviceInterfaceReport),
            0x85 => Ok(Self::GetDeviceInterfaceState),
            0x05 => Ok(Self::DeviceInterfaceState),
            0x86 => Ok(Self::StartInterfaceRequest),
            0x06 => Ok(Self::StartInterfaceResponse),
            0x87 => Ok(Self::StopInterfaceRequest),
            0x07 => Ok(Self::StopInterfaceResponse),
            0x88 => Ok(Self::BindP2PStreamRequest),
            0x08 => Ok(Self::BindP2PStreamResponse),
            0x89 => Ok(Self::UnbindP2PStreamRequest),
            0x09 => Ok(Self::UnbindP2PStreamResponse),
            0x8A => Ok(Self::SetMmioAttributeRequest),
            0x0A => Ok(Self::SetMmioAttributeResponse),
            0x8B => Ok(Self::VdmRequest),
            0x0B => Ok(Self::VdmResponse),
            0x7F => Ok(Self::ErrorResponse),
            _ => Err(TdispError::UnsupportedRequest),
        }
    }
}

/// TDISP error response codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TdispError {
    InvalidRequest = 0x01,
    Busy = 0x03,
    InvalidInterfaceState = 0x04,
    Unspecified = 0x05,
    UnsupportedRequest = 0x07,
    VersionMismatch = 0x41,
    VendorSpecificError = 0xFF,
    InvalidInterface = 0x101,
    InvalidNonce = 0x102,
    InsufficientEntropy = 0x103,
    InvalidDeviceConfiguration = 0x104,
}

impl From<u32> for TdispError {
    fn from(value: u32) -> Self {
        match value {
            0x01 => Self::InvalidRequest,
            0x03 => Self::Busy,
            0x04 => Self::InvalidInterfaceState,
            0x05 => Self::Unspecified,
            0x07 => Self::UnsupportedRequest,
            0x41 => Self::VersionMismatch,
            0xFF => Self::VendorSpecificError,
            0x101 => Self::InvalidInterface,
            0x102 => Self::InvalidNonce,
            0x103 => Self::InsufficientEntropy,
            0x104 => Self::InvalidDeviceConfiguration,
            _ => Self::Unspecified,
        }
    }
}

/// FunctionID of the device hosting the TDI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FunctionId(pub u32);

impl FunctionId {
    /// Returns the PCIe requester id field.
    pub const fn requester_id(self) -> u16 {
        (self.0 & 0xffff) as u16
    }

    /// Returns the requester segment field.
    pub const fn requester_segment(self) -> u8 {
        ((self.0 >> 16) & 0xff) as u8
    }

    /// Returns true when the requester segment is valid.
    pub const fn requester_segment_valid(self) -> bool {
        ((self.0 >> 24) & 1) != 0
    }
}

/// Interface identifier carried in every TDISP message header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterfaceId {
    /// PCI function identifier.
    pub function_id: FunctionId,
    /// Reserved 64-bit field preserved as decoded.
    pub reserved: u64,
}

/// TDISP common message header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispMessageHeader {
    /// TDISP wire version.
    pub version: u8,
    /// TDISP command code.
    pub message_type: u8,
    /// Reserved header field.
    pub reserved: u16,
    /// Target interface id.
    pub interface_id: InterfaceId,
}

impl TdispMessageHeader {
    /// Creates a response header.
    pub const fn new(version: u8, message_type: TdispCommand, interface_id: InterfaceId) -> Self {
        Self {
            version,
            message_type: message_type as u8,
            reserved: 0,
            interface_id,
        }
    }

    fn decode(input: &[u8]) -> SpdmResult<(Self, &[u8])> {
        let hdr = input.get(..TDISP_HEADER_LEN).ok_or(SPDM_INVALID_REQUEST)?;
        Ok((
            Self {
                version: hdr[0],
                message_type: hdr[1],
                reserved: read_u16(&hdr[2..4]),
                interface_id: InterfaceId {
                    function_id: FunctionId(read_u32(&hdr[4..8])),
                    reserved: read_u64(&hdr[8..16]),
                },
            },
            &input[TDISP_HEADER_LEN..],
        ))
    }

    fn encode(self, out: &mut [u8]) -> SpdmResult<()> {
        let out = out.get_mut(..TDISP_HEADER_LEN).ok_or(SPDM_UNSPECIFIED)?;
        out[0] = self.version;
        out[1] = self.message_type;
        out[2..4].copy_from_slice(&self.reserved.to_le_bytes());
        out[4..8].copy_from_slice(&self.interface_id.function_id.0.to_le_bytes());
        out[8..16].copy_from_slice(&self.interface_id.reserved.to_le_bytes());
        Ok(())
    }
}

/// GET_TDISP_CAPABILITIES request payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispReqCapabilities {
    /// Requester TSM capabilities.
    pub tsm_caps: u32,
}

impl TdispReqCapabilities {
    fn decode(input: &[u8]) -> SpdmResult<Self> {
        if input.len() != TDISP_CAPS_REQ_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        Ok(Self {
            tsm_caps: read_u32(input),
        })
    }
}

/// TDISP responder capabilities payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispRespCapabilities {
    /// Responder DSM capability bits.
    pub dsm_capabilities: u32,
    /// Supported request message bitmap.
    pub req_msgs_supported: [u8; 16],
    /// Supported LOCK_INTERFACE flags.
    pub lock_interface_flags_supported: u16,
    /// Device address width.
    pub dev_addr_width: u8,
    /// Number of requesters for this interface.
    pub num_req_this: u8,
    /// Number of requesters across all interfaces.
    pub num_req_all: u8,
}

impl TdispRespCapabilities {
    /// Creates a capabilities payload.
    pub const fn new(
        dsm_capabilities: u32,
        req_msgs_supported: [u8; 16],
        lock_interface_flags_supported: u16,
        dev_addr_width: u8,
        num_req_this: u8,
        num_req_all: u8,
    ) -> Self {
        Self {
            dsm_capabilities,
            req_msgs_supported,
            lock_interface_flags_supported,
            dev_addr_width,
            num_req_this,
            num_req_all,
        }
    }

    fn encode(self, out: &mut [u8]) -> SpdmResult<()> {
        let out = out.get_mut(..TDISP_CAPS_RSP_LEN).ok_or(SPDM_UNSPECIFIED)?;
        out[0..4].copy_from_slice(&self.dsm_capabilities.to_le_bytes());
        out[4..20].copy_from_slice(&self.req_msgs_supported);
        out[20..22].copy_from_slice(&self.lock_interface_flags_supported.to_le_bytes());
        out[22..25].fill(0);
        out[25] = self.dev_addr_width;
        out[26] = self.num_req_this;
        out[27] = self.num_req_all;
        Ok(())
    }
}

/// LOCK_INTERFACE_REQUEST flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispLockInterfaceFlags(pub u16);

/// LOCK_INTERFACE_REQUEST payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispLockInterfaceParam {
    /// Requested lock flags.
    pub flags: TdispLockInterfaceFlags,
    /// Default stream id.
    pub default_stream_id: u8,
    /// Reserved byte.
    pub reserved: u8,
    /// MMIO reporting offset.
    pub mmio_reporting_offset: [u8; 8],
    /// P2P address mask.
    pub bind_p2p_addr_mask: [u8; 8],
}

impl TdispLockInterfaceParam {
    fn decode(input: &[u8]) -> SpdmResult<Self> {
        if input.len() != LOCK_INTERFACE_PARAM_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        let mut mmio_reporting_offset = [0u8; 8];
        let mut bind_p2p_addr_mask = [0u8; 8];
        mmio_reporting_offset.copy_from_slice(&input[4..12]);
        bind_p2p_addr_mask.copy_from_slice(&input[12..20]);
        Ok(Self {
            flags: TdispLockInterfaceFlags(read_u16(&input[0..2])),
            default_stream_id: input[2],
            reserved: input[3],
            mmio_reporting_offset,
            bind_p2p_addr_mask,
        })
    }
}

/// TDI state values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum TdiStatus {
    /// CONFIG_UNLOCKED state.
    #[default]
    ConfigUnlocked = 0,
    /// CONFIG_LOCKED state.
    ConfigLocked = 1,
    /// RUN state.
    Run = 2,
    /// ERROR state.
    Error = 3,
    /// Reserved/invalid state.
    Reserved = 0xff,
}

/// Error codes returned by a TDISP platform driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdispDriverError {
    InvalidArgument = 0x01,
    NoMemory = 0x02,
    GetTdispCapabilitiesFail = 0x03,
    GetDeviceInterfaceStateFail = 0x04,
    LockInterfaceReqFail = 0x05,
    StartInterfaceReqFail = 0x06,
    StopInterfaceReqFail = 0x07,
    GetInterfaceReportFail = 0x08,
    GetMmioRangesFail = 0x09,
    FunctionNotImplemented = 0x0A,
    InsufficientEntropy = 0x0B,
}

/// Result type returned by TDISP drivers.
pub type TdispDriverResult<T> = Result<T, TdispDriverError>;

/// Platform abstraction used by the TDISP responder.
#[allow(async_fn_in_trait)]
pub trait TdispDriver {
    /// Fills `out` with a START_INTERFACE nonce.
    async fn generate_start_interface_nonce(
        &self,
        out: &mut [u8; START_INTERFACE_NONCE_SIZE],
    ) -> TdispDriverResult<()>;

    /// Gets responder capabilities.
    async fn get_capabilities(
        &self,
        req_caps: TdispReqCapabilities,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32>;

    /// Locks an interface.
    async fn lock_interface(
        &self,
        function_id: FunctionId,
        param: TdispLockInterfaceParam,
    ) -> TdispDriverResult<u32>;

    /// Returns the total device interface report length.
    async fn get_device_interface_report_len(
        &self,
        function_id: FunctionId,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32>;

    /// Copies a device interface report portion.
    async fn get_device_interface_report(
        &self,
        function_id: FunctionId,
        offset: u16,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32>;

    /// Gets the current device interface state.
    async fn get_device_interface_state(
        &self,
        function_id: FunctionId,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32>;

    /// Starts an interface.
    async fn start_interface(&self, function_id: FunctionId) -> TdispDriverResult<u32>;

    /// Stops an interface.
    async fn stop_interface(&self, function_id: FunctionId) -> TdispDriverResult<u32>;
}

/// TDISP responder with fixed-size state storage.
pub struct TdispResponder<D> {
    supported_versions: &'static [TdispVersion],
    driver: D,
    state: TdispState,
}

impl<D> TdispResponder<D> {
    /// Creates a TDISP responder.
    pub const fn new(supported_versions: &'static [TdispVersion], driver: D) -> Self {
        Self {
            supported_versions,
            driver,
            state: TdispState::new(),
        }
    }

    /// Returns the inner driver.
    pub fn driver(&self) -> &D {
        &self.driver
    }
}

impl<D> TdispResponder<D>
where
    D: TdispDriver,
{
    /// Handles a TDISP payload excluding the PCI-SIG protocol id byte.
    pub async fn handle_tdisp_payload(
        &self,
        payload: &[u8],
        out: &mut [u8],
    ) -> SpdmResult<VdmResponseKind> {
        let (req_hdr, req_payload) = TdispMessageHeader::decode(payload)?;
        if TdispVersion::try_from(req_hdr.version).is_err() {
            return self.write_error(
                req_hdr.version,
                req_hdr.interface_id,
                TdispError::VersionMismatch,
                0,
                out,
            );
        }

        let req_code = match TdispCommand::try_from(req_hdr.message_type) {
            Ok(command) => command,
            Err(_) => {
                return self.write_error(
                    req_hdr.version,
                    req_hdr.interface_id,
                    TdispError::UnsupportedRequest,
                    req_hdr.message_type as u32,
                    out,
                )
            }
        };

        if req_payload.len() != req_code.payload_len() {
            return self.write_error(
                req_hdr.version,
                req_hdr.interface_id,
                TdispError::InvalidRequest,
                0,
                out,
            );
        }

        let result = match req_code {
            TdispCommand::GetTdispVersion => self.handle_get_version(req_hdr, out),
            TdispCommand::GetTdispCapabilities => {
                self.handle_get_capabilities(req_hdr, req_payload, out)
                    .await
            }
            TdispCommand::LockInterface => self.handle_lock(req_hdr, req_payload, out).await,
            TdispCommand::GetDeviceInterfaceReport => {
                self.handle_report(req_hdr, req_payload, out).await
            }
            TdispCommand::GetDeviceInterfaceState => self.handle_state(req_hdr, out).await,
            TdispCommand::StartInterfaceRequest => {
                self.handle_start(req_hdr, req_payload, out).await
            }
            TdispCommand::StopInterfaceRequest => self.handle_stop(req_hdr, out).await,
            TdispCommand::BindP2PStreamRequest
            | TdispCommand::UnbindP2PStreamRequest
            | TdispCommand::SetMmioAttributeRequest
            | TdispCommand::VdmRequest => Ok(TdispHandlerResult::Error(
                TdispError::UnsupportedRequest,
                req_hdr.message_type as u32,
            )),
            _ => Err(SPDM_INVALID_REQUEST),
        }?;

        match result {
            TdispHandlerResult::Response(payload_len) => {
                let Some(response_code) = req_code.response() else {
                    return Err(SPDM_INVALID_REQUEST);
                };
                TdispMessageHeader::new(req_hdr.version, response_code, req_hdr.interface_id)
                    .encode(out)?;
                Ok(VdmResponseKind::Inline(TDISP_HEADER_LEN + payload_len))
            }
            TdispHandlerResult::Error(error, data) => {
                self.write_error(req_hdr.version, req_hdr.interface_id, error, data, out)
            }
        }
    }

    fn handle_get_version(
        &self,
        req_hdr: TdispMessageHeader,
        out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        if self.supported_versions.is_empty() || !self.state.init_interface(req_hdr.interface_id) {
            return Ok(TdispHandlerResult::Error(TdispError::InvalidInterface, 0));
        }
        let payload = out.get_mut(TDISP_HEADER_LEN..).ok_or(SPDM_UNSPECIFIED)?;
        let needed = 1usize
            .checked_add(self.supported_versions.len())
            .ok_or(SPDM_UNSPECIFIED)?;
        let payload = payload.get_mut(..needed).ok_or(SPDM_UNSPECIFIED)?;
        payload[0] = self.supported_versions.len() as u8;
        for (dst, version) in payload[1..].iter_mut().zip(self.supported_versions.iter()) {
            *dst = version.to_u8();
        }
        Ok(TdispHandlerResult::Response(needed))
    }

    async fn handle_get_capabilities(
        &self,
        _req_hdr: TdispMessageHeader,
        req_payload: &[u8],
        out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        let req_caps = TdispReqCapabilities::decode(req_payload)?;
        let mut rsp_caps = TdispRespCapabilities::default();
        match self.driver.get_capabilities(req_caps, &mut rsp_caps).await {
            Ok(0) => {
                rsp_caps.encode(
                    out.get_mut(TDISP_HEADER_LEN..TDISP_HEADER_LEN + TDISP_CAPS_RSP_LEN)
                        .ok_or(SPDM_UNSPECIFIED)?,
                )?;
                Ok(TdispHandlerResult::Response(TDISP_CAPS_RSP_LEN))
            }
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    async fn handle_lock(
        &self,
        req_hdr: TdispMessageHeader,
        req_payload: &[u8],
        out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        if self.state.interface_state(req_hdr.interface_id).is_none() {
            return Ok(TdispHandlerResult::Error(TdispError::InvalidInterface, 0));
        }
        let mut nonce = [0u8; START_INTERFACE_NONCE_SIZE];
        if self
            .driver
            .generate_start_interface_nonce(&mut nonce)
            .await
            .is_err()
        {
            return Ok(TdispHandlerResult::Error(
                TdispError::InsufficientEntropy,
                0,
            ));
        }
        let param = TdispLockInterfaceParam::decode(req_payload)?;
        match self
            .driver
            .lock_interface(req_hdr.interface_id.function_id, param)
            .await
        {
            Ok(0) => {
                self.state.set_nonce(req_hdr.interface_id, Some(nonce));
                out.get_mut(TDISP_HEADER_LEN..TDISP_HEADER_LEN + START_INTERFACE_NONCE_SIZE)
                    .ok_or(SPDM_UNSPECIFIED)?
                    .copy_from_slice(&nonce);
                Ok(TdispHandlerResult::Response(START_INTERFACE_NONCE_SIZE))
            }
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    async fn handle_report(
        &self,
        req_hdr: TdispMessageHeader,
        req_payload: &[u8],
        out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        if self.state.interface_state(req_hdr.interface_id).is_none() {
            return Ok(TdispHandlerResult::Error(TdispError::InvalidInterface, 0));
        }
        let req = DeviceInterfaceReportReq::decode(req_payload)?;
        let mut report_len = 0u16;
        match self
            .driver
            .get_device_interface_report_len(req_hdr.interface_id.function_id, &mut report_len)
            .await
        {
            Ok(0) if req.offset as usize >= report_len as usize => {
                return Ok(TdispHandlerResult::Error(TdispError::InvalidRequest, 0))
            }
            Ok(0) => {}
            Ok(e) => return Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => return Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }

        let payload = out.get_mut(TDISP_HEADER_LEN..).ok_or(SPDM_UNSPECIFIED)?;
        let max_report = payload
            .len()
            .checked_sub(DEVICE_INTERFACE_REPORT_RSP_HDR_LEN)
            .ok_or(SPDM_UNSPECIFIED)?;
        let remaining = report_len.saturating_sub(req.offset);
        let portion = (remaining as usize)
            .min(req.length as usize)
            .min(max_report);
        payload[0..2].copy_from_slice(&(portion as u16).to_le_bytes());
        payload[2..4].copy_from_slice(&remaining.saturating_sub(portion as u16).to_le_bytes());

        let mut copied = 0usize;
        match self
            .driver
            .get_device_interface_report(
                req_hdr.interface_id.function_id,
                req.offset,
                &mut payload[DEVICE_INTERFACE_REPORT_RSP_HDR_LEN
                    ..DEVICE_INTERFACE_REPORT_RSP_HDR_LEN + portion],
                &mut copied,
            )
            .await
        {
            Ok(0) if copied == portion => Ok(TdispHandlerResult::Response(
                DEVICE_INTERFACE_REPORT_RSP_HDR_LEN + copied,
            )),
            Ok(0) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    async fn handle_state(
        &self,
        req_hdr: TdispMessageHeader,
        out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        let mut tdi_status = TdiStatus::Reserved;
        match self
            .driver
            .get_device_interface_state(req_hdr.interface_id.function_id, &mut tdi_status)
            .await
        {
            Ok(0) if tdi_status != TdiStatus::Reserved => {
                *out.get_mut(TDISP_HEADER_LEN).ok_or(SPDM_UNSPECIFIED)? = tdi_status as u8;
                Ok(TdispHandlerResult::Response(1))
            }
            Ok(0) => Ok(TdispHandlerResult::Error(
                TdispError::InvalidInterfaceState,
                0,
            )),
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    async fn handle_start(
        &self,
        req_hdr: TdispMessageHeader,
        req_payload: &[u8],
        _out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        let mut nonce = [0u8; START_INTERFACE_NONCE_SIZE];
        nonce.copy_from_slice(req_payload);
        let Some(interface_state) = self.state.interface_state(req_hdr.interface_id) else {
            return Ok(TdispHandlerResult::Error(TdispError::InvalidInterface, 0));
        };
        let Some(expected_nonce) = interface_state.start_interface_nonce else {
            return Ok(TdispHandlerResult::Error(
                TdispError::InvalidInterfaceState,
                0,
            ));
        };
        if !ct_eq(&expected_nonce, &nonce) {
            return Ok(TdispHandlerResult::Error(
                TdispError::InvalidInterfaceState,
                0,
            ));
        }
        match self
            .driver
            .start_interface(req_hdr.interface_id.function_id)
            .await
        {
            Ok(0) => {
                self.state.set_nonce(req_hdr.interface_id, None);
                Ok(TdispHandlerResult::Response(0))
            }
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    async fn handle_stop(
        &self,
        req_hdr: TdispMessageHeader,
        _out: &mut [u8],
    ) -> SpdmResult<TdispHandlerResult> {
        match self
            .driver
            .stop_interface(req_hdr.interface_id.function_id)
            .await
        {
            Ok(0) => Ok(TdispHandlerResult::Response(0)),
            Ok(e) => Ok(TdispHandlerResult::Error(e.into(), 0)),
            Err(_) => Ok(TdispHandlerResult::Error(TdispError::Unspecified, 0)),
        }
    }

    fn write_error(
        &self,
        version: u8,
        interface_id: InterfaceId,
        error: TdispError,
        error_data: u32,
        out: &mut [u8],
    ) -> SpdmResult<VdmResponseKind> {
        let out = out.get_mut(..ERROR_RSP_LEN).ok_or(SPDM_UNSPECIFIED)?;
        TdispMessageHeader::new(version, TdispCommand::ErrorResponse, interface_id).encode(out)?;
        out[TDISP_HEADER_LEN..TDISP_HEADER_LEN + 4].copy_from_slice(&(error as u32).to_le_bytes());
        out[TDISP_HEADER_LEN + 4..TDISP_HEADER_LEN + 8].copy_from_slice(&error_data.to_le_bytes());
        Ok(VdmResponseKind::Inline(ERROR_RSP_LEN))
    }
}

#[derive(Clone, Copy)]
enum TdispHandlerResult {
    Response(usize),
    Error(TdispError, u32),
}

#[derive(Clone, Copy)]
struct DeviceInterfaceReportReq {
    offset: u16,
    length: u16,
}

impl DeviceInterfaceReportReq {
    fn decode(input: &[u8]) -> SpdmResult<Self> {
        if input.len() != DEVICE_INTERFACE_REPORT_REQ_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        Ok(Self {
            offset: read_u16(&input[0..2]),
            length: read_u16(&input[2..4]),
        })
    }
}

struct TdispState {
    interfaces: [Cell<Option<TdispInterfaceState>>; MAX_TDISP_INTERFACES],
}

impl TdispState {
    const fn new() -> Self {
        Self {
            interfaces: [const { Cell::new(None) }; MAX_TDISP_INTERFACES],
        }
    }

    fn interface_state(&self, interface_id: InterfaceId) -> Option<TdispInterfaceState> {
        self.interfaces.iter().find_map(|slot| match slot.get() {
            Some(state) if state.interface_id == interface_id => Some(state),
            _ => None,
        })
    }

    fn init_interface(&self, interface_id: InterfaceId) -> bool {
        if let Some(slot) = self
            .interfaces
            .iter()
            .find(|slot| matches!(slot.get(), Some(state) if state.interface_id == interface_id))
        {
            slot.set(Some(TdispInterfaceState::new(interface_id)));
            return true;
        }
        if let Some(slot) = self.interfaces.iter().find(|slot| slot.get().is_none()) {
            slot.set(Some(TdispInterfaceState::new(interface_id)));
            return true;
        }
        false
    }

    fn set_nonce(
        &self,
        interface_id: InterfaceId,
        nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
    ) -> bool {
        if let Some(slot) = self
            .interfaces
            .iter()
            .find(|slot| matches!(slot.get(), Some(state) if state.interface_id == interface_id))
        {
            slot.set(Some(TdispInterfaceState {
                interface_id,
                start_interface_nonce: nonce,
            }));
            return true;
        }
        false
    }
}

#[derive(Clone, Copy)]
struct TdispInterfaceState {
    interface_id: InterfaceId,
    start_interface_nonce: Option<[u8; START_INTERFACE_NONCE_SIZE]>,
}

impl TdispInterfaceState {
    const fn new(interface_id: InterfaceId) -> Self {
        Self {
            interface_id,
            start_interface_nonce: None,
        }
    }
}

/// Minimal emulator implementation for DOE/SPDM TDISP validation.
pub struct EmulatedTdispDriver {
    state: Cell<TdiStatus>,
    nonce_counter: Cell<u8>,
}

impl EmulatedTdispDriver {
    /// Creates an emulator driver in CONFIG_UNLOCKED state.
    pub const fn new() -> Self {
        Self {
            state: Cell::new(TdiStatus::ConfigUnlocked),
            nonce_counter: Cell::new(0),
        }
    }
}

impl Default for EmulatedTdispDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl TdispDriver for EmulatedTdispDriver {
    async fn generate_start_interface_nonce(
        &self,
        out: &mut [u8; START_INTERFACE_NONCE_SIZE],
    ) -> TdispDriverResult<()> {
        let start = self.nonce_counter.get().wrapping_add(1);
        self.nonce_counter.set(start);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = start.wrapping_add(i as u8);
        }
        Ok(())
    }

    async fn get_capabilities(
        &self,
        _req_caps: TdispReqCapabilities,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32> {
        *resp_caps = TdispRespCapabilities::new(
            0x01,
            [
                0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            0x1f,
            48,
            1,
            1,
        );
        Ok(0)
    }

    async fn lock_interface(
        &self,
        _function_id: FunctionId,
        _param: TdispLockInterfaceParam,
    ) -> TdispDriverResult<u32> {
        if self.state.get() != TdiStatus::ConfigUnlocked {
            return Ok(TdispError::InvalidInterfaceState as u32);
        }
        self.state.set(TdiStatus::ConfigLocked);
        Ok(0)
    }

    async fn get_device_interface_report_len(
        &self,
        _function_id: FunctionId,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32> {
        *intf_report_len = 16;
        Ok(0)
    }

    async fn get_device_interface_report(
        &self,
        _function_id: FunctionId,
        offset: u16,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32> {
        let data = [0u8; 16];
        let offset = offset as usize;
        if offset >= data.len() || offset + report.len() > data.len() {
            return Ok(TdispError::InvalidRequest as u32);
        }
        let end = offset + report.len();
        report.copy_from_slice(&data[offset..end]);
        *copied = report.len();
        Ok(0)
    }

    async fn get_device_interface_state(
        &self,
        _function_id: FunctionId,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32> {
        *tdi_state = self.state.get();
        Ok(0)
    }

    async fn start_interface(&self, _function_id: FunctionId) -> TdispDriverResult<u32> {
        if self.state.get() != TdiStatus::ConfigLocked {
            return Ok(TdispError::InvalidInterfaceState as u32);
        }
        self.state.set(TdiStatus::Run);
        Ok(0)
    }

    async fn stop_interface(&self, _function_id: FunctionId) -> TdispDriverResult<u32> {
        self.state.set(TdiStatus::ConfigUnlocked);
        Ok(0)
    }
}

fn read_u16(input: &[u8]) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&input[..2]);
    u16::from_le_bytes(bytes)
}

fn read_u32(input: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&input[..4]);
    u32::from_le_bytes(bytes)
}

fn read_u64(input: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&input[..8]);
    u64::from_le_bytes(bytes)
}

fn ct_eq(a: &[u8; START_INTERFACE_NONCE_SIZE], b: &[u8; START_INTERFACE_NONCE_SIZE]) -> bool {
    let mut diff = 0u8;
    for i in 0..START_INTERFACE_NONCE_SIZE {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci_sig::{PciSigTdispVdm, TDISP_PROTOCOL_ID};
    use crate::{SpdmVdmBackend, StandardsBodyId, VdmRequest, VdmResponseBuffers};

    const VENDOR_ID: u16 = 0x1414;
    const IFACE: [u8; TDISP_HEADER_LEN - 2] = [0u8; TDISP_HEADER_LEN - 2];

    fn request(command: TdispCommand, payload: &[u8], out: &mut [u8]) -> usize {
        out[0] = TDISP_VERSION_1_0;
        out[1] = command as u8;
        out[2..TDISP_HEADER_LEN].copy_from_slice(&IFACE);
        out[TDISP_HEADER_LEN..TDISP_HEADER_LEN + payload.len()].copy_from_slice(payload);
        TDISP_HEADER_LEN + payload.len()
    }

    #[test]
    fn test_version_lock_start_stop_flow() {
        futures::executor::block_on(async {
            let backend = PciSigTdispVdm::new(
                VENDOR_ID,
                TdispResponder::new(&[TdispVersion::V10], EmulatedTdispDriver::new()),
            );
            let mut req_buf = [0u8; 128];
            let mut rsp_buf = [0u8; 128];

            req_buf[0] = TDISP_PROTOCOL_ID;
            let len = request(TdispCommand::GetTdispVersion, &[], &mut req_buf[1..]) + 1;
            let got = backend
                .handle_request(
                    VdmRequest {
                        standard_id: StandardsBodyId::PciSig,
                        vendor_id: &VENDOR_ID.to_le_bytes(),
                        secure_session: true,
                        payload: &req_buf[..len],
                    },
                    VdmResponseBuffers {
                        inline: &mut rsp_buf,
                        large: None,
                    },
                )
                .await;
            assert!(matches!(got, Ok(VdmResponseKind::Inline(19))));
            assert_eq!(rsp_buf[0], TDISP_PROTOCOL_ID);
            assert_eq!(rsp_buf[2], TdispCommand::TdispVersion as u8);
            assert_eq!(rsp_buf[17], 1);
            assert_eq!(rsp_buf[18], TDISP_VERSION_1_0);

            let lock_payload = [0u8; LOCK_INTERFACE_PARAM_LEN];
            req_buf[0] = TDISP_PROTOCOL_ID;
            let len = request(
                TdispCommand::LockInterface,
                &lock_payload,
                &mut req_buf[1..],
            ) + 1;
            let got = backend
                .handle_request(
                    VdmRequest {
                        standard_id: StandardsBodyId::PciSig,
                        vendor_id: &VENDOR_ID.to_le_bytes(),
                        secure_session: true,
                        payload: &req_buf[..len],
                    },
                    VdmResponseBuffers {
                        inline: &mut rsp_buf,
                        large: None,
                    },
                )
                .await;
            assert!(matches!(got, Ok(VdmResponseKind::Inline(49))));
            let mut nonce = [0u8; START_INTERFACE_NONCE_SIZE];
            nonce.copy_from_slice(&rsp_buf[17..49]);

            req_buf[0] = TDISP_PROTOCOL_ID;
            let len = request(
                TdispCommand::StartInterfaceRequest,
                &nonce,
                &mut req_buf[1..],
            ) + 1;
            let got = backend
                .handle_request(
                    VdmRequest {
                        standard_id: StandardsBodyId::PciSig,
                        vendor_id: &VENDOR_ID.to_le_bytes(),
                        secure_session: true,
                        payload: &req_buf[..len],
                    },
                    VdmResponseBuffers {
                        inline: &mut rsp_buf,
                        large: None,
                    },
                )
                .await;
            assert!(matches!(got, Ok(VdmResponseKind::Inline(17))));
            assert_eq!(rsp_buf[2], TdispCommand::StartInterfaceResponse as u8);
        });
    }
}
