// Licensed under the Apache-2.0 license

//! Shared TDISP wire protocol types.

use mcu_spdm_lite_codec::errors::{SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED};
use mcu_spdm_lite_traits::McuResult;

/// TDISP version 1.0 wire value.
pub const TDISP_VERSION_1_0: u8 = 0x10;
/// Size of the START_INTERFACE nonce.
pub const START_INTERFACE_NONCE_SIZE: usize = 32;
/// TDISP common message header length.
pub const TDISP_HEADER_LEN: usize = 16;
/// GET_TDISP_CAPABILITIES request payload length.
pub const TDISP_CAPS_REQ_LEN: usize = 4;
/// GET_TDISP_CAPABILITIES response payload length.
pub const TDISP_CAPS_RSP_LEN: usize = 28;
/// LOCK_INTERFACE request payload length.
pub const LOCK_INTERFACE_PARAM_LEN: usize = 20;
/// GET_DEVICE_INTERFACE_REPORT request payload length.
pub const DEVICE_INTERFACE_REPORT_REQ_LEN: usize = 4;
/// GET_DEVICE_INTERFACE_REPORT response payload header length.
pub const DEVICE_INTERFACE_REPORT_RSP_HDR_LEN: usize = 4;
/// TDISP ERROR response total length including the TDISP header.
pub const ERROR_RSP_LEN: usize = TDISP_HEADER_LEN + 8;

/// TDISP wire error code type.
pub type TdispErrorCode = u32;

/// INVALID_REQUEST TDISP wire error code.
pub const TDISP_ERROR_INVALID_REQUEST: TdispErrorCode = 0x01;
/// BUSY TDISP wire error code.
pub const TDISP_ERROR_BUSY: TdispErrorCode = 0x03;
/// INVALID_INTERFACE_STATE TDISP wire error code.
pub const TDISP_ERROR_INVALID_INTERFACE_STATE: TdispErrorCode = 0x04;
/// UNSPECIFIED TDISP wire error code.
pub const TDISP_ERROR_UNSPECIFIED: TdispErrorCode = 0x05;
/// UNSUPPORTED_REQUEST TDISP wire error code.
pub const TDISP_ERROR_UNSUPPORTED_REQUEST: TdispErrorCode = 0x07;
/// VERSION_MISMATCH TDISP wire error code.
pub const TDISP_ERROR_VERSION_MISMATCH: TdispErrorCode = 0x41;
/// VENDOR_SPECIFIC_ERROR TDISP wire error code.
pub const TDISP_ERROR_VENDOR_SPECIFIC_ERROR: TdispErrorCode = 0xff;
/// INVALID_INTERFACE TDISP wire error code.
pub const TDISP_ERROR_INVALID_INTERFACE: TdispErrorCode = 0x101;
/// INVALID_NONCE TDISP wire error code.
pub const TDISP_ERROR_INVALID_NONCE: TdispErrorCode = 0x102;
/// INSUFFICIENT_ENTROPY TDISP wire error code.
pub const TDISP_ERROR_INSUFFICIENT_ENTROPY: TdispErrorCode = 0x103;
/// INVALID_DEVICE_CONFIGURATION TDISP wire error code.
pub const TDISP_ERROR_INVALID_DEVICE_CONFIGURATION: TdispErrorCode = 0x104;

/// Maps a driver-provided TDISP wire error value to a supported response code.
pub const fn tdisp_error_code(value: u32) -> TdispErrorCode {
    match value {
        TDISP_ERROR_INVALID_REQUEST
        | TDISP_ERROR_BUSY
        | TDISP_ERROR_INVALID_INTERFACE_STATE
        | TDISP_ERROR_UNSPECIFIED
        | TDISP_ERROR_UNSUPPORTED_REQUEST
        | TDISP_ERROR_VERSION_MISMATCH
        | TDISP_ERROR_VENDOR_SPECIFIC_ERROR
        | TDISP_ERROR_INVALID_INTERFACE
        | TDISP_ERROR_INVALID_NONCE
        | TDISP_ERROR_INSUFFICIENT_ENTROPY
        | TDISP_ERROR_INVALID_DEVICE_CONFIGURATION => value,
        _ => TDISP_ERROR_UNSPECIFIED,
    }
}

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
    type Error = TdispErrorCode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TDISP_VERSION_1_0 => Ok(Self::V10),
            _ => Err(TDISP_ERROR_VERSION_MISMATCH),
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
    /// Returns the matching response command for a request command.
    pub(crate) const fn response(self) -> Option<Self> {
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

    /// Returns the exact request payload length used by spdm-lib.
    pub(crate) const fn payload_len(self) -> usize {
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
    type Error = TdispErrorCode;

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
            _ => Err(TDISP_ERROR_UNSUPPORTED_REQUEST),
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

    pub(crate) fn decode(input: &[u8]) -> McuResult<(Self, &[u8])> {
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

    pub(crate) fn encode(self, out: &mut [u8]) -> McuResult<()> {
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
    pub(crate) fn decode(input: &[u8]) -> McuResult<Self> {
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

    pub(crate) fn encode(self, out: &mut [u8]) -> McuResult<()> {
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
    pub(crate) fn decode(input: &[u8]) -> McuResult<Self> {
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

/// GET_DEVICE_INTERFACE_REPORT request payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeviceInterfaceReportReq {
    pub(crate) offset: u16,
    pub(crate) length: u16,
}

impl DeviceInterfaceReportReq {
    pub(crate) fn decode(input: &[u8]) -> McuResult<Self> {
        if input.len() != DEVICE_INTERFACE_REPORT_REQ_LEN {
            return Err(SPDM_INVALID_REQUEST);
        }
        Ok(Self {
            offset: read_u16(&input[0..2]),
            length: read_u16(&input[2..4]),
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

pub(crate) fn read_u16(input: &[u8]) -> u16 {
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

pub(crate) fn ct_eq(a: &[u8; START_INTERFACE_NONCE_SIZE], b: &[u8]) -> bool {
    if b.len() != START_INTERFACE_NONCE_SIZE {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in a.iter().zip(b.iter()) {
        diff |= *a ^ *b;
    }
    diff == 0
}
