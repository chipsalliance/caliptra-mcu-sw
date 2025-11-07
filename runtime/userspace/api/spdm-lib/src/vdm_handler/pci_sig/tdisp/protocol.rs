// Licensed under the Apache-2.0 license

use crate::codec::{CommonCodec, DataKind};
use crate::vdm_handler::{VdmError, VdmResult};
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const START_INTERFACE_NONCE_SIZE: usize = 32;

#[derive(Debug, PartialEq)]
pub enum TdispVersion {
    V10 = 0x10,
}

impl TryFrom<u8> for TdispVersion {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(TdispVersion::V10),
            _ => Err(VdmError::UnsupportedTdispVersion),
        }
    }
}

impl TdispVersion {
    pub fn to_u8(&self) -> u8 {
        match self {
            TdispVersion::V10 => 0x10,
        }
    }
}

/// TdispCommand represents the request/response code for TDISP messages.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TdispCommand {
    /// Request to get the TDISP version.
    GetTdispVersion = 0x81,
    /// Response containing the TDISP version supported by device.
    TdispVersion = 0x01,
    /// Request to get the TDISP capabilities.
    GetTdispCapabilities = 0x82,
    /// Response containing the TDISP capabilities.
    TdispCapabilities = 0x02,
    /// Move TDI to CONFIG_LOCKED state.
    LockInterface = 0x83,
    /// Response to LOCK_INTERFACE_REQUEST
    LockInterfaceResponse = 0x03,
    /// Obtain a TDI Report.
    GetDeviceInterfaceReport = 0x84,
    /// Report for a TDI
    DeviceInterfaceReport = 0x04,
    /// Obtain state of a TDI
    GetDeviceInterfaceState = 0x85,
    /// Return TDI state
    DeviceInterfaceState = 0x05,
    /// Start a TDI
    StartInterfaceRequest = 0x86,
    /// Response to request to move TDI to RUN state
    StartInterfaceResponse = 0x06,
    /// Stop and move TDI to CONFIG_UNLOCKED state(if not already in that state)
    StopInterfaceRequest = 0x87,
    /// Response to a STOP_INTERFACE_REQUEST
    StopInterfaceResponse = 0x07,
    /// Bind P2P sream request
    BindP2PStreamRequest = 0x88,
    /// Response to a BIND_P2P_STREAM_REQUEST
    BindP2PStreamResponse = 0x08,
    /// Unbind P2P stream request
    UnbindP2PStreamRequest = 0x89,
    /// Response to a UNBIND_P2P_STREAM_REQUEST
    UnbindP2PStreamResponse = 0x09,
    /// SET_MMIO_ATTRIBUTE_REQUEST
    SetMmioAttributeRequest = 0x8A,
    /// Response to a SET_MMIO_ATTRIBUTE_REQUEST
    SetMmioAttributeResponse = 0x0A,
    /// VDM_REQUEST
    VdmRequest = 0x8B,
    /// Response to a VDM_REQUEST
    VdmResponse = 0x0B,
    /// Error in handling request
    ErrorResponse = 0x7F,
}

impl TdispCommand {
    pub fn response(&self) -> VdmResult<Self> {
        match self {
            TdispCommand::GetTdispVersion => Ok(TdispCommand::TdispVersion),
            TdispCommand::GetTdispCapabilities => Ok(TdispCommand::TdispCapabilities),
            TdispCommand::LockInterface => Ok(TdispCommand::LockInterfaceResponse),
            TdispCommand::GetDeviceInterfaceReport => Ok(TdispCommand::DeviceInterfaceReport),
            TdispCommand::GetDeviceInterfaceState => Ok(TdispCommand::DeviceInterfaceState),
            TdispCommand::StartInterfaceRequest => Ok(TdispCommand::StartInterfaceResponse),
            TdispCommand::StopInterfaceRequest => Ok(TdispCommand::StopInterfaceResponse),
            TdispCommand::BindP2PStreamRequest => Ok(TdispCommand::BindP2PStreamResponse),
            TdispCommand::UnbindP2PStreamRequest => Ok(TdispCommand::UnbindP2PStreamResponse),
            TdispCommand::SetMmioAttributeRequest => Ok(TdispCommand::SetMmioAttributeResponse),
            TdispCommand::VdmRequest => Ok(TdispCommand::VdmResponse),
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }

    pub fn payload_size(&self) -> usize {
        match self {
            TdispCommand::GetTdispVersion => 0,
            TdispCommand::GetTdispCapabilities => size_of::<TdispReqCapabilities>(),
            TdispCommand::LockInterface => size_of::<TdispLockInterfaceParam>(),
            TdispCommand::GetDeviceInterfaceReport => size_of::<GetDeviceIntfReportReq>(),
            TdispCommand::GetDeviceInterfaceState => 0,
            TdispCommand::StartInterfaceRequest => START_INTERFACE_NONCE_SIZE,
            TdispCommand::StopInterfaceRequest => 0,
            TdispCommand::BindP2PStreamRequest => 0,
            TdispCommand::UnbindP2PStreamRequest => 0,
            TdispCommand::SetMmioAttributeRequest => 0,
            _ => 0,
        }
    }
}

impl TryFrom<u8> for TdispCommand {
    type Error = VdmError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x81 => Ok(TdispCommand::GetTdispVersion),
            0x01 => Ok(TdispCommand::TdispVersion),
            0x82 => Ok(TdispCommand::GetTdispCapabilities),
            0x02 => Ok(TdispCommand::TdispCapabilities),
            0x83 => Ok(TdispCommand::LockInterface),
            0x03 => Ok(TdispCommand::LockInterfaceResponse),
            0x84 => Ok(TdispCommand::GetDeviceInterfaceReport),
            0x04 => Ok(TdispCommand::DeviceInterfaceReport),
            0x85 => Ok(TdispCommand::GetDeviceInterfaceState),
            0x05 => Ok(TdispCommand::DeviceInterfaceState),
            0x86 => Ok(TdispCommand::StartInterfaceRequest),
            0x06 => Ok(TdispCommand::StartInterfaceResponse),
            0x87 => Ok(TdispCommand::StopInterfaceRequest),
            0x07 => Ok(TdispCommand::StopInterfaceResponse),
            0x88 => Ok(TdispCommand::BindP2PStreamRequest),
            0x08 => Ok(TdispCommand::BindP2PStreamResponse),
            0x89 => Ok(TdispCommand::UnbindP2PStreamRequest),
            0x09 => Ok(TdispCommand::UnbindP2PStreamResponse),
            0x8A => Ok(TdispCommand::SetMmioAttributeRequest),
            0x0A => Ok(TdispCommand::SetMmioAttributeResponse),
            0x8B => Ok(TdispCommand::VdmRequest),
            0x0B => Ok(TdispCommand::VdmResponse),
            0x7F => Ok(TdispCommand::ErrorResponse),
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }
}

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
            0x01 => TdispError::InvalidRequest,
            0x03 => TdispError::Busy,
            0x04 => TdispError::InvalidInterfaceState,
            0x05 => TdispError::Unspecified,
            0x07 => TdispError::UnsupportedRequest,
            0x41 => TdispError::VersionMismatch,
            0xFF => TdispError::VendorSpecificError,
            0x101 => TdispError::InvalidInterface,
            0x102 => TdispError::InvalidNonce,
            0x103 => TdispError::InsufficientEntropy,
            0x104 => TdispError::InvalidDeviceConfiguration,
            _ => TdispError::Unspecified,
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, Default, Debug, Copy, Clone, PartialEq)]
#[repr(C, packed)]
pub struct InterfaceId {
    pub function_id: FunctionId,
    pub reserved: u64, // 8 bytes reserved
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Copy, Clone, PartialEq)]
    #[repr(C)]
    pub struct FunctionId(u32);
    impl Debug;
    u16;
    pub requester_id, set_requester_id: 15, 0; // Bits 15:0 Requester ID
    u8;
    pub requester_segment, set_requester_segment: 23, 16; // Bits 23:16 Requester Segment
    pub requester_segment_valid, set_requester_segment_valid: 24, 24; // Bit 24 Requester Segment Valid
    reserved, _: 31, 25; // Bits 31:25 Reserved
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispMessageHeader {
    pub version: u8,
    pub message_type: u8,
    pub reserved: u16,
    pub interface_id: InterfaceId,
}

impl CommonCodec for TdispMessageHeader {
    const DATA_KIND: DataKind = DataKind::Header;
}

impl TdispMessageHeader {
    pub fn new(version: u8, message_type: TdispCommand, interface_id: InterfaceId) -> Self {
        TdispMessageHeader {
            version,
            message_type: message_type as u8,
            reserved: 0,
            interface_id,
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispReqCapabilities {
    pub tsm_caps: u32,
}

impl CommonCodec for TdispReqCapabilities {}

#[derive(FromBytes, IntoBytes, Immutable, Default, Clone, Copy)]
#[repr(C)]
pub struct TdispRespCapabilities {
    dsm_capabilities: u32,
    req_msgs_supported: [u8; 16],
    lock_interface_flags_supported: u16,
    reserved: [u8; 3],
    dev_addr_width: u8,
    num_req_this: u8,
    num_req_all: u8,
}

impl CommonCodec for TdispRespCapabilities {}

impl TdispRespCapabilities {
    pub fn new(
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
            reserved: [0; 3],
            dev_addr_width,
            num_req_this,
            num_req_all,
        }
    }
}

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispLockInterfaceFlags(u16);
impl Debug;
u8;
    pub no_fw_update, set_no_fw_update: 0, 0; // Bit 0 NO_FW_UPDATE
    pub system_cache_line_size, set_system_cache_line_size: 1, 1; // Bits 1:1 SYSTEM_CACHE_LINE_SIZE
    pub lock_msix, set_lock_msix: 2, 2; // Bit 2 LOCK_MSIX
    pub bind_p2p, set_bind_p2p: 3, 3; // Bit 3 BIND_P2P
    pub all_req_redirect, set_all_req_redirect: 4, 4; // Bit 4 ALL_REQUEST_REDIRECT
    pub reserved, _: 15, 5; // Bits 15:5 Reserved
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispLockInterfaceParam {
    flags: TdispLockInterfaceFlags,
    default_stream_id: u8,
    reserved: u8,
    mmio_reporting_offset: [u8; 8],
    bind_p2p_addr_mask: [u8; 8],
}

impl CommonCodec for TdispLockInterfaceParam {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct GetDeviceIntfReportReq {
    offset: u16,
    length: u16,
}

impl CommonCodec for GetDeviceIntfReportReq {}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TdiStatus {
    ConfigUnlocked = 0,
    ConfigLocked = 1,
    Run = 2,
    Error = 3,
    Reserved,
}

impl From<u8> for TdiStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => TdiStatus::ConfigUnlocked,
            1 => TdiStatus::ConfigLocked,
            2 => TdiStatus::Run,
            3 => TdiStatus::Error,
            _ => TdiStatus::Reserved,
        }
    }
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct TdiReportStructureBase {
    pub interface_info: InterfaceInfo,
    pub msi_x_message_control: u16,
    pub lnr_control: u16,
    pub tph_control: u32,
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Copy, Clone, PartialEq)]
    #[repr(C)]
    pub struct InterfaceInfo(u16);
    impl Debug;
    u8;
    pub fw_updates_permitted, set_fw_updates_permitted: 0, 0; // Bit 0 Firmware Updates Permitted
    pub dma_requests_without_pasid, set_dma_requests_without_pasid: 1, 1; // Bit 1- TDI generates DMA Requests Without PASID
    pub dma_requests_with_pasid, set_dma_requests_with_pasid: 2, 2; // Bit 2- TDI generates DMA Requests With PASID
    pub ats_supported_enabled, set_ats_supported_enabled: 3, 3; // Bit 3- ATS Supported and enabled for the TDI
    pub prs_supported_enabled, set_prs_supported_enabled: 4, 4; // Bit 4- PRS Supported and enabled for the TDI
    reserved, _: 15, 5; // Bits 15:5 Reserved
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
pub struct TdispMmioRange {
    pub first_page_with_offset_added: u64,
    pub number_of_pages: u32,
    pub range_attributes: MmioRangeAttribute,
}

impl CommonCodec for TdispMmioRange {}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default, Copy, Clone, PartialEq)]
    #[repr(C)]
    pub struct MmioRangeAttribute(u32);
    impl Debug;
    u8;
    pub msix_table, set_msix_table: 0, 0; // Bit 0 : if the range maps MSI-X Table
    pub msix_pba, set_msix_pba: 1, 1; // Bit 1 : if the range maps MSI-X PBA
    pub non_tee_memory, set_non_tee_memory: 2, 2; // Bit 2 : if range is Non-TEE Memory
    pub mem_attr_updatable, set_mem_attr_updatable: 3, 3; // Bit 3 : if attributes of this range is updatable
    reserved, _: 15, 4; // Bits 15:4 Reserved
    range_id, set_range_id: 31, 16; // Bits 31:16 Range ID
}
