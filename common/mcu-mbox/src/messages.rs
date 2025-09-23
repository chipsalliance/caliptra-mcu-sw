// Licensed under the Apache-2.0 license

pub use caliptra_api::mailbox::{MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize};
pub use caliptra_api::{calc_checksum, verify_checksum};
use core::convert::From;
use core::num::NonZeroU32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAX_RESP_DATA_SIZE: usize = 4 * 1024;
pub const MAX_FW_VERSION_STR_LEN: usize = 32;
pub const DEVICE_CAPS_SIZE: usize = 32;
pub const MAX_UUID_SIZE: usize = 32;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct McuMboxError(pub NonZeroU32);
pub type McuMboxResult<T> = Result<T, McuMboxError>;

impl McuMboxError {
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("McuMboxError cannot be 0"),
        }
    }
    // add a new error type
    pub const MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE: McuMboxError = Self::new_const(0x0000_0001);
    pub const MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT: McuMboxError = Self::new_const(0x0000_0002);
    pub const MCU_RUNTIME_INSUFFICIENT_MEMORY: McuMboxError = Self::new_const(0x0000_0003);
}

/// A trait implemented by request types. Describes the associated command ID
/// and response type.
pub trait Request: IntoBytes + FromBytes + Immutable + KnownLayout {
    const ID: CommandId;
    type Resp: Response;
}

/// A trait implemented by response types.
pub trait Response: IntoBytes + FromBytes
where
    Self: Sized,
{
    /// The minimum size (in bytes) of this response. Transports that receive at
    /// least this much data should pad the missing data with zeroes. If they
    /// receive fewer bytes than MIN_SIZE, they should error.
    const MIN_SIZE: usize = core::mem::size_of::<Self>();
}

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const MC_FIRMWARE_VERSION: Self = Self(0x4D46_5756); // "MFWV"
    pub const MC_DEVICE_CAPABILITIES: Self = Self(0x4D43_4150); // "MCAP"
    pub const MC_DEVICE_ID: Self = Self(0x4D44_4944); // "MDID"
    pub const MC_DEVICE_INFO: Self = Self(0x4D44_494E); // "MDIN"
    pub const MC_GET_LOG: Self = Self(0x4D47_4C47); // "MGLG"
    pub const MC_CLEAR_LOG: Self = Self(0x4D43_4C47); // "MCLG"
}

impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

// Contains all the possible MCU mailbox request structs
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum McuMailboxReq {
    FirmwareVersion(FirmwareVersionReq),
    DeviceCaps(DeviceCapsReq),
    DeviceId(DeviceIdReq),
    DeviceInfo(DeviceInfoReq),
    GetLog(GetLogReq),
    ClearLog(ClearLogReq),
}

impl McuMailboxReq {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_bytes()),
            McuMailboxReq::DeviceCaps(req) => Ok(req.as_bytes()),
            McuMailboxReq::DeviceId(req) => Ok(req.as_bytes()),
            McuMailboxReq::DeviceInfo(req) => Ok(req.as_bytes()),
            McuMailboxReq::GetLog(req) => Ok(req.as_bytes()),
            McuMailboxReq::ClearLog(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DeviceCaps(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DeviceId(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DeviceInfo(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::GetLog(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ClearLog(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            McuMailboxReq::FirmwareVersion(_) => CommandId::MC_FIRMWARE_VERSION,
            McuMailboxReq::DeviceCaps(_) => CommandId::MC_DEVICE_CAPABILITIES,
            McuMailboxReq::DeviceId(_) => CommandId::MC_DEVICE_ID,
            McuMailboxReq::DeviceInfo(_) => CommandId::MC_DEVICE_INFO,
            McuMailboxReq::GetLog(_) => CommandId::MC_GET_LOG,
            McuMailboxReq::ClearLog(_) => CommandId::MC_CLEAR_LOG,
        }
    }

    // Calculate and set the checksum for a request payload
    pub fn populate_chksum(&mut self) -> McuMboxResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = calc_checksum(
            self.cmd_code().into(),
            &self.as_bytes()?[size_of::<i32>()..],
        );

        let hdr: &mut MailboxReqHeader = MailboxReqHeader::mut_from_bytes(
            &mut self.as_mut_bytes()?[..size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| McuMboxError::MCU_RUNTIME_INSUFFICIENT_MEMORY)?;

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

// Contains all the possible MCU mailbox response structs
#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum McuMailboxResp {
    Header(MailboxRespHeader),
    FirmwareVersion(FirmwareVersionResp),
    DeviceCaps(DeviceCapsResp),
    DeviceId(DeviceIdResp),
    DeviceInfo(DeviceInfoResp),
    GetLog(GetLogResp),
    ClearLog(ClearLogResp),
}

/// A trait for responses with variable size data.
pub trait McuResponseVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn data(&self) -> McuMboxResult<&[u8]> {
        let (hdr, data) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.data_len as usize)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> McuMboxResult<usize> {
        let (hdr, _) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(core::mem::size_of::<MailboxRespHeaderVarSize>() + hdr.data_len as usize)
    }

    fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
        self.as_bytes()
            .get(..self.partial_len()?)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
        let partial_len = self.partial_len()?;
        self.as_mut_bytes()
            .get_mut(..partial_len)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }
}
impl<T: McuResponseVarSize> Response for T {
    const MIN_SIZE: usize = core::mem::size_of::<MailboxRespHeaderVarSize>();
}

impl McuMailboxResp {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial(),
            McuMailboxResp::DeviceCaps(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DeviceId(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DeviceInfo(resp) => resp.as_bytes_partial(),
            McuMailboxResp::GetLog(resp) => resp.as_bytes_partial(),
            McuMailboxResp::ClearLog(resp) => Ok(resp.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::DeviceCaps(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DeviceId(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DeviceInfo(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::GetLog(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::ClearLog(resp) => Ok(resp.as_mut_bytes()),
        }
    }

    /// Calculate and set the checksum for a response payload.
    pub fn populate_chksum(&mut self) -> McuMboxResult<()> {
        // Calc checksum, use the size override if provided
        let resp_bytes = self.as_bytes()?;
        if size_of::<u32>() >= resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT);
        }
        let checksum = calc_checksum(0, &resp_bytes[size_of::<u32>()..]);

        let mut_resp_bytes = self.as_mut_bytes()?;
        if size_of::<MailboxRespHeader>() > mut_resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT);
        }
        let hdr: &mut MailboxRespHeader = MailboxRespHeader::mut_from_bytes(
            &mut mut_resp_bytes[..size_of::<MailboxRespHeader>()],
        )
        .map_err(|_| McuMboxError::MCU_RUNTIME_INSUFFICIENT_MEMORY)?;

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FwIndex {
    CaliptraCore,
    McuRuntime,
    SoC,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVersionReq {
    pub hdr: MailboxReqHeader,
    pub index: u32,
}
impl Request for FirmwareVersionReq {
    const ID: CommandId = CommandId::MC_FIRMWARE_VERSION;
    type Resp = FirmwareVersionResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVersionResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub version: [u8; MAX_FW_VERSION_STR_LEN], // variable length
}
impl McuResponseVarSize for FirmwareVersionResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceCapsReq {
    pub hdr: MailboxReqHeader,
}
impl Request for DeviceCapsReq {
    const ID: CommandId = CommandId::MC_DEVICE_CAPABILITIES;
    type Resp = DeviceCapsResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceCapsResp {
    pub hdr: MailboxRespHeader,
    pub caps: [u8; DEVICE_CAPS_SIZE],
}
impl Response for DeviceCapsResp {}

// Define device id and device info structures for future use
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceIdReq {
    pub hdr: MailboxReqHeader,
}
impl Request for DeviceIdReq {
    const ID: CommandId = CommandId::MC_DEVICE_ID;
    type Resp = DeviceIdResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceIdResp {
    pub hdr: MailboxRespHeader,
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}
impl Response for DeviceIdResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceInfoReq {
    pub hdr: MailboxReqHeader,
    pub index: u32,
}
impl Request for DeviceInfoReq {
    const ID: CommandId = CommandId::MC_DEVICE_INFO;
    type Resp = DeviceInfoResp;
}
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceInfoResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_UUID_SIZE], // variable length
}
impl McuResponseVarSize for DeviceInfoResp {}

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LogType {
    DebugLog = 0,
    AttestationLog = 1,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLogReq {
    pub hdr: MailboxReqHeader,
    pub log_type: u32,
}
impl Request for GetLogReq {
    const ID: CommandId = CommandId::MC_GET_LOG;
    type Resp = GetLogResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLogResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_RESP_DATA_SIZE], // variable length
}
impl McuResponseVarSize for GetLogResp {}

impl Default for GetLogResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_RESP_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ClearLogReq {
    pub hdr: MailboxReqHeader,
    pub log_type: u32,
}
impl Request for ClearLogReq {
    const ID: CommandId = CommandId::MC_CLEAR_LOG;
    type Resp = ClearLogResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ClearLogResp(MailboxRespHeader);
impl Response for ClearLogResp {}
