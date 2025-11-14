// Licensed under the Apache-2.0 license

pub use caliptra_api::mailbox::{
    CmAesDecryptInitReq, CmAesDecryptUpdateReq, CmAesEncryptInitReq, CmAesEncryptInitResp,
    CmAesEncryptUpdateReq, CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp,
    CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq,
    CmAesGcmDecryptUpdateResp, CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp,
    CmAesGcmEncryptInitReq, CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq,
    CmAesGcmEncryptUpdateResp, CmAesResp, CmDeleteReq, CmEcdhGenerateReq, CmImportReq,
    CmImportResp, CmKeyUsage, CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq,
    CmShaFinalReq, CmShaFinalResp, CmShaInitReq, CmShaInitResp, CmShaUpdateReq, CmStatusResp, Cmk,
    MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize, ResponseVarSize,
    MAX_CMB_DATA_SIZE,
};
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
    pub const MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE: McuMboxError = Self::new_const(0x0000_0004);
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
    pub const MC_SHA_INIT: Self = Self(0x4D43_5349); // "MCSI"
    pub const MC_SHA_UPDATE: Self = Self(0x4D43_5355); // "MCSU"
    pub const MC_SHA_FINAL: Self = Self(0x4D43_5346); // "MCSF"
    pub const MC_AES_ENCRYPT_INIT: Self = Self(0x4D43_4349); // "MCCI"
    pub const MC_AES_ENCRYPT_UPDATE: Self = Self(0x4D43_4355); // "MCMU"
    pub const MC_AES_DECRYPT_INIT: Self = Self(0x4D43_414A); // "MCAJ"
    pub const MC_AES_DECRYPT_UPDATE: Self = Self(0x4D43_4155); // "MCAU"
    pub const MC_AES_GCM_ENCRYPT_INIT: Self = Self(0x4D43_4749); // "MCGI"
    pub const MC_AES_GCM_ENCRYPT_UPDATE: Self = Self(0x4D43_4755); // "MCGU"
    pub const MC_AES_GCM_ENCRYPT_FINAL: Self = Self(0x4D43_4746); // "MCGF"
    pub const MC_AES_GCM_DECRYPT_INIT: Self = Self(0x4D43_4449); // "MCDI"
    pub const MC_AES_GCM_DECRYPT_UPDATE: Self = Self(0x4D43_4455); // "MCDU"
    pub const MC_AES_GCM_DECRYPT_FINAL: Self = Self(0x4D43_4446); // "MCDF"
    pub const MC_RANDOM_STIR: Self = Self(0x4D43_5253); // "MCRS"
    pub const MC_RANDOM_GENERATE: Self = Self(0x4D43_5247); // "MCRG"
    pub const MC_IMPORT: Self = Self(0x4D43_494D); // "MCIM"
    pub const MC_DELETE: Self = Self(0x4D43_444C); // "MCDL"
    pub const MC_CM_STATUS: Self = Self(0x4D43_5354); // "MCST"
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
    ShaInit(McuShaInitReq),
    ShaUpdate(McuShaUpdateReq),
    ShaFinal(McuShaFinalReq),
    AesEncryptInit(McuAesEncryptInitReq),
    AesEncryptUpdate(McuAesEncryptUpdateReq),
    AesDecryptInit(McuAesDecryptInitReq),
    AesDecryptUpdate(McuAesDecryptUpdateReq),
    AesGcmEncryptInit(McuAesGcmEncryptInitReq),
    AesGcmEncryptUpdate(McuAesGcmEncryptUpdateReq),
    AesGcmEncryptFinal(McuAesGcmEncryptFinalReq),
    AesGcmDecryptInit(McuAesGcmDecryptInitReq),
    AesGcmDecryptUpdate(McuAesGcmDecryptUpdateReq),
    AesGcmDecryptFinal(McuAesGcmDecryptFinalReq),
    Import(McuCmImportReq),
    Delete(McuCmDeleteReq),
    CmStatus(McuCmStatusReq),
    RandomStir(McuRandomStirReq),
    RandomGenerate(McuRandomGenerateReq),
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
            McuMailboxReq::ShaInit(req) => req.as_bytes_partial(),
            McuMailboxReq::ShaUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::ShaFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::AesEncryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesEncryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesDecryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesDecryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::Import(req) => req.as_bytes_partial(),
            McuMailboxReq::Delete(req) => Ok(req.as_bytes()),
            McuMailboxReq::CmStatus(req) => Ok(req.as_bytes()),
            McuMailboxReq::RandomStir(req) => req.as_bytes_partial(),
            McuMailboxReq::RandomGenerate(req) => Ok(req.as_bytes()),
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
            McuMailboxReq::ShaInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::ShaUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::ShaFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesEncryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesEncryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesDecryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesDecryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Import(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Delete(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::CmStatus(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::RandomStir(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::RandomGenerate(req) => Ok(req.as_mut_bytes()),
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
            McuMailboxReq::ShaInit(_) => CommandId::MC_SHA_INIT,
            McuMailboxReq::ShaUpdate(_) => CommandId::MC_SHA_UPDATE,
            McuMailboxReq::ShaFinal(_) => CommandId::MC_SHA_FINAL,
            McuMailboxReq::AesEncryptInit(_) => CommandId::MC_AES_ENCRYPT_INIT,
            McuMailboxReq::AesEncryptUpdate(_) => CommandId::MC_AES_ENCRYPT_UPDATE,
            McuMailboxReq::AesDecryptInit(_) => CommandId::MC_AES_DECRYPT_INIT,
            McuMailboxReq::AesDecryptUpdate(_) => CommandId::MC_AES_DECRYPT_UPDATE,
            McuMailboxReq::AesGcmEncryptInit(_) => CommandId::MC_AES_GCM_ENCRYPT_INIT,
            McuMailboxReq::AesGcmEncryptUpdate(_) => CommandId::MC_AES_GCM_ENCRYPT_UPDATE,
            McuMailboxReq::AesGcmEncryptFinal(_) => CommandId::MC_AES_GCM_ENCRYPT_FINAL,
            McuMailboxReq::AesGcmDecryptInit(_) => CommandId::MC_AES_GCM_DECRYPT_INIT,
            McuMailboxReq::AesGcmDecryptUpdate(_) => CommandId::MC_AES_GCM_DECRYPT_UPDATE,
            McuMailboxReq::AesGcmDecryptFinal(_) => CommandId::MC_AES_GCM_DECRYPT_FINAL,
            McuMailboxReq::Import(_) => CommandId::MC_IMPORT,
            McuMailboxReq::Delete(_) => CommandId::MC_DELETE,
            McuMailboxReq::CmStatus(_) => CommandId::MC_CM_STATUS,
            McuMailboxReq::RandomStir(_) => CommandId::MC_RANDOM_STIR,
            McuMailboxReq::RandomGenerate(_) => CommandId::MC_RANDOM_GENERATE,
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
    ShaInit(McuShaInitResp),
    ShaUpdate(McuShaInitResp),
    ShaFinal(McuShaFinalResp),
    AesEncryptInit(McuAesEncryptInitResp),
    AesEncryptUpdate(McuAesEncryptUpdateResp),
    AesDecryptInit(McuAesDecryptInitResp),
    AesDecryptUpdate(McuAesDecryptUpdateResp),
    AesGcmEncryptInit(McuAesGcmEncryptInitResp),
    AesGcmEncryptUpdate(McuAesGcmEncryptUpdateResp),
    AesGcmEncryptFinal(McuAesGcmEncryptFinalResp),
    AesGcmDecryptInit(McuAesGcmDecryptInitResp),
    AesGcmDecryptUpdate(McuAesGcmDecryptUpdateResp),
    AesGcmDecryptFinal(McuAesGcmDecryptFinalResp),
    Import(McuCmImportResp),
    Delete(McuCmDeleteResp),
    CmStatus(McuCmStatusResp),
    RandomStir(McuRandomStirResp),
    RandomGenerate(McuRandomGenerateResp),
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

// Macro to implement McuResponseVarSize for tuple response wrappers
macro_rules! impl_mcu_response_varsize {
    ($wrapper:ty, $inner:ty) => {
        impl McuResponseVarSize for $wrapper {
            fn data(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .data()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn partial_len(&self) -> McuMboxResult<usize> {
                self.0
                    .partial_len()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .as_bytes_partial()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
                self.0
                    .as_bytes_partial_mut()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
        }
    };
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
            McuMailboxResp::ShaInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ShaUpdate(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ShaFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesEncryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesEncryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesDecryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesDecryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmEncryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesGcmEncryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmEncryptFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmDecryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesGcmDecryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmDecryptFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::Import(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::Delete(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::CmStatus(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::RandomStir(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::RandomGenerate(resp) => resp.as_bytes_partial(),
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
            McuMailboxResp::ShaInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ShaUpdate(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ShaFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesGcmEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmEncryptFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesGcmDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmDecryptFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::Import(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::Delete(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::CmStatus(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::RandomStir(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::RandomGenerate(resp) => resp.as_bytes_partial_mut(),
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

pub trait McuRequestVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn as_bytes_partial(&self) -> McuMboxResult<&[u8]>;
    fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]>;
}

// Macro to implement McuRequestVarSize for tuple wrappers
macro_rules! impl_mcu_request_varsize {
    ($wrapper:ty, $inner:ty) => {
        impl McuRequestVarSize for $wrapper {
            fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .as_bytes_partial()
                    .map_err(|_| McuMboxError::MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
                self.0
                    .as_bytes_partial_mut()
                    .map_err(|_| McuMboxError::MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE)
            }
        }
    };
}

// Create a wrapper for ShaInitReq. MCU mailbox sha init request is the same format of CmShaInitReq
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuShaInitReq(pub CmShaInitReq);

impl Request for McuShaInitReq {
    const ID: CommandId = CommandId::MC_SHA_INIT;
    type Resp = McuShaInitResp;
}
impl_mcu_request_varsize!(McuShaInitReq, CmShaInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuShaInitResp(pub CmShaInitResp);
impl Response for McuShaInitResp {}

// Add ShaUpdateReq and ShaFinalReq similar to McuShaInitReq if needed in the future
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaUpdateReq(pub CmShaUpdateReq);
impl Request for McuShaUpdateReq {
    const ID: CommandId = CommandId::MC_SHA_UPDATE;
    type Resp = McuShaInitResp; // Same response as ShaInit
}
impl_mcu_request_varsize!(McuShaUpdateReq, CmShaUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaFinalReq(pub CmShaFinalReq);
impl Request for McuShaFinalReq {
    const ID: CommandId = CommandId::MC_SHA_FINAL;
    type Resp = McuShaFinalResp;
}
impl_mcu_request_varsize!(McuShaFinalReq, CmShaFinalReq);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaFinalResp(pub CmShaFinalResp);
impl_mcu_response_varsize!(McuShaFinalResp, CmShaFinalResp);

// ---- AES Encrypt/Decrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptInitReq(pub CmAesEncryptInitReq);
impl Request for McuAesEncryptInitReq {
    const ID: CommandId = CommandId::MC_AES_ENCRYPT_INIT;
    type Resp = McuAesEncryptInitResp;
}
impl_mcu_request_varsize!(McuAesEncryptInitReq, CmAesEncryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptInitResp(pub CmAesEncryptInitResp);
impl Response for McuAesEncryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptUpdateReq(pub CmAesEncryptUpdateReq);
impl Request for McuAesEncryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_ENCRYPT_UPDATE;
    type Resp = McuAesEncryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesEncryptUpdateReq, CmAesEncryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptUpdateResp(pub CmAesResp);
impl_mcu_response_varsize!(McuAesEncryptUpdateResp, CmAesResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptInitReq(pub CmAesDecryptInitReq);
impl Request for McuAesDecryptInitReq {
    const ID: CommandId = CommandId::MC_AES_DECRYPT_INIT;
    type Resp = McuAesDecryptInitResp;
}
impl_mcu_request_varsize!(McuAesDecryptInitReq, CmAesDecryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptInitResp(pub CmAesEncryptInitResp); // Reuse encrypt init resp if needed
impl Response for McuAesDecryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptUpdateReq(pub CmAesDecryptUpdateReq);
impl Request for McuAesDecryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_DECRYPT_UPDATE;
    type Resp = McuAesDecryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesDecryptUpdateReq, CmAesDecryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptUpdateResp(pub CmAesResp); // Reuse encrypt update resp if needed
impl_mcu_response_varsize!(McuAesDecryptUpdateResp, CmAesResp);

// ---- AES-GCM Encrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptInitReq(pub CmAesGcmEncryptInitReq);
impl Request for McuAesGcmEncryptInitReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_INIT;
    type Resp = McuAesGcmEncryptInitResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptInitReq, CmAesGcmEncryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptInitResp(pub CmAesGcmEncryptInitResp);
impl Response for McuAesGcmEncryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptUpdateReq(pub CmAesGcmEncryptUpdateReq);
impl Request for McuAesGcmEncryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_UPDATE;
    type Resp = McuAesGcmEncryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptUpdateResp(pub CmAesGcmEncryptUpdateResp);
impl_mcu_response_varsize!(McuAesGcmEncryptUpdateResp, CmAesGcmEncryptUpdateResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptFinalReq(pub CmAesGcmEncryptFinalReq);
impl Request for McuAesGcmEncryptFinalReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_FINAL;
    type Resp = McuAesGcmEncryptFinalResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptFinalReq, CmAesGcmEncryptFinalReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptFinalResp(pub CmAesGcmEncryptFinalResp);
impl_mcu_response_varsize!(McuAesGcmEncryptFinalResp, CmAesGcmEncryptFinalResp);

// ---- AES-GCM Decrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptInitReq(pub CmAesGcmDecryptInitReq);
impl Request for McuAesGcmDecryptInitReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_INIT;
    type Resp = McuAesGcmDecryptInitResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptInitReq, CmAesGcmDecryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptInitResp(pub CmAesGcmDecryptInitResp);
impl Response for McuAesGcmDecryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptUpdateReq(pub CmAesGcmDecryptUpdateReq);
impl Request for McuAesGcmDecryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_UPDATE;
    type Resp = McuAesGcmDecryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptUpdateResp(pub CmAesGcmDecryptUpdateResp);
impl_mcu_response_varsize!(McuAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptFinalReq(pub CmAesGcmDecryptFinalReq);
impl Request for McuAesGcmDecryptFinalReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_FINAL;
    type Resp = McuAesGcmDecryptFinalResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptFinalReq, CmAesGcmDecryptFinalReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptFinalResp(pub CmAesGcmDecryptFinalResp);
impl_mcu_response_varsize!(McuAesGcmDecryptFinalResp, CmAesGcmDecryptFinalResp);

// ---- MCU wrappers for Import, RandomStir, RandomGenerate ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmImportReq(pub CmImportReq);
impl Request for McuCmImportReq {
    const ID: CommandId = CommandId::MC_IMPORT;
    type Resp = McuCmImportResp;
}
impl_mcu_request_varsize!(McuCmImportReq, CmImportReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmImportResp(pub CmImportResp);
impl Response for McuCmImportResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmDeleteReq(pub CmDeleteReq);
impl Request for McuCmDeleteReq {
    const ID: CommandId = CommandId::MC_DELETE;
    type Resp = McuCmDeleteResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmStatusReq(pub MailboxReqHeader);
impl Request for McuCmStatusReq {
    const ID: CommandId = CommandId::MC_CM_STATUS;
    type Resp = McuCmStatusResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmStatusResp(pub CmStatusResp);
impl Response for McuCmStatusResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmDeleteResp(pub MailboxRespHeader);
impl Response for McuCmDeleteResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomStirReq(pub CmRandomStirReq);
impl Request for McuRandomStirReq {
    const ID: CommandId = CommandId::MC_RANDOM_STIR;
    type Resp = McuRandomStirResp;
}
impl_mcu_request_varsize!(McuRandomStirReq, CmRandomStirReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomStirResp(pub MailboxRespHeader);
impl Response for McuRandomStirResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomGenerateReq(pub CmRandomGenerateReq);
impl Request for McuRandomGenerateReq {
    const ID: CommandId = CommandId::MC_RANDOM_GENERATE;
    type Resp = McuRandomGenerateResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomGenerateResp(pub CmRandomGenerateResp);
impl_mcu_response_varsize!(McuRandomGenerateResp, CmRandomGenerateResp);
