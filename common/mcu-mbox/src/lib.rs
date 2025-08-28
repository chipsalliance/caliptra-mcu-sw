// Licensed under the Apache-2.0 license

// Define MCU mailbox request and response structures to share between MCU runtime and emulator (for testing).

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod codec;

use crate::codec::{Codec, CodecError};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};

pub use caliptra_api::mailbox::{
    populate_checksum, MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize, Response,
    ResponseVarSize, VarSizeDataResp,
};
pub use caliptra_api::{calc_checksum, verify_checksum};

use core::convert::From;
use core::num::{NonZeroU32, TryFromIntError};

pub const MAX_RESP_DATA_SIZE: usize = 1024;
pub const MAX_FW_VERSION_STR_LEN: usize = 32;

/// Caliptra Error Type
/// Derives debug, copy, clone, eq, and partial eq
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
    pub const MCU_RUNTIME_INSUFFICIENT_MEMORY: McuMboxError = Self::new_const(0x0000_0002);
}

/// A trait implemented by request types. Describes the associated command ID
/// and response type.
pub trait Request: IntoBytes + FromBytes + Immutable + KnownLayout {
    const ID: CommandId;
    type Resp: Response;
}

/* MCU mailbox command ID

| **Name**                          | **Command Code** | **Description**                                                                                     |
|-----------------------------------|------------------|-----------------------------------------------------------------------------------------------------|
| MC_FIRMWARE_VERSION               | 0x4D46_5756 ("MFWV") | Retrieves the version of the target firmware.                                                      |
| MC_DEVICE_CAPABILITIES            | 0x4D43_4150 ("MCAP") | Retrieve the device capabilities.                                                                  |
| MC_DEVICE_ID                      | 0x4D44_4944 ("MDID") | Retrieves the device ID.                                                                           |
| MC_DEVICE_INFO                    | 0x4D44_494E ("MDIN") | Retrieves information about the target device.                                                     |
| MC_GET_LOG                        | 0x4D47_4C47 ("MGLG") | Retrieves the internal log for the RoT.                                                            |
| MC_CLEAR_LOG                      | 0x4D43_4C47 ("MCLG") | Clears the log in the RoT subsystem.                                                               |


## Command Format

### MC_FIRMWARE_VERSION

Retrieves the version of the target firmware.

Command Code: `0x4D46_5756` ("MFWV")

*Table: `MC_FIRMWARE_VERSION` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |
| index      |  u32           | - `00h` = Caliptra core firmware       |
|            |                | - `01h` = MCU runtime firmware         |
|            |                | - `02h` = SoC firmware                 |
|            |                |Additional indexes are firmware-specific |

*Table: `MC_FIRMWARE_VERSION` output arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |
| fips_status|  u32           | FIPS approved or an error               |
| version    |  u8[32]        | Firmware Version Number in ASCII format |

### MC_DEVICE_CAPABILITIES

Retrieve the device capabilites.

Command Code: `0x4D43_4150` ("MCAP")

*Table: `MC_DEVICE_CAPABILITIES` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |

*Table: `MC_DEVICE_CAPABILITIES` output arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     | u32            |                                         |
| fips_status | u32            | FIPS approved or an error    |
| caps       | u8[32]         | - Bytes [0:7]: Reserved for Caliptra RT |
|            |                | - Bytes [8:11]: Reserved for Caliptra FMC |
|            |                | - Bytes [12:15]: Reserved for Caliptra ROM |
|            |                | - Bytes [16:23]: Reserved for MCU RT    |
|            |                | - Bytes [24:27]: Reserved for MCU ROM   |
|            |                | - Bytes [28:31]: Reserved               |

### MC_DEVICE_ID

Retrieves the device ID.

Command Code: `0x4D44_4944` ("MDID")

*Table: `MC_DEVICE_ID` input arguments*
| **Name**   | **Type**       | **Description**                         |
| ---------- | -------------- | --------------------------------------- |
| chksum     |  u32           |                                         |

*Table: `MC_DEVICE_ID` output arguments*
| **Name**               | **Type** | **Description**               |
|------------------------| -------- | ----------------------------- |
| chksum                 |  u32     |                               |
| fips_status            | u32      | FIPS approved or an error     |
| vendor_id              | u16      | Vendor ID; LSB                |
| device_id              | u16      | Device ID; LSB                |
| subsystem_vendor_id    | u16      | Subsystem Vendor ID; LSB      |
| subsystem_id           | u16      | Subsystem ID; LSB             |

### MC_DEVICE_INFO

Retrieves information about the target device.

Command Code: `0x4D44_494E` ("MDIN")

*Table: `MC_DEVICE_INFO` input arguments*
| **Name**   | **Type** | **Description**                         |
| ---------- | -------- | --------------------------------------- |
| chksum     | u32      |                                         |
| index      | u32      | Information Index:                     |
|            |          | - `00h` = Unique Chip Identifier       |
|            |          | Additional indexes are firmware-specific |

*Table: `MC_DEVICE_INFO` output arguments*
| **Name**    | **Type**       | **Description**                         |
| ----------- | -------------- | --------------------------------------- |
| chksum      | u32            |                                         |
| fips_status | u32            | FIPS approved or an error              |
| data_size   | u32            | Size of the requested data in bytes     |
| data        | u8[data_size]  | Requested information in binary format  |
*/

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

// Contains all the possible mailbox response structs
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum McuMailboxReq {
    FirmwareVersion(FirmwareVersionReq),
    //DeviceCaps(DeviceCapsReq),
    //DeviceId(DeviceIdReq),
    //DeviceInfo(DeviceInfoReq),
    //GetLog(GetLogReq),
    //ClearLog(ClearLogReq),
}

impl McuMailboxReq {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            McuMailboxReq::FirmwareVersion(_) => CommandId::MC_FIRMWARE_VERSION,
        }
    }

    /// Calculate and set the checksum for a request payload
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

// Contains all the possible mailbox response structs
#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum McuMailboxResp {
    Header(MailboxRespHeader),
    FirmwareVersion(FirmwareVersionResp),
    //DeviceCaps(DeviceCapsResp),
    //DeviceId(DeviceIdResp),
    //DeviceInfo(DeviceInfoResp),
    //GetLog(GetLogResp),
    //ClearLog(ClearLogResp),
}

impl McuMailboxResp {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial(),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial_mut(),
        }
    }

    /// Calculate and set the checksum for a response payload
    /// Takes into account the size override for variable-length payloads
    pub fn populate_chksum(&mut self) -> McuMboxResult<()> {
        // Calc checksum, use the size override if provided
        let resp_bytes = self.as_bytes()?;
        if size_of::<u32>() >= resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE);
        }
        let checksum = calc_checksum(0, &resp_bytes[size_of::<u32>()..]);

        let mut_resp_bytes = self.as_mut_bytes()?;
        if size_of::<MailboxRespHeader>() > mut_resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE);
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
    Combo, // Version number for combo firmware (e.g. Caliptra + MCU + SoC)
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
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVersionResp {
    pub hdr: MailboxRespHeader,
    pub len: u32,
    pub version: [u8; FirmwareVersionResp::MAX_FW_VERSION_LEN], // variable length
}

// Implement the Response trait for FirmwareVersionResp
impl Response for FirmwareVersionResp {}

impl FirmwareVersionResp {
    pub const MAX_FW_VERSION_LEN: usize = 32;

    pub fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
        if self.len as usize > Self::MAX_FW_VERSION_LEN {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_FW_VERSION_LEN - self.len as usize;
        Ok(&self.as_bytes()[..size_of::<Self>() - unused_byte_count])
    }

    pub fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
        if self.len as usize > Self::MAX_FW_VERSION_LEN {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE);
        }
        let unused_byte_count = Self::MAX_FW_VERSION_LEN - self.len as usize;
        Ok(&mut self.as_mut_bytes()[..size_of::<Self>() - unused_byte_count])
    }
}

impl Default for FirmwareVersionResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            len: 0,
            version: [0u8; Self::MAX_FW_VERSION_LEN],
        }
    }
}
