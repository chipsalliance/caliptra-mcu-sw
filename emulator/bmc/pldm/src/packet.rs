//! # PLDM Packet Encoder/Decoder
//!
//! This module provides functionality for encoding and decoding a generic PLDM (Platform Level Data Model) packet.
//! It includes fields defined in the PLDM specification and the ability to work with PLDM message payloads.
//!
//! ## PLDM Packet Header Format
//!
//! The PLDM message format contains the following fields in the packet header:
//!
//! ```ascii
//!  +--------+--------+--------+--------+----------+
//!  | Rq | D | R |Instance ID | Hdr Ver | PLDM Type|
//!  +----------------------------------------------+
//!  |       PLDM Command Code       | Completion*  |
//!  +----------------------------------------------+
//!  |                PLDM Message Payload*         |
//!  +----------------------------------------------+
//! ```
//!
//! - **Rq** (Request bit): 1 bit
//! - **D** (Data Integrity Check): 1 bit
//! - **R** (Reserved): 1 bit
//! - **Instance ID**: 5 bits
//! - **Hdr Ver** (Header Version): 2 bits
//! - **PLDM Type**: 6 bits
//! - **PLDM Command Code**: 8 bits
//! - **PLDM Completion Code**: 8 bits (optional)
//! - **Payload**: Variable-length message payload (optional)

use num_derive::{FromPrimitive, ToPrimitive};
pub const PLDM_MAX_PACKET_SIZE: usize = 1024;
pub const PLDM_HEADER_VERSION: u8 = 0x00;
/// A structure representing a PLDM packet
#[derive(Debug, PartialEq)]
pub struct PldmPacket {
    pub rq: bool,                 // Request bit
    pub d: bool,                  // Datagram bit
    pub instance_id: u8,          // Instance ID (5 bits)
    pub hdr_ver: u8,              // Header version (2 bits)
    pub pldm_type: u8,            // PLDM type (6 bits, as a u8)
    pub pldm_command: u8,         // PLDM command code (8 bits)
    pub payload: Option<Vec<u8>>, // Optional payload (0 or more bytes) including completion code
}

impl PldmPacket {
    /// Public constructor for creating a new PLDM packet.
    pub fn new(
        rq: bool,
        d: bool,
        instance_id: u8,
        hdr_ver: u8,
        pldm_type: u8,
        pldm_command: u8,
        payload: Option<Vec<u8>>,
    ) -> Self {
        PldmPacket {
            rq,
            d,
            instance_id: instance_id & 0x1F, // Ensure it’s 5 bits
            hdr_ver: hdr_ver & 0x03,         // Ensure it’s 2 bits
            pldm_type: pldm_type & 0x3F,     // Ensure it’s 6 bits
            pldm_command,
            payload,
        }
    }

    /// Encodes the PLDM packet into a binary format (byte array).
    ///
    /// The reserved bit is always encoded as 0.
    pub fn encode(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        // Byte 1: Rq (1 bit), D (1 bit), Reserved (1 bit = 0), Instance ID (5 bits)
        let byte1 = ((self.rq as u8) << 7) | ((self.d as u8) << 6) | (self.instance_id & 0x1F);
        packet.push(byte1);

        // Byte 2: Hdr Ver (2 bits), PLDM Type (6 bits)
        let byte2 = ((self.hdr_ver & 0x03) << 6) | (self.pldm_type & 0x3F);
        packet.push(byte2);

        // Byte 3: PLDM Command Code
        packet.push(self.pldm_command);

        // Payload (if any)
        if let Some(payload) = &self.payload {
            packet.extend(payload);
        }

        packet
    }

    /// Decodes a binary PLDM packet into a `PldmPacket` struct.
    ///
    /// # Arguments
    /// * `buffer` - A slice of bytes representing the PLDM packet.
    ///
    /// # Returns
    /// * `Result<PldmPacket, String>` - Returns a `PldmPacket` on success, or a string with an error message.
    pub fn decode(buffer: &[u8]) -> Result<Self, String> {
        if buffer.len() < 3 {
            return Err("Buffer too short to decode a PLDM packet".to_string());
        }

        // Byte 1: Extract Rq, D, and Instance ID (ignore Reserved bit)
        let rq = (buffer[0] & 0x80) != 0;
        let d = (buffer[0] & 0x40) != 0;
        let instance_id = buffer[0] & 0x1F;

        // Byte 2: Extract Hdr Ver and PLDM Type
        let hdr_ver = (buffer[1] >> 6) & 0x03;
        let pldm_type = buffer[1] & 0x3F;

        // Byte 3: Extract PLDM Command Code
        let pldm_command = buffer[2];

        // Extract the remaining bytes as the payload
        let mut payload = None;
        if buffer.len() > 3 {
            payload = Some(buffer[3..].to_vec());
        }

        Ok(PldmPacket {
            rq,
            d,
            instance_id,
            hdr_ver,
            pldm_type,
            pldm_command,
            payload,
        })
    }
}

/// Represents the different types of PLDM messages.
///
/// The PLDM Type field identifies the type of PLDM message.
/// These types are defined in the PLDM specification and can be encoded and decoded.
///
/// | PLDM Type                        | Binary Code |
/// |-----------------------------------|-------------|
/// | MessagingControlAndDiscovery      | 000000      |
/// | SMBIOS                            | 000001      |
/// | PlatformMonitoringAndControl      | 000010      |
/// | BiosControlAndConfiguration       | 000011      |
/// | FruData                           | 000100      |
/// | FirmwareUpdate                    | 000101      |
/// | RedfishDeviceEnablement           | 000110      |
/// | FileTransfer                      | 000111      |
/// | OemSpecific                       | 111111      |
#[derive(Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum PldmType {
    MessagingControlAndDiscovery = 0b000000,
    SMBIOS = 0b000001,
    PlatformMonitoringAndControl = 0b000010,
    BiosControlAndConfiguration = 0b000011,
    FruData = 0b000100,
    FirmwareUpdate = 0b000101,
    RedfishDeviceEnablement = 0b000110,
    FileTransfer = 0b000111,
    OemSpecific = 0b111111,
}

/// Represents PLDM completion codes.
///
/// The completion codes are used to indicate the success or failure of a PLDM command.
/// These codes are defined in the PLDM specification and can be encoded and decoded.
#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum PldmCompletionCode {
    Success = 0x00,
    Error = 0x01,
    ErrorInvalidData = 0x02,
    ErrorInvalidLength = 0x03,
    ErrorNotReady = 0x04,
    ErrorUnsupportedPldmCmd = 0x05,
    ErrorInvalidPldmType = 0x20,
    ErrorInvalidTransferContext = 0x21,
    ErrorInvalidDataTransferHandle = 0x22,
    ErrorUnexpectedTransferFlagOperation = 0x23,
    ErrorInvalidRequestedSectionOffset = 0x24,
    CommandSpecific(u8),
    Reserved(u8),
}

impl PldmCompletionCode {
    pub fn from_u8(value: u8) -> PldmCompletionCode {
        match value {
            0x00 => PldmCompletionCode::Success,
            0x01 => PldmCompletionCode::Error,
            0x02 => PldmCompletionCode::ErrorInvalidData,
            0x03 => PldmCompletionCode::ErrorInvalidLength,
            0x04 => PldmCompletionCode::ErrorNotReady,
            0x05 => PldmCompletionCode::ErrorUnsupportedPldmCmd,
            0x20 => PldmCompletionCode::ErrorInvalidPldmType,
            0x21 => PldmCompletionCode::ErrorInvalidTransferContext,
            0x22 => PldmCompletionCode::ErrorInvalidDataTransferHandle,
            0x23 => PldmCompletionCode::ErrorUnexpectedTransferFlagOperation,
            0x24 => PldmCompletionCode::ErrorInvalidRequestedSectionOffset,
            0x80..=0xFF => PldmCompletionCode::CommandSpecific(value),
            _ => PldmCompletionCode::Reserved(value),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            PldmCompletionCode::Success => 0x00,
            PldmCompletionCode::Error => 0x01,
            PldmCompletionCode::ErrorInvalidData => 0x02,
            PldmCompletionCode::ErrorInvalidLength => 0x03,
            PldmCompletionCode::ErrorNotReady => 0x04,
            PldmCompletionCode::ErrorUnsupportedPldmCmd => 0x05,
            PldmCompletionCode::ErrorInvalidPldmType => 0x20,
            PldmCompletionCode::ErrorInvalidTransferContext => 0x21,
            PldmCompletionCode::ErrorInvalidDataTransferHandle => 0x22,
            PldmCompletionCode::ErrorUnexpectedTransferFlagOperation => 0x23,
            PldmCompletionCode::ErrorInvalidRequestedSectionOffset => 0x24,
            PldmCompletionCode::CommandSpecific(value) => *value,
            PldmCompletionCode::Reserved(value) => *value,
        }
    }
}
