// Licensed under the Apache-2.0 license

use crate::error::VdmError;
use bitfield::bitfield;
use core::convert::TryFrom;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// MCTP message type for Vendor Defined Messages.
pub const MCTP_VDM_MSG_TYPE: u8 = 0x7E;

/// PCI Vendor ID for Caliptra (Microsoft).
pub const CALIPTRA_PCI_VENDOR_ID: u16 = 0x1414;

/// Length of the VDM message header in bytes.
/// Header consists of: Vendor ID (2 bytes) + Request/Crypt byte (1 byte) + Command Code (1 byte)
pub const VDM_MSG_HEADER_LEN: usize = 4;

/// VDM completion codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VdmCompletionCode {
    /// Command completed successfully.
    Success = 0x00,
    /// General error.
    GeneralError = 0x01,
    /// Invalid data in the request.
    InvalidData = 0x02,
    /// Invalid length.
    InvalidLength = 0x03,
    /// Device is not ready.
    NotReady = 0x04,
    /// Command is not supported.
    UnsupportedCommand = 0x05,
}

impl TryFrom<u32> for VdmCompletionCode {
    type Error = VdmError;

    fn try_from(value: u32) -> Result<Self, VdmError> {
        match value {
            0x00 => Ok(VdmCompletionCode::Success),
            0x01 => Ok(VdmCompletionCode::GeneralError),
            0x02 => Ok(VdmCompletionCode::InvalidData),
            0x03 => Ok(VdmCompletionCode::InvalidLength),
            0x04 => Ok(VdmCompletionCode::NotReady),
            0x05 => Ok(VdmCompletionCode::UnsupportedCommand),
            _ => Err(VdmError::InvalidCompletionCode),
        }
    }
}

impl From<VdmCompletionCode> for u32 {
    fn from(code: VdmCompletionCode) -> Self {
        code as u32
    }
}

bitfield! {
    /// Request/Response control byte.
    /// Bit 7: Request Type (1 = request, 0 = response)
    /// Bit 6: Crypt (1 = encrypted, 0 = not encrypted)
    /// Bits 5:0: Reserved (must be 0)
    #[repr(C)]
    #[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, PartialEq, Default)]
    pub struct VdmControlByte(u8);
    impl Debug;
    pub u8, request_type, set_request_type: 7, 7;
    pub u8, crypt, set_crypt: 6, 6;
    pub u8, reserved, _: 5, 0;
}

impl VdmControlByte {
    /// Create a new control byte for a request message.
    pub fn new_request() -> Self {
        let mut ctrl = VdmControlByte(0);
        ctrl.set_request_type(1);
        ctrl
    }

    /// Create a new control byte for a response message.
    pub fn new_response() -> Self {
        VdmControlByte(0)
    }

    /// Check if this is a request message.
    pub fn is_request(&self) -> bool {
        self.request_type() == 1
    }

    /// Check if this is a response message.
    pub fn is_response(&self) -> bool {
        self.request_type() == 0
    }
}

/// VDM Message Header structure.
/// This is the header that follows the MCTP common header (msg type 0x7E).
///
/// Layout:
/// - Bytes 0:1 - PCI Vendor ID (little-endian, 0x1414 for Caliptra)
/// - Byte 2    - Control byte (Request/Crypt/Reserved)
/// - Byte 3    - Command Code
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct VdmMsgHeader {
    /// PCI Vendor ID (little-endian).
    pub vendor_id: u16,
    /// Control byte containing request type and crypt flags.
    pub control: VdmControlByte,
    /// Command code.
    pub command_code: u8,
}

impl VdmMsgHeader {
    /// Create a new VDM message header for a request.
    pub fn new_request(command_code: u8) -> Self {
        VdmMsgHeader {
            vendor_id: CALIPTRA_PCI_VENDOR_ID,
            control: VdmControlByte::new_request(),
            command_code,
        }
    }

    /// Create a new VDM message header for a response.
    pub fn new_response(command_code: u8) -> Self {
        VdmMsgHeader {
            vendor_id: CALIPTRA_PCI_VENDOR_ID,
            control: VdmControlByte::new_response(),
            command_code,
        }
    }

    /// Convert this header to a response header (keeping same command code).
    pub fn into_response(&self) -> Self {
        VdmMsgHeader {
            vendor_id: self.vendor_id,
            control: VdmControlByte::new_response(),
            command_code: self.command_code,
        }
    }

    /// Check if the vendor ID is valid (Caliptra/Microsoft).
    pub fn is_vendor_id_valid(&self) -> bool {
        self.vendor_id == CALIPTRA_PCI_VENDOR_ID
    }

    /// Check if this is a request message.
    pub fn is_request(&self) -> bool {
        self.control.is_request()
    }

    /// Check if this is a response message.
    pub fn is_response(&self) -> bool {
        self.control.is_response()
    }
}

/// A generic failure response containing only header and completion code.
#[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct VdmFailureResponse {
    /// VDM message header.
    pub hdr: VdmMsgHeader,
    /// Completion code (u32).
    pub completion_code: u32,
}

impl VdmFailureResponse {
    /// Create a new failure response.
    pub fn new(command_code: u8, completion_code: VdmCompletionCode) -> Self {
        VdmFailureResponse {
            hdr: VdmMsgHeader::new_response(command_code),
            completion_code: completion_code.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::VdmCodec;

    #[test]
    fn test_vdm_control_byte() {
        let req = VdmControlByte::new_request();
        assert!(req.is_request());
        assert!(!req.is_response());
        assert_eq!(req.0, 0x80);

        let resp = VdmControlByte::new_response();
        assert!(!resp.is_request());
        assert!(resp.is_response());
        assert_eq!(resp.0, 0x00);
    }

    #[test]
    fn test_vdm_msg_header_request() {
        let hdr = VdmMsgHeader::new_request(0x01);
        let vendor_id = hdr.vendor_id;
        let command_code = hdr.command_code;
        assert_eq!(vendor_id, CALIPTRA_PCI_VENDOR_ID);
        assert!(hdr.is_request());
        assert!(hdr.is_vendor_id_valid());
        assert_eq!(command_code, 0x01);
    }

    #[test]
    fn test_vdm_msg_header_response() {
        let hdr = VdmMsgHeader::new_response(0x02);
        let vendor_id = hdr.vendor_id;
        let command_code = hdr.command_code;
        assert_eq!(vendor_id, CALIPTRA_PCI_VENDOR_ID);
        assert!(hdr.is_response());
        assert!(hdr.is_vendor_id_valid());
        assert_eq!(command_code, 0x02);
    }

    #[test]
    fn test_vdm_msg_header_into_response() {
        let req = VdmMsgHeader::new_request(0x03);
        let resp = req.into_response();
        let command_code = resp.command_code;
        let vendor_id = resp.vendor_id;
        assert!(resp.is_response());
        assert_eq!(command_code, 0x03);
        assert_eq!(vendor_id, CALIPTRA_PCI_VENDOR_ID);
    }

    #[test]
    fn test_vdm_msg_header_encode_decode() {
        let hdr = VdmMsgHeader::new_request(0x01);
        let mut buffer = [0u8; VDM_MSG_HEADER_LEN];
        let size = hdr.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN);

        let decoded = VdmMsgHeader::decode(&buffer).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn test_vdm_failure_response() {
        let resp = VdmFailureResponse::new(0x01, VdmCompletionCode::UnsupportedCommand);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(
            completion_code,
            VdmCompletionCode::UnsupportedCommand as u32
        );

        let mut buffer = [0u8; 8];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, 8);

        let decoded = VdmFailureResponse::decode(&buffer).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_completion_code_conversion() {
        assert_eq!(
            VdmCompletionCode::try_from(0x00),
            Ok(VdmCompletionCode::Success)
        );
        assert_eq!(
            VdmCompletionCode::try_from(0x05),
            Ok(VdmCompletionCode::UnsupportedCommand)
        );
        assert_eq!(
            VdmCompletionCode::try_from(0xFF),
            Err(VdmError::InvalidCompletionCode)
        );
    }
}
