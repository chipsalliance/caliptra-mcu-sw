// Licensed under the Apache-2.0 license

use crate::error::VdmError;
use bitfield::bitfield;
use core::convert::TryFrom;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// MCTP message type for IANA Vendor Defined Messages.
pub const MCTP_VDM_MSG_TYPE: u8 = 0x7F;

/// OCP IANA enterprise number used for Caliptra VDM commands.
pub const CALIPTRA_IANA_ENTERPRISE_ID: u32 = 42623;
pub const CALIPTRA_IANA_ENTERPRISE_ID_BYTES: [u8; 4] = [0x00, 0x00, 0xA6, 0x7F];

/// Length of the VDM message header in bytes.
/// Header consists of: IANA enterprise ID (4 bytes) + Request/Reserved byte (1 byte) + Command Code (1 byte)
pub const VDM_MSG_HEADER_LEN: usize = 6;

/// VDM completion codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VdmCompletionCode {
    Success = 0x00,
    GeneralError = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidIdentifier = 0x04,
    OperationFailed = 0x05,
    InsufficientResources = 0x06,
    UnsupportedOperation = 0x07,
    DeviceNotReady = 0x08,
    InvalidCommandVersion = 0x09,
    InvalidPayloadSize = 0x0A,
    Timeout = 0x0B,
    AccessDenied = 0x0C,
    ResourceUnavailable = 0x0D,
    PolicyViolation = 0x0E,
    InvalidState = 0x0F,
    CaliptraMailboxBusy = 0xC0,
    CaliptraBufferTooSmall = 0xC1,
}

impl TryFrom<u32> for VdmCompletionCode {
    type Error = VdmError;

    fn try_from(value: u32) -> Result<Self, VdmError> {
        match value {
            0x00 => Ok(VdmCompletionCode::Success),
            0x01 => Ok(VdmCompletionCode::GeneralError),
            0x02 => Ok(VdmCompletionCode::InvalidParameter),
            0x03 => Ok(VdmCompletionCode::InvalidLength),
            0x04 => Ok(VdmCompletionCode::InvalidIdentifier),
            0x05 => Ok(VdmCompletionCode::OperationFailed),
            0x06 => Ok(VdmCompletionCode::InsufficientResources),
            0x07 => Ok(VdmCompletionCode::UnsupportedOperation),
            0x08 => Ok(VdmCompletionCode::DeviceNotReady),
            0x09 => Ok(VdmCompletionCode::InvalidCommandVersion),
            0x0A => Ok(VdmCompletionCode::InvalidPayloadSize),
            0x0B => Ok(VdmCompletionCode::Timeout),
            0x0C => Ok(VdmCompletionCode::AccessDenied),
            0x0D => Ok(VdmCompletionCode::ResourceUnavailable),
            0x0E => Ok(VdmCompletionCode::PolicyViolation),
            0x0F => Ok(VdmCompletionCode::InvalidState),
            0xC0 => Ok(VdmCompletionCode::CaliptraMailboxBusy),
            0xC1 => Ok(VdmCompletionCode::CaliptraBufferTooSmall),
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
    /// Bits 6:0: Reserved (must be 0)
    #[repr(C)]
    #[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, PartialEq, Eq, Default)]
    pub struct VdmControlByte(u8);
    impl Debug;
    pub u8, request_type, set_request_type: 7, 7;
    pub u8, reserved, _: 6, 0;
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

    /// Check whether all reserved bits are zero.
    pub fn reserved_is_zero(&self) -> bool {
        self.reserved() == 0
    }
}

/// VDM Message Header structure.
/// This is the header that follows the MCTP common header (msg type 0x7F).
///
/// Layout:
/// - Bytes 0:3 - IANA enterprise ID (MSB first, OCP 42623 for Caliptra VDM commands)
/// - Byte 4    - Control byte (Request/Reserved)
/// - Byte 5    - Command Code
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct VdmMsgHeader {
    /// IANA enterprise ID (MSB first).
    pub enterprise_id: [u8; 4],
    /// Control byte containing request type and reserved bits.
    pub control: VdmControlByte,
    /// Command code.
    pub command_code: u8,
}

impl VdmMsgHeader {
    /// Create a new VDM message header for a request.
    pub fn new_request(command_code: u8) -> Self {
        VdmMsgHeader {
            enterprise_id: CALIPTRA_IANA_ENTERPRISE_ID_BYTES,
            control: VdmControlByte::new_request(),
            command_code,
        }
    }

    /// Create a new VDM message header for a response.
    pub fn new_response(command_code: u8) -> Self {
        VdmMsgHeader {
            enterprise_id: CALIPTRA_IANA_ENTERPRISE_ID_BYTES,
            control: VdmControlByte::new_response(),
            command_code,
        }
    }

    /// Convert this header to a response header (keeping same command code).
    pub fn into_response(&self) -> Self {
        VdmMsgHeader {
            enterprise_id: self.enterprise_id,
            control: VdmControlByte::new_response(),
            command_code: self.command_code,
        }
    }

    /// Return the IANA enterprise ID as an integer.
    pub fn enterprise_id(&self) -> u32 {
        u32::from_be_bytes(self.enterprise_id)
    }

    /// Check if the vendor ID is valid (OCP for Caliptra VDM commands).
    pub fn is_vendor_id_valid(&self) -> bool {
        self.enterprise_id == CALIPTRA_IANA_ENTERPRISE_ID_BYTES
    }

    /// Check whether all reserved control bits are zero.
    pub fn reserved_is_zero(&self) -> bool {
        self.control.reserved_is_zero()
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
        assert!(req.reserved_is_zero());
        assert_eq!(req.0, 0x80);

        let resp = VdmControlByte::new_response();
        assert!(!resp.is_request());
        assert!(resp.is_response());
        assert!(resp.reserved_is_zero());
        assert_eq!(resp.0, 0x00);

        let reserved_set = VdmControlByte(0x40);
        assert!(!reserved_set.reserved_is_zero());
    }

    #[test]
    fn test_vdm_msg_header_request() {
        let hdr = VdmMsgHeader::new_request(0x01);
        let command_code = hdr.command_code;
        assert_eq!(hdr.enterprise_id(), CALIPTRA_IANA_ENTERPRISE_ID);
        assert!(hdr.is_request());
        assert!(hdr.is_vendor_id_valid());
        assert_eq!(command_code, 0x01);
    }

    #[test]
    fn test_vdm_msg_header_response() {
        let hdr = VdmMsgHeader::new_response(0x02);
        let command_code = hdr.command_code;
        assert_eq!(hdr.enterprise_id(), CALIPTRA_IANA_ENTERPRISE_ID);
        assert!(hdr.is_response());
        assert!(hdr.is_vendor_id_valid());
        assert_eq!(command_code, 0x02);
    }

    #[test]
    fn test_vdm_msg_header_into_response() {
        let req = VdmMsgHeader::new_request(0x03);
        let resp = req.into_response();
        let command_code = resp.command_code;
        assert!(resp.is_response());
        assert_eq!(command_code, 0x03);
        assert_eq!(resp.enterprise_id(), CALIPTRA_IANA_ENTERPRISE_ID);
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
        let resp = VdmFailureResponse::new(0x01, VdmCompletionCode::UnsupportedOperation);
        assert!(resp.hdr.is_response());
        let completion_code = resp.completion_code;
        assert_eq!(
            completion_code,
            VdmCompletionCode::UnsupportedOperation as u32
        );

        let mut buffer = [0u8; VDM_MSG_HEADER_LEN + 4];
        let size = resp.encode(&mut buffer).unwrap();
        assert_eq!(size, VDM_MSG_HEADER_LEN + 4);

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
            Ok(VdmCompletionCode::OperationFailed)
        );
        assert_eq!(
            VdmCompletionCode::try_from(0x07),
            Ok(VdmCompletionCode::UnsupportedOperation)
        );
        assert_eq!(
            VdmCompletionCode::try_from(0x08),
            Ok(VdmCompletionCode::DeviceNotReady)
        );
        assert_eq!(
            VdmCompletionCode::try_from(0xFF),
            Err(VdmError::InvalidCompletionCode)
        );
    }
}
