// Licensed under the Apache-2.0 license

//! MCTP transport utilities for VDM messages.

use crate::error::UtilError;
use crate::protocol::VDM_MSG_HEADER_LEN;
use bitfield::bitfield;

/// MCTP message type for Vendor Defined Messages.
pub const MCTP_VDM_MSG_TYPE: u8 = 0x7E;

/// Offset of the MCTP common header in the payload.
pub const MCTP_COMMON_HEADER_OFFSET: usize = 0;

/// Offset of the VDM message (after MCTP common header).
pub const VDM_MSG_OFFSET: usize = 1;

bitfield! {
    /// MCTP Common Header (first byte of MCTP message body).
    /// - Bit 7: IC (Integrity Check bit)
    /// - Bits 6:0: Message Type (0x7E for VDM)
    #[derive(Copy, Clone, PartialEq)]
    pub struct MctpCommonHeader(u8);
    impl Debug;
    pub u8, ic, set_ic: 7, 7;
    pub u8, msg_type, set_msg_type: 6, 0;
}

impl MctpCommonHeader {
    /// Create a new MCTP common header for VDM messages.
    pub fn new_vdm() -> Self {
        let mut header = MctpCommonHeader(0);
        header.set_ic(0);
        header.set_msg_type(MCTP_VDM_MSG_TYPE);
        header
    }

    /// Check if the message type is VDM.
    pub fn is_vdm(&self) -> bool {
        self.msg_type() == MCTP_VDM_MSG_TYPE
    }
}

/// Extracts the VDM message from the given MCTP payload.
///
/// The MCTP payload is expected to have the following format:
/// - Byte 0: MCTP common header (IC + Message Type)
/// - Bytes 1:N: VDM message (header + payload)
///
/// # Arguments
///
/// * `mctp_payload` - A mutable reference to the MCTP payload.
///
/// # Returns
///
/// A mutable reference to the VDM message slice (excluding MCTP common header).
pub fn extract_vdm_msg(mctp_payload: &mut [u8]) -> Result<&mut [u8], UtilError> {
    // Check if the payload length is sufficient to contain the MCTP common header and VDM message header.
    if mctp_payload.len() < VDM_MSG_OFFSET + VDM_MSG_HEADER_LEN {
        return Err(UtilError::InvalidMctpPayloadLength);
    }

    // Extract the MCTP common header from the payload.
    let mctp_common_header = MctpCommonHeader(mctp_payload[MCTP_COMMON_HEADER_OFFSET]);

    // Validate the integrity check (IC) and message type fields.
    if mctp_common_header.ic() != 0 || mctp_common_header.msg_type() != MCTP_VDM_MSG_TYPE {
        return Err(UtilError::InvalidMctpMsgType);
    }

    // Return a mutable reference to the VDM message slice.
    Ok(&mut mctp_payload[VDM_MSG_OFFSET..])
}

/// Constructs an MCTP payload with a VDM message.
///
/// This function initializes the MCTP common header for VDM messages
/// and returns a mutable reference to the VDM message portion.
///
/// # Arguments
///
/// * `mctp_payload` - A mutable reference to the MCTP payload buffer.
///
/// # Returns
///
/// A mutable reference to the VDM message slice (for writing the VDM header and payload).
pub fn construct_mctp_vdm_msg(mctp_payload: &mut [u8]) -> Result<&mut [u8], UtilError> {
    // Check if the payload length is sufficient to contain the MCTP common header and VDM message header.
    if mctp_payload.len() < VDM_MSG_OFFSET + VDM_MSG_HEADER_LEN {
        return Err(UtilError::InvalidMctpPayloadLength);
    }

    // Initialize the MCTP common header for VDM.
    let mctp_common_header = MctpCommonHeader::new_vdm();
    mctp_payload[MCTP_COMMON_HEADER_OFFSET] = mctp_common_header.0;

    // Return a mutable reference to the VDM message slice.
    Ok(&mut mctp_payload[VDM_MSG_OFFSET..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mctp_common_header_vdm() {
        let header = MctpCommonHeader::new_vdm();
        assert_eq!(header.ic(), 0);
        assert_eq!(header.msg_type(), MCTP_VDM_MSG_TYPE);
        assert!(header.is_vdm());
        assert_eq!(header.0, 0x7E);
    }

    #[test]
    fn test_extract_vdm_msg() {
        let mut mctp_payload = [0u8; 16];
        // Invalid message type
        assert_eq!(
            extract_vdm_msg(&mut mctp_payload),
            Err(UtilError::InvalidMctpMsgType)
        );

        // Valid VDM message
        mctp_payload[0] = 0x7E;
        let vdm_msg = extract_vdm_msg(&mut mctp_payload).unwrap();
        assert_eq!(vdm_msg.len(), 15); // 16 - 1 (MCTP common header)

        // Buffer too short
        let mut short_payload = [0x7E; 3];
        assert_eq!(
            extract_vdm_msg(&mut short_payload),
            Err(UtilError::InvalidMctpPayloadLength)
        );
    }

    #[test]
    fn test_construct_mctp_vdm_msg() {
        let mut mctp_payload = [0u8; 16];
        {
            let vdm_msg = construct_mctp_vdm_msg(&mut mctp_payload).unwrap();
            assert_eq!(vdm_msg.len(), 15);
        }
        assert_eq!(mctp_payload[0], 0x7E);

        // Buffer too short
        let mut short_payload = [0u8; 3];
        assert_eq!(
            construct_mctp_vdm_msg(&mut short_payload),
            Err(UtilError::InvalidMctpPayloadLength)
        );
    }
}
