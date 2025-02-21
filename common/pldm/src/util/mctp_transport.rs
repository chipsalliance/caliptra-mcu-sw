// Licensed under the Apache-2.0 license

use crate::error::TransportError;
use crate::protocol::base::PLDM_MSG_HEADER_LEN;
use bitfield::bitfield;

pub const MCTP_PLDM_MSG_TYPE: u8 = 0x01;
pub const MCTP_COMMON_HEADER_OFFSET: usize = 0;
pub const PLDM_MSG_OFFSET: usize = 1;

bitfield! {
    #[derive(Copy, Clone, PartialEq)]
    pub struct MctpCommonHeader(u8);
    impl Debug;
    pub u8, ic, set_ic: 7, 7;
    pub u8, msg_type, set_msg_type: 6, 0;
}

//
/// Extracts the PLDM message from the given MCTP payload.
///
/// # Arguments
///
/// * `mctp_payload` - A mutable reference to the MCTP payload.
///
/// # Returns
///
/// * `Result<&mut [u8], TransportError>` - A result containing a mutable reference to the PLDM message slice
///   if successful, or a `TransportError` if the payload length is invalid or the message type is incorrect.
pub fn extract_pldm_msg(mctp_payload: &mut [u8]) -> Result<&mut [u8], TransportError> {
    // Check if the payload length is sufficient to contain the MCTP common header and PLDM message header.
    if mctp_payload.len() < 1 + PLDM_MSG_HEADER_LEN {
        return Err(TransportError::InvalidMctpPayloadLength);
    }

    // Extract the MCTP common header from the payload.
    let mctp_common_header = MctpCommonHeader(mctp_payload[MCTP_COMMON_HEADER_OFFSET]);

    // Validate the integrity check (IC) and message type fields.
    if mctp_common_header.ic() != 0 || mctp_common_header.msg_type() != MCTP_PLDM_MSG_TYPE {
        return Err(TransportError::InvalidMctpMsgType);
    }

    // Return a mutable reference to the PLDM message slice.
    Ok(&mut mctp_payload[PLDM_MSG_OFFSET..])
}

/// Constructs an MCTP payload with a PLDM message.
///
/// # Arguments
///
/// * `mctp_payload` - A mutable reference to the MCTP payload.
///
/// # Returns
///
/// * `Result<&mut [u8], TransportError>` - A result containing a mutable reference to the PLDM message slice
///   if successful, or a `TransportError` if the payload length is invalid.
pub fn construct_mctp_pldm_msg(mctp_payload: &mut [u8]) -> Result<&mut [u8], TransportError> {
    // Check if the payload length is sufficient to contain the MCTP common header and PLDM message header.
    if mctp_payload.len() < 1 + PLDM_MSG_HEADER_LEN {
        return Err(TransportError::InvalidMctpPayloadLength);
    }

    // Initialize the MCTP common header.
    let mut mctp_common_header = MctpCommonHeader(0);
    mctp_common_header.set_ic(0);
    mctp_common_header.set_msg_type(MCTP_PLDM_MSG_TYPE);

    // Set the MCTP common header in the payload.
    mctp_payload[MCTP_COMMON_HEADER_OFFSET] = mctp_common_header.0;

    // Return a mutable reference to the PLDM message slice.
    Ok(&mut mctp_payload[PLDM_MSG_OFFSET..])
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_retrieve_pldm_msg() {
        let mut mctp_payload = [0u8; 8];
        assert_eq!(
            extract_pldm_msg(&mut mctp_payload),
            Err(TransportError::InvalidMctpMsgType)
        );
        mctp_payload[0] = 0x01;
        assert_eq!(extract_pldm_msg(&mut mctp_payload).unwrap(), &mut [0u8; 7]);
        let mut mctp_payload = [0u8; 3];
        assert_eq!(
            extract_pldm_msg(&mut mctp_payload),
            Err(TransportError::InvalidMctpPayloadLength)
        );
    }

    #[test]
    fn test_construct_mctp_pldm_msg() {
        let mut mctp_payload = [0u8; 10];
        assert_eq!(
            construct_mctp_pldm_msg(&mut mctp_payload).unwrap(),
            &mut [0u8; 9]
        );
        assert_eq!(mctp_payload[0], 0x01);
        let mut mctp_payload = [0u8; 3];
        assert_eq!(
            construct_mctp_pldm_msg(&mut mctp_payload),
            Err(TransportError::InvalidMctpPayloadLength)
        );
    }
}
