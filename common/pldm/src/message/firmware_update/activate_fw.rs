// Licensed under the Apache-2.0 license

use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::FwUpdateCmd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum SelfContainedActivationRequest {
    NotActivateSelfContainedComponents = 0,
    ActivateSelfContainedComponents = 1,
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct ActivateFirmwareRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub self_contained_activation_req: u8,
}

impl ActivateFirmwareRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        self_contained_activation_req: SelfContainedActivationRequest,
    ) -> ActivateFirmwareRequest {
        ActivateFirmwareRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::ActivateFirmware as u8,
            ),
            self_contained_activation_req: self_contained_activation_req as u8,
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct ActivateFirmwareResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub estimated_time_activation: u16,
}

impl ActivateFirmwareResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        estimated_time_activation: u16,
    ) -> ActivateFirmwareResponse {
        ActivateFirmwareResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::ActivateFirmware as u8,
            ),
            completion_code,
            estimated_time_activation,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::codec::PldmCodec;

    #[test]
    fn test_activate_firmware_request() {
        let request = ActivateFirmwareRequest::new(
            1,
            PldmMsgType::Request,
            SelfContainedActivationRequest::ActivateSelfContainedComponents,
        );

        let mut buffer = [0u8; core::mem::size_of::<ActivateFirmwareRequest>()];
        request.encode(&mut buffer).unwrap();

        let decoded_request = ActivateFirmwareRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_activate_firmware_response() {
        let response = ActivateFirmwareResponse::new(1, 0, 10);

        let mut buffer = [0u8; core::mem::size_of::<ActivateFirmwareResponse>()];
        response.encode(&mut buffer).unwrap();

        let decoded_response = ActivateFirmwareResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }
}
