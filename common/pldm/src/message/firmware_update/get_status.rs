// Licensed under the Apache-2.0 license

use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::{FirmwareDeviceState, FwUpdateCmd, UpdateOptionFlags};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const PROGRESS_PERCENT_NOT_SUPPORTED: u8 = 101;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressPercent(u8);

impl Default for ProgressPercent {
    fn default() -> Self {
        ProgressPercent::new(PROGRESS_PERCENT_NOT_SUPPORTED).unwrap()
    }
}
impl ProgressPercent {
    pub fn new(value: u8) -> Result<Self, PldmError> {
        if value > PROGRESS_PERCENT_NOT_SUPPORTED {
            Err(PldmError::InvalidData)
        } else {
            Ok(ProgressPercent(value))
        }
    }

    pub fn value(&self) -> u8 {
        self.0
    }

    pub fn set_value(&mut self, value: u8) -> Result<(), PldmError> {
        if value > 100 {
            Err(PldmError::InvalidData)
        } else {
            self.0 = value;
            Ok(())
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxState {
    OperationInProgress = 0,
    OperationSuccessful = 1,
    OperationFailed = 2,
    IdleLearnComponentsReadXfer = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxStateStatus {
    AuxStateInProgressOrSuccess = 0x00,
    Reserved,
    Timeout = 0x09,
    GenericError = 0x0a,
    VendorDefined,
}

impl TryFrom<u8> for AuxStateStatus {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x00 => Ok(AuxStateStatus::AuxStateInProgressOrSuccess),
            0x01..=0x08 => Ok(AuxStateStatus::Reserved),
            0x09 => Ok(AuxStateStatus::Timeout),
            0x0a => Ok(AuxStateStatus::GenericError),
            0x70..=0xef => Ok(AuxStateStatus::VendorDefined),
            _ => Err(PldmError::InvalidAuxStateStatus),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetStatusReasonCode {
    Initialization = 0,
    ActivateFw = 1,
    CancelUpdate = 2,
    LearnComponentTimeout = 3,
    ReadyXferTimeout = 4,
    DownloadTimeout = 5,
    VerifyTimeout = 6,
    ApplyTimeout = 7,
    VendorDefined,
}

impl TryFrom<u8> for GetStatusReasonCode {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0 => Ok(GetStatusReasonCode::Initialization),
            1 => Ok(GetStatusReasonCode::ActivateFw),
            2 => Ok(GetStatusReasonCode::CancelUpdate),
            3 => Ok(GetStatusReasonCode::LearnComponentTimeout),
            4 => Ok(GetStatusReasonCode::ReadyXferTimeout),
            5 => Ok(GetStatusReasonCode::DownloadTimeout),
            6 => Ok(GetStatusReasonCode::VerifyTimeout),
            7 => Ok(GetStatusReasonCode::ApplyTimeout),
            200..=255 => Ok(GetStatusReasonCode::VendorDefined),
            _ => Err(PldmError::InvalidGetStatusReasonCode),
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct GetStatusRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
}

impl GetStatusRequest {
    pub fn new(instance_id: InstanceId, msg_type: PldmMsgType) -> GetStatusRequest {
        GetStatusRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::GetStatus as u8,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[repr(u8)]
pub enum UpdateOptionResp {
    NoForceUpdate = 0,
    ForceUpdate = 1,
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct GetStatusResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
    pub current_state: u8,
    pub previous_state: u8,
    pub aux_state: u8,
    pub aux_state_status: u8,
    pub progress_percent: u8,
    pub reason_code: u8,
    pub update_option_flags_enabled: u32, // Assuming bitfield32_t is a 32-bit integer
}

#[allow(clippy::too_many_arguments)]
impl GetStatusResponse {
    pub fn new(
        instance_id: InstanceId,
        completion_code: u8,
        current_state: FirmwareDeviceState,
        previous_state: FirmwareDeviceState,
        aux_state: AuxState,
        aux_state_status: u8,
        progress_percent: ProgressPercent,
        reason_code: GetStatusReasonCode,
        update_option: UpdateOptionResp,
    ) -> GetStatusResponse {
        GetStatusResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::GetStatus as u8,
            ),
            completion_code,
            current_state: current_state as u8,
            previous_state: previous_state as u8,
            aux_state: aux_state as u8,
            aux_state_status,
            progress_percent: progress_percent.value(),
            reason_code: reason_code as u8,
            update_option_flags_enabled: {
                let mut flags = UpdateOptionFlags(0);
                flags.set_request_force_update(update_option == UpdateOptionResp::ForceUpdate);
                flags.0
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::codec::PldmCodec;

    #[test]
    fn test_get_status_request() {
        let instance_id = 1;
        let msg_type = PldmMsgType::Request;
        let request = GetStatusRequest::new(instance_id, msg_type);
        let mut buffer = [0u8; 16];
        let encoded_size = request.encode(&mut buffer).unwrap();
        assert_eq!(encoded_size, core::mem::size_of::<GetStatusRequest>());

        let decoded_request = GetStatusRequest::decode(&buffer).unwrap();
        assert_eq!(request, decoded_request);
    }

    #[test]
    fn test_get_status_response() {
        let response = GetStatusResponse::new(
            1,
            0,
            FirmwareDeviceState::Idle,
            FirmwareDeviceState::Idle,
            AuxState::IdleLearnComponentsReadXfer,
            AuxStateStatus::AuxStateInProgressOrSuccess as u8,
            ProgressPercent::new(50).unwrap(),
            GetStatusReasonCode::Initialization,
            UpdateOptionResp::NoForceUpdate,
        );

        let mut buffer = [0u8; 32];
        let encoded_size = response.encode(&mut buffer).unwrap();
        assert_eq!(encoded_size, core::mem::size_of::<GetStatusResponse>());

        let decoded_response = GetStatusResponse::decode(&buffer).unwrap();
        assert_eq!(response, decoded_response);
    }
}
