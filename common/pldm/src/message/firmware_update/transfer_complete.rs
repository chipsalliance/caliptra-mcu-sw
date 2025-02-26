// Licensed under the Apache-2.0 license

use crate::error::PldmError;
use crate::protocol::base::{
    InstanceId, PldmMsgHeader, PldmMsgType, PldmSupportedType, PLDM_MSG_HEADER_LEN,
};
use crate::protocol::firmware_update::FwUpdateCmd;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferResult {
    TransferSuccess = 0x00,
    TransferErrorImageCorrupt = 0x01,
    TransferErrorVersionMismatch = 0x02,
    FdAbortedTransfer = 0x03,
    FdAbortedTransferLowPowerState = 0x0b,
    FdAbortedTransferResetNeeded = 0x0c,
    FdAbortedTransferStorageIssue = 0x0d,
    FdAbortedTransferInvalidComponentOpaqueData = 0x0e,
    FdAbortedTransferDownstreamDeviceIssue = 0x0f,
    FdAbortedTransferSecurityRevisionError = 0x10,
    VendorDefined, // 0x70..=0x8f
}

impl TryFrom<u8> for TransferResult {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        match value {
            0x00 => Ok(TransferResult::TransferSuccess),
            0x01 => Ok(TransferResult::TransferErrorImageCorrupt),
            0x02 => Ok(TransferResult::TransferErrorVersionMismatch),
            0x03 => Ok(TransferResult::FdAbortedTransfer),
            0x0b => Ok(TransferResult::FdAbortedTransferLowPowerState),
            0x0c => Ok(TransferResult::FdAbortedTransferResetNeeded),
            0x0d => Ok(TransferResult::FdAbortedTransferStorageIssue),
            0x0e => Ok(TransferResult::FdAbortedTransferInvalidComponentOpaqueData),
            0x0f => Ok(TransferResult::FdAbortedTransferDownstreamDeviceIssue),
            0x10 => Ok(TransferResult::FdAbortedTransferSecurityRevisionError),
            0x70..=0x8f => Ok(TransferResult::VendorDefined),
            _ => Err(PldmError::InvalidTransferResult),
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct TransferCompleteRequest {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub tranfer_result: u8,
}

impl TransferCompleteRequest {
    pub fn new(
        instance_id: InstanceId,
        msg_type: PldmMsgType,
        tranfer_result: TransferResult,
    ) -> Self {
        TransferCompleteRequest {
            hdr: PldmMsgHeader::new(
                instance_id,
                msg_type,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::TransferComplete as u8,
            ),
            tranfer_result: tranfer_result as u8,
        }
    }
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct TransferCompleteResponse {
    pub hdr: PldmMsgHeader<[u8; PLDM_MSG_HEADER_LEN]>,
    pub completion_code: u8,
}

impl TransferCompleteResponse {
    pub fn new(instance_id: InstanceId, completion_code: u8) -> TransferCompleteResponse {
        TransferCompleteResponse {
            hdr: PldmMsgHeader::new(
                instance_id,
                PldmMsgType::Response,
                PldmSupportedType::FwUpdate,
                FwUpdateCmd::TransferComplete as u8,
            ),
            completion_code,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::codec::PldmCodec;

    #[test]
    fn test_transfer_complete_request() {
        let request = TransferCompleteRequest::new(
            0x01,
            PldmMsgType::Request,
            TransferResult::TransferSuccess,
        );
        let mut buffer = [0u8; core::mem::size_of::<TransferCompleteRequest>()];
        request.encode(&mut buffer).unwrap();
        let decoded_request = TransferCompleteRequest::decode(&buffer).unwrap();
        assert_eq!(decoded_request, request);
    }

    #[test]
    fn test_transfer_complete_response() {
        let response = TransferCompleteResponse::new(0x01, 0x00);
        let mut buffer = [0u8; core::mem::size_of::<TransferCompleteResponse>()];
        response.encode(&mut buffer).unwrap();
        let decoded_response = TransferCompleteResponse::decode(&buffer).unwrap();
        assert_eq!(decoded_response, response);
    }
}
