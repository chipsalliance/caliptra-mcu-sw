// Licensed under the Apache-2.0 license

#[derive(Debug, Clone, PartialEq)]
pub enum PldmError {
    InvalidData,
    InvalidLength,
    InvalidMsgType,
    InvalidProtocolVersion,
    UnsupportedCmd,
    UnsupportedPldmType,
    InvalidCompletionCode,
    InvalidTransferOpFlag,
    InvalidTransferRespFlag,

    InvalidVersionStringType,
    InvalidVersionStringLength,
    InvalidFdState,
    InvalidDescriptorType,
    InvalidDescriptorLength,
    InvalidDescriptorCount,
    InvalidComponentClassification,
    InvalidComponentResponseCode,
    InvalidComponentCompatibilityResponse,
    InvalidComponentCompatibilityResponseCode,
    InvalidTransferResult,
    InvalidVerifyResult,
    InvalidApplyResult,
    InvalidGetStatusReasonCode,
    InvalidAuxStateStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportError {
    InvalidMctpPayloadLength,
    InvalidMctpMsgType,
}
