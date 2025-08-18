// Licensed under the Apache-2.0 license

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispVersion(u8);
    impl Debug;
    u8;
    pub minor, set_minor: 3, 0; // Bits 3:0 Minor version
    pub major, set_major: 7, 4; // Bits 7:4 Major version
}

/// TdispReqRespCode represents the request/response code for TDISP messages.
#[allow(dead_code)]
pub(crate) enum TdispReqRespCode {
    /// Request to get the TDISP version.
    GetTdispVersion = 0x81,
    /// Response containing the TDISP version supported by device.
    TdispVersion = 0x01,
    /// Request to get the TDISP capabilities.
    GetTdispCapabilities = 0x82,
    /// Response containing the TDISP capabilities.
    TdispCapabilities = 0x02,
    /// Move TDI to CONFIG_LOCKED state.
    LockInterface = 0x83,
    /// Response to LOCK_INTERFACE_REQUEST
    LockInterfaceResponse = 0x03,
    /// Obtain a TDI Report.
    GetDeviceInterfaceReport = 0x84,
    /// Report for a TDI
    DeviceInterfaceReport = 0x04,
    /// Obtain state of a TDI
    GetDeviceInterfaceState = 0x85,
    /// Return TDI state
    DeviceInterfaceState = 0x05,
    /// Start a TDI
    StartInterfaceRequest = 0x86,
    /// Response to request to move TDI to RUN state
    StartInterfaceResponse = 0x06,
    /// Stop and move TDI to CONFIG_UNLOCKED state(if not already in that state)
    StopInterfaceRequest = 0x87,
    /// Response to a STOP_INTERFACE_REQUEST
    StopInterfaceResponse = 0x07,
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C, packed)]
pub struct InterfaceId {
    function_id: FunctionId,
    reserved: u64, // 8 bytes reserved
}

bitfield! {
    #[derive(FromBytes, IntoBytes, Immutable, Default)]
    #[repr(C)]
    pub struct FunctionId(u32);
    impl Debug;
    u16;
    pub requester_id, set_requester_id: 15, 0; // Bits 15:0 Requester ID
    u8;
    pub requester_segment, set_requester_segment: 23, 16; // Bits 23:16 Requester Segment
    pub requester_segment_valid, set_requester_segment_valid: 24, 24; // Bit 24 Requester Segment Valid
    reserved, _: 31, 25; // Bits 31:25 Reserved
}

#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispMessageHeader {
    version: TdispVersion,
    message_type: u8,
    reserved: u16,
    interface_id: InterfaceId,
}
