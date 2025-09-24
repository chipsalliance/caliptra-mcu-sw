// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::vdm_handler::pci_sig::tdisp::protocol::FunctionId;
use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Error codes returned by TDISP driver
pub enum TdispDriverError {
    /// Input parameter is null or invalid.
    InvalidArgument,
    /// Memory allocation failed.
    NoMemory,
    /// The driver failed to get TDISP capabilities.
    GetTdispCapabilitiesFail,
    /// The driver failed to get the device interface state.
    GetDeviceInterfaceStateFail,
    /// The driver failed to lock the device interface.
    LockInterfaceReqFail,
    /// The driver failed to start the device interface.
    StartInterfaceReqFail,
    /// The driver failed to stop the device interface.
    StopInterfaceReqFail,
    /// The driver failed to get the device interface report.
    GetInterfaceReportFail,
    /// The driver failed to get the mmio ranges.
    GetMmioRangesFail,
    /// The driver function is not implemented.
    FunctionNotImplemented,
}

pub type TdispDriverResult<T> = Result<T, TdispDriverError>;

#[allow(dead_code)]
pub struct TdispResponderCapabilities {
    dsm_capabilities: u32,
    req_msgs_supported: [u8; 16],
    lock_interface_flags_supported: u16,
    reserved: [u8; 3],
    dev_addr_width: u8,
    num_req_this: u8,
    num_req_all: u8,
}

#[allow(dead_code)]
pub struct TdispLockInterfaceParam {
    flags: TdispLockInterfaceFlags,
    default_stream_id: u8,
    reserved: u8,
    mmio_reporting_offset: [u8; 8],
    bind_p2p_addr_mask: [u8; 8],
}

bitfield! {
#[derive(FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct TdispLockInterfaceFlags(u16);
impl Debug;
u8;
    pub no_fw_update, set_no_fw_update: 0, 0; // Bit 0 NO_FW_UPDATE
    pub system_cache_line_size, set_system_cache_line_size: 1, 1; // Bits 1:1 SYSTEM_CACHE_LINE_SIZE
    pub lock_msix, set_lock_msix: 2, 2; // Bit 2 LOCK_MSIX
    pub bind_p2p, set_bind_p2p: 3, 3; // Bit 3 BIND_P2P
    pub all_req_redirect, set_all_req_redirect: 4, 4; // Bit 4 ALL_REQUEST_REDIRECT
    pub reserved, _: 15, 5; // Bits 15:5 Reserved
}

/// TDISP Driver trait that defines the interface for TDISP operations.
/// This trait is intended to be implemented by a TDISP driver
/// that interacts with the TDISP device.
#[async_trait]
pub trait TdispDriver {
    /// Gets the TDISP device capabilities.
    ///
    /// # Arguments
    /// * `tsm_caps` - TSM capability flags
    ///
    /// # Returns
    /// `TdispResponderCapabilities` on success or an error on failure.
    async fn get_capabilities(
        &self,
        tsm_caps: u32,
    ) -> TdispDriverResult<TdispResponderCapabilities>;

    /// Lock Interface Request
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    /// * `param` - Lock Interface parameters from the request
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn lock_interface(
        &self,
        function_id: FunctionId,
        param: TdispLockInterfaceParam,
    ) -> TdispDriverResult<u32>;

    /// Get the device interface report.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    /// * `offset` - Offset from the start of the report requested
    /// * `report` - report buffer slice to fill
    /// * `copied` - Length of the TDI report copied
    /// * `remainder` - Remaining length of the TDI report
    ///
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn get_device_interface_report(
        &self,
        function_id: FunctionId,
        offset: u16,
        report: &mut [u8],
        copied: &mut usize,
        remainder: &mut usize,
    ) -> TdispDriverResult<u32>;

    /// Get the device interface state.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    /// * `tdi_state` - Device Interface State to fill
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn get_device_interface_state(
        &self,
        function_id: FunctionId,
        tdi_state: &mut u8,
    ) -> TdispDriverResult<u32>;

    /// Start the device interface.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn start_interface(&self, function_id: FunctionId) -> TdispDriverResult<u32>;

    /// Stop the device interface.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn stop_interface(&self, function_id: FunctionId) -> TdispDriverResult<u32>;
}
