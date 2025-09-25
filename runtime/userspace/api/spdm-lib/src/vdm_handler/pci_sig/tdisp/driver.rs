// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use alloc::boxed::Box;
use async_trait::async_trait;

/// Error codes returned by TDISP driver
#[derive(Debug, PartialEq)]
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

/// TDISP Driver trait that defines the interface for TDISP operations.
/// This trait is intended to be implemented by a TDISP driver
/// that interacts with the TDISP device.
#[async_trait]
pub trait TdispDriver: Send + Sync {
    /// Gets the TDISP device capabilities.
    ///
    /// # Arguments
    /// * `req_caps` - Requester (TSM) capability flags
    /// * `resp_caps` - Responder (DSM) capability flags
    ///
    /// # Returns
    /// 0 on success or an error response code as per the TDISP specification on failure.
    async fn get_capabilities(
        &self,
        req_caps: TdispReqCapabilities,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32>;

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

    /// Get the length of the device interface report.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    /// * `intf_report_len` - Total device interface report length
    ///
    /// # Returns
    /// Length of the device interface report on success or an error response code.
    async fn get_device_interface_report_len(
        &self,
        function_id: FunctionId,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32>;

    /// Get the device interface report.
    ///
    /// # Arguments
    /// * `function_id` - Device Interface Function ID
    /// * `offset` - Offset from the start of the report requested
    /// * `report` - report buffer slice to fill
    /// * `copied` - Length of the TDI report copied
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
        tdi_state: &mut TdiStatus,
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
