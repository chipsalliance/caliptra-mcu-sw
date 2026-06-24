// Licensed under the Apache-2.0 license

//! TDISP platform driver abstraction.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use caliptra_mcu_spdm_codec::vendor_defined::pci_sig::tdisp::{
    FunctionId, TdiStatus, TdispLockInterfaceParam, TdispReqCapabilities, TdispRespCapabilities,
    START_INTERFACE_NONCE_SIZE,
};
/// Error codes returned by TDISP driver
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdispDriverError {
    /// Input parameter is null or invalid.
    InvalidArgument = 0x01,
    /// Memory allocation failed.
    NoMemory = 0x02,
    /// The driver failed to get TDISP capabilities.
    GetTdispCapabilitiesFail = 0x03,
    /// The driver failed to get the device interface state.
    GetDeviceInterfaceStateFail = 0x04,
    /// The driver failed to lock the device interface.
    LockInterfaceReqFail = 0x05,
    /// The driver failed to start the device interface.
    StartInterfaceReqFail = 0x06,
    /// The driver failed to stop the device interface.
    StopInterfaceReqFail = 0x07,
    /// The driver failed to get the device interface report.
    GetInterfaceReportFail = 0x08,
    /// The driver failed to get the mmio ranges.
    GetMmioRangesFail = 0x09,
    /// The driver function is not implemented.
    FunctionNotImplemented = 0x0A,
}

/// Result type returned by TDISP drivers.
pub type TdispDriverResult<T> = Result<T, TdispDriverError>;

/// Platform abstraction used by the TDISP responder.
#[allow(async_fn_in_trait)]
pub trait TdispDriver {
    /// Fills `out` with a START_INTERFACE nonce.
    async fn generate_start_interface_nonce<Alloc>(
        &self,
        scratch: &Alloc,
        out: &mut [u8; START_INTERFACE_NONCE_SIZE],
    ) -> TdispDriverResult<()>
    where
        Alloc: SpdmPalAlloc;

    /// Gets responder capabilities.
    async fn get_capabilities<Alloc>(
        &self,
        req_caps: TdispReqCapabilities,
        scratch: &Alloc,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Locks an interface.
    async fn lock_interface<Alloc>(
        &self,
        function_id: FunctionId,
        param: TdispLockInterfaceParam,
        scratch: &Alloc,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Returns the total device interface report length.
    async fn get_device_interface_report_len<Alloc>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Copies a device interface report portion.
    async fn get_device_interface_report<Alloc>(
        &self,
        function_id: FunctionId,
        offset: u16,
        scratch: &Alloc,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Gets the current device interface state.
    async fn get_device_interface_state<Alloc>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Starts an interface.
    async fn start_interface<Alloc>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;

    /// Stops an interface.
    async fn stop_interface<Alloc>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc;
}
