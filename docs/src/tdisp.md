# TDISP (TEE Device Interface Security Protocol) Support

Caliptra Subsystem supports handling of TDISP messages by processing them as VENDOR_DEFINED_REQUEST/VENDOR_DEFINED_RESPONSE message payloads. These messages are transported and processed within the secure session established between the host and the TDISP device as specified by Secured CMA/SPDM.

To facilitate the TDISP protocol, devices provide a platform implementation of the `TdispDriver` trait from `mcu-spdm-lite-vdm-handler::pci_sig::tdisp`. The responder owns the TDISP wire-format handling, command dispatch, and protocol state; the driver supplies device-specific operations such as capabilities, interface state transitions, nonce generation, and interface report contents.

The relevant public driver API is summarized below.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TdispDriverError {
    InvalidArgument = 0x01,
    NoMemory = 0x02,
    GetTdispCapabilitiesFail = 0x03,
    GetDeviceInterfaceStateFail = 0x04,
    LockInterfaceReqFail = 0x05,
    StartInterfaceReqFail = 0x06,
    StopInterfaceReqFail = 0x07,
    GetInterfaceReportFail = 0x08,
    GetMmioRangesFail = 0x09,
    FunctionNotImplemented = 0x0A,
}

pub type TdispDriverResult<T> = Result<T, TdispDriverError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FunctionId(pub u32);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispReqCapabilities {
    pub tsm_caps: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispRespCapabilities {
    pub dsm_capabilities: u32,
    pub req_msgs_supported: [u8; 16],
    pub lock_interface_flags_supported: u16,
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispLockInterfaceFlags(pub u16);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TdispLockInterfaceParam {
    pub flags: TdispLockInterfaceFlags,
    pub default_stream_id: u8,
    pub reserved: u8,
    pub mmio_reporting_offset: [u8; 8],
    pub bind_p2p_addr_mask: [u8; 8],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum TdiStatus {
    #[default]
    ConfigUnlocked = 0,
    ConfigLocked = 1,
    Run = 2,
    Error = 3,
    Reserved = 0xff,
}

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
```
