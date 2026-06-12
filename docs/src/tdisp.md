# TDISP (TEE Device Interface Security Protocol) Support

Caliptra Subsystem handles TDISP messages as PCI-SIG SPDM
`VENDOR_DEFINED_REQUEST` / `VENDOR_DEFINED_RESPONSE` payloads. The PCI-SIG VDM
payload starts with protocol ID `0x01` for TDISP, followed by the TDISP message.
TDISP is expected to be carried in an SPDM secured session, for example over DOE
Secure SPDM.

The SPDM-Lite implementation lives under
`runtime/userspace/api/spdm-lite/vdm-handler/src/pci_sig/`:

- `PciSigTdispVdm` matches PCI-SIG VDM envelopes for a configured vendor ID and
  requires `secure_session` before dispatching TDISP.
- `tdisp::TdispResponder` decodes TDISP wire messages from borrowed slices and
  writes responses into caller-provided buffers.
- `tdisp::TdispDriver` is the platform hook for device-specific TDISP
  operations.

The implementation intentionally avoids `async_trait`, boxed futures, and a
heap-backed handler table. The stack is generic over the backend type, so async
methods compile to concrete state machines. Driver hooks receive the current
request-scoped PAL scratch allocator and I/O handle, matching the OCP VDM
pattern so platform code can stage mailbox/syscall requests without heap, large
stack buffers, or retained persistent buffers.

## Platform driver interface

A platform that wants to serve TDISP implements the `TdispDriver` trait and
constructs a `TdispResponder` with the supported protocol versions. The driver
returns `Ok(0)` on success, or `Ok(<TDISP error code>)` when the request should
be completed with a TDISP `ERROR_RESPONSE`. Transport/allocation/internal
failures use `Err(TdispDriverError)`.

```rust
pub enum TdispDriverError {
    InvalidArgument,
    NoMemory,
    FunctionNotImplemented,
}

pub type TdispDriverResult<T> = Result<T, TdispDriverError>;

pub struct FunctionId(pub u32);

pub struct TdispReqCapabilities {
    pub tsm_caps: u32,
}

pub struct TdispRespCapabilities {
    pub dsm_capabilities: u32,
    pub req_msgs_supported: [u8; 16],
    pub lock_interface_flags_supported: u16,
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
}

pub struct TdispLockInterfaceParam {
    pub flags: TdispLockInterfaceFlags,
    pub default_stream_id: u8,
    pub mmio_reporting_offset: [u8; 8],
    pub bind_p2p_addr_mask: [u8; 8],
}

pub struct TdispLockInterfaceFlags(pub u16);

pub enum TdiStatus {
    ConfigUnlocked = 0,
    ConfigLocked = 1,
    Run = 2,
    Error = 3,
    Reserved,
}

pub trait TdispDriver {
    async fn generate_start_interface_nonce<Alloc, Io>(
        &self,
        scratch: &Alloc,
        io: &Io,
        out: &mut [u8; START_INTERFACE_NONCE_SIZE],
    ) -> TdispDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn get_capabilities<Alloc, Io>(
        &self,
        req_caps: TdispReqCapabilities,
        scratch: &Alloc,
        io: &Io,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn lock_interface<Alloc, Io>(
        &self,
        function_id: FunctionId,
        param: TdispLockInterfaceParam,
        scratch: &Alloc,
        io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn get_device_interface_report_len<Alloc, Io>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        io: &Io,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn get_device_interface_report<Alloc, Io>(
        &self,
        function_id: FunctionId,
        offset: u16,
        scratch: &Alloc,
        io: &Io,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn get_device_interface_state<Alloc, Io>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        io: &Io,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn start_interface<Alloc, Io>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;

    async fn stop_interface<Alloc, Io>(
        &self,
        function_id: FunctionId,
        scratch: &Alloc,
        io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo;
}
```

## Current support

The current SPDM-Lite TDISP responder supports:

- `GET_TDISP_VERSION`
- `GET_TDISP_CAPABILITIES`
- `LOCK_INTERFACE`
- `GET_DEVICE_INTERFACE_REPORT`
- `GET_DEVICE_INTERFACE_STATE`
- `START_INTERFACE`
- `STOP_INTERFACE`

`BIND_P2P_STREAM`, `UNBIND_P2P_STREAM`, `SET_MMIO_ATTRIBUTE`, TDISP VDM nested
requests, and IDE-KM are not implemented. Unsupported TDISP request opcodes are
reported as TDISP `ERROR_RESPONSE` payloads with `UnsupportedRequest` rather than
outer SPDM errors when a valid TDISP header is present.
