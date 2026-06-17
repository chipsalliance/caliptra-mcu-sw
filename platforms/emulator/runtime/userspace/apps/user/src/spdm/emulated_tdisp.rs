// Licensed under the Apache-2.0 license

//! Emulator TDISP driver used by the DOE/SPDM TDISP validator test.

use core::cell::Cell;

use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};
use mcu_spdm_lite_vdm_handler::pci_sig::tdisp::{
    FunctionId, TdiStatus, TdispDriver, TdispDriverResult, TdispLockInterfaceParam,
    TdispReqCapabilities, TdispRespCapabilities, START_INTERFACE_NONCE_SIZE,
    TDISP_ERROR_INVALID_INTERFACE_STATE, TDISP_ERROR_INVALID_REQUEST,
};

const EMULATED_REQ_MSGS_SUPPORTED: [u8; 16] = [
    0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const EMULATED_ZERO_MMIO_REPORT: [u8; 20] = [0; 20];

/// Minimal emulator implementation for DOE/SPDM TDISP validation.
pub struct EmulatedTdispDriver {
    state: Cell<TdiStatus>,
    nonce_counter: Cell<u8>,
}

impl EmulatedTdispDriver {
    /// Creates an emulator driver in CONFIG_UNLOCKED state.
    pub const fn new() -> Self {
        Self {
            state: Cell::new(TdiStatus::ConfigUnlocked),
            nonce_counter: Cell::new(0),
        }
    }
}

impl Default for EmulatedTdispDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl TdispDriver for EmulatedTdispDriver {
    async fn generate_start_interface_nonce<Alloc, Io>(
        &self,
        _scratch: &Alloc,
        _io: &Io,
        out: &mut [u8; START_INTERFACE_NONCE_SIZE],
    ) -> TdispDriverResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        let start = self.nonce_counter.get().wrapping_add(1);
        self.nonce_counter.set(start);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = start.wrapping_add(i as u8);
        }
        Ok(())
    }

    async fn get_capabilities<Alloc, Io>(
        &self,
        _req_caps: TdispReqCapabilities,
        _scratch: &Alloc,
        _io: &Io,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        *resp_caps = TdispRespCapabilities::new(0, EMULATED_REQ_MSGS_SUPPORTED, 0x07, 48, 0, 0);
        Ok(0)
    }

    async fn lock_interface<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        _param: TdispLockInterfaceParam,
        _scratch: &Alloc,
        _io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if self.state.get() != TdiStatus::ConfigUnlocked {
            return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
        }
        self.state.set(TdiStatus::ConfigLocked);
        Ok(0)
    }

    async fn get_device_interface_report_len<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        _scratch: &Alloc,
        _io: &Io,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        *intf_report_len = if self.state.get() == TdiStatus::ConfigUnlocked {
            0
        } else {
            EMULATED_ZERO_MMIO_REPORT.len() as u16
        };
        Ok(0)
    }

    async fn get_device_interface_report<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        offset: u16,
        _scratch: &Alloc,
        _io: &Io,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        let offset = offset as usize;
        if self.state.get() == TdiStatus::ConfigUnlocked
            || offset >= EMULATED_ZERO_MMIO_REPORT.len()
            || offset + report.len() > EMULATED_ZERO_MMIO_REPORT.len()
        {
            return Ok(TDISP_ERROR_INVALID_REQUEST);
        }
        let end = offset + report.len();
        report.copy_from_slice(&EMULATED_ZERO_MMIO_REPORT[offset..end]);
        *copied = report.len();
        Ok(0)
    }

    async fn get_device_interface_state<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        _scratch: &Alloc,
        _io: &Io,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        *tdi_state = self.state.get();
        Ok(0)
    }

    async fn start_interface<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        _scratch: &Alloc,
        _io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if self.state.get() != TdiStatus::ConfigLocked {
            return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
        }
        self.state.set(TdiStatus::Run);
        Ok(0)
    }

    async fn stop_interface<Alloc, Io>(
        &self,
        _function_id: FunctionId,
        _scratch: &Alloc,
        _io: &Io,
    ) -> TdispDriverResult<u32>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if self.state.get() == TdiStatus::ConfigUnlocked {
            return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
        }
        self.state.set(TdiStatus::ConfigUnlocked);
        Ok(0)
    }
}
