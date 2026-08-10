// Licensed under the Apache-2.0 license

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;
use spdm_lib::vdm_handler::pci_sig::tdisp::driver::{TdispDriver, TdispDriverResult};
use spdm_lib::vdm_handler::pci_sig::tdisp::protocol::*;

/// Supported TDISP versions for testing
pub const SUPPORTED_TDISP_VERSIONS: &[TdispVersion] = &[TdispVersion::V10];

pub struct TestTdispDriver {
    capabilities: TdispRespCapabilities,
    tdi_state: TdiStatus,
    dev_intf_report_size: u16,
}

impl TestTdispDriver {
    pub fn new() -> Self {
        Self {
            capabilities: TdispRespCapabilities::new(
                0x01, // dsm_capabilities: LOCK_INTERFACE_SUPPORTED
                [
                    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ], // req_msgs_supported
                0x1F, // lock_interface_flags_supported: All flags supported
                48,   // dev_addr_width: 48-bit addressing
                1,    // num_req_this: Number of requesters for this interface
                1,    // num_req_all: Total number of requesters
            ),
            tdi_state: TdiStatus::ConfigUnlocked,
            dev_intf_report_size: Self::total_report_size(),
        }
    }

    fn total_report_size() -> u16 {
        // MMIO range count = 0
        // Device specific info size = 0
        (size_of::<TdiReportStructureBase>() as usize + 4 + 4) as u16
    }

    fn device_report_data(&self) -> [u8; size_of::<TdiReportStructureBase>() + 4 + 4] {
        [0x00u8; size_of::<TdiReportStructureBase>() + 4 + 4] // example test report
    }
}

#[async_trait]
impl TdispDriver for TestTdispDriver {
    async fn get_capabilities(
        &self,
        _req_caps: TdispReqCapabilities,
        resp_caps: &mut TdispRespCapabilities,
    ) -> TdispDriverResult<u32> {
        // Copy from self.capabilities
        *resp_caps = self.capabilities;
        Ok(0)
    }

    async fn lock_interface(
        &mut self,
        _function_id: FunctionId,
        _param: TdispLockInterfaceParam,
    ) -> TdispDriverResult<u32> {
        // Always succeed in test
        self.tdi_state = TdiStatus::ConfigLocked;
        Ok(0)
    }

    async fn get_device_interface_report_len(
        &self,
        _function_id: FunctionId,
        intf_report_len: &mut u16,
    ) -> TdispDriverResult<u32> {
        *intf_report_len = self.dev_intf_report_size;
        Ok(0)
    }

    async fn get_device_interface_report(
        &self,
        _function_id: FunctionId,
        offset: u16,
        report: &mut [u8],
        copied: &mut usize,
    ) -> TdispDriverResult<u32> {
        if offset as usize >= Self::total_report_size() as usize {
            return Ok(TdispError::InvalidRequest as u32);
        }
        let report_data = self.device_report_data(); // example test report
        let to_copy = report_data.len().min(report.len());

        if offset as usize + to_copy > Self::total_report_size() as usize {
            return Ok(TdispError::InvalidRequest as u32);
        }

        report[..to_copy].copy_from_slice(&report_data[offset as usize..offset as usize + to_copy]);
        *copied = to_copy;
        Ok(0)
    }

    async fn get_device_interface_state(
        &self,
        _function_id: FunctionId,
        tdi_state: &mut TdiStatus,
    ) -> TdispDriverResult<u32> {
        *tdi_state = self.tdi_state;
        Ok(0)
    }

    async fn start_interface(&mut self, _function_id: FunctionId) -> TdispDriverResult<u32> {
        self.tdi_state = TdiStatus::Run;
        Ok(0)
    }

    async fn stop_interface(&mut self, _function_id: FunctionId) -> TdispDriverResult<u32> {
        self.tdi_state = TdiStatus::ConfigUnlocked;
        Ok(0)
    }
}
