// Licensed under the Apache-2.0 license

use libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use libsyscall_caliptra::mci::{mci_reg::RESET_REASON, Mci as MciSyscall};
#[allow(unused)]
use libsyscall_caliptra::system::System;
use libtock_platform::ErrorCode;

use libsyscall_caliptra::DefaultSyscalls;
use user_app_common::image_loader::RESET_REASON_FW_HITLESS_UPD_RESET_MASK;

/// FPGA DMA mapping - identity mapping for now.
pub struct FpgaDMAMap {}
impl DMAMapping for FpgaDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }
}

#[allow(dead_code)]
pub static FPGA_DMA_MAPPING: FpgaDMAMap = FpgaDMAMap {};

#[embassy_executor::task]
pub async fn image_loading_task() {
    let mbox_sram = libsyscall_caliptra::mbox_sram::MboxSram::<DefaultSyscalls>::new(
        libsyscall_caliptra::mbox_sram::DRIVER_NUM_MCU_MBOX1_SRAM,
    );
    let mci = MciSyscall::<DefaultSyscalls>::new();
    let reset_reason = mci.read(RESET_REASON, 0).unwrap();
    if reset_reason & RESET_REASON_FW_HITLESS_UPD_RESET_MASK
        == RESET_REASON_FW_HITLESS_UPD_RESET_MASK
    {
        mbox_sram.release_lock().unwrap();
    }
    #[cfg(any(
        feature = "test-pldm-streaming-boot",
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
        feature = "test-pldm-fw-update-e2e",
    ))]
    {
        // Release SRAM lock, in case previous session hasn't released it
        if mbox_sram.acquire_lock().is_err() {
            mbox_sram.release_lock().unwrap();
            mbox_sram.acquire_lock().unwrap();
        }
        let spawner = crate::EXECUTOR.get().spawner();
        match user_app_common::image_loader::image_loading(&FPGA_DMA_MAPPING, spawner).await {
            Ok(_) => {}
            Err(_) => System::exit(1),
        }
        mbox_sram.release_lock().unwrap();
        System::exit(0);
    }
}
