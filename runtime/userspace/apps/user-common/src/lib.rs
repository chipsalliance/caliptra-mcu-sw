// Licensed under the Apache-2.0 license

//! Common platform-agnostic code shared between emulator and FPGA user apps.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![allow(static_mut_refs)]

use core::fmt::Write;
#[allow(unused)]
use embassy_executor::Spawner;
use libsyscall_caliptra::dma::{AXIAddr, DMAMapping};
use libtock_platform::ErrorCode;
use libtockasync::TockExecutor;

pub mod image_loader;
pub mod mcu_mbox;
pub mod soc_env;
pub mod spdm;
pub mod vdm;

// ---------------------------------------------------------------------------
// Shared identity DMA mapping
// ---------------------------------------------------------------------------

/// Identity DMA mapping suitable for platforms where MCU SRAM addresses
/// are the same on both the MCU and AXI buses (emulator, FPGA).
pub struct IdentityDMAMap;

impl DMAMapping for IdentityDMAMap {
    fn mcu_sram_to_mcu_axi(&self, addr: u32) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }

    fn cptra_axi_to_mcu_axi(&self, addr: AXIAddr) -> Result<AXIAddr, ErrorCode> {
        Ok(addr as AXIAddr)
    }
}

/// Global identity DMA mapping instance.
pub static IDENTITY_DMA_MAPPING: IdentityDMAMap = IdentityDMAMap;

// ---------------------------------------------------------------------------
// Shared MMIO writer (emulator + FPGA use the same address)
// ---------------------------------------------------------------------------

/// MMIO-based writer that prints one byte at a time to a fixed address.
/// Both the emulator and FPGA currently use address `0x1000_1041`.
pub struct MmioWriter {
    pub addr: *mut u8,
}

/// Safety: the MMIO address is a device register, not shared mutable memory.
unsafe impl Sync for MmioWriter {}
unsafe impl Send for MmioWriter {}

impl Write for MmioWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            unsafe {
                core::ptr::write_volatile(self.addr, b);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared async_main – spawns the common set of tasks
// ---------------------------------------------------------------------------

/// Spawn the standard set of user-app tasks and enter the executor poll loop.
///
/// `image_loading_spawner` is a closure that spawns the platform-specific
/// `image_loading_task` onto the executor.  Everything else is identical
/// across platforms.
pub async fn async_main(
    executor: &'static TockExecutor,
    image_loading_spawner: impl FnOnce(Spawner),
) {
    let spawner = executor.spawner();

    // TODO: Debug spawning the SPDM task causes a hardfault in FPGA when firmware
    // update is enabled. For now, disable the SPDM task if either FW update test
    // is enabled.
    #[cfg(not(any(
        feature = "test-firmware-update-streaming",
        feature = "test-firmware-update-flash"
    )))]
    spawner.spawn(spdm::spdm_task(spawner)).unwrap();

    image_loading_spawner(spawner);

    spawner.spawn(mcu_mbox::mcu_mbox_task(spawner)).unwrap();

    #[cfg(feature = "test-mcu-mbox-fips-periodic")]
    spawner
        .spawn(mcu_mbox_lib::fips_periodic::fips_periodic_task())
        .unwrap();

    #[cfg(feature = "test-mctp-vdm-cmds")]
    spawner.spawn(vdm::vdm_task(spawner)).unwrap();

    loop {
        executor.poll();
    }
}
