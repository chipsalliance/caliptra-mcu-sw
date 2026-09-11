// Licensed under the Apache-2.0 license

// Component for DMA driver.

use caliptra_mcu_capsules_runtime::dma::hil::Dma as DmaHal;
use core::mem::MaybeUninit;
use kernel::capabilities;
use kernel::component::Component;
use kernel::create_capability;

pub struct DmaComponent {
    driver: &'static dyn DmaHal,
    board_kernel: &'static kernel::Kernel,
    driver_num: usize,
    sram_local_base: u32,
    sram_size: u32,
    cptra_sram_axi_base: u32,
}

impl DmaComponent {
    pub fn new(
        driver: &'static dyn DmaHal,
        board_kernel: &'static kernel::Kernel,
        driver_num: usize,
        sram_local_base: u32,
        sram_size: u32,
        cptra_sram_axi_base: u32,
    ) -> Self {
        Self {
            driver,
            board_kernel,
            driver_num,
            sram_local_base,
            sram_size,
            cptra_sram_axi_base,
        }
    }
}

impl Component for DmaComponent {
    type StaticInput = &'static mut MaybeUninit<caliptra_mcu_capsules_emulator::dma::Dma<'static>>;

    type Output = &'static caliptra_mcu_capsules_emulator::dma::Dma<'static>;

    fn finalize(self, static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);
        let dma: &caliptra_mcu_capsules_emulator::dma::Dma<'_> =
            static_buffer.write(caliptra_mcu_capsules_emulator::dma::Dma::new(
                self.driver,
                self.board_kernel.create_grant(self.driver_num, &grant_cap),
                self.sram_local_base,
                self.sram_size,
                self.cptra_sram_axi_base,
            ));
        self.driver.set_client(dma);
        dma
    }
}
