// Licensed under the Apache-2.0 license

use crate::io::SemihostUart;
use capsules_core::virtualizers::virtual_alarm::MuxAlarm;
use kernel::platform::chip::InterruptService;
use mcu_tock_veer::timers::InternalTimers;
use registers_generated::mci;

pub struct FpgaPeripherals<'a> {
    pub uart: SemihostUart<'a>,
    //    pub dma: dma_driver::axicdma::AxiCDMA<'a, InternalTimers<'a>>,
    pub dma: dma_driver::nodma::NoDMA<'a, InternalTimers<'a>>,
    pub flash_ctrl: flash_ctrl_fpga::EmulatedFlashCtrl<'a>,
}

impl<'a> FpgaPeripherals<'a> {
    pub fn new(
        alarm: &'a MuxAlarm<'a, InternalTimers<'a>>,
        mci_regs: romtime::StaticRef<mci::regs::Mci>,
    ) -> Self {
        Self {
            uart: SemihostUart::new(alarm),
            //            dma: dma_driver::axicdma::AxiCDMA::new(dma_driver::axicdma::DMA_CTRL_BASE, false, alarm),
            dma: dma_driver::nodma::NoDMA::new(alarm),
            flash_ctrl: flash_ctrl_fpga::EmulatedFlashCtrl::new(mci_regs),
        }
    }

    pub fn init(&'static self) {
        kernel::deferred_call::DeferredCallClient::register(&self.uart);
        self.dma.init();
        self.uart.init();
        self.flash_ctrl.init();
        kernel::deferred_call::DeferredCallClient::register(&self.flash_ctrl);
    }
}

impl<'a> InterruptService for FpgaPeripherals<'a> {
    unsafe fn service_interrupt(&self, _interrupt: u32) -> bool {
        false
    }
}
