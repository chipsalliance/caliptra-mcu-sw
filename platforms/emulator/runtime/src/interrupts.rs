// Licensed under the Apache-2.0 license

use crate::io::SemihostUart;
use capsules_core::virtualizers::virtual_alarm::MuxAlarm;
use kernel::platform::chip::InterruptService;
use mcu_tock_veer::timers::InternalTimers;

pub const UART_IRQ: u8 = 0x10;
pub const MAIN_FLASH_CTRL_ERROR_IRQ: u8 = 0x13;
pub const MAIN_FLASH_CTRL_EVENT_IRQ: u8 = 0x14;
pub const RECOVERY_FLASH_CTRL_EVENT_IRQ: u8 = 0x15;
pub const RECOVERY_FLASH_CTRL_ERROR_IRQ: u8 = 0x16;
pub const DMA_EVENT_IRQ: u8 = 0x17;
pub const DMA_ERROR_IRQ: u8 = 0x18;
pub const DOE_MBOX_EVENT_IRQ: u8 = 0x19;

pub struct EmulatorPeripherals<'a> {
    pub uart: SemihostUart<'a>,
    pub primary_flash_ctrl: flash_driver::flash_ctrl::EmulatedFlashCtrl<'a>,
    pub secondary_flash_ctrl: flash_driver::flash_ctrl::EmulatedFlashCtrl<'a>,
    pub dma: dma_driver::axicdma::AxiCDMA<'a>,
    pub doe_transport: doe_mbox_driver::EmulatedDoeTransport<'a, InternalTimers<'a>>,
}

impl<'a> EmulatorPeripherals<'a> {
    pub fn new(alarm: &'a MuxAlarm<'a, InternalTimers<'a>>) -> Self {
        Self {
            uart: SemihostUart::new(),
            primary_flash_ctrl: flash_driver::flash_ctrl::EmulatedFlashCtrl::new(
                flash_driver::flash_ctrl::PRIMARY_FLASH_CTRL_BASE,
            ),
            secondary_flash_ctrl: flash_driver::flash_ctrl::EmulatedFlashCtrl::new(
                flash_driver::flash_ctrl::SECONDARY_FLASH_CTRL_BASE,
            ),
            dma: dma_driver::axicdma::AxiCDMA::new(dma_driver::axicdma::DMA_CTRL_BASE),
            doe_transport: doe_mbox_driver::EmulatedDoeTransport::new(
                doe_mbox_driver::DOE_MBOX_BASE,
                alarm,
            ),
        }
    }

    pub fn init(&'static self) {
        kernel::deferred_call::DeferredCallClient::register(&self.uart);
        self.uart.init();
        self.primary_flash_ctrl.init();
        self.secondary_flash_ctrl.init();
        self.dma.init();
        self.doe_transport.init();
    }
}

impl<'a> InterruptService for EmulatorPeripherals<'a> {
    unsafe fn service_interrupt(&self, interrupt: u32) -> bool {
        if interrupt == UART_IRQ as u32 {
            self.uart.handle_interrupt();
            return true;
        } else if interrupt == MAIN_FLASH_CTRL_ERROR_IRQ as u32
            || interrupt == MAIN_FLASH_CTRL_EVENT_IRQ as u32
        {
            self.primary_flash_ctrl.handle_interrupt();
            return true;
        } else if interrupt == RECOVERY_FLASH_CTRL_ERROR_IRQ as u32
            || interrupt == RECOVERY_FLASH_CTRL_EVENT_IRQ as u32
        {
            self.secondary_flash_ctrl.handle_interrupt();
            return true;
        } else if interrupt == DMA_ERROR_IRQ as u32 || interrupt == DMA_EVENT_IRQ as u32 {
            self.dma.handle_interrupt();
            return true;
        } else if interrupt == DOE_MBOX_EVENT_IRQ as u32 {
            self.doe_transport.handle_interrupt();
            return true;
        }
        false
    }
}
