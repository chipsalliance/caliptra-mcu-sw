/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{spi_host::SpiHost, EmuCtrl, Uart};
use emulator_bus::{Clock, Ram, Rom};
use emulator_cpu::{Pic, PicMmioRegisters};
use emulator_derive::Bus;
use emulator_types::RAM_SIZE;
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
};

/// Caliptra Root Bus Arguments
#[derive(Default)]
pub struct CaliptraRootBusArgs {
    pub pic: Rc<Pic>,
    pub clock: Rc<Clock>,
    pub rom: Vec<u8>,
    pub firmware: Vec<u8>,
    pub log_dir: PathBuf,
    pub uart_output: Option<Rc<RefCell<Vec<u8>>>>,
    pub uart_rx: Option<Arc<Mutex<Option<u8>>>>,
}

#[derive(Bus)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, len = 0xc000)]
    pub rom: Rom,

    #[peripheral(offset = 0x1000_1000, len = 0x100)]
    pub uart: Uart,

    #[peripheral(offset = 0x1000_2000, len = 0x4)]
    pub ctrl: EmuCtrl,

    #[peripheral(offset = 0x2000_0000, len = 0x40)]
    pub spi: SpiHost,

    #[peripheral(offset = 0x4000_0000, len = 0x60000)]
    pub ram: Rc<RefCell<Ram>>,

    #[peripheral(offset = 0x6000_0000, len = 0x507d)]
    pub pic_regs: PicMmioRegisters,
}

impl CaliptraRootBus {
    pub const UART_NOTIF_IRQ: u8 = 16;
    pub const I3C_ERROR_IRQ: u8 = 17;
    pub const I3C_NOTIF_IRQ: u8 = 18;
    pub const MAIN_FLASH_CTRL_ERROR_IRQ: u8 = 19;
    pub const MAIN_FLASH_CTRL_EVENT_IRQ: u8 = 20;
    pub const RECOVERY_FLASH_CTRL_ERROR_IRQ: u8 = 21;
    pub const RECOVERY_FLASH_CTRL_EVENT_IRQ: u8 = 22;

    pub fn new(mut args: CaliptraRootBusArgs) -> Result<Self, std::io::Error> {
        let clock = args.clock;
        let pic = args.pic;
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let uart_irq = pic.register_irq(Self::UART_NOTIF_IRQ);
        let mut ram = Ram::new(vec![0; RAM_SIZE as usize]);
        // copy runtime firmware into ICCM
        ram.data_mut()[0x80..0x80 + args.firmware.len()].copy_from_slice(&args.firmware);

        Ok(Self {
            rom,
            ram: Rc::new(RefCell::new(ram)),
            spi: SpiHost::new(&clock.clone()),
            uart: Uart::new(args.uart_output, args.uart_rx, uart_irq, &clock.clone()),
            ctrl: EmuCtrl::new(),
            pic_regs: pic.mmio_regs(clock.clone()),
        })
    }
}
