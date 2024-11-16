/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{EmuCtrl, Otp, Uart};
use emulator_bus::{Clock, Ram, Rom};
use emulator_cpu::{Pic, PicMmioRegisters};
use emulator_derive::Bus;
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
    pub otp_file: Option<PathBuf>,
    pub uart_rx: Option<Arc<Mutex<Option<u8>>>>,
}

#[derive(Bus)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, len = 0xc000)]
    pub rom: Rom,

    #[peripheral(offset = 0x2000_1000, len = 0x100)]
    pub uart: Uart,

    #[peripheral(offset = 0x2000_f000, len = 0x4)]
    pub ctrl: EmuCtrl,

    #[peripheral(offset = 0x3000_4000, len = 0x1000)]
    pub otp: Otp,

    #[peripheral(offset = 0x4000_0000, len = 0x40000)]
    pub iccm: Ram,

    #[peripheral(offset = 0x5000_0000, len = 0x20000)]
    pub dccm: Ram,

    #[peripheral(offset = 0x6000_0000, len = 0x507d)]
    pub pic_regs: PicMmioRegisters,
}

impl CaliptraRootBus {
    pub const UART_NOTIF_IRQ: u8 = 16;
    pub const ROM_SIZE: usize = 48 * 1024;
    pub const RAM_SIZE: usize = 256 * 1024;

    pub fn new(mut args: CaliptraRootBusArgs) -> Result<Self, std::io::Error> {
        let clock = args.clock;
        let pic = args.pic;
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let uart_irq = pic.register_irq(Self::UART_NOTIF_IRQ);
        let mut iccm = Ram::new(vec![0; Self::RAM_SIZE]);
        // copy runtime firmware into ICCM
        iccm.data_mut()[0x80..0x80 + args.firmware.len()].copy_from_slice(&args.firmware);

        Ok(Self {
            rom,
            iccm,
            dccm: Ram::new(vec![0; Self::RAM_SIZE]),
            uart: Uart::new(args.uart_output, args.uart_rx, uart_irq, &clock.clone()),
            ctrl: EmuCtrl::new(),
            otp: Otp::new(&clock.clone(), args.otp_file)?,
            pic_regs: pic.mmio_regs(clock.clone()),
        })
    }
}

/*
#[cfg(test)]
mod tests {
    // TODO
}
*/
