/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{spi_host::SpiHost, EmuCtrl, Uart};
use caliptra_emu_bus::{Device, Event, EventData};
use emulator_bus::{Bus, Clock, Ram, Rom};
use emulator_consts::RAM_SIZE;
use emulator_cpu::{Pic, PicMmioRegisters};
use emulator_derive::Bus;
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{mpsc, Arc, Mutex},
};

/// Caliptra Root Bus Arguments
#[derive(Default)]
pub struct CaliptraRootBusArgs {
    pub pic: Rc<Pic>,
    pub clock: Rc<Clock>,
    pub rom: Vec<u8>,
    pub log_dir: PathBuf,
    pub uart_output: Option<Rc<RefCell<Vec<u8>>>>,
    pub uart_rx: Option<Arc<Mutex<Option<u8>>>>,
}

#[derive(Bus)]
#[incoming_event_fn(handle_incoming_event)]
#[register_outgoing_events_fn(register_outgoing_events)]
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

    event_sender: Option<mpsc::Sender<Event>>,
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
        let ram = Ram::new(vec![0; RAM_SIZE as usize]);
        Ok(Self {
            rom,
            ram: Rc::new(RefCell::new(ram)),
            spi: SpiHost::new(&clock.clone()),
            uart: Uart::new(args.uart_output, args.uart_rx, uart_irq, &clock.clone()),
            ctrl: EmuCtrl::new(),
            pic_regs: pic.mmio_regs(clock.clone()),
            event_sender: None,
        })
    }

    pub fn load_ram(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.ram.borrow().len() as usize {
            panic!("Data exceeds RAM size");
        }
        self.ram.borrow_mut().data_mut()[offset..offset + data.len()].copy_from_slice(data);
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.rom.register_outgoing_events(sender.clone());
        self.uart.register_outgoing_events(sender.clone());
        self.ctrl.register_outgoing_events(sender.clone());
        self.spi.register_outgoing_events(sender.clone());
        self.ram
            .borrow_mut()
            .register_outgoing_events(sender.clone());
        self.pic_regs.register_outgoing_events(sender.clone());
        self.event_sender = Some(sender);
    }

    fn handle_incoming_event(&mut self, event: Rc<Event>) {
        self.rom.incoming_event(event.clone());
        self.uart.incoming_event(event.clone());
        self.ctrl.incoming_event(event.clone());
        self.spi.incoming_event(event.clone());
        self.ram.borrow_mut().incoming_event(event.clone());
        self.pic_regs.incoming_event(event.clone());

        if let (Device::MCU, EventData::MemoryRead { start_addr, len }) =
            (event.dest, event.event.clone())
        {
            // TODO: we need to adjust the interrupt vector table to be at the end or rewrite our LD script to add it automatically
            let start = (start_addr + 0x80) as usize;
            let len = len as usize;
            if start >= RAM_SIZE as usize || start + len >= RAM_SIZE as usize {
                println!(
                    "Ignoring invalid MCU RAM read from {}..{}",
                    start,
                    start + len
                );
            } else {
                let ram = self.ram.borrow();
                let ram_size = ram.len() as usize;
                let len = len.min(ram_size - start);

                if let Some(event_sender) = self.event_sender.as_ref() {
                    event_sender
                        .send(Event {
                            src: Device::MCU,
                            dest: event.src,
                            event: EventData::MemoryReadResponse {
                                start_addr,
                                data: ram.data()[start..start + len].to_vec(),
                            },
                        })
                        .unwrap();
                }
            }
        }

        if let (Device::MCU, EventData::MemoryWrite { start_addr, data }) =
            (event.dest, event.event.clone())
        {
            let start = (start_addr + 0x80) as usize;
            if start >= RAM_SIZE as usize || start + data.len() >= RAM_SIZE as usize {
                println!(
                    "Ignoring invalid MCU RAM write to {}..{}",
                    start,
                    start + data.len()
                );
            } else {
                let mut ram = self.ram.borrow_mut();
                let ram_size = ram.len() as usize;
                let len = data.len().min(ram_size - start);
                ram.data_mut()[start..start + len].copy_from_slice(&data[..len]);
            }
        }
    }
}
