/*++

Licensed under the Apache-2.0 license.

File Name:

    network_root_bus.rs

Abstract:

    File contains the root Bus implementation for the Network Coprocessor emulator.
    The Network Coprocessor is a dedicated RISC-V CPU that handles network boot
    recovery, implementing DHCP client and TFTP client functionality.

--*/

use crate::{EmuCtrl, Uart};
use caliptra_emu_bus::Event;
use caliptra_emu_bus::{Bus, BusError, Clock, Ram, Rom};
use caliptra_emu_cpu::{Pic, PicMmioRegisters};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use network_config::DEFAULT_NETWORK_MEMORY_MAP;
use std::{
    cell::RefCell,
    path::PathBuf,
    rc::Rc,
    sync::{mpsc, Arc, Mutex},
};

/// Offsets for peripherals mounted to the Network Coprocessor bus.
#[derive(Debug, Clone)]
pub struct NetworkRootBusOffsets {
    pub rom_offset: u32,
    pub rom_size: u32,
    pub uart_offset: u32,
    pub uart_size: u32,
    pub ctrl_offset: u32,
    pub ctrl_size: u32,
    pub iccm_offset: u32,
    pub iccm_size: u32,
    pub dccm_offset: u32,
    pub dccm_size: u32,
    pub pic_offset: u32,
    pub pic_size: u32,
}

impl Default for NetworkRootBusOffsets {
    fn default() -> Self {
        Self {
            rom_offset: DEFAULT_NETWORK_MEMORY_MAP.rom_offset,
            rom_size: DEFAULT_NETWORK_MEMORY_MAP.rom_size,
            uart_offset: DEFAULT_NETWORK_MEMORY_MAP.uart_offset,
            uart_size: DEFAULT_NETWORK_MEMORY_MAP.uart_size,
            ctrl_offset: DEFAULT_NETWORK_MEMORY_MAP.ctrl_offset,
            ctrl_size: DEFAULT_NETWORK_MEMORY_MAP.ctrl_size,
            iccm_offset: DEFAULT_NETWORK_MEMORY_MAP.iccm_offset,
            iccm_size: DEFAULT_NETWORK_MEMORY_MAP.iccm_size,
            dccm_offset: DEFAULT_NETWORK_MEMORY_MAP.dccm_offset,
            dccm_size: DEFAULT_NETWORK_MEMORY_MAP.dccm_size,
            pic_offset: DEFAULT_NETWORK_MEMORY_MAP.pic_offset,
            pic_size: DEFAULT_NETWORK_MEMORY_MAP.pic_size,
        }
    }
}

/// Network Root Bus Arguments
#[derive(Default)]
pub struct NetworkRootBusArgs {
    pub pic: Rc<Pic>,
    pub clock: Rc<Clock>,
    pub rom: Vec<u8>,
    pub log_dir: PathBuf,
    pub uart_output: Option<Rc<RefCell<Vec<u8>>>>,
    pub uart_rx: Option<Arc<Mutex<Option<u8>>>>,
    pub offsets: NetworkRootBusOffsets,
}

/// The Network Coprocessor Root Bus
///
/// This bus implements the memory map for the Network Coprocessor, which is responsible
/// for network boot recovery operations. It contains:
/// - ROM: Contains the Network ROM firmware (DHCP/TFTP client)
/// - ICCM: Instruction Closely Coupled Memory for the Network Coprocessor
/// - DCCM: Data Closely Coupled Memory for stack/heap
/// - UART: Debug output
/// - PIC: Interrupt controller
pub struct NetworkRootBus {
    pub rom: Rom,
    pub uart: Uart,
    ctrl: EmuCtrl,
    pub iccm: Rc<RefCell<Ram>>,
    pub dccm: Rc<RefCell<Ram>>,
    pub pic_regs: PicMmioRegisters,
    event_sender: Option<mpsc::Sender<Event>>,
    offsets: NetworkRootBusOffsets,
}

impl NetworkRootBus {
    pub const UART_NOTIF_IRQ: u8 = 16;

    pub fn new(mut args: NetworkRootBusArgs) -> Result<Self, std::io::Error> {
        let clock = args.clock;
        let pic = args.pic;
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let uart_irq = pic.register_irq(Self::UART_NOTIF_IRQ);
        let iccm = Ram::new(vec![0; args.offsets.iccm_size as usize]);
        let dccm = Ram::new(vec![0; args.offsets.dccm_size as usize]);

        let ctrl = EmuCtrl::new();

        Ok(Self {
            rom,
            iccm: Rc::new(RefCell::new(iccm)),
            dccm: Rc::new(RefCell::new(dccm)),
            uart: Uart::new(args.uart_output, args.uart_rx, uart_irq, &clock.clone()),
            ctrl,
            pic_regs: pic.mmio_regs(clock.clone()),
            event_sender: None,
            offsets: args.offsets,
        })
    }

    /// Load data into ICCM at the specified offset
    pub fn load_iccm(&mut self, offset: usize, data: &[u8]) {
        if offset + data.len() > self.iccm.borrow().len() as usize {
            panic!("Data exceeds ICCM size");
        }
        self.iccm.borrow_mut().data_mut()[offset..offset + data.len()].copy_from_slice(data);
    }
}

impl Bus for NetworkRootBus {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        // ROM access
        if addr >= self.offsets.rom_offset && addr < self.offsets.rom_offset + self.offsets.rom_size
        {
            return self.rom.read(size, addr - self.offsets.rom_offset);
        }
        // UART access
        if addr >= self.offsets.uart_offset
            && addr < self.offsets.uart_offset + self.offsets.uart_size
        {
            return self.uart.read(size, addr - self.offsets.uart_offset);
        }
        // Control register access
        if addr >= self.offsets.ctrl_offset
            && addr < self.offsets.ctrl_offset + self.offsets.ctrl_size
        {
            let ctrl_addr = addr - self.offsets.ctrl_offset;
            return self.ctrl.read(size, ctrl_addr);
        }
        // ICCM access
        if addr >= self.offsets.iccm_offset
            && addr < self.offsets.iccm_offset + self.offsets.iccm_size
        {
            return self
                .iccm
                .borrow_mut()
                .read(size, addr - self.offsets.iccm_offset);
        }
        // DCCM access
        if addr >= self.offsets.dccm_offset
            && addr < self.offsets.dccm_offset + self.offsets.dccm_size
        {
            return self
                .dccm
                .borrow_mut()
                .read(size, addr - self.offsets.dccm_offset);
        }
        // PIC access
        if addr >= self.offsets.pic_offset && addr < self.offsets.pic_offset + self.offsets.pic_size
        {
            return self.pic_regs.read(size, addr - self.offsets.pic_offset);
        }
        Err(BusError::LoadAccessFault)
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        // ROM is read-only, but we still check the range
        if addr >= self.offsets.rom_offset && addr < self.offsets.rom_offset + self.offsets.rom_size
        {
            return Err(BusError::StoreAccessFault); // ROM is read-only
        }
        // UART access
        if addr >= self.offsets.uart_offset
            && addr < self.offsets.uart_offset + self.offsets.uart_size
        {
            return self.uart.write(size, addr - self.offsets.uart_offset, val);
        }
        // Control register access
        if addr >= self.offsets.ctrl_offset
            && addr < self.offsets.ctrl_offset + self.offsets.ctrl_size
        {
            let ctrl_addr = addr - self.offsets.ctrl_offset;
            return self.ctrl.write(size, ctrl_addr, val);
        }
        // ICCM access
        if addr >= self.offsets.iccm_offset
            && addr < self.offsets.iccm_offset + self.offsets.iccm_size
        {
            return self
                .iccm
                .borrow_mut()
                .write(size, addr - self.offsets.iccm_offset, val);
        }
        // DCCM access
        if addr >= self.offsets.dccm_offset
            && addr < self.offsets.dccm_offset + self.offsets.dccm_size
        {
            return self
                .dccm
                .borrow_mut()
                .write(size, addr - self.offsets.dccm_offset, val);
        }
        // PIC access
        if addr >= self.offsets.pic_offset && addr < self.offsets.pic_offset + self.offsets.pic_size
        {
            return self
                .pic_regs
                .write(size, addr - self.offsets.pic_offset, val);
        }
        Err(BusError::StoreAccessFault)
    }

    fn poll(&mut self) {
        self.rom.poll();
        self.uart.poll();
        self.ctrl.poll();
        self.iccm.borrow_mut().poll();
        self.dccm.borrow_mut().poll();
        self.pic_regs.poll();
    }

    fn warm_reset(&mut self) {
        self.rom.warm_reset();
        self.uart.warm_reset();
        self.ctrl.warm_reset();
        self.iccm.borrow_mut().warm_reset();
        self.dccm.borrow_mut().warm_reset();
        self.pic_regs.warm_reset();
    }

    fn update_reset(&mut self) {
        self.rom.update_reset();
        self.uart.update_reset();
        self.ctrl.update_reset();
        self.iccm.borrow_mut().update_reset();
        self.dccm.borrow_mut().update_reset();
        self.pic_regs.update_reset();
    }

    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.rom.register_outgoing_events(sender.clone());
        self.uart.register_outgoing_events(sender.clone());
        self.ctrl.register_outgoing_events(sender.clone());
        self.iccm
            .borrow_mut()
            .register_outgoing_events(sender.clone());
        self.dccm
            .borrow_mut()
            .register_outgoing_events(sender.clone());
        self.pic_regs.register_outgoing_events(sender.clone());
        self.event_sender = Some(sender);
    }

    fn incoming_event(&mut self, event: Rc<Event>) {
        self.rom.incoming_event(event.clone());
        self.uart.incoming_event(event.clone());
        self.ctrl.incoming_event(event.clone());
        self.iccm.borrow_mut().incoming_event(event.clone());
        self.dccm.borrow_mut().incoming_event(event.clone());
        self.pic_regs.incoming_event(event.clone());
    }
}
