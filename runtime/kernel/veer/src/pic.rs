// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.

//! Platform Level Interrupt Control peripheral driver for VeeR.

use core::cell::Cell;
use core::ptr::write_volatile;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::register_bitfields;
use registers_generated::el2_pic_ctrl::bits::{Meie, Meigwctrl, Meipl, Mpiccfg};
use registers_generated::el2_pic_ctrl::regs::El2PicCtrl;
use riscv_csr::csr::ReadWriteRiscvCsr;
use romtime::StaticRef;

register_bitfields![usize,
    MEIVT [
        BASE OFFSET(10) NUMBITS(22) []
    ],
    MEIPT [
        PRITHRESH OFFSET(0) NUMBITS(4) []
    ],
    MEICIDPL [
        CLIDPRI OFFSET(0) NUMBITS(4) []
    ],
    MEICURPL [
        CURRPRI OFFSET(0) NUMBITS(4) []
    ],
    MEICPCT [
        RESERVED OFFSET(0) NUMBITS(32) []
    ],
    MEIHAP [
        ZERO OFFSET(0) NUMBITS(2) [],
        CLAIMID OFFSET(2) NUMBITS(8) [],
        BASE OFFSET(10) NUMBITS(22) [],
    ],
];

pub struct Pic {
    registers: StaticRef<El2PicCtrl>,
    saved: [Cell<u32>; 8],
    meivt: ReadWriteRiscvCsr<usize, MEIVT::Register, 0xBC8>,
    meipt: ReadWriteRiscvCsr<usize, MEIPT::Register, 0xBC9>,
    meicidpl: ReadWriteRiscvCsr<usize, MEICIDPL::Register, 0xBCB>,
    meicurpl: ReadWriteRiscvCsr<usize, MEICURPL::Register, 0xBCC>,
    meihap: ReadWriteRiscvCsr<usize, MEIHAP::Register, 0xFC8>,
}

impl Pic {
    pub const fn new(pic_addr: u32) -> Self {
        Pic {
            registers: unsafe { StaticRef::new(pic_addr as *const El2PicCtrl) },
            saved: [
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
                Cell::new(0),
            ],
            meivt: ReadWriteRiscvCsr::new(),
            meipt: ReadWriteRiscvCsr::new(),
            meicidpl: ReadWriteRiscvCsr::new(),
            meicurpl: ReadWriteRiscvCsr::new(),
            meihap: ReadWriteRiscvCsr::new(),
        }
    }

    pub fn init(&self, pic_vector_table_addr: u32) {
        self.registers.mpiccfg.write(
            Mpiccfg::Priord::CLEAR, // standard priority order
        );

        self.disable_all();

        let meivt_base = pic_vector_table_addr;

        // redirect all PIC interrupts to _start_trap
        for irq in 0..256 {
            unsafe {
                write_volatile(
                    (meivt_base + irq * 4) as *mut u32,
                    rv32i::_start_trap as usize as u32,
                );
            }
        }

        assert_eq!(meivt_base & 0x3FF, 0, "MEIVT base must be 1KB aligned");

        // set the meivt to point to the base
        self.meivt.write(MEIVT::BASE.val(meivt_base as usize >> 10));

        for priority in self.registers.meipl.iter().skip(1) {
            priority.write(Meipl::Priority.val(15)); // highest priority
        }

        for property in self.registers.meigwctrl.iter().skip(1) {
            property.write(
                Meigwctrl::Polarity::CLEAR // active high
                + Meigwctrl::Inttype::CLEAR, // level triggered
            );
        }

        self.clear_all_pending();

        self.meipt.set(0);
        self.meicidpl.set(0);
        self.meicurpl.set(0);
    }

    pub fn bits(&self) -> u32 {
        self.registers.meip[0].get()
    }

    /// Clear all pending interrupts.
    pub fn clear_all_pending(&self) {
        for clear in self.registers.meigwclr.iter().skip(1) {
            clear.set(0);
        }
    }

    /// Enable all interrupts.
    pub fn enable_all(&self) {
        for enable in self.registers.meie.iter().skip(1) {
            enable.write(Meie::Inten::SET);
        }
    }
    /// Disable all interrupts.
    pub fn disable_all(&self) {
        for enable in self.registers.meie.iter().skip(1) {
            enable.write(Meie::Inten::CLEAR);
        }
    }

    /// Get the index (0-255) of the lowest number pending interrupt, or `None` if
    /// none is pending. PIC has a "claim" register which makes it easy
    /// to grab the highest priority pending interrupt.
    pub fn next_pending(&self) -> Option<u32> {
        let claimid = self.meihap.read(MEIHAP::CLAIMID);
        if claimid == 0 {
            None
        } else {
            // Clear the interrupt
            self.registers.meigwclr[claimid].set(0);
            // Disable the interrupt, we re-enable it in the complete step
            self.registers.meie[claimid].write(Meie::Inten::CLEAR);

            Some(claimid as u32)
        }
    }

    /// Save the current interrupt to be handled later
    /// This will save the interrupt at index internally to be handled later.
    /// Interrupts must be disabled before this is called.
    /// Saved interrupts can be retrieved by calling `get_saved_interrupts()`.
    /// Saved interrupts are cleared when `'complete()` is called.
    pub fn save_interrupt(&self, index: u32) {
        let offset = (index / 32) as usize;
        if offset >= self.saved.len() {
            // Ignore impossible interrupts.
            romtime::println!("[mcu-runtime-veer] Ignoring impossible interrupt {}", index);
            return;
        };
        let irq = index % 32;

        // OR the current saved state with the new value
        let new_saved = self.saved[offset].get() | 1 << irq;

        // Set the new state
        self.saved[offset].set(new_saved);
    }

    /// The `next_pending()` function will only return enabled interrupts.
    /// This function will return a pending interrupt that has been disabled by
    /// `save_interrupt()`.
    pub fn get_saved_interrupts(&self) -> Option<u32> {
        for (i, pending) in self.saved.iter().enumerate() {
            let saved = pending.get();
            if saved != 0 {
                return Some(saved.trailing_zeros() + (i as u32 * 32));
            }
        }

        None
    }

    /// Signal that an interrupt is finished being handled. In Tock, this should be
    /// called from the normal main loop (not the interrupt handler).
    /// Interrupts must be disabled before this is called.
    pub fn complete(&self, index: u32) {
        let offset = (index / 32) as usize;
        let irq = index % 32;

        if offset > self.saved.len() {
            // Impossible but helps remove panic.
            return;
        }

        if index >= 1 && index < self.registers.meigwclr.len() as u32 {
            // Clear the interrupt
            self.registers.meigwclr[index as usize].set(0);
            // Enable the interrupt
            self.registers.meie[index as usize].write(Meie::Inten::SET);
        }

        // clear the saved interrupt
        let new_saved = self.saved[offset].get() & !(1 << irq);
        self.saved[offset].set(new_saved);
    }
}
