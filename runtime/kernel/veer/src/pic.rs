// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.

//! Platform Level Interrupt Control peripheral driver for VeeR.
//!
//! The `Pic` struct has a fixed-size array of 8 cells (supporting up to 256 interrupts),
//! but the `USED_CELLS` const generic controls how many cells are actually scanned
//! when checking for pending interrupts. This allows the compiler to optimize out
//! unnecessary loop iterations while keeping the struct size constant for FFI compatibility.
//!
//! - `USED_CELLS = 1` → scans 32 interrupts
//! - `USED_CELLS = 2` → scans 64 interrupts
//! - ...
//! - `USED_CELLS = 8` → scans all 256 interrupts

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

/// Total number of cells in the saved interrupt array (fixed for FFI compatibility).
const TOTAL_CELLS: usize = 8;

/// Programmable Interrupt Controller for VeeR.
///
/// The `USED_CELLS` const generic controls how many cells are scanned when
/// checking for pending interrupts. The struct always has 8 cells (256 interrupts max)
/// for consistent size, but only `USED_CELLS` are checked in the hot path.
///
/// Valid values are 1 through 8.
pub struct Pic<const USED_CELLS: usize = 8> {
    registers: StaticRef<El2PicCtrl>,
    saved: [Cell<u32>; TOTAL_CELLS],
    meivt: ReadWriteRiscvCsr<usize, MEIVT::Register, 0xBC8>,
    meipt: ReadWriteRiscvCsr<usize, MEIPT::Register, 0xBC9>,
    meicidpl: ReadWriteRiscvCsr<usize, MEICIDPL::Register, 0xBCB>,
    meicurpl: ReadWriteRiscvCsr<usize, MEICURPL::Register, 0xBCC>,
    meihap: ReadWriteRiscvCsr<usize, MEIHAP::Register, 0xFC8>,
}

impl<const USED_CELLS: usize> Pic<USED_CELLS> {
    /// Compile-time check that USED_CELLS is a valid value (1-8).
    const CHECK_USED_CELLS: () = {
        assert!(
            USED_CELLS >= 1 && USED_CELLS <= 8,
            "USED_CELLS must be between 1 and 8 (supporting 32 to 256 interrupts)"
        );
    };

    pub const fn new(pic_addr: u32) -> Self {
        // Trigger compile-time check
        let _ = Self::CHECK_USED_CELLS;

        Pic {
            registers: unsafe { StaticRef::new(pic_addr as *const El2PicCtrl) },
            saved: [const { Cell::new(0) }; TOTAL_CELLS],
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
    ///
    /// Only scans the first `USED_CELLS` cells, allowing the compiler to
    /// optimize out unnecessary iterations when fewer interrupts are needed.
    pub fn get_saved_interrupts(&self) -> Option<u32> {
        for i in 0..USED_CELLS {
            let saved = self.saved[i].get();
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
