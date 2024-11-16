// Licensed under the Apache-2.0 license.

// Copyright Tock Contributors 2022.
// Copyright (c) 2024 Antmicro <www.antmicro.com>

//! High-level setup and interrupt mapping for the chip.

#![allow(static_mut_refs)]

use crate::io::SemihostUart;
use crate::timers::{InternalTimers, TimerInterrupts};
use crate::CHIP;
use capsules_core::virtualizers::virtual_alarm::MuxAlarm;
use core::fmt::Write;
use core::ptr::addr_of;
use kernel::debug;
use kernel::platform::chip::{Chip, InterruptService};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable};
use kernel::utilities::StaticRef;
use rv32i::csr::{mcause, mie::mie, CSR};
use rv32i::pmp::{simple::SimplePMP, PMPUserMPU};
use rv32i::syscall::SysCall;

use crate::pic::Pic;
use crate::pic::PicRegisters;

pub const PIC_BASE: StaticRef<PicRegisters> =
    unsafe { StaticRef::new(0x6000_0000 as *const PicRegisters) };

pub static mut PIC: Pic = Pic::new(PIC_BASE);
pub static mut TIMERS: InternalTimers<'static> = InternalTimers::new();
pub const UART_IRQ: u8 = 0x10;

pub struct VeeR<'a, I: InterruptService + 'a> {
    userspace_kernel_boundary: SysCall,
    pic: &'a Pic,
    timers: &'static InternalTimers<'static>,
    pic_interrupt_service: &'a I,
    pmp: PMPUserMPU<4, SimplePMP<8>>,
}

pub struct VeeRDefaultPeripherals<'a> {
    pub uart: SemihostUart<'a>,
}

impl<'a> VeeRDefaultPeripherals<'a> {
    pub fn new(alarm: &'a MuxAlarm<'a, InternalTimers<'a>>) -> Self {
        Self {
            uart: SemihostUart::new(alarm),
        }
    }

    pub fn init(&'static self) {
        kernel::deferred_call::DeferredCallClient::register(&self.uart);
    }
}

impl<'a> InterruptService for VeeRDefaultPeripherals<'a> {
    unsafe fn service_interrupt(&self, interrupt: u32) -> bool {
        if interrupt == UART_IRQ as u32 {
            self.uart.handle_interrupt();
            return true;
        }
        debug!("Unhandled interrupt {}", interrupt);
        false
    }
}

impl<'a, I: InterruptService + 'a> VeeR<'a, I> {
    /// # Safety
    /// Accesses memory-mapped registers.
    pub unsafe fn new(pic_interrupt_service: &'a I) -> Self {
        Self {
            userspace_kernel_boundary: SysCall::new(),
            pic: &*addr_of!(PIC),
            timers: &*addr_of!(TIMERS),
            pic_interrupt_service,
            pmp: PMPUserMPU::new(SimplePMP::new().unwrap()),
        }
    }

    pub fn enable_pic_interrupts(&self) {
        self.pic.enable_all();
    }

    pub fn enable_timer_interrupts(&self) {
        self.timers.enable_timer0();
    }

    fn handle_timer_interrupts(&self) {
        self.timers.service_interrupts();
    }

    unsafe fn handle_pic_interrupts(&self) {
        while let Some(interrupt) = self.pic.get_saved_interrupts() {
            if !self.pic_interrupt_service.service_interrupt(interrupt) {
                panic!("Unhandled interrupt {}", interrupt);
            }
            self.atomic(|| {
                // Safe as interrupts are disabled
                self.pic.complete(interrupt);
            });
        }
    }
}

impl<'a, I: InterruptService + 'a> kernel::platform::chip::Chip for VeeR<'a, I> {
    type MPU = PMPUserMPU<4, SimplePMP<8>>;
    type UserspaceKernelBoundary = SysCall;

    fn mpu(&self) -> &Self::MPU {
        &self.pmp
    }

    fn userspace_kernel_boundary(&self) -> &SysCall {
        &self.userspace_kernel_boundary
    }

    fn service_pending_interrupts(&self) {
        loop {
            if self.pic.get_saved_interrupts().is_some() {
                unsafe {
                    self.handle_pic_interrupts();
                }
            }
            if self.timers.get_saved_interrupts() != TimerInterrupts::None {
                self.handle_timer_interrupts();
            }
            if self.pic.get_saved_interrupts().is_none()
                && self.timers.get_saved_interrupts() == TimerInterrupts::None
            {
                break;
            }
        }

        // Re-enable all MIE interrupts that we care about. Since we looped
        // until we handled them all, we can re-enable all of them.
        CSR.mie.modify(mie::mext::SET + mie::BIT29::SET);
    }

    fn has_pending_interrupts(&self) -> bool {
        self.pic.get_saved_interrupts().is_some()
            || self.timers.get_saved_interrupts() != TimerInterrupts::None
    }

    fn sleep(&self) {
        unsafe {
            rv32i::support::wfi();
        }
    }

    unsafe fn atomic<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        rv32i::support::atomic(f)
    }

    unsafe fn print_state(&self, writer: &mut dyn Write) {
        rv32i::print_riscv_state(writer);
    }
}

fn handle_exception(exception: mcause::Exception) {
    match exception {
        mcause::Exception::UserEnvCall | mcause::Exception::SupervisorEnvCall => (),

        mcause::Exception::InstructionMisaligned
        | mcause::Exception::InstructionFault
        | mcause::Exception::IllegalInstruction
        | mcause::Exception::Breakpoint
        | mcause::Exception::LoadMisaligned
        | mcause::Exception::LoadFault
        | mcause::Exception::StoreMisaligned
        | mcause::Exception::StoreFault
        | mcause::Exception::MachineEnvCall
        | mcause::Exception::InstructionPageFault
        | mcause::Exception::LoadPageFault
        | mcause::Exception::StorePageFault
        | mcause::Exception::Unknown => {
            panic!("fatal exception: {:?}: {:#x}", exception, CSR.mtval.get());
        }
    }
}

unsafe fn handle_interrupt(intr: mcause::Interrupt, mcause: u32) {
    if mcause == 0x8000_001D {
        CSR.mie.modify(mie::BIT29::CLEAR);
        TIMERS.save_interrupt(0);
        return;
    } else if mcause == 0x8000_001C {
        CSR.mie.modify(mie::BIT28::CLEAR);
        TIMERS.save_interrupt(1);
        return;
    }
    match intr {
        mcause::Interrupt::UserSoft
        | mcause::Interrupt::UserTimer
        | mcause::Interrupt::UserExternal => {
            panic!("unexpected user-mode interrupt");
        }
        mcause::Interrupt::SupervisorExternal
        | mcause::Interrupt::SupervisorTimer
        | mcause::Interrupt::SupervisorSoft => {
            panic!("unexpected supervisor-mode interrupt");
        }

        mcause::Interrupt::MachineSoft => {
            CSR.mie.modify(mie::msoft::CLEAR);
        }
        mcause::Interrupt::MachineTimer => {
            CSR.mie.modify(mie::mtimer::CLEAR);
        }
        mcause::Interrupt::MachineExternal => {
            // We received an interrupt, disable interrupts while we handle them
            CSR.mie.modify(mie::mext::CLEAR);

            // Claim the interrupt, unwrap() as we know an interrupt exists
            // Once claimed this interrupt won't fire until it's completed
            // NOTE: The interrupt is no longer pending in the PIC
            loop {
                let interrupt = PIC.next_pending();

                match interrupt {
                    Some(irq) => {
                        // this one is level-triggered and can't be cleared without handling it
                        if irq == UART_IRQ as u32 {
                            CHIP.unwrap().pic_interrupt_service.service_interrupt(irq);
                        }
                        PIC.save_interrupt(irq);
                    }
                    None => {
                        // Enable generic interrupts
                        CSR.mie.modify(mie::mext::SET);
                        break;
                    }
                }
            }
        }

        mcause::Interrupt::Unknown => {
            panic!("interrupt of unknown cause");
        }
    }
}

/// Trap handler for board/chip specific code.
///
/// This gets called when an interrupt occurs while the chip is
/// in kernel mode.
///
/// # Safety
/// Accesses CSRs.
#[export_name = "_start_trap_rust_from_kernel"]
pub unsafe extern "C" fn start_trap_rust() {
    let mcause = CSR.mcause.extract();
    // print_to_console(b"Tock handling trap, mcause: ");
    // print_hex(mcause.get() as u32);
    // print_to_console(b"\n");
    match mcause::Trap::from(mcause) {
        mcause::Trap::Interrupt(interrupt) => {
            handle_interrupt(interrupt, mcause.get() as u32);
        }
        mcause::Trap::Exception(exception) => {
            handle_exception(exception);
        }
    }
}

/// Function that gets called if an interrupt occurs while an app was running.
/// mcause is passed in, and this function should correctly handle disabling the
/// interrupt that fired so that it does not trigger again.
#[export_name = "_disable_interrupt_trap_rust_from_app"]
pub extern "C" fn disable_interrupt_trap_handler(mcause_val: u32) {
    match mcause::Trap::from(mcause_val as usize) {
        mcause::Trap::Interrupt(interrupt) => unsafe {
            handle_interrupt(interrupt, mcause_val);
        },
        _ => {
            panic!("unexpected non-interrupt\n");
        }
    }
}
