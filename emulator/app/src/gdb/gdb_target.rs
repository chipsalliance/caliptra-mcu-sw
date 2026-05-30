/*++

Licensed under the Apache-2.0 license.

File Name:

    gdb_target.rs

Abstract:

    File contains gdb_target module for Caliptra Emulator.

--*/

use caliptra_emu_cpu::xreg_file::XReg;
use caliptra_emu_cpu::WatchPtrKind;
use caliptra_emu_types::RvSize;
use gdbstub::arch::SingleStepGdbBehavior;
use gdbstub::common::Signal;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target;
use gdbstub::target::ext::base::singlethread::{SingleThreadBase, SingleThreadResume};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::WatchKind;
use gdbstub::target::Target;
use gdbstub::target::TargetResult;
use gdbstub_arch;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::emulator::Emulator;
use caliptra_emu_cpu::StepAction as SystemStepAction;

pub enum ExecMode {
    Step,
    Continue,
}

#[derive(Clone, Debug)]
pub enum GdbStopReason {
    Breakpoint,
    SingleStep,
    Interrupt,
    Watchpoint { addr: u32, kind: WatchKind },
    Exit,
}

pub struct GdbTarget {
    emulator: Emulator,
    exec_mode: ExecMode,
    breakpoints: Vec<u32>,
    interrupt_requested: Arc<AtomicBool>,
    should_stop: Arc<AtomicBool>,
    last_stop_reason: Option<GdbStopReason>,
}

impl GdbTarget {
    // Create new instance of GdbTarget
    pub fn new(emulator: Emulator) -> Self {
        Self {
            emulator,
            exec_mode: ExecMode::Continue,
            breakpoints: Vec::new(),
            interrupt_requested: Arc::new(AtomicBool::new(false)),
            should_stop: Arc::new(AtomicBool::new(false)),
            last_stop_reason: None,
        }
    }

    // Get a reference to the underlying emulator
    pub fn emulator(&self) -> &Emulator {
        &self.emulator
    }

    // Get a mutable reference to the underlying emulator
    pub fn emulator_mut(&mut self) -> &mut Emulator {
        &mut self.emulator
    }

    // Extract the emulator from the GdbTarget, consuming the GdbTarget
    pub fn into_emulator(self) -> Emulator {
        self.emulator
    }

    // Signal an interrupt request (called when Ctrl+C is received)
    pub fn request_interrupt(&mut self) {
        self.interrupt_requested.store(true, Ordering::Relaxed);
    }

    // Get a clone of the interrupt flag for non-blocking access
    pub fn get_interrupt_flag(&self) -> Arc<AtomicBool> {
        self.interrupt_requested.clone()
    }

    // Get a clone of the stop flag for non-blocking access
    pub fn get_stop_flag(&self) -> Arc<AtomicBool> {
        self.should_stop.clone()
    }

    // Check if execution should stop (non-blocking)
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::Relaxed)
    }

    // Set the stop flag
    pub fn set_should_stop(&self, value: bool) {
        self.should_stop.store(value, Ordering::Relaxed);
    }

    // Set the interrupt and stop flags (for integration with controlled server)
    pub fn set_interrupt_flag(&mut self, flag: Arc<AtomicBool>) {
        self.interrupt_requested = flag;
    }

    pub fn set_stop_flag(&mut self, flag: Arc<AtomicBool>) {
        self.should_stop = flag;
    }

    // Check for stop conditions after the emulator has already been stepped by C code
    pub fn check_stop_conditions(
        &mut self,
        step_action: SystemStepAction,
    ) -> Option<SingleThreadStopReason<u32>> {
        // Check for interrupt request first
        if self.interrupt_requested.load(Ordering::Relaxed) {
            self.interrupt_requested.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        // Check for external stop request
        if self.should_stop.load(Ordering::Relaxed) {
            self.should_stop.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        // Check the result of the step that was already performed
        match step_action {
            SystemStepAction::Continue => {
                let current_pc = self.emulator.mcu_cpu.read_pc();
                if self.breakpoints.contains(&current_pc) {
                    self.last_stop_reason = Some(GdbStopReason::Breakpoint);
                    return Some(SingleThreadStopReason::SwBreak(()));
                }
            }
            SystemStepAction::Break => {
                let watch = self.emulator.mcu_cpu.get_watchptr_hit().unwrap();
                let kind = if watch.kind == WatchPtrKind::Write {
                    WatchKind::Write
                } else {
                    WatchKind::Read
                };
                self.last_stop_reason = Some(GdbStopReason::Watchpoint {
                    addr: watch.addr,
                    kind,
                });
                return Some(SingleThreadStopReason::Watch {
                    tid: (),
                    kind,
                    addr: watch.addr,
                });
            }
            SystemStepAction::Fatal => {
                self.last_stop_reason = Some(GdbStopReason::Exit);
                return Some(SingleThreadStopReason::Exited(0));
            }
        }

        // Check for single step mode
        if matches!(self.exec_mode, ExecMode::Step) {
            self.last_stop_reason = Some(GdbStopReason::SingleStep);
            return Some(SingleThreadStopReason::DoneStep);
        }

        None
    }

    // Check if we should stop before executing the next instruction
    // This helps catch breakpoints immediately when they're hit
    pub fn should_stop_before_step(&mut self) -> Option<SingleThreadStopReason<u32>> {
        // Check for interrupt request first
        if self.interrupt_requested.load(Ordering::Relaxed) {
            self.interrupt_requested.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        // Check for external stop request
        if self.should_stop.load(Ordering::Relaxed) {
            self.should_stop.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        // Check if we're at a breakpoint before executing
        let current_pc = self.emulator.mcu_cpu.read_pc();
        if self.breakpoints.contains(&current_pc) {
            self.last_stop_reason = Some(GdbStopReason::Breakpoint);
            return Some(SingleThreadStopReason::SwBreak(()));
        }

        None
    }

    // Check if we're in single step mode and should stop after executing one instruction
    pub fn is_single_step_mode(&self) -> bool {
        matches!(self.exec_mode, ExecMode::Step)
    }

    // Check if we should stop after executing the next instruction (for single stepping)
    // This should be called after emulator_step() when in single step mode
    pub fn should_stop_after_step(&mut self) -> Option<SingleThreadStopReason<u32>> {
        // In single step mode, we should always stop after one instruction
        if matches!(self.exec_mode, ExecMode::Step) {
            self.last_stop_reason = Some(GdbStopReason::SingleStep);
            return Some(SingleThreadStopReason::DoneStep);
        }
        None
    }

    // Perform a single step and check for stop conditions
    pub fn step_and_check(&mut self) -> Option<SingleThreadStopReason<u32>> {
        // Check for interrupt request first
        if self.interrupt_requested.load(Ordering::Relaxed) {
            self.interrupt_requested.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        // Check for external stop request
        if self.should_stop.load(Ordering::Relaxed) {
            self.should_stop.store(false, Ordering::Relaxed);
            self.last_stop_reason = Some(GdbStopReason::Interrupt);
            return Some(SingleThreadStopReason::Signal(Signal::SIGINT));
        }

        match self.emulator.step() {
            SystemStepAction::Continue => {
                if self.breakpoints.contains(&self.emulator.mcu_cpu.read_pc()) {
                    self.last_stop_reason = Some(GdbStopReason::Breakpoint);
                    return Some(SingleThreadStopReason::SwBreak(()));
                }
            }
            SystemStepAction::Break => {
                let watch = self.emulator.mcu_cpu.get_watchptr_hit().unwrap();
                let kind = if watch.kind == WatchPtrKind::Write {
                    WatchKind::Write
                } else {
                    WatchKind::Read
                };
                self.last_stop_reason = Some(GdbStopReason::Watchpoint {
                    addr: watch.addr,
                    kind,
                });
                return Some(SingleThreadStopReason::Watch {
                    tid: (),
                    kind,
                    addr: watch.addr,
                });
            }
            SystemStepAction::Fatal => {
                self.last_stop_reason = Some(GdbStopReason::Exit);
                return Some(SingleThreadStopReason::Exited(0));
            }
        }

        if matches!(self.exec_mode, ExecMode::Step) {
            self.last_stop_reason = Some(GdbStopReason::SingleStep);
            return Some(SingleThreadStopReason::DoneStep);
        }

        None
    }

    // Execute the target with responsive interrupt checking
    pub fn run_responsive(&mut self) -> SingleThreadStopReason<u32> {
        match self.exec_mode {
            ExecMode::Step => {
                self.emulator.step();
                SingleThreadStopReason::DoneStep
            }
            ExecMode::Continue => {
                // Execute with interrupt checking every few steps
                for _ in 0..1000 {
                    if let Some(stop_reason) = self.step_and_check() {
                        return stop_reason;
                    }
                }

                // If we reach here, we've executed 1000 steps without hitting a breakpoint
                // Return a temporary stop to allow gdbstub to check for interrupts
                // This creates a responsive execution loop
                SingleThreadStopReason::Signal(Signal::SIGALRM)
            }
        }
    }
}

impl Target for GdbTarget {
    type Arch = gdbstub_arch::riscv::Riscv32;
    type Error = &'static str;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }

    fn guard_rail_single_step_gdb_behavior(&self) -> SingleStepGdbBehavior {
        SingleStepGdbBehavior::Optional
    }

    fn support_breakpoints(
        &mut self,
    ) -> Option<target::ext::breakpoints::BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadBase for GdbTarget {
    fn read_registers(
        &mut self,
        regs: &mut gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        // Read PC
        regs.pc = self.emulator.mcu_cpu.read_pc();

        // Read XReg
        for idx in 0..regs.x.len() {
            regs.x[idx] = self
                .emulator
                .mcu_cpu
                .read_xreg(XReg::from(idx as u16))
                .unwrap();
        }

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &gdbstub_arch::riscv::reg::RiscvCoreRegs<u32>,
    ) -> TargetResult<(), Self> {
        // Write PC
        self.emulator.mcu_cpu.write_pc(regs.pc);

        // Write XReg
        for idx in 0..regs.x.len() {
            self.emulator
                .mcu_cpu
                .write_xreg(XReg::from(idx as u16), regs.x[idx])
                .unwrap();
        }

        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u32, data: &mut [u8]) -> TargetResult<(), Self> {
        #[allow(clippy::needless_range_loop)]
        for i in 0..data.len() {
            data[i] = self
                .emulator
                .mcu_cpu
                .read_bus(RvSize::Byte, start_addr.wrapping_add(i as u32))
                .unwrap_or_default() as u8;
        }
        Ok(())
    }

    fn write_addrs(&mut self, start_addr: u32, data: &[u8]) -> TargetResult<(), Self> {
        #[allow(clippy::needless_range_loop)]
        for i in 0..data.len() {
            self.emulator
                .mcu_cpu
                .write_bus(
                    RvSize::Byte,
                    start_addr.wrapping_add(i as u32),
                    data[i] as u32,
                )
                .unwrap_or_default();
        }
        Ok(())
    }

    fn support_resume(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::base::singlethread::SingleThreadSingleStep for GdbTarget {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        // Handle signals appropriately
        match signal {
            None => {
                // Normal single step without signal
                self.exec_mode = ExecMode::Step;
            }
            Some(Signal::SIGINT) => {
                // SIGINT can be safely ignored when stepping - just step normally
                self.exec_mode = ExecMode::Step;
            }
            Some(Signal::SIGALRM) => {
                // SIGALRM is our internal signal for responsive execution - step normally
                self.exec_mode = ExecMode::Step;
            }
            Some(_other_signal) => {
                // For other signals, we don't support signal injection
                return Err("no support for stepping with signal");
            }
        }

        Ok(())
    }
}

impl SingleThreadResume for GdbTarget {
    fn resume(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        // Handle signals appropriately
        match signal {
            None => {
                // Normal continue without signal
                self.exec_mode = ExecMode::Continue;
            }
            Some(Signal::SIGINT) => {
                // SIGINT can be safely ignored when resuming - just continue normally
                self.exec_mode = ExecMode::Continue;
            }
            Some(Signal::SIGALRM) => {
                // SIGALRM is our internal signal for responsive execution - continue normally
                self.exec_mode = ExecMode::Continue;
            }
            Some(_other_signal) => {
                // For other signals, we don't support signal injection
                return Err("no support for continuing with signal");
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn support_single_step(
        &mut self,
    ) -> Option<target::ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::breakpoints::Breakpoints for GdbTarget {
    #[inline(always)]
    fn support_sw_breakpoint(
        &mut self,
    ) -> Option<target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }
    #[inline(always)]
    fn support_hw_watchpoint(
        &mut self,
    ) -> Option<target::ext::breakpoints::HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl target::ext::breakpoints::SwBreakpoint for GdbTarget {
    fn add_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        self.breakpoints.push(addr);
        Ok(true)
    }

    fn remove_sw_breakpoint(&mut self, addr: u32, _kind: usize) -> TargetResult<bool, Self> {
        match self.breakpoints.iter().position(|x| *x == addr) {
            None => return Ok(false),
            Some(pos) => self.breakpoints.remove(pos),
        };
        Ok(true)
    }
}

impl target::ext::breakpoints::HwWatchpoint for GdbTarget {
    fn add_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        // Add Watchpointer (and transform WatchKind to WatchPtrKind)
        self.emulator.mcu_cpu.add_watchptr(
            addr,
            len,
            if kind == WatchKind::Write {
                WatchPtrKind::Write
            } else {
                WatchPtrKind::Read
            },
        );

        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u32,
        len: u32,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        // Remove Watchpointer (and transform WatchKind to WatchPtrKind)
        self.emulator.mcu_cpu.remove_watchptr(
            addr,
            len,
            if kind == WatchKind::Write {
                WatchPtrKind::Write
            } else {
                WatchPtrKind::Read
            },
        );
        Ok(true)
    }
}
