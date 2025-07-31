// Licensed under the Apache-2.0 license

use caliptra_emu_bus::BusError;
use caliptra_emu_bus::{Bus, Clock, Ram, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_types::{RvAddr, RvSize};
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::{Readable, Writeable};

const MCU_MAILBOX_SRAM_SIZE: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct MciMailboxRam {
    ram: Rc<RefCell<Ram>>,
}

impl MciMailboxRam {
    pub fn new() -> Self {
        Self {
            ram: Rc::new(RefCell::new(Ram::new(vec![0u8; MCU_MAILBOX_SRAM_SIZE]))),
        }
    }
}

#[derive(Clone)]
pub struct MciMailboxInternal {
    pub regs: Rc<RefCell<MciMailboxImpl>>,
}

impl MciMailboxInternal {
    pub fn new(clock: &Clock) -> Self {
        Self {
            regs: Rc::new(RefCell::new(MciMailboxImpl::new(clock))),
        }
    }

    pub fn as_external(&self, soc_agent: MciMailboxRequester) -> MciMailboxExternal {
        MciMailboxExternal {
            soc_agent,
            regs: self.regs.clone(),
        }
    }

    /// Returns the last IRQ event type if an interrupt is pending, and clears the IRQ flag and event.
    pub fn get_notif_irq(&mut self) -> Option<InterruptToMcu> {
        let mut regs = self.regs.borrow_mut();
        if regs.irq {
            regs.irq = false;
            let event = regs.last_irq_event;
            regs.last_irq_event = None;
            return event;
        }
        None
    }

    #[cfg(test)]
    pub fn set_notif_irq(&mut self, event: InterruptToMcu) {
        let mut regs = self.regs.borrow_mut();
        regs.irq = true;
        regs.last_irq_event = Some(event);
    }
}

pub struct MciMailboxExternal {
    pub soc_agent: MciMailboxRequester,
    pub regs: Rc<RefCell<MciMailboxImpl>>,
}

pub struct MciMailboxImpl {
    /// 0x0: Mailbox SRAM
    sram: MciMailboxRam,

    /// 0x200000: Mailbox Lock
    lock: ReadOnlyRegister<u32>,

    /// 0x200004: Mailbox USER
    user: ReadOnlyRegister<u32>,

    /// 0x200008: Mailbox Target USER
    target_user: ReadWriteRegister<u32>,

    /// 0x20000C: Mailbox Target USER Valid
    target_user_valid: ReadWriteRegister<u32>,

    /// 0x200010: Mailbox Command
    cmd: ReadWriteRegister<u32>,

    /// 0x200014: Mailbox Data Length
    dlen: ReadWriteRegister<u32>,

    /// 0x200018: Mailbox Execute
    execute: ReadWriteRegister<u32>,

    /// 0x20001C: Mailbox Target Status
    target_status: ReadWriteRegister<u32>,

    /// 0x200020: Mailbox Command Status
    cmd_status: ReadWriteRegister<u32>,

    /// 0x200024: Mailbox HW Status
    hw_status: ReadOnlyRegister<u32>,

    pub requester: MciMailboxRequester,

    max_dlen_in_lock_session: usize,

    /// Trigger interrupt
    irq: bool,

    /// Last IRQ event type
    last_irq_event: Option<InterruptToMcu>,

    timer: Timer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MciMailboxRequester {
    /// Requester is the MCU
    Mcu,
    /// Requester is the SOC Agent
    SocAgent(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptToMcu {
    Mbox0CmdAvailable,
    Mbox0TargetDone,
}

impl From<MciMailboxRequester> for u32 {
    fn from(requester: MciMailboxRequester) -> Self {
        match requester {
            MciMailboxRequester::Mcu => 0xFFFF_FFFF,
            MciMailboxRequester::SocAgent(id) => id,
        }
    }
}

impl From<u32> for MciMailboxRequester {
    fn from(value: u32) -> Self {
        if value == 0xFFFF_FFFF {
            MciMailboxRequester::Mcu
        } else {
            MciMailboxRequester::SocAgent(value)
        }
    }
}

impl MciMailboxImpl {
    // Register initial values as consts
    const LOCK_VAL: u32 = 0;
    const USER_VAL: u32 = 0;
    const TARGET_USER_VAL: u32 = 0x0;
    const TARGET_USER_VALID_VAL: u32 = 0x0;
    const CMD_VAL: u32 = 0x0;
    const DLEN_VAL: u32 = 0x0;
    const EXECUTE_VAL: u32 = 0x0;
    const TARGET_STATUS_VAL: u32 = 0x0;
    const CMD_STATUS_VAL: u32 = 0x0;
    const HW_STATUS_VAL: u32 = 0x0;

    pub fn new(clock: &Clock) -> Self {
        Self {
            sram: MciMailboxRam::new(),
            lock: ReadOnlyRegister::new(Self::LOCK_VAL),
            user: ReadOnlyRegister::new(Self::USER_VAL),
            target_user: ReadWriteRegister::new(Self::TARGET_USER_VAL),
            target_user_valid: ReadWriteRegister::new(Self::TARGET_USER_VALID_VAL),
            cmd: ReadWriteRegister::new(Self::CMD_VAL),
            dlen: ReadWriteRegister::new(Self::DLEN_VAL),
            execute: ReadWriteRegister::new(Self::EXECUTE_VAL),
            target_status: ReadWriteRegister::new(Self::TARGET_STATUS_VAL),
            cmd_status: ReadWriteRegister::new(Self::CMD_STATUS_VAL),
            hw_status: ReadOnlyRegister::new(Self::HW_STATUS_VAL),
            requester: MciMailboxRequester::Mcu,
            irq: false,
            last_irq_event: None,
            timer: Timer::new(clock),
            max_dlen_in_lock_session: 0,
        }
    }

    pub fn set_requester(&mut self, requester: MciMailboxRequester) {
        self.requester = requester;
    }

    /// Clears mailbox SRAM and resets mailbox registers as per protocol
    pub fn mailbox_zeroization(&mut self) {
        // Start clearing SRAM from 0 to max DLEN seen in this lock session
        let dlen = self.max_dlen_in_lock_session;
        let mut ram = self.sram.ram.borrow_mut();
        for offset in (0..dlen).step_by(4) {
            if let Err(e) = ram.write(RvSize::Word, offset as u32, 0) {
                panic!("Failed to zeroize mcu_mbox0 SRAM at offset {offset}: {e:?}");
            }
        }

        self.target_user.reg.set(0);
        self.target_user_valid.reg.set(0);
        self.cmd.reg.set(0);
        self.dlen.reg.set(0);
        self.execute.reg.set(0);
        self.target_status.reg.set(0);
        self.cmd_status.reg.set(0);
        // Clear interrupt event
        self.last_irq_event = None;

        self.max_dlen_in_lock_session = 0; // Reset after clearing
        self.user.reg.set(0); // Clear user
        self.lock.reg.set(0); // Release lock after clearing
    }

    pub fn read_mcu_mbox0_csr_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        self.sram
            .ram
            .borrow_mut()
            .read(RvSize::Word, (index * 4) as RvAddr)
            .unwrap_or_else(|e| {
                if matches!(e, BusError::InstrAccessFault | BusError::LoadAccessFault) {
                    self.hw_status.reg.set(
                        registers_generated::mci::bits::MboxHwStatus::EccDoubleError::SET.value,
                    );
                }
                panic!("Failed to read mcu_mbox0 SRAM at index {index}: {e:?}")
            })
    }

    pub fn write_mcu_mbox0_csr_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        if let Err(e) = self
            .sram
            .ram
            .borrow_mut()
            .write(RvSize::Word, (index * 4) as RvAddr, val)
        {
            panic!("Failed to write mcu_mbox0 SRAM at index {index}: {e:?}");
        }
    }

    pub fn read_mcu_mbox0_csr_mbox_lock(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, registers_generated::mbox::bits::MboxLock::Register>
    {
        // If the lock is not held, we can grant it to the current requester
        if self.lock.reg.get() == 0 {
            // Grant lock to current requester
            self.user.reg.set(self.requester.into());
            // Lock the mailbox
            self.lock.reg.set(1);
            // Reset max_dlen_in_lock_session for new session
            self.max_dlen_in_lock_session = 0;
        }
        caliptra_emu_bus::ReadWriteRegister::<
            u32,
            registers_generated::mbox::bits::MboxLock::Register,
        >::new(self.lock.reg.get())
    }

    pub fn read_mcu_mbox0_csr_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.user.reg.get()
    }

    pub fn read_mcu_mbox0_csr_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.target_user.reg.get()
    }

    pub fn write_mcu_mbox0_csr_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        self.target_user.reg.set(val);
    }

    pub fn read_mcu_mbox0_csr_mbox_target_user_valid(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetUserValid::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.target_user_valid.reg.get())
    }

    pub fn write_mcu_mbox0_csr_mbox_target_user_valid(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetUserValid::Register,
        >,
    ) {
        self.target_user_valid.reg.set(val.reg.get());
    }

    pub fn read_mcu_mbox0_csr_mbox_cmd(&mut self) -> caliptra_emu_types::RvData {
        self.cmd.reg.get()
    }

    pub fn write_mcu_mbox0_csr_mbox_cmd(&mut self, val: caliptra_emu_types::RvData) {
        self.cmd.reg.set(val);
    }

    pub fn read_mcu_mbox0_csr_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.dlen.reg.get()
    }
    pub fn write_mcu_mbox0_csr_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        self.dlen.reg.set(val);
        // Track max DLEN for this lock session
        let dlen = val as usize;
        if dlen > self.max_dlen_in_lock_session {
            self.max_dlen_in_lock_session = dlen;
        }
    }

    pub fn read_mcu_mbox0_csr_mbox_execute(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mbox::bits::MboxExecute::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.execute.reg.get())
    }

    pub fn write_mcu_mbox0_csr_mbox_execute(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mbox::bits::MboxExecute::Register,
        >,
    ) {
        let new_val = val.reg.get();
        let prev_val = self.execute.reg.get();

        self.execute.reg.set(new_val);

        // Only trigger on rising edge (0 -> 1)
        if prev_val == 0 && new_val == 1 {
            // If SoC is the sender, this is a CMD_AVAILABLE event for MCU
            if let MciMailboxRequester::SocAgent(_) = self.user.reg.get().into() {
                self.irq = true;
                self.last_irq_event = Some(InterruptToMcu::Mbox0CmdAvailable);

                self.timer.schedule_poll_in(1);
            }
        }
        // If mailbox is being released (1 -> 0), start SRAM clearing process
        if prev_val == 1 && new_val == 0 {
            self.mailbox_zeroization();
        }
    }

    pub fn read_mcu_mbox0_csr_mbox_target_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.target_status.reg.get())
    }

    pub fn write_mcu_mbox0_csr_mbox_target_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetStatus::Register,
        >,
    ) {
        let prev = self.target_status.reg.get();
        let new_val = val.reg.get();
        self.target_status.reg.set(new_val);
        // If the DONE bit is set (rising edge), trigger TARGET_DONE event
        let prev_done = prev & registers_generated::mci::bits::MboxTargetStatus::Done::SET.value;
        let new_done = new_val & registers_generated::mci::bits::MboxTargetStatus::Done::SET.value;
        if prev_done == 0 && new_done != 0 {
            self.irq = true;
            self.last_irq_event = Some(InterruptToMcu::Mbox0TargetDone);

            self.timer.schedule_poll_in(1);
        }
    }

    pub fn read_mcu_mbox0_csr_mbox_cmd_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxCmdStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.cmd_status.reg.get())
    }

    pub fn write_mcu_mbox0_csr_mbox_cmd_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxCmdStatus::Register,
        >,
    ) {
        self.cmd_status.reg.set(val.reg.get());
    }

    pub fn read_mcu_mbox0_csr_mbox_hw_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxHwStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.hw_status.reg.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mci::Mci;
    use crate::McuRootBus;
    use caliptra_emu_bus::{Bus, Clock};
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::root_bus::AutoRootBus;

    const MCI_BASE_ADDR: u32 = 0x2100_0000;
    const MCU_MAILBOX0_CSR_BASE_OFFSET: u32 = 0x40_0000;
    const MCU_MAILBOX0_SRAM_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET;
    const MBOX_LOCK_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0000;
    const MBOX_USER_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0004;
    const MBOX_TARGET_USER_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0008;
    const MBOX_TARGET_USER_VALID_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_000C;
    const MBOX_CMD_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0010;
    const MBOX_DLEN_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0014;
    const MBOX_EXECUTE_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0018;
    const MBOX_TARGET_STATUS_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_001C;
    const MBOX_CMD_STATUS_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0020;
    const MBOX_HW_STATUS_OFFSET: u32 = MCU_MAILBOX0_CSR_BASE_OFFSET + 0x20_0024;

    const SOC_AGENT_ID: u32 = 0x1;

    fn test_helper_setup_autobus(clock: &Clock) -> AutoRootBus {
        let pic = Pic::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let mci_irq = pic.register_irq(McuRootBus::MCI_IRQ);
        let mci = Mci::new(
            &clock,
            ext_mci_regs.clone(),
            Rc::new(RefCell::new(mci_irq)),
            Some(MciMailboxInternal::new(&clock)),
        );

        AutoRootBus::new(
            vec![],
            None,
            None,
            None,
            None,
            Some(Box::new(mci)),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_mcu_mailbox_register_access() {
        // Set up auto root bus. Then read and write to the registers
        let dummy_clock = Clock::new();
        let mut bus = test_helper_setup_autobus(&dummy_clock);

        let sram_base = MCI_BASE_ADDR + MCU_MAILBOX0_SRAM_OFFSET;
        let sram_words = (MCU_MAILBOX_SRAM_SIZE / 4) as u32;
        for i in 0..sram_words {
            let addr = sram_base + i * 4;
            let pattern = 0xA5A50000 | (i & 0xFFFF);
            bus.write(RvSize::Word, addr, pattern)
                .expect("SRAM write failed");
        }
        for i in 0..sram_words {
            let addr = sram_base + i * 4;
            let pattern = 0xA5A50000 | (i & 0xFFFF);
            let val = bus.read(RvSize::Word, addr).expect("SRAM read failed");
            assert_eq!(val, pattern, "SRAM mismatch at word {}", i);
        }

        // Test register read/write access for mailbox CSRs, one by one for clarity
        // Lock register: should grant lock and return 1
        let lock_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_LOCK_OFFSET)
            .expect("Lock read failed");
        assert_eq!(lock_val, 1, "Lock register should be 1");

        // User register: should reflect the requester (MCU by default)
        let user_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_USER_OFFSET)
            .expect("User read failed");
        assert_eq!(
            user_val,
            u32::from(MciMailboxRequester::Mcu),
            "User register should be MCU by default"
        );

        // Target User register: write and read
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_TARGET_USER_OFFSET,
            SOC_AGENT_ID,
        )
        .expect("Target user write failed");
        let target_user_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_USER_OFFSET)
            .expect("Target user read failed");
        assert_eq!(
            target_user_val, SOC_AGENT_ID,
            "Target user register mismatch"
        );

        // Target User Valid register: write and read
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_TARGET_USER_VALID_OFFSET,
            0x1,
        )
        .expect("Target user valid write failed");
        let target_user_valid_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_USER_VALID_OFFSET)
            .expect("Target user valid read failed");
        assert_eq!(
            target_user_valid_val, 0x1,
            "Target user valid register mismatch"
        );

        // Command register: write and read
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET, 0xCAFEBABE)
            .expect("CMD write failed");
        let cmd_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET)
            .expect("CMD read failed");
        assert_eq!(cmd_val, 0xCAFEBABE, "CMD register mismatch");

        // Data Length register: write and read
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET, 0x20)
            .expect("DLEN write failed");
        let dlen_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET)
            .expect("DLEN read failed");
        assert_eq!(dlen_val, 0x20, "DLEN register mismatch");

        // Execute register: write and read
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET, 1)
            .expect("EXECUTE write failed");
        let execute_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET)
            .expect("EXECUTE read failed");
        assert_eq!(execute_val, 1, "EXECUTE register mismatch");

        // Target Status register: write and read
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_STATUS_OFFSET, 0x2)
            .expect("Target status write failed");
        let target_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_STATUS_OFFSET)
            .expect("Target status read failed");
        assert_eq!(target_status_val, 0x2, "Target status register mismatch");

        // Command Status register: write and read
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_STATUS_OFFSET, 0x3)
            .expect("CMD status write failed");
        let cmd_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_STATUS_OFFSET)
            .expect("CMD status read failed");
        assert_eq!(cmd_status_val, 0x3, "CMD status register mismatch");

        // HW Status register: should be 0 by default (read only)
        let hw_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_HW_STATUS_OFFSET)
            .expect("HW status read failed");
        assert_eq!(hw_status_val, 0, "HW status should be 0");
    }
}
