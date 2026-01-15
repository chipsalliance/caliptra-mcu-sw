// Licensed under the Apache-2.0 license

use caliptra_emu_bus::BusError;
use caliptra_emu_bus::{Bus, Clock, Ram, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_types::{RvAddr, RvSize};
use emulator_consts::MCU_MAILBOX0_SRAM_SIZE;
use registers_generated::mci::bits::MboxExecute;
use std::sync::{Arc, Mutex};
use tock_registers::interfaces::{Readable, Writeable};

#[derive(Clone)]
pub struct MciMailboxRam {
    pub ram: Arc<Mutex<Ram>>,
}

impl Default for MciMailboxRam {
    fn default() -> Self {
        Self::new()
    }
}

impl MciMailboxRam {
    pub fn new() -> Self {
        Self {
            ram: Arc::new(Mutex::new(Ram::new(vec![
                0u8;
                MCU_MAILBOX0_SRAM_SIZE as usize
            ]))),
        }
    }
}

//  MCU Mailbox 0 Interface used by MCU.
#[derive(Clone)]
pub struct McuMailbox0Internal {
    pub regs: Arc<Mutex<MciMailboxImpl>>,
}

impl McuMailbox0Internal {
    pub fn new(clock: &Clock) -> Self {
        Self {
            regs: Arc::new(Mutex::new(MciMailboxImpl::new(clock))),
        }
    }

    pub fn as_external(&self, soc_agent: MciMailboxRequester) -> McuMailbox0External {
        McuMailbox0External {
            soc_agent,
            regs: self.regs.clone(),
        }
    }

    pub fn get_notif_irq(&mut self) -> Option<IrqEventToMcu> {
        let mut regs = self.regs.lock().unwrap();
        if regs.irq {
            regs.irq = false;
            let event = regs.last_irq_event;
            regs.last_irq_event = None;
            return event;
        }
        None
    }

    #[cfg(test)]
    pub fn set_notif_irq(&mut self, event: IrqEventToMcu) {
        let mut regs = self.regs.lock().unwrap();
        regs.irq = true;
        regs.last_irq_event = Some(event);
    }
}

// External interface for MCU Mailbox 0, used by SoC agent.
#[derive(Clone)]
pub struct McuMailbox0External {
    pub soc_agent: MciMailboxRequester,
    pub regs: Arc<Mutex<MciMailboxImpl>>,
}

// MCU Mailbox 0 implementation.
pub struct MciMailboxImpl {
    /// Mailbox SRAM
    pub sram: MciMailboxRam,

    /// Mailbox Lock register
    lock: ReadOnlyRegister<u32>,

    /// Mailbox USER register
    user: ReadOnlyRegister<u32>,

    /// Mailbox Target USER register
    target_user: ReadWriteRegister<u32>,

    /// Mailbox Target USER Valid register
    target_user_valid: ReadWriteRegister<u32>,

    /// Mailbox Command register
    cmd: ReadWriteRegister<u32>,

    /// Mailbox Data Length register
    dlen: ReadWriteRegister<u32>,

    /// Mailbox Execute register
    execute: ReadWriteRegister<u32>,

    /// Mailbox Target Status register
    target_status: ReadWriteRegister<u32>,

    /// Mailbox Command Status register
    cmd_status: ReadWriteRegister<u32>,

    /// Mailbox HW Status register
    hw_status: ReadOnlyRegister<u32>,

    /// Current requester (MCU or SoC agent)
    pub requester: MciMailboxRequester,

    /// Maximum DLEN seen in the current lock session (for zeroization)
    max_dlen_in_lock_session: usize,

    /// Interrupt pending flag
    irq: bool,

    /// Last IRQ event type, if any
    last_irq_event: Option<IrqEventToMcu>,

    /// Timer for scheduling poll actions
    timer: Timer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrqEventToMcu {
    Mbox0CmdAvailable,
    Mbox0TargetDone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MciMailboxRequester {
    Mcu,
    SocAgent(u32),
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
    const LOCK_VAL: u32 = 0x0;
    const USER_VAL: u32 = 0x0;
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

    // The mailbox starts locked by the MCU to prevent data leaks across warm resets.
    // The MCU must set MBOX_DLEN to the full SRAM size and write 0 to MBOX_EXECUTE
    // to release and wipe the mailbox SRAM before allowing further use.
    pub fn reset(&mut self) {
        self.read_mcu_mbox0_csr_mbox_lock();
        assert!(self.is_locked(), "MCU can't acquire MCU mailbox lock");
        self.write_mcu_mbox0_csr_mbox_dlen(MCU_MAILBOX0_SRAM_SIZE);
        self.write_mcu_mbox0_csr_mbox_execute(caliptra_emu_bus::ReadWriteRegister::new(
            MboxExecute::Execute::CLEAR.value,
        ));
    }

    pub fn set_requester(&mut self, requester: MciMailboxRequester) {
        self.requester = requester;
    }

    pub fn is_locked(&self) -> bool {
        self.lock.reg.get() != 0
    }

    pub fn lock(&self) {
        self.lock.reg.set(1);
    }

    /// Clears mailbox SRAM and resets mailbox registers as per protocol
    pub fn mailbox_zeroization(&mut self) {
        // Start clearing SRAM from 0 to max DLEN seen in this lock session
        let dlen = self.max_dlen_in_lock_session;
        let mut ram = self.sram.ram.lock().unwrap();
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
        self.hw_status.reg.set(0);
        self.last_irq_event = None;
        self.max_dlen_in_lock_session = 0;
        self.user.reg.set(0);
        self.lock.reg.set(0); // Release lock after clearing
    }

    pub fn read_mcu_mbox0_csr_mbox_sram_block(&mut self, index: usize, len: usize) -> Vec<u8> {
        if index + len > MCU_MAILBOX0_SRAM_SIZE as usize {
            panic!(
                "Read length {len} exceeds mcu_mbox0 SRAM size of {}",
                MCU_MAILBOX0_SRAM_SIZE
            );
        }
        let sram = self.sram.ram.lock().unwrap();
        let mem = sram.data();
        mem[index..index + len].to_vec()
    }

    pub fn read_mcu_mbox0_csr_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        if index >= (MCU_MAILBOX0_SRAM_SIZE as usize / 4) {
            panic!("Index out of bounds for mcu_mbox0 SRAM: {index}");
        }

        self.sram
            .ram
            .lock()
            .unwrap()
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
        if !self.is_locked() {
            panic!("Cannot write to mcu_mbox0 SRAM when mailbox is unlocked");
        }

        if index >= (MCU_MAILBOX0_SRAM_SIZE as usize / 4) {
            panic!("Index out of bounds for mcu_mbox0 SRAM: {index}");
        }
        if let Err(e) =
            self.sram
                .ram
                .lock()
                .unwrap()
                .write(RvSize::Word, (index * 4) as RvAddr, val)
        {
            panic!("Failed to write mcu_mbox0 SRAM at index {index}: {e:?}");
        }
    }

    pub fn write_mcu_mbox0_csr_mbox_sram_block(&mut self, data: &[u8], index: usize) {
        if !self.is_locked() {
            panic!("Cannot write to mcu_mbox0 SRAM when mailbox is unlocked");
        }

        let dlen = data.len();
        if index + dlen > MCU_MAILBOX0_SRAM_SIZE as usize {
            panic!(
                "Data length {dlen} exceeds mcu_mbox0 SRAM size of {}",
                MCU_MAILBOX0_SRAM_SIZE
            );
        }
        let mut sram = self.sram.ram.lock().unwrap();
        let mem = sram.data_mut();
        mem[index..index + dlen].copy_from_slice(data);
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

            // Return 0 to indicate lock is now held
            caliptra_emu_bus::ReadWriteRegister::<
                u32,
                registers_generated::mbox::bits::MboxLock::Register,
            >::new(0)
        } else {
            caliptra_emu_bus::ReadWriteRegister::<
                u32,
                registers_generated::mbox::bits::MboxLock::Register,
            >::new(self.lock.reg.get())
        }
    }

    pub fn read_mcu_mbox0_csr_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.user.reg.get()
    }

    pub fn read_mcu_mbox0_csr_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.target_user.reg.get()
    }

    pub fn write_mcu_mbox0_csr_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        if !self.is_locked() {
            panic!("Cannot write mcu_mbox0 target user when mailbox is unlocked");
        }
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
        if !self.is_locked() {
            panic!("Cannot write mcu_mbox0 target user valid when mailbox is unlocked");
        }
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
        if val > MCU_MAILBOX0_SRAM_SIZE {
            panic!("DLEN value {val} exceeds mcu_mbox0 SRAM size");
        }
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
        if !self.is_locked() {
            panic!("Cannot write mcu_mbox0 execute when mailbox is unlocked");
        }

        let new_val = val.reg.get();
        self.execute.reg.set(new_val);
        if new_val == MboxExecute::Execute::SET.value {
            // Workaround: temporarily lift the check for mailbox requester to support integration tests
            if cfg!(feature = "test-mcu-mbox")
                || matches!(self.user.reg.get().into(), MciMailboxRequester::SocAgent(_))
            {
                self.irq = true;
                self.last_irq_event = Some(IrqEventToMcu::Mbox0CmdAvailable);
                self.timer.schedule_poll_in(1);
            }
        } else if new_val == MboxExecute::Execute::CLEAR.value {
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
            self.last_irq_event = Some(IrqEventToMcu::Mbox0TargetDone);
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
    use std::{cell::RefCell, rc::Rc};

    use super::*;
    use crate::mci::Mci;
    use crate::McuRootBus;
    use caliptra_emu_bus::{Bus, Clock};
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use registers_generated::mci::bits::{
        MboxCmdStatus, MboxExecute, MboxTargetStatus, Notif0IntrEnT, Notif0IntrT,
    };

    const MCI_BASE_ADDR: u32 = 0x2100_0000;
    const NOTIF0_INTR_EN_OFFSET: u32 = 0x100c;
    const NOTIF0_INTERNAL_INTR_R_OFFSET: u32 = 0x1024;
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

    fn test_helper_setup_autobus(clock: &Clock, mcu_mailbox0: &McuMailbox0Internal) -> AutoRootBus {
        let pic = Pic::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let mci_irq = pic.register_irq(McuRootBus::MCI_IRQ);
        let mci = Mci::new(
            clock,
            ext_mci_regs.clone(),
            Rc::new(RefCell::new(mci_irq)),
            Some(mcu_mailbox0.clone()),
            None,
            None,
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

    fn test_mailbox_zeroization(test_dlen: u32, mcu_mailbox0: &McuMailbox0Internal) {
        let mut regs = mcu_mailbox0.regs.lock().unwrap();
        // Check SRAM is zeroized
        for i in 0..(test_dlen as usize / 4) {
            let val = regs.read_mcu_mbox0_csr_mbox_sram(i);
            assert_eq!(val, 0, "SRAM should be zeroized at word {}", i);
        }

        // Check mailbox CSRs are zeroized
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_target_user(),
            0,
            "Target user should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_target_user_valid().reg.get(),
            0,
            "Target user valid should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_cmd(),
            0,
            "CMD should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_dlen(),
            0,
            "DLEN should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_execute().reg.get(),
            0,
            "EXECUTE should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_target_status().reg.get(),
            0,
            "TARGET_STATUS should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_cmd_status().reg.get(),
            0,
            "CMD_STATUS should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_hw_status().reg.get(),
            0,
            "HW_STATUS should be zeroized"
        );
        assert_eq!(
            regs.read_mcu_mbox0_csr_mbox_user(),
            0,
            "USER should be zeroized"
        );
        assert_eq!(
            regs.max_dlen_in_lock_session, 0,
            "Max DLEN in lock session should be reset to 0"
        );
        assert_eq!(
            regs.last_irq_event, None,
            "Last IRQ event should be cleared"
        );
        // Check that the mailbox is unlocked
        assert!(
            !regs.is_locked(),
            "Mailbox should be unlocked after zeroization"
        );
    }

    #[test]
    fn test_mcu_mailbox0_register_access() {
        let dummy_clock = Clock::new();
        let mcu_mailbox0 = McuMailbox0Internal::new(&dummy_clock);
        let mut bus = test_helper_setup_autobus(&dummy_clock, &mcu_mailbox0);

        mcu_mailbox0.regs.lock().unwrap().reset();
        assert!(
            !mcu_mailbox0.regs.lock().unwrap().is_locked(),
            "Mailbox should be unlocked after reset"
        );

        let lock_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_LOCK_OFFSET)
            .expect("Lock read failed");
        // When locking, the MCU should get 0 back to indicate it has acquired the lock
        assert_eq!(lock_val, 0, "Lock register should be 0");

        // When read again, it should now be 1
        let lock_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_LOCK_OFFSET)
            .expect("Lock read failed");
        assert_eq!(lock_val, 1, "Lock register should be 1");

        let user_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_USER_OFFSET)
            .expect("User read failed");
        assert_eq!(
            user_val,
            u32::from(MciMailboxRequester::Mcu),
            "User register should be MCU by default"
        );

        let sram_base = MCI_BASE_ADDR + MCU_MAILBOX0_SRAM_OFFSET;
        let sram_words = MCU_MAILBOX0_SRAM_SIZE / 4;
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

        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET, 0xCAFEBABE)
            .expect("CMD write failed");
        let cmd_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET)
            .expect("CMD read failed");
        assert_eq!(cmd_val, 0xCAFEBABE, "CMD register mismatch");

        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET, 0x20)
            .expect("DLEN write failed");
        let dlen_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET)
            .expect("DLEN read failed");
        assert_eq!(dlen_val, 0x20, "DLEN register mismatch");

        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET, 1)
            .expect("EXECUTE write failed");
        let execute_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET)
            .expect("EXECUTE read failed");
        assert_eq!(execute_val, 1, "EXECUTE register mismatch");

        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_STATUS_OFFSET, 0x2)
            .expect("Target status write failed");
        let target_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_TARGET_STATUS_OFFSET)
            .expect("Target status read failed");
        assert_eq!(target_status_val, 0x2, "Target status register mismatch");

        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_STATUS_OFFSET, 0x3)
            .expect("CMD status write failed");
        let cmd_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_STATUS_OFFSET)
            .expect("CMD status read failed");
        assert_eq!(cmd_status_val, 0x3, "CMD status register mismatch");

        let hw_status_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_HW_STATUS_OFFSET)
            .expect("HW status read failed");
        assert_eq!(hw_status_val, 0, "HW status should be 0");
    }

    #[test]
    fn test_soc_send_mcu_receive() {
        let dummy_clock = Clock::new();
        let mcu_mailbox0 = McuMailbox0Internal::new(&dummy_clock);

        mcu_mailbox0.regs.lock().unwrap().reset();
        assert!(
            !mcu_mailbox0.regs.lock().unwrap().is_locked(),
            "Mailbox should be unlocked after reset"
        );

        let mut bus = test_helper_setup_autobus(&dummy_clock, &mcu_mailbox0);

        let en_bit = Notif0IntrEnT::NotifMbox0CmdAvailEn::SET.value;
        // Enable the interrupt
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + NOTIF0_INTR_EN_OFFSET,
            Notif0IntrEnT::NotifMbox0CmdAvailEn::SET.value,
        )
        .unwrap();
        let notif_en = bus
            .read(RvSize::Word, MCI_BASE_ADDR + NOTIF0_INTR_EN_OFFSET)
            .unwrap();
        assert_eq!(notif_en & en_bit, en_bit);

        let soc = mcu_mailbox0.as_external(MciMailboxRequester::SocAgent(SOC_AGENT_ID));
        soc.regs
            .lock()
            .unwrap()
            .set_requester(MciMailboxRequester::SocAgent(SOC_AGENT_ID));

        let test_cmd = 0x55;
        let test_dlen = 0x10;
        let test_data: [u32; 4] = [0xAABBCCDD, 0x11223344, 0x55667788, 0xDEADBEEF];
        let response_data: [u32; 4] = [0xCAFEBABE, 0xFEEDFACE, 0x0BADF00D, 0x1234ABCD];
        let response_status = MboxCmdStatus::Status::CmdComplete.value;

        // SoC acquires the lock
        soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_lock();
        assert!(
            soc.regs.lock().unwrap().is_locked(),
            "Mailbox should be locked after acquiring lock"
        );

        assert_eq!(
            soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_user(),
            u32::from(MciMailboxRequester::SocAgent(SOC_AGENT_ID)),
            "User register should reflect SOC agent ID"
        );

        // SoC writes data to SRAM
        for (i, word) in test_data.iter().enumerate() {
            soc.regs
                .lock()
                .unwrap()
                .write_mcu_mbox0_csr_mbox_sram(*word, i);
        }
        // SoC writes DLEN
        soc.regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_dlen(test_dlen);
        // SoC writes CMD
        soc.regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd(test_cmd);
        // SoC writes 1 to EXECUTE
        soc.regs.lock().unwrap().write_mcu_mbox0_csr_mbox_execute(
            caliptra_emu_bus::ReadWriteRegister::new(MboxExecute::Execute::SET.value),
        );

        for _ in 0..1000 {
            dummy_clock.increment_and_process_timer_actions(1, &mut bus);
        }
        bus.poll();

        let sts_bit = Notif0IntrT::NotifMbox0CmdAvailSts::SET.value;
        // Check that the status bit is set
        let notif_status = bus
            .read(RvSize::Word, MCI_BASE_ADDR + NOTIF0_INTERNAL_INTR_R_OFFSET)
            .unwrap();
        assert_eq!(notif_status & sts_bit, sts_bit);

        // MCU reads command, dlen, and data (using bus)
        let sram_base = MCI_BASE_ADDR + MCU_MAILBOX0_SRAM_OFFSET;
        let cmd_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET)
            .unwrap();
        let dlen_val = bus
            .read(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET)
            .unwrap();
        assert_eq!(cmd_val, test_cmd, "MCU should read correct CMD");
        assert_eq!(dlen_val, test_dlen, "MCU should read correct DLEN");
        for (i, word) in test_data.iter().enumerate() {
            let val = bus.read(RvSize::Word, sram_base + (i as u32) * 4).unwrap();
            assert_eq!(
                val, *word,
                "MCU should read correct SRAM data at word {}",
                i
            );
        }
        // MCU writes response data and DLEN
        for (i, word) in response_data.iter().enumerate() {
            bus.write(RvSize::Word, sram_base + (i as u32) * 4, *word)
                .unwrap();
        }
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET, test_dlen)
            .unwrap();

        // MCU updates CMD_STATUS
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_CMD_STATUS_OFFSET,
            response_status,
        )
        .unwrap();

        // SoC reads the response data and status via direct access (regs)
        for (i, word) in response_data.iter().enumerate() {
            let val = soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_sram(i);
            assert_eq!(
                val, *word,
                "SoC should read correct response data at word {}",
                i
            );
        }
        let cmd_status_val = soc
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd_status();
        assert_eq!(
            cmd_status_val.reg.get(),
            response_status,
            "SoC should read correct CMD_STATUS"
        );

        // SoC writes 0 to EXECUTE to release the mailbox
        soc.regs.lock().unwrap().write_mcu_mbox0_csr_mbox_execute(
            caliptra_emu_bus::ReadWriteRegister::new(MboxExecute::Execute::CLEAR.value),
        );

        test_mailbox_zeroization(test_dlen, &mcu_mailbox0);
    }

    #[test]
    fn test_mcu_send_soc_receive() {
        let dummy_clock = Clock::new();
        let mcu_mailbox0 = McuMailbox0Internal::new(&dummy_clock);
        let mut bus = test_helper_setup_autobus(&dummy_clock, &mcu_mailbox0);

        mcu_mailbox0.regs.lock().unwrap().reset();
        assert!(
            !mcu_mailbox0.regs.lock().unwrap().is_locked(),
            "Mailbox should be unlocked after reset"
        );

        let en_bit = Notif0IntrEnT::NotifMbox0TargetDoneEn::SET.value;
        // Enable the TARGET_DONE interrupt
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + NOTIF0_INTR_EN_OFFSET,
            Notif0IntrEnT::NotifMbox0TargetDoneEn::SET.value,
        )
        .unwrap();
        let notif_en = bus
            .read(RvSize::Word, MCI_BASE_ADDR + NOTIF0_INTR_EN_OFFSET)
            .unwrap();
        assert_eq!(notif_en & en_bit, en_bit);

        let soc = mcu_mailbox0.as_external(MciMailboxRequester::SocAgent(SOC_AGENT_ID));
        // MCU acquires the lock (simulate by calling lock read API)
        bus.read(RvSize::Word, MCI_BASE_ADDR + MBOX_LOCK_OFFSET)
            .unwrap();
        assert!(
            mcu_mailbox0.regs.lock().unwrap().is_locked(),
            "Mailbox should be locked"
        );

        // Check user is set to MCU
        assert_eq!(
            soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_user(),
            u32::from(MciMailboxRequester::Mcu),
            "User register should reflect MCU requester"
        );

        // MCU writes data to SRAM
        let sram_base = MCI_BASE_ADDR + MCU_MAILBOX0_SRAM_OFFSET;
        let test_cmd = 0xAA;
        let test_dlen = 0x10;
        let test_data: [u32; 4] = [0x11112222, 0x33334444, 0x55556666, 0x77778888];
        let response_status =
            MboxTargetStatus::Status::CmdComplete.value | MboxTargetStatus::Done::SET.value;

        for (i, word) in test_data.iter().enumerate() {
            bus.write(RvSize::Word, sram_base + (i as u32) * 4, *word)
                .unwrap();
        }
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_DLEN_OFFSET, test_dlen)
            .unwrap();
        bus.write(RvSize::Word, MCI_BASE_ADDR + MBOX_CMD_OFFSET, test_cmd)
            .unwrap();

        // MCU set target user and valid
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_TARGET_USER_OFFSET,
            SOC_AGENT_ID,
        )
        .unwrap();

        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_TARGET_USER_VALID_OFFSET,
            0x1,
        )
        .unwrap();

        // MCU writes 1 to EXECUTE
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET,
            MboxExecute::Execute::SET.value,
        )
        .unwrap();

        // SoC reads data and status via direct access (regs)
        for (i, word) in test_data.iter().enumerate() {
            let val = soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_sram(i);
            assert_eq!(
                val, *word,
                "SoC should read correct SRAM data at word {}",
                i
            );
        }
        let cmd_val = soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_cmd();
        let dlen_val = soc.regs.lock().unwrap().read_mcu_mbox0_csr_mbox_dlen();
        assert_eq!(cmd_val, test_cmd, "SoC should read correct CMD");
        assert_eq!(dlen_val, test_dlen, "SoC should read correct DLEN");

        // SoC writes target status (simulate command complete)
        soc.regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_status(caliptra_emu_bus::ReadWriteRegister::new(
                response_status,
            ));

        // Poll to process the interrupt
        for _ in 0..1000 {
            dummy_clock.increment_and_process_timer_actions(1, &mut bus);
        }
        bus.poll();

        // Check interrupt status register
        let sts_bit = Notif0IntrT::NotifMbox0TargetDoneSts::SET.value;
        let notif_status = bus
            .read(RvSize::Word, MCI_BASE_ADDR + NOTIF0_INTERNAL_INTR_R_OFFSET)
            .unwrap();
        assert_eq!(notif_status & sts_bit, sts_bit);

        // MCU reads the response data and status via direct access (regs)
        for (i, word) in test_data.iter().enumerate() {
            let val = mcu_mailbox0
                .regs
                .lock()
                .unwrap()
                .read_mcu_mbox0_csr_mbox_sram(i);
            assert_eq!(
                val, *word,
                "MCU should read correct response data at word {}",
                i
            );
        }
        let target_status_val = mcu_mailbox0
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_status();
        assert_eq!(
            target_status_val.reg.get() & MboxTargetStatus::Status::CmdComplete.value,
            MboxTargetStatus::Status::CmdComplete.value,
            "MCU should read correct TARGET_STATUS"
        );
        assert_eq!(
            target_status_val.reg.get() & MboxTargetStatus::Done::SET.value,
            MboxTargetStatus::Done::SET.value,
            "MCU should read DONE bit set in TARGET_STATUS"
        );

        // MCU writes 0 to EXECUTE to release the mailbox (simulate via internal API)
        bus.write(
            RvSize::Word,
            MCI_BASE_ADDR + MBOX_EXECUTE_OFFSET,
            MboxExecute::Execute::CLEAR.value,
        )
        .unwrap();

        // MCI clears mailbox CSRs and SRAM (zeroization)
        test_mailbox_zeroization(test_dlen, &mcu_mailbox0);
    }
}
