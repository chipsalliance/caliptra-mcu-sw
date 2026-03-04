// Licensed under the Apache-2.0 license

use caliptra_emu_bus::BusError;
use caliptra_emu_bus::{Bus, Clock, Ram, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_types::{RvAddr, RvSize};
use caliptra_mcu_emulator_consts::NETWORK_MAILBOX_SRAM_SIZE;
use caliptra_mcu_emulator_registers_generated::network_mbox::NetworkMboxPeripheral;
use caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxExecute;
use std::sync::{Arc, Mutex};
use tock_registers::interfaces::{Readable, Writeable};

#[derive(Clone)]
pub struct NetworkMailboxRam {
    pub ram: Arc<Mutex<Ram>>,
}

impl Default for NetworkMailboxRam {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMailboxRam {
    pub fn new() -> Self {
        Self {
            ram: Arc::new(Mutex::new(Ram::new(vec![
                0u8;
                NETWORK_MAILBOX_SRAM_SIZE as usize
            ]))),
        }
    }
}

/// Network Mailbox Internal Interface used by the Network Coprocessor.
#[derive(Clone)]
pub struct NetworkMailboxInternal {
    pub regs: Arc<Mutex<NetworkMailboxImpl>>,
}

impl NetworkMailboxInternal {
    pub fn new(clock: &Clock) -> Self {
        Self {
            regs: Arc::new(Mutex::new(NetworkMailboxImpl::new(clock))),
        }
    }

    pub fn get_notif_irq(&mut self) -> Option<NetworkMboxIrqEvent> {
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
    pub fn set_notif_irq(&mut self, event: NetworkMboxIrqEvent) {
        let mut regs = self.regs.lock().unwrap();
        regs.irq = true;
        regs.last_irq_event = Some(event);
    }
}

pub struct NetworkMailboxImpl {
    pub sram: NetworkMailboxRam,
    lock: ReadOnlyRegister<u32>,
    user: ReadOnlyRegister<u32>,
    target_user: ReadWriteRegister<u32>,
    target_user_valid: ReadWriteRegister<u32>,
    cmd: ReadWriteRegister<u32>,
    dlen: ReadWriteRegister<u32>,
    execute: ReadWriteRegister<u32>,
    target_status: ReadWriteRegister<u32>,
    cmd_status: ReadWriteRegister<u32>,
    hw_status: ReadOnlyRegister<u32>,
    pub requester: NetworkMailboxRequester,
    /// Tracks the maximum DLEN written during the current lock session for SRAM zeroization.
    max_dlen_in_lock_session: usize,
    irq: bool,
    last_irq_event: Option<NetworkMboxIrqEvent>,
    timer: Timer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkMboxIrqEvent {
    NetworkMboxCmdAvailable,
    NetworkMboxTargetDone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkMailboxRequester {
    Network,
    ExternalAgent(u32),
}

impl From<NetworkMailboxRequester> for u32 {
    fn from(requester: NetworkMailboxRequester) -> Self {
        match requester {
            NetworkMailboxRequester::Network => 0xFFFF_FFFF,
            NetworkMailboxRequester::ExternalAgent(id) => id,
        }
    }
}

impl From<u32> for NetworkMailboxRequester {
    fn from(value: u32) -> Self {
        if value == 0xFFFF_FFFF {
            NetworkMailboxRequester::Network
        } else {
            NetworkMailboxRequester::ExternalAgent(value)
        }
    }
}

impl NetworkMailboxImpl {
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
            sram: NetworkMailboxRam::new(),
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
            requester: NetworkMailboxRequester::Network,
            irq: false,
            last_irq_event: None,
            timer: Timer::new(clock),
            max_dlen_in_lock_session: 0,
        }
    }

    // The network mailbox starts locked by the Network coprocessor to prevent
    // data leaks across warm resets. The Network coprocessor must set DLEN to
    // the full SRAM size and write 0 to EXECUTE to release and wipe the
    // mailbox SRAM before allowing further use.
    pub fn reset(&mut self) {
        self.read_network_mbox_lock();
        assert!(
            self.is_locked(),
            "Network coprocessor can't acquire network mailbox lock"
        );
        self.write_network_mbox_dlen(NETWORK_MAILBOX_SRAM_SIZE);
        self.write_network_mbox_execute(caliptra_emu_bus::ReadWriteRegister::new(
            NetworkMboxExecute::Execute::CLEAR.value,
        ));
    }

    pub fn set_requester(&mut self, requester: NetworkMailboxRequester) {
        self.requester = requester;
    }

    pub fn is_locked(&self) -> bool {
        self.lock.reg.get() != 0
    }

    pub fn lock(&self) {
        self.lock.reg.set(1);
    }

    pub fn mailbox_zeroization(&mut self) {
        let dlen = self.max_dlen_in_lock_session;
        let mut ram = self.sram.ram.lock().unwrap();
        for offset in (0..dlen).step_by(4) {
            if let Err(e) = ram.write(RvSize::Word, offset as u32, 0) {
                panic!("Failed to zeroize network_mbox SRAM at offset {offset}: {e:?}");
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
        self.lock.reg.set(0);
    }

    pub fn read_network_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        if index >= (NETWORK_MAILBOX_SRAM_SIZE as usize / 4) {
            panic!("Index out of bounds for network_mbox SRAM: {index}");
        }

        self.sram
            .ram
            .lock()
            .unwrap()
            .read(RvSize::Word, (index * 4) as RvAddr)
            .unwrap_or_else(|e| {
                if matches!(e, BusError::InstrAccessFault | BusError::LoadAccessFault) {
                    self.hw_status.reg.set(
                        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxHwStatus::EccDoubleError::SET.value,
                    );
                }
                panic!("Failed to read network_mbox SRAM at index {index}: {e:?}")
            })
    }

    pub fn write_network_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        if !self.is_locked() {
            panic!("Cannot write to network_mbox SRAM when mailbox is unlocked");
        }

        if index >= (NETWORK_MAILBOX_SRAM_SIZE as usize / 4) {
            panic!("Index out of bounds for network_mbox SRAM: {index}");
        }
        if let Err(e) =
            self.sram
                .ram
                .lock()
                .unwrap()
                .write(RvSize::Word, (index * 4) as RvAddr, val)
        {
            panic!("Failed to write network_mbox SRAM at index {index}: {e:?}");
        }
    }

    pub fn read_network_mbox_lock(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxLock::Register,
    > {
        if self.lock.reg.get() == 0 {
            self.user.reg.set(self.requester.into());
            self.lock.reg.set(1);
            self.max_dlen_in_lock_session = 0;

            caliptra_emu_bus::ReadWriteRegister::<
                u32,
                caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxLock::Register,
            >::new(0)
        } else {
            caliptra_emu_bus::ReadWriteRegister::<
                u32,
                caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxLock::Register,
            >::new(self.lock.reg.get())
        }
    }

    pub fn read_network_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.user.reg.get()
    }

    pub fn read_network_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.target_user.reg.get()
    }

    pub fn write_network_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        if !self.is_locked() {
            panic!("Cannot write network_mbox target user when mailbox is unlocked");
        }
        self.target_user.reg.set(val);
    }

    pub fn read_network_mbox_target_user_valid(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetUserValid::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.target_user_valid.reg.get())
    }

    pub fn write_network_mbox_target_user_valid(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetUserValid::Register,
        >,
    ) {
        if !self.is_locked() {
            panic!("Cannot write network_mbox target user valid when mailbox is unlocked");
        }
        self.target_user_valid.reg.set(val.reg.get());
    }

    pub fn read_network_mbox_cmd(&mut self) -> caliptra_emu_types::RvData {
        self.cmd.reg.get()
    }

    pub fn write_network_mbox_cmd(&mut self, val: caliptra_emu_types::RvData) {
        self.cmd.reg.set(val);
    }

    pub fn read_network_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.dlen.reg.get()
    }

    pub fn write_network_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        if val > NETWORK_MAILBOX_SRAM_SIZE {
            panic!("DLEN value {val} exceeds network_mbox SRAM size");
        }
        self.dlen.reg.set(val);
        let dlen = val as usize;
        if dlen > self.max_dlen_in_lock_session {
            self.max_dlen_in_lock_session = dlen;
        }
    }

    pub fn read_network_mbox_execute(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxExecute::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.execute.reg.get())
    }

    pub fn write_network_mbox_execute(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxExecute::Register,
        >,
    ) {
        if !self.is_locked() {
            panic!("Cannot write network_mbox execute when mailbox is unlocked");
        }

        let new_val = val.reg.get();
        self.execute.reg.set(new_val);
        if new_val == NetworkMboxExecute::Execute::SET.value {
            if matches!(
                self.user.reg.get().into(),
                NetworkMailboxRequester::ExternalAgent(_)
            ) {
                self.irq = true;
                self.last_irq_event = Some(NetworkMboxIrqEvent::NetworkMboxCmdAvailable);
                self.timer.schedule_poll_in(1);
            }
        } else if new_val == NetworkMboxExecute::Execute::CLEAR.value {
            self.mailbox_zeroization();
        }
    }

    pub fn read_network_mbox_target_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.target_status.reg.get())
    }

    pub fn write_network_mbox_target_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Register,
        >,
    ) {
        let prev = self.target_status.reg.get();
        let new_val = val.reg.get();
        self.target_status.reg.set(new_val);
        // If the DONE bit is set (rising edge), trigger TARGET_DONE event
        let prev_done = prev
            & caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Done::SET.value;
        let new_done = new_val
            & caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Done::SET.value;
        if prev_done == 0 && new_done != 0 {
            self.irq = true;
            self.last_irq_event = Some(NetworkMboxIrqEvent::NetworkMboxTargetDone);
            self.timer.schedule_poll_in(1);
        }
    }

    pub fn read_network_mbox_cmd_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxCmdStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.cmd_status.reg.get())
    }

    pub fn write_network_mbox_cmd_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxCmdStatus::Register,
        >,
    ) {
        self.cmd_status.reg.set(val.reg.get());
    }

    pub fn read_network_mbox_hw_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxHwStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(self.hw_status.reg.get())
    }
}

impl NetworkMboxPeripheral for NetworkMailboxInternal {
    fn poll(&mut self) {}

    fn warm_reset(&mut self) {
        self.regs.lock().unwrap().reset();
    }

    fn update_reset(&mut self) {
        self.regs.lock().unwrap().reset();
    }

    fn read_network_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        self.regs.lock().unwrap().read_network_mbox_sram(index)
    }

    fn write_network_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        self.regs
            .lock()
            .unwrap()
            .write_network_mbox_sram(val, index)
    }

    fn read_network_mbox_lock(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxLock::Register,
    > {
        self.regs.lock().unwrap().read_network_mbox_lock()
    }

    fn read_network_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.regs.lock().unwrap().read_network_mbox_user()
    }

    fn read_network_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.regs.lock().unwrap().read_network_mbox_target_user()
    }

    fn write_network_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        self.regs
            .lock()
            .unwrap()
            .write_network_mbox_target_user(val)
    }

    fn read_network_mbox_target_user_valid(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetUserValid::Register,
    > {
        self.regs
            .lock()
            .unwrap()
            .read_network_mbox_target_user_valid()
    }

    fn write_network_mbox_target_user_valid(
        &mut self,
        val: ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetUserValid::Register,
        >,
    ) {
        self.regs
            .lock()
            .unwrap()
            .write_network_mbox_target_user_valid(val)
    }

    fn read_network_mbox_cmd(&mut self) -> caliptra_emu_types::RvData {
        self.regs.lock().unwrap().read_network_mbox_cmd()
    }

    fn write_network_mbox_cmd(&mut self, val: caliptra_emu_types::RvData) {
        self.regs.lock().unwrap().write_network_mbox_cmd(val)
    }

    fn read_network_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.regs.lock().unwrap().read_network_mbox_dlen()
    }

    fn write_network_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        self.regs.lock().unwrap().write_network_mbox_dlen(val)
    }

    fn read_network_mbox_execute(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxExecute::Register,
    > {
        self.regs.lock().unwrap().read_network_mbox_execute()
    }

    fn write_network_mbox_execute(
        &mut self,
        val: ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxExecute::Register,
        >,
    ) {
        self.regs.lock().unwrap().write_network_mbox_execute(val)
    }

    fn read_network_mbox_target_status(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Register,
    > {
        self.regs.lock().unwrap().read_network_mbox_target_status()
    }

    fn write_network_mbox_target_status(
        &mut self,
        val: ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxTargetStatus::Register,
        >,
    ) {
        self.regs
            .lock()
            .unwrap()
            .write_network_mbox_target_status(val)
    }

    fn read_network_mbox_cmd_status(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxCmdStatus::Register,
    > {
        self.regs.lock().unwrap().read_network_mbox_cmd_status()
    }

    fn write_network_mbox_cmd_status(
        &mut self,
        val: ReadWriteRegister<
            u32,
            caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxCmdStatus::Register,
        >,
    ) {
        self.regs.lock().unwrap().write_network_mbox_cmd_status(val)
    }

    fn read_network_mbox_hw_status(
        &mut self,
    ) -> ReadWriteRegister<
        u32,
        caliptra_mcu_registers_generated::network_mbox::bits::NetworkMboxHwStatus::Register,
    > {
        self.regs.lock().unwrap().read_network_mbox_hw_status()
    }
}
