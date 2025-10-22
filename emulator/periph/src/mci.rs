// Licensed under the Apache-2.0 license

use crate::mcu_mbox0::McuMailbox0Internal;
use crate::reset_reason::ResetReasonEmulator;
use caliptra_emu_bus::{ActionHandle, Clock, ReadWriteRegister, Timer, TimerAction};
use caliptra_emu_cpu::Irq;
use caliptra_emu_types::RvData;
use emulator_registers_generated::mci::MciPeripheral;
use registers_generated::mci::bits::{
    Error0IntrT, Notif0IntrEnT, Notif0IntrT, ResetReason, ResetRequest, WdtStatus, WdtTimer1Ctrl,
    WdtTimer1En, WdtTimer2Ctrl, WdtTimer2En,
};
use std::{cell::RefCell, rc::Rc};
use tock_registers::interfaces::{ReadWriteable, Readable};

const RESET_STATUS_MCU_RESET_MASK: u32 = 0x2;
const RESET_REQUEST_MCU_REQ_MASK: u32 = 0x1; // McuReq bit (bit 0)

pub struct Mci {
    ext_mci_regs: caliptra_emu_periph::mci::Mci,

    error0_internal_intr_r: ReadWriteRegister<u32, Error0IntrT::Register>,
    timer: Timer,
    op_wdt_timer1_expired_action: Option<ActionHandle>,
    op_wdt_timer2_expired_action: Option<ActionHandle>,
    op_mcu_reset_request_action: Option<ActionHandle>,
    op_mcu_assert_mcu_reset_status_action: Option<ActionHandle>,
    op_mcu_deassert_mcu_reset_status_action: Option<ActionHandle>,

    // emulates the RESET_REASON register
    reset_reason: ResetReasonEmulator,
    irq: Rc<RefCell<Irq>>,
    mcu_mailbox0: Option<McuMailbox0Internal>,

    // machine timer compare
    mtimecmp: u64,
    op_mtimecmp_due_action: Option<ActionHandle>,
    mcu_mailbox1: Option<McuMailbox0Internal>,
}

impl Mci {
    pub fn new(
        clock: &Clock,
        ext_mci_regs: caliptra_emu_periph::mci::Mci,
        irq: Rc<RefCell<Irq>>,
        mcu_mailbox0: Option<McuMailbox0Internal>,
        mcu_mailbox1: Option<McuMailbox0Internal>,
    ) -> Self {
        // Clear the reset status, MCU and Caiptra are out of reset
        ext_mci_regs.regs.borrow_mut().reset_status = 0;

        let mut reset_reason = ResetReasonEmulator::new(ext_mci_regs.clone());
        reset_reason.handle_power_up();

        let timer = Timer::new(clock);

        // Reasonable default: ~4B ticks in the future (within scheduling horizon).
        let default_mtimecmp = timer.now().wrapping_add(1u64 << 32);

        Self {
            ext_mci_regs,

            error0_internal_intr_r: ReadWriteRegister::new(0),
            timer: Timer::new(clock),
            op_wdt_timer1_expired_action: None,
            op_wdt_timer2_expired_action: None,
            op_mcu_reset_request_action: None,
            op_mcu_assert_mcu_reset_status_action: None,
            op_mcu_deassert_mcu_reset_status_action: None,
            reset_reason,
            irq,
            mcu_mailbox0,

            // --- init mtimecmp ---
            mtimecmp: default_mtimecmp,
            op_mtimecmp_due_action: None,
            mcu_mailbox1,
        }
    }

    fn arm_mtime_interrupt(&mut self) {
        // clean up previous pending timers

        if let Some(old) = self.op_mtimecmp_due_action.take() {
            self.timer.cancel(old);
        }

        //If we’re already past  (now >= mtimecmp), set a minimal positive delay of 1
        // tick so the event fires on the next clock increment.

        //Otherwise, schedule exactly the difference (mtimecmp - now).
        let now = self.timer.now();
        let delay = if now >= self.mtimecmp {
            1
        } else {
            self.mtimecmp - now
        };

        // Directly schedule the machine timer interrupt
        self.op_mtimecmp_due_action = Some(
            self.timer
                .schedule_action_in(delay, TimerAction::MachineTimerInterrupt),
        );
    }
}

impl MciPeripheral for Mci {
    fn read_mci_reg_fw_flow_status(&mut self) -> caliptra_emu_types::RvData {
        self.ext_mci_regs.regs.borrow().flow_status
    }

    fn write_mci_reg_fw_flow_status(&mut self, val: caliptra_emu_types::RvData) {
        self.ext_mci_regs.regs.borrow_mut().flow_status = val;
    }

    fn read_mci_reg_wdt_timer1_en(&mut self) -> ReadWriteRegister<u32, WdtTimer1En::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().wdt_timer1_en)
    }

    fn read_mci_reg_wdt_timer1_ctrl(&mut self) -> ReadWriteRegister<u32, WdtTimer1Ctrl::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().wdt_timer1_ctrl)
    }

    fn read_mci_reg_wdt_timer1_timeout_period(&mut self, index: usize) -> RvData {
        self.ext_mci_regs.regs.borrow().wdt_timer1_timeout_period[index]
    }

    fn read_mci_reg_wdt_timer2_en(&mut self) -> ReadWriteRegister<u32, WdtTimer2En::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().wdt_timer2_en)
    }

    fn read_mci_reg_wdt_timer2_ctrl(&mut self) -> ReadWriteRegister<u32, WdtTimer2Ctrl::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().wdt_timer2_ctrl)
    }

    fn read_mci_reg_wdt_timer2_timeout_period(&mut self, index: usize) -> RvData {
        self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[index]
    }

    fn read_mci_reg_wdt_status(&mut self) -> ReadWriteRegister<u32, WdtStatus::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().wdt_status)
    }

    fn read_mci_reg_wdt_cfg(&mut self, index: usize) -> RvData {
        self.ext_mci_regs.regs.borrow().wdt_cfg[index]
    }

    //  mtime mcu_rv_mtime_l and cu_rv_mtime_h
    fn read_mci_reg_mcu_rv_mtime_l(&mut self) -> caliptra_emu_types::RvData {
        self.timer.now() as u32
    }

    fn write_mci_reg_mcu_rv_mtime_l(&mut self, _val: caliptra_emu_types::RvData) {}

    fn read_mci_reg_mcu_rv_mtime_h(&mut self) -> caliptra_emu_types::RvData {
        (self.timer.now() >> 32) as u32
    }

    fn write_mci_reg_mcu_rv_mtime_h(&mut self, _val: caliptra_emu_types::RvData) {}

    //  mtime mcu_rv_mtimecmp_l and cu_rv_mtimecmp_h
    fn read_mci_reg_mcu_rv_mtimecmp_l(&mut self) -> caliptra_emu_types::RvData {
        (self.mtimecmp) as u32
    }

    fn write_mci_reg_mcu_rv_mtimecmp_l(&mut self, val: caliptra_emu_types::RvData) {
        self.mtimecmp = (self.mtimecmp & 0xffff_ffff_0000_0000) | val as u64;
        self.arm_mtime_interrupt();
    }

    fn read_mci_reg_mcu_rv_mtimecmp_h(&mut self) -> caliptra_emu_types::RvData {
        (self.mtimecmp >> 32) as u32
    }

    fn write_mci_reg_mcu_rv_mtimecmp_h(&mut self, val: caliptra_emu_types::RvData) {
        self.mtimecmp = (self.mtimecmp & 0x0000_0000_ffff_ffff) | ((val as u64) << 32);
        self.arm_mtime_interrupt();
    }

    fn read_mci_reg_reset_reason(&mut self) -> ReadWriteRegister<u32, ResetReason::Register> {
        ReadWriteRegister::new(self.reset_reason.get())
    }

    fn write_mci_reg_reset_reason(&mut self, val: ReadWriteRegister<u32, ResetReason::Register>) {
        self.reset_reason.set(val.reg.get());
    }

    fn read_mci_reg_reset_request(&mut self) -> ReadWriteRegister<u32, ResetRequest::Register> {
        ReadWriteRegister::new(self.ext_mci_regs.regs.borrow().reset_request)
    }

    fn write_mci_reg_wdt_timer1_en(&mut self, val: ReadWriteRegister<u32, WdtTimer1En::Register>) {
        self.ext_mci_regs.regs.borrow_mut().wdt_timer1_en = val.reg.get();

        let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
            self.ext_mci_regs.regs.borrow_mut().wdt_status,
        );

        wdt_status.reg.modify(WdtStatus::T1Timeout::CLEAR);

        self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

        // If timer is enabled, schedule a callback on expiry.
        let en = ReadWriteRegister::<u32, WdtTimer1En::Register>::new(val.reg.get());
        if en.reg.is_set(WdtTimer1En::Timer1En) {
            let timer_period: u64 =
                (self.ext_mci_regs.regs.borrow().wdt_timer1_timeout_period[1] as u64) << 32
                    | self.ext_mci_regs.regs.borrow().wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer1_expired_action = None;
        }
    }

    fn write_mci_reg_wdt_timer1_ctrl(
        &mut self,
        val: ReadWriteRegister<u32, WdtTimer1Ctrl::Register>,
    ) {
        self.ext_mci_regs.regs.borrow_mut().wdt_timer1_ctrl = val.reg.get();

        let en = ReadWriteRegister::<u32, WdtTimer1En::Register>::new(
            self.ext_mci_regs.regs.borrow_mut().wdt_timer1_en,
        );
        if en.reg.is_set(WdtTimer1En::Timer1En) && val.reg.is_set(WdtTimer1Ctrl::Timer1Restart) {
            let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
                self.ext_mci_regs.regs.borrow_mut().wdt_status,
            );

            wdt_status.reg.modify(WdtStatus::T1Timeout::CLEAR);

            self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

            let timer_period: u64 =
                (self.ext_mci_regs.regs.borrow().wdt_timer1_timeout_period[1] as u64) << 32
                    | self.ext_mci_regs.regs.borrow().wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
    }

    fn write_mci_reg_wdt_timer1_timeout_period(&mut self, val: RvData, index: usize) {
        self.ext_mci_regs
            .regs
            .borrow_mut()
            .wdt_timer1_timeout_period[index] = val;
    }

    fn write_mci_reg_wdt_timer2_en(&mut self, val: ReadWriteRegister<u32, WdtTimer2En::Register>) {
        self.ext_mci_regs.regs.borrow_mut().wdt_timer2_en = val.reg.get();

        let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
            self.ext_mci_regs.regs.borrow_mut().wdt_status,
        );
        wdt_status.reg.modify(WdtStatus::T2Timeout::CLEAR);
        self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

        // If timer is enabled, schedule a callback on expiry.
        let en = ReadWriteRegister::<u32, WdtTimer2En::Register>::new(
            self.ext_mci_regs.regs.borrow().wdt_timer2_en,
        );
        if en.reg.is_set(WdtTimer2En::Timer2En) {
            let timer_period: u64 =
                (self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[1] as u64) << 32
                    | self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer2_expired_action = None;
        }
    }

    fn write_mci_reg_wdt_timer2_ctrl(
        &mut self,
        val: ReadWriteRegister<u32, WdtTimer2Ctrl::Register>,
    ) {
        self.ext_mci_regs.regs.borrow_mut().wdt_timer2_ctrl = val.reg.get();

        let en = ReadWriteRegister::<u32, WdtTimer2En::Register>::new(
            self.ext_mci_regs.regs.borrow().wdt_timer2_en,
        );
        if en.reg.is_set(WdtTimer2En::Timer2En) && val.reg.is_set(WdtTimer2Ctrl::Timer2Restart) {
            let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
                self.ext_mci_regs.regs.borrow().wdt_status,
            );
            wdt_status.reg.modify(WdtStatus::T2Timeout::CLEAR);
            self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

            let timer_period: u64 =
                (self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[1] as u64) << 32
                    | self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
    }

    fn write_mci_reg_wdt_timer2_timeout_period(&mut self, val: RvData, index: usize) {
        self.ext_mci_regs
            .regs
            .borrow_mut()
            .wdt_timer2_timeout_period[index] = val;
    }

    fn read_mci_reg_intr_block_rf_notif0_intr_trig_r(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::Notif0IntrTrigT::Register,
    > {
        self.ext_mci_regs
            .regs
            .borrow()
            .intr_block_rf_notif0_intr_trig_r
            .into()
    }
    fn write_mci_reg_intr_block_rf_notif0_intr_trig_r(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::Notif0IntrTrigT::Register,
        >,
    ) {
        let cur_value = self
            .read_mci_reg_intr_block_rf_notif0_intr_trig_r()
            .reg
            .get();
        let new_val = cur_value & !val.reg.get();

        self.ext_mci_regs
            .regs
            .borrow_mut()
            .intr_block_rf_notif0_intr_trig_r = new_val;

        let cur_value = self
            .read_mci_reg_intr_block_rf_notif0_internal_intr_r()
            .reg
            .get();
        let new_val = cur_value | val.reg.get();
        self.ext_mci_regs
            .regs
            .borrow_mut()
            .intr_block_rf_notif0_internal_intr_r = new_val;
    }

    fn write_mci_reg_reset_request(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::ResetRequest::Register,
        >,
    ) {
        // Store value in shared ext_mci register (will be consumed by emulator)
        self.ext_mci_regs.regs.borrow_mut().reset_request = val.reg.get();

        if val.reg.is_set(ResetRequest::McuReq) {
            let reason = self.reset_reason.get();
            // If the reason isn't set or it is set to warm reset, perform a warm reset
            if reason == 0 || reason == ResetReason::WarmReset::SET.mask() {
                // Set warm reset reason immediately
                self.reset_reason.handle_warm_reset();
            }

            // Schedule the reset status assertion
            self.op_mcu_reset_request_action = Some(self.timer.schedule_poll_in(100));
        }
    }

    fn read_mci_reg_intr_block_rf_notif0_internal_intr_r(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::Notif0IntrT::Register,
    > {
        self.ext_mci_regs
            .regs
            .borrow()
            .intr_block_rf_notif0_internal_intr_r
            .into()
    }

    fn write_mci_reg_intr_block_rf_notif0_internal_intr_r(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::Notif0IntrT::Register,
        >,
    ) {
        let cur = self
            .ext_mci_regs
            .regs
            .borrow()
            .intr_block_rf_notif0_internal_intr_r;
        let clear_mask = val.reg.get();
        let new_val = cur & !clear_mask;
        self.ext_mci_regs
            .regs
            .borrow_mut()
            .intr_block_rf_notif0_internal_intr_r = new_val;
        // If all bits are cleared, lower the IRQ
        if new_val == 0 {
            self.irq.borrow_mut().set_level(false);
        }
    }

    fn read_mci_reg_intr_block_rf_notif0_intr_en_r(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::Notif0IntrEnT::Register,
    > {
        self.ext_mci_regs
            .regs
            .borrow()
            .intr_block_rf_notif0_intr_en_r
            .into()
    }

    fn write_mci_reg_intr_block_rf_notif0_intr_en_r(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::Notif0IntrEnT::Register,
        >,
    ) {
        self.ext_mci_regs
            .regs
            .borrow_mut()
            .intr_block_rf_notif0_intr_en_r = val.reg.get();
    }

    fn read_mcu_mbox0_csr_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_sram(index)
    }

    fn write_mcu_mbox0_csr_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_sram(val, index)
    }

    fn read_mcu_mbox0_csr_mbox_lock(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, registers_generated::mbox::bits::MboxLock::Register>
    {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_lock()
    }

    fn read_mcu_mbox0_csr_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_user()
    }

    fn read_mcu_mbox0_csr_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user()
    }

    fn write_mcu_mbox0_csr_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_user(val);
    }

    fn read_mcu_mbox0_csr_mbox_target_user_valid(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetUserValid::Register,
    > {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user_valid()
    }

    fn write_mcu_mbox0_csr_mbox_target_user_valid(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetUserValid::Register,
        >,
    ) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_user_valid(val);
    }

    fn read_mcu_mbox0_csr_mbox_cmd(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd()
    }

    fn write_mcu_mbox0_csr_mbox_cmd(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd(val);
    }

    fn read_mcu_mbox0_csr_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_dlen()
    }

    fn write_mcu_mbox0_csr_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_dlen(val);
    }

    fn read_mcu_mbox0_csr_mbox_execute(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mbox::bits::MboxExecute::Register,
    > {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_execute()
    }

    fn write_mcu_mbox0_csr_mbox_execute(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mbox::bits::MboxExecute::Register,
        >,
    ) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_execute(val);
    }

    fn read_mcu_mbox0_csr_mbox_target_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetStatus::Register,
    > {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_status()
    }

    fn write_mcu_mbox0_csr_mbox_target_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetStatus::Register,
        >,
    ) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_status(val);
    }

    fn read_mcu_mbox0_csr_mbox_cmd_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxCmdStatus::Register,
    > {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd_status()
    }

    fn write_mcu_mbox0_csr_mbox_cmd_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxCmdStatus::Register,
        >,
    ) {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd_status(val);
    }

    fn read_mcu_mbox0_csr_mbox_hw_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxHwStatus::Register,
    > {
        self.mcu_mailbox0
            .as_mut()
            .expect("mcu_mbox0 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_hw_status()
    }

    fn read_mcu_mbox1_csr_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_sram(index)
    }

    fn write_mcu_mbox1_csr_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_sram(val, index)
    }

    fn read_mcu_mbox1_csr_mbox_lock(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, registers_generated::mbox::bits::MboxLock::Register>
    {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_lock()
    }

    fn read_mcu_mbox1_csr_mbox_user(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_user()
    }

    fn read_mcu_mbox1_csr_mbox_target_user(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user()
    }

    fn write_mcu_mbox1_csr_mbox_target_user(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_user(val);
    }

    fn read_mcu_mbox1_csr_mbox_target_user_valid(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetUserValid::Register,
    > {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_user_valid()
    }

    fn write_mcu_mbox1_csr_mbox_target_user_valid(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetUserValid::Register,
        >,
    ) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_user_valid(val);
    }

    fn read_mcu_mbox1_csr_mbox_cmd(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd()
    }

    fn write_mcu_mbox1_csr_mbox_cmd(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd(val);
    }

    fn read_mcu_mbox1_csr_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_dlen()
    }

    fn write_mcu_mbox1_csr_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_dlen(val);
    }

    fn read_mcu_mbox1_csr_mbox_execute(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mbox::bits::MboxExecute::Register,
    > {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_execute()
    }

    fn write_mcu_mbox1_csr_mbox_execute(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mbox::bits::MboxExecute::Register,
        >,
    ) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_execute(val);
    }

    fn read_mcu_mbox1_csr_mbox_target_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxTargetStatus::Register,
    > {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_target_status()
    }

    fn write_mcu_mbox1_csr_mbox_target_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxTargetStatus::Register,
        >,
    ) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_target_status(val);
    }

    fn read_mcu_mbox1_csr_mbox_cmd_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxCmdStatus::Register,
    > {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd_status()
    }

    fn write_mcu_mbox1_csr_mbox_cmd_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::mci::bits::MboxCmdStatus::Register,
        >,
    ) {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd_status(val);
    }

    fn read_mcu_mbox1_csr_mbox_hw_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::mci::bits::MboxHwStatus::Register,
    > {
        self.mcu_mailbox1
            .as_mut()
            .expect("mcu_mbox1 is not initialized")
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_hw_status()
    }

    fn read_mci_reg_hw_rev_id(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<u32, registers_generated::mci::bits::HwRevId::Register>
    {
        caliptra_emu_bus::ReadWriteRegister::new(0x1000)
    }

    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_wdt_timer1_expired_action) {
            // Set T1Timeout in WDT status register
            let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
                self.ext_mci_regs.regs.borrow().wdt_status,
            );
            wdt_status.reg.modify(WdtStatus::T1Timeout::SET);
            self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

            self.error0_internal_intr_r
                .reg
                .modify(Error0IntrT::ErrorWdtTimer1TimeoutSts::SET);

            // If WDT2 is disabled, schedule a callback on its expiry.
            let wdt2_en = ReadWriteRegister::<u32, WdtTimer2En::Register>::new(
                self.ext_mci_regs.regs.borrow().wdt_timer2_en,
            );
            if !wdt2_en.reg.is_set(WdtTimer2En::Timer2En) {
                // Clear T2Timeout in WDT status register
                let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
                    self.ext_mci_regs.regs.borrow().wdt_status,
                );
                wdt_status.reg.modify(WdtStatus::T2Timeout::CLEAR);
                self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

                self.error0_internal_intr_r
                    .reg
                    .modify(Error0IntrT::ErrorWdtTimer2TimeoutSts::CLEAR);

                let timer_period: u64 =
                    (self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[1] as u64) << 32
                        | self.ext_mci_regs.regs.borrow().wdt_timer2_timeout_period[0] as u64;

                self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
            }
        }

        if self.timer.fired(&mut self.op_wdt_timer2_expired_action) {
            let wdt_status = ReadWriteRegister::<u32, WdtStatus::Register>::new(
                self.ext_mci_regs.regs.borrow().wdt_status,
            );
            wdt_status.reg.modify(WdtStatus::T2Timeout::SET);
            self.ext_mci_regs.regs.borrow_mut().wdt_status = wdt_status.reg.get();

            // If WDT2 was not scheduled due to WDT1 expiry (i.e WDT2 is disabled), schedule an NMI.
            // Else, do nothing.
            let wdt2_en = ReadWriteRegister::<u32, WdtTimer2En::Register>::new(
                self.ext_mci_regs.regs.borrow().wdt_timer2_en,
            );
            if wdt2_en.reg.is_set(WdtTimer2En::Timer2En) {
                self.error0_internal_intr_r
                    .reg
                    .modify(Error0IntrT::ErrorWdtTimer2TimeoutSts::SET);
                return;
            }

            // Raise an NMI. NMIs don't fire immediately; a couple instructions is a fairly typicaly delay on VeeR.
            const NMI_DELAY: u64 = 2;

            // From RISC-V_VeeR_EL2_PRM.pdf
            const NMI_CAUSE_WDT_TIMEOUT: u32 = 0x0000_0000; // [TODO] Need correct mcause value.

            self.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_WDT_TIMEOUT,
                },
            );
        }

        if self.timer.fired(&mut self.op_mcu_reset_request_action) {
            // Handle MCU reset request
            println!("[MCI] TimerAction::UpdateReset");
            self.timer.schedule_action_in(100, TimerAction::UpdateReset);
            self.op_wdt_timer2_expired_action = None;
            // Allow enough time for MCU to reset before asserting RESET_STATUS_MCU_RESET
            self.op_mcu_assert_mcu_reset_status_action = Some(self.timer.schedule_poll_in(100));
        }
        if self
            .timer
            .fired(&mut self.op_mcu_assert_mcu_reset_status_action)
        {
            // MCU is now in reset, assert the reset status
            self.ext_mci_regs.regs.borrow_mut().reset_status |= RESET_STATUS_MCU_RESET_MASK;

            // At this point MCU is already reset, clear reset request
            self.ext_mci_regs.regs.borrow_mut().reset_request &= !RESET_REQUEST_MCU_REQ_MASK;

            self.op_mcu_assert_mcu_reset_status_action = None;
            // Allow enough time for Caliptra to process the reset status before deasserting it
            self.op_mcu_deassert_mcu_reset_status_action = Some(self.timer.schedule_poll_in(1000));
        }
        if self
            .timer
            .fired(&mut self.op_mcu_deassert_mcu_reset_status_action)
        {
            // MCU is now out of reset, deassert the reset status and interrupt
            self.ext_mci_regs.regs.borrow_mut().reset_status &= !RESET_STATUS_MCU_RESET_MASK;
            self.op_mcu_deassert_mcu_reset_status_action = None;
            self.irq.borrow_mut().set_level(false);
        }

        // Check if there are any mcu_mbox0 IRQ events to process.
        if let Some(event) = self.mcu_mailbox0.as_mut().and_then(|mb| mb.get_notif_irq()) {
            let mut notif_reg = self
                .ext_mci_regs
                .regs
                .borrow()
                .intr_block_rf_notif0_internal_intr_r;

            let notif_en = self
                .ext_mci_regs
                .regs
                .borrow()
                .intr_block_rf_notif0_intr_en_r;

            // Set the corresponding bit for the event if enabled
            match event {
                crate::mcu_mbox0::IrqEventToMcu::Mbox0CmdAvailable => {
                    if notif_en & Notif0IntrEnT::NotifMbox0CmdAvailEn::SET.value != 0 {
                        notif_reg |= Notif0IntrT::NotifMbox0CmdAvailSts::SET.value;
                    }
                }
                crate::mcu_mbox0::IrqEventToMcu::Mbox0TargetDone => {
                    if notif_en & Notif0IntrEnT::NotifMbox0TargetDoneEn::SET.value != 0 {
                        notif_reg |= Notif0IntrT::NotifMbox0TargetDoneSts::SET.value;
                    }
                }
            }
            self.ext_mci_regs
                .regs
                .borrow_mut()
                .intr_block_rf_notif0_internal_intr_r = notif_reg;
            // Raise IRQ level if any bit is set
            if notif_reg != 0 {
                self.irq.borrow_mut().set_level(true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcu_mbox0::IrqEventToMcu;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::mci::MciBus;
    use tock_registers::registers::InMemoryRegister;

    pub const CPTRA_WDT_TIMER1_EN_START: u32 = 0xb0;
    pub const CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START: u32 = 0xb8;
    pub const CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START: u32 = 0xc8;
    pub const CPTRA_WDT_STATUS_START: u32 = 0xd0;
    pub const NOTIF0_INTR_EN_OFFSET: u32 = 0x100c;
    pub const NOTIF0_INTERNAL_INTR_R_OFFSET: u32 = 0x1024;

    fn next_action(clock: &Clock) -> Option<TimerAction> {
        let mut actions = clock.increment(4);
        match actions.len() {
            0 => None,
            1 => actions.drain().next(),
            _ => panic!("More than one action scheduled; unexpected"),
        }
    }

    #[test]
    fn test_wdt() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mci_reg: Mci = Mci::new(&clock, ext_mci_regs, Rc::new(RefCell::new(irq)), None, None);
        let mut mci_bus = MciBus {
            periph: Box::new(mci_reg),
        };
        mci_bus
            .write(RvSize::Word, CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START, 4)
            .unwrap();
        // Read back to verify
        mci_bus
            .read(RvSize::Word, CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START)
            .unwrap();
        mci_bus
            .write(RvSize::Word, CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START + 4, 0)
            .unwrap();
        mci_bus
            .write(RvSize::Word, CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START, 1)
            .unwrap();
        mci_bus
            .write(RvSize::Word, CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START + 4, 0)
            .unwrap();
        mci_bus
            .write(RvSize::Word, CPTRA_WDT_TIMER1_EN_START, 1)
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, WdtStatus::Register>::new(
                mci_bus.read(RvSize::Word, CPTRA_WDT_STATUS_START).unwrap(),
            );
            if status.is_set(WdtStatus::T2Timeout) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut mci_bus);
        }

        assert_eq!(
            next_action(&clock),
            Some(TimerAction::Nmi {
                mcause: 0x0000_0000,
            })
        );
    }

    fn check_mcu_mailbox0_interrupt(
        clock: &Clock,
        mci_bus: &mut MciBus,
        mcu_mailbox: &mut McuMailbox0Internal,
        irq_event: IrqEventToMcu,
        en_bit: u32,
        sts_bit: u32,
    ) {
        // Enable the interrupt
        mci_bus
            .write(RvSize::Word, NOTIF0_INTR_EN_OFFSET, en_bit)
            .unwrap();
        let notif_en = mci_bus.read(RvSize::Word, NOTIF0_INTR_EN_OFFSET).unwrap();
        assert_eq!(notif_en & en_bit, en_bit);

        // Simulate mailbox event
        mcu_mailbox.set_notif_irq(irq_event);
        for _ in 0..1000 {
            clock.increment_and_process_timer_actions(1, mci_bus);
        }
        mci_bus.periph.poll();

        // Check that the status bit is set
        let notif_status = mci_bus
            .read(RvSize::Word, NOTIF0_INTERNAL_INTR_R_OFFSET)
            .unwrap();
        assert_eq!(notif_status & sts_bit, sts_bit);
        // Write 1 to status bit to clear
        mci_bus
            .write(RvSize::Word, NOTIF0_INTERNAL_INTR_R_OFFSET, sts_bit)
            .unwrap();
        // read back and check if it is cleared
        let notif_status = mci_bus
            .read(RvSize::Word, NOTIF0_INTERNAL_INTR_R_OFFSET)
            .unwrap();
        assert_eq!(notif_status & sts_bit, 0);
    }

    #[test]
    fn test_mailbox_interrupt_handling() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mci_reg = Mci::new(
            &clock,
            ext_mci_regs.clone(),
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );
        let mut mcu_mailbox = mci_reg.mcu_mailbox0.clone().unwrap();
        let mut mci_bus = MciBus {
            periph: Box::new(mci_reg),
        };
        // Test CMD_AVAILABLE
        check_mcu_mailbox0_interrupt(
            &clock,
            &mut mci_bus,
            &mut mcu_mailbox,
            IrqEventToMcu::Mbox0CmdAvailable,
            Notif0IntrEnT::NotifMbox0CmdAvailEn::SET.value,
            Notif0IntrT::NotifMbox0CmdAvailSts::SET.value,
        );
        // Test TARGET_DONE
        check_mcu_mailbox0_interrupt(
            &clock,
            &mut mci_bus,
            &mut mcu_mailbox,
            IrqEventToMcu::Mbox0TargetDone,
            Notif0IntrEnT::NotifMbox0TargetDoneEn::SET.value,
            Notif0IntrT::NotifMbox0TargetDoneSts::SET.value,
        );
    }

    #[test]
    fn test_mtimecmp_write_high_then_low() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        let hi: u32 = 0x0022_3344;
        let lo: u32 = 0x5566_7788;

        mci.write_mci_reg_mcu_rv_mtimecmp_h(hi);
        mci.write_mci_reg_mcu_rv_mtimecmp_l(lo);

        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_h(), hi);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_l(), lo);

        let combined: u64 = ((mci.read_mci_reg_mcu_rv_mtimecmp_h() as u64) << 32)
            | (mci.read_mci_reg_mcu_rv_mtimecmp_l() as u64);
        assert_eq!(combined, 0x0022_3344_5566_7788u64);
    }

    #[test]
    fn test_mtimecmp_write_low_then_high() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        let lo: u32 = 0x0000_FFFF;
        let hi: u32 = 0x0000_5678;

        mci.write_mci_reg_mcu_rv_mtimecmp_l(lo);
        mci.write_mci_reg_mcu_rv_mtimecmp_h(hi);

        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_l(), lo);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_h(), hi);

        let combined: u64 = ((mci.read_mci_reg_mcu_rv_mtimecmp_h() as u64) << 32)
            | (mci.read_mci_reg_mcu_rv_mtimecmp_l() as u64);
        assert_eq!(combined, 0x0000_5678_0000_FFFFu64);
    }

    #[test]
    fn test_mtimecmp_write_low_multiple_times() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        // Seed a known value.
        mci.write_mci_reg_mcu_rv_mtimecmp_h(0x00BB_CCDD);
        mci.write_mci_reg_mcu_rv_mtimecmp_l(0x0123_4567);

        // Change only the low half.
        mci.write_mci_reg_mcu_rv_mtimecmp_l(0x89AB_CDEF);

        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_h(), 0x00BB_CCDD);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_l(), 0x89AB_CDEF);
    }

    #[test]

    fn test_mtimecmp_write_high_multiple_times() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        // use a safe 48-bit range: 0x0000_DEAD_FFFF_FFFE
        mci.write_mci_reg_mcu_rv_mtimecmp_h(0x0000_DEAD);
        mci.write_mci_reg_mcu_rv_mtimecmp_l(0xFFFF_FFFE);

        // Change only the high half; low must remain unchanged.
        mci.write_mci_reg_mcu_rv_mtimecmp_h(0x0000_BEEF);

        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_l(), 0xFFFF_FFFE);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtimecmp_h(), 0x0000_BEEF);

        let combined = ((mci.read_mci_reg_mcu_rv_mtimecmp_h() as u64) << 32)
            | (mci.read_mci_reg_mcu_rv_mtimecmp_l() as u64);
        assert_eq!(combined, 0x0000_BEEF_FFFF_FFFEu64);
    }

    #[test]
    fn test_mtime_reads() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        // Initial time is 0
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_l(), 0);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_h(), 0);

        // Advance to an arbitrary large timestamp and check split
        clock.increment(0x1234_5678_0000_0000);
        let now = clock.now();
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_l(), now as u32);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_h(), (now >> 32) as u32);
    }

    #[test]
    fn test_mtime_writes() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        // Move time to a known value.
        clock.increment(1234);
        let now = clock.now();
        assert_eq!(now, 1234);

        // Writes should be ignored (no-ops).
        mci.write_mci_reg_mcu_rv_mtime_l(0xDEAD_BEEF);
        mci.write_mci_reg_mcu_rv_mtime_h(0xFEED_FACE);

        // Reads still reflect clock time, not the written values.
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_l(), now as u32);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_h(), (now >> 32) as u32);

        // Advance time again and ensure reads keep tracking time.
        clock.increment(1);
        let now2 = clock.now();
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_l(), now2 as u32);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_h(), (now2 >> 32) as u32);
    }

    #[test]
    fn test_mtime_after_clock_advance_32bit() {
        let clock = Clock::new();
        let ext_mci_regs = caliptra_emu_periph::mci::Mci::new(vec![]);
        let pic = caliptra_emu_cpu::Pic::new();
        let irq = pic.register_irq(1);
        let mut mci = Mci::new(
            &clock,
            ext_mci_regs,
            Rc::new(RefCell::new(irq)),
            Some(McuMailbox0Internal::new(&clock)),
            None,
        );

        // Advance by 2^32 + 1 -> high = 1, low = 1, as clock start at 0
        clock.increment(0x1_0000_0001);
        let now = clock.now();
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_l(), now as u32);
        assert_eq!(mci.read_mci_reg_mcu_rv_mtime_h(), (now >> 32) as u32);
    }
}
