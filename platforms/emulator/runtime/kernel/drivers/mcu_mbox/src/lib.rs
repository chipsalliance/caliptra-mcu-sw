// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use mcu_mbox_comm::hil::{Mailbox, MailboxClient, MailboxStatus};
use registers_generated::mci;
use registers_generated::mci::bits::{MboxCmdStatus, Notif0IntrEnT, Notif0IntrT};

pub const MCI_BASE: StaticRef<mci::regs::Mci> =
    unsafe { StaticRef::new(mci::MCI_TOP_ADDR as *const mci::regs::Mci) };

pub const MCU_MBOX0_SRAM_BASE: u32 = mci::MCI_TOP_ADDR + 0x40_0000;

#[derive(Copy, Clone, Debug, PartialEq)]
enum McuMboxState {
    Idle,
    RxWait,       // Driver waiting for data to be received from SoC.
    TxInProgress, // Transmit is in progress. Need to wait for send_done.
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum TimerMode {
    NoTimer,
    SendDoneDefer,
}

pub struct McuMailbox<'a, A: Alarm<'a>> {
    pub registers: StaticRef<mci::regs::Mci>,
    data_buf: TakeCell<'static, [u32]>,
    data_buf_len: usize,
    state: Cell<McuMboxState>,
    timer_mode: Cell<TimerMode>,
    alarm: VirtualMuxAlarm<'a, A>,
    client: OptionalCell<&'a dyn MailboxClient>,
}

fn mcu_mbox0_sram_static_ref(len: usize) -> &'static mut [u32] {
    unsafe { core::slice::from_raw_parts_mut(MCU_MBOX0_SRAM_BASE as *mut u32, len) }
}

impl<'a, A: Alarm<'a>> McuMailbox<'a, A> {
    const DEFER_SEND_DONE_TICKS: u32 = 10000;

    pub fn new(registers: StaticRef<mci::regs::Mci>, alarm: &'a MuxAlarm<'a, A>) -> Self {
        let dw_len = registers.mcu_mbox0_csr_mbox_sram.len();
        McuMailbox {
            registers,
            data_buf: TakeCell::new(mcu_mbox0_sram_static_ref(dw_len)),
            data_buf_len: dw_len,
            state: Cell::new(McuMboxState::Idle),
            timer_mode: Cell::new(TimerMode::NoTimer),
            alarm: VirtualMuxAlarm::new(alarm),
            client: OptionalCell::empty(),
        }
    }

    pub fn init(&'static self) {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        self.reset_before_use();
        self.state.set(McuMboxState::RxWait);
    }

    pub fn enable(&self) {
        self.enable_interrupts();
    }

    pub fn disable(&self) {
        self.disable_interrupts();
    }

    fn reset_before_use(&self) {
        let mbox_sram_size = (self.registers.mcu_mbox0_csr_mbox_sram.len() * 4) as u32;
        // MCU acquires the lock to allow SRAM clearing.
        self.registers.mcu_mbox0_csr_mbox_lock.get();
        self.registers.mcu_mbox0_csr_mbox_dlen.set(mbox_sram_size);
        self.registers.mcu_mbox0_csr_mbox_execute.set(0);
    }

    // Restores the data buffer after it has been taken. This method is intended to be called by client.
    pub fn set_rx_buffer(&self, rx_buf: &'static mut [u32]) {
        self.data_buf.replace(rx_buf);
    }

    pub fn handle_interrupt(&self) {
        let intr_status = self
            .registers
            .intr_block_rf_notif0_internal_intr_r
            .extract();

        self.disable_interrupts();

        if intr_status.is_set(Notif0IntrT::NotifMbox0CmdAvailSts) {
            self.registers
                .intr_block_rf_notif0_internal_intr_r
                .modify(Notif0IntrT::NotifMbox0CmdAvailSts::SET);

            self.handle_incoming_request();
        }
        self.enable_interrupts();
    }

    pub fn schedule_send_done(&self) {
        self.timer_mode.set(TimerMode::SendDoneDefer);
        let now = self.alarm.now();
        self.alarm
            .set_alarm(now, Self::DEFER_SEND_DONE_TICKS.into());
    }

    fn handle_incoming_request(&self) {
        if self.state.get() != McuMboxState::RxWait {
            return;
        }
        let command = self.registers.mcu_mbox0_csr_mbox_cmd.get();
        let dw_len = (self.registers.mcu_mbox0_csr_mbox_dlen.get() / 4) as usize;
        if dw_len > self.data_buf_len {
            debug!("MCU_MBOX_DRIVER: Incoming request length exceeds buffer size");
            self.registers
                .mcu_mbox0_csr_mbox_cmd_status
                .write(MboxCmdStatus::Status::CmdFailure);
            return;
        }

        if let Some(client) = self.client.get() {
            if let Some(buf) = self.data_buf.take() {
                // It is expected that the client restores buffer with set_rx_buffer().
                client.request_received(command, buf, dw_len);
            } else {
                panic!("MCU_MBOX_DRIVER: No data buffer available for incoming request.");
            }
        } else {
            debug!("MCU_MBOX_DRIVER: No client registered for incoming request.");
        }
    }

    fn enable_interrupts(&self) {
        self.registers
            .intr_block_rf_notif0_intr_en_r
            .modify(Notif0IntrEnT::NotifMbox0CmdAvailEn::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .intr_block_rf_notif0_intr_en_r
            .modify(Notif0IntrEnT::NotifMbox0CmdAvailEn::CLEAR);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for McuMailbox<'a, A> {
    fn alarm(&self) {
        match self.timer_mode.get() {
            TimerMode::NoTimer => {}
            TimerMode::SendDoneDefer => {
                if let Some(client) = self.client.get() {
                    client.send_done(Ok(()));
                } else {
                    debug!("MCU_MBOX_DRIVER: No client registered to receive send_done.");
                }
                self.state.set(McuMboxState::RxWait);
            }
        }
        self.timer_mode.set(TimerMode::NoTimer);
    }
}

impl<'a, A: Alarm<'a>> Mailbox<'a> for McuMailbox<'a, A> {
    fn send_request(&self, _command: u32, _request_data: &[u32]) -> Result<(), ErrorCode> {
        unimplemented!("MCU_MBOX_DRIVER only supports receiver mode");
    }

    fn send_response(&self, response_data: &[u32], status: MailboxStatus) -> Result<(), ErrorCode> {
        let resp_len = response_data.len();
        if resp_len > self.data_buf_len {
            return Err(ErrorCode::INVAL);
        }

        self.state.set(McuMboxState::TxInProgress);

        if let Some(buf) = self.data_buf.take() {
            // Copy response data into driver buffer which maps to mailbox sram directly.
            buf[..resp_len].copy_from_slice(response_data);
            self.data_buf.replace(buf);

            // Set cmd_status register
            self.registers
                .mcu_mbox0_csr_mbox_cmd_status
                .write(match status {
                    MailboxStatus::Complete => MboxCmdStatus::Status::CmdComplete,
                    MailboxStatus::Failure => MboxCmdStatus::Status::CmdFailure,
                    MailboxStatus::DataReady => MboxCmdStatus::Status::DataReady,
                    MailboxStatus::Busy => MboxCmdStatus::Status::CmdBusy,
                });

            self.schedule_send_done();
            Ok(())
        } else {
            debug!("MCU_MBOX_DRIVER: No data buffer available for sending response.");
            Err(ErrorCode::FAIL)
        }
    }

    fn max_mbox_sram_dw_size(&self) -> usize {
        self.registers.mcu_mbox0_csr_mbox_sram.len()
    }

    fn set_client(&self, client: &'a dyn MailboxClient) {
        self.client.set(client);
    }
}
