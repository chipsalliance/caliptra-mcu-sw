// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use core::cell::Cell;
use kernel::hil::time::{Alarm, AlarmClient, Time};

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::{debug, ErrorCode};
use mcu_mbox_comm::hil::{Mailbox, MailboxClient, MailboxStatus};
use registers_generated::mci;
use registers_generated::mci::bits::{MboxCmdStatus, Notif0IntrEnT, Notif0IntrT};

pub const MCI_BASE: StaticRef<mci::regs::Mci> =
    unsafe { StaticRef::new(mci::MCI_TOP_ADDR as *const mci::regs::Mci) };

// pub const MCU_MBOX0_SRAM_SIZE: usize = 2 * 1024 * 1024; // 2MB SRAM size for MCU Mailbox 0
pub const MCU_MBOX0_SRAM_BASE: u32 = mci::MCI_TOP_ADDR + 0x40_0000; // SRAM offset from MCI base address

#[derive(Copy, Clone, Debug, PartialEq)]
enum McuMboxState {
    Idle,
    RxWait,       // Driver waiting for data to be received from SoC.
    TxInProgress, // Transmit is in progress. Need to wait for send_done.
}

enum TimerMode {
    NoTimer,
    SendDoneDefer,
}

/// MCU Mailbox 0 driver for Tock kernel
pub struct McuMailbox<'a, A: Alarm<'a>> {
    pub registers: StaticRef<mci::regs::Mci>,
    // Buffer to send/receive mailbox data
    data_buf: TakeCell<'static, [u8]>,
    data_buf_len: usize,
    state: Cell<McuMboxState>,
    timer_mode: Cell<TimerMode>,
    alarm: VirtualMuxAlarm<'a, A>,
    client: OptionalCell<&'a dyn MailboxClient<'a>>,
}

fn mcu_mbox0_sram_static_ref(len: usize) -> &'static mut [u8] {
    // SAFETY: We assume the SRAM is initialized and the address is valid.
    // The length is provided by the caller and should match the actual SRAM size.
    unsafe { core::slice::from_raw_parts_mut(MCU_MBOX0_SRAM_BASE as *mut u8, len) }
}

impl<'a, A: Alarm<'a>> McuMailbox<'a, A> {
    pub fn new(registers: StaticRef<mci::regs::Mci>, alarm: &'a MuxAlarm<'a, A>) -> Self {
        let len_in_bytes = registers.mcu_mbox0_csr_mbox_sram.len() as usize * 4;
        McuMailbox {
            registers,
            data_buf: TakeCell::new(mcu_mbox0_sram_static_ref(len_in_bytes)),
            data_buf_len: len_in_bytes,
            state: Cell::new(McuMboxState::Idle),
            timer_mode: Cell::new(TimerMode::NoTimer),
            alarm: VirtualMuxAlarm::new(alarm),
            client: OptionalCell::empty(),
        }
    }

    pub fn init(&'static self) {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
        // Reset mailbox to release lock and wipe SRAM
        self.reset_before_use();

        self.enable_interrupts();
        self.clear_event_interrupts();
        // Start receiving data
        self.state.set(McuMboxState::RxWait);
    }

    pub fn reset_before_use(&self) {
        let mbox_sram_size = (self.registers.mcu_mbox0_csr_mbox_sram.len() * 4) as u32;
        self.registers.mcu_mbox0_csr_mbox_dlen.set(mbox_sram_size);
        self.registers.mcu_mbox0_csr_mbox_execute.set(0);
    }

    pub fn handle_interrupt(&self) {
        // Read and clear interrupt status
        let intr_status = self
            .registers
            .intr_block_rf_notif0_internal_intr_r
            .extract();

        self.disable_interrupts();

        // Handle command available interrupt
        if intr_status.is_set(Notif0IntrT::NotifMbox0CmdAvailSts) {
            // Clear the interrupt by writing 1 to the status bit
            self.registers
                .intr_block_rf_notif0_internal_intr_r
                .modify(Notif0IntrT::NotifMbox0CmdAvailSts::SET);

            self.handle_incoming_request();
        }

        self.enable_interrupts();
    }

    fn handle_incoming_request(&self) {
        if self.state.get() != McuMboxState::RxWait {
            // Not currently waiting for data, ignore COMMAND_AVAILABLE
            return;
        }

        // TODO: Shall we check if the sender is a valid AXI user?

        // Read command and data length from registers (example, adjust as needed)
        let command = self.registers.mcu_mbox0_csr_mbox_cmd.get();
        let length = self.registers.mcu_mbox0_csr_mbox_dlen.get() as usize;

        if length > self.data_buf_len {
            // Length exceeds buffer size, invalid request
            debug!("MCU_MBOX_DRIVER: Incoming request length exceeds buffer size.");
            self.registers
                .mcu_mbox0_csr_mbox_cmd_status
                .write(MboxCmdStatus::Status::CmdFailure);
            return;
        }

        if let Some(client) = self.client.get() {
            if let Some(buf) = self.data_buf.take() {
                // Pass the buffer to the client callback
                client.request_received(command, buf, length);
            } else {
                romtime::println!(
                    "[xs debug]MCU_MBOX_DRIVER: No data buffer available for incoming request."
                );
                debug!("MCU_MBOX_DRIVER: No data buffer available for incoming request.");
            }
        } else {
            romtime::println!(
                "[xs debug]MCU_MBOX_DRIVER: No client registered for incoming request."
            );
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

    fn clear_event_interrupts(&self) {
        // Clear mailbox command available and target done interrupts. SW Write 1 to clear.
        self.registers
            .intr_block_rf_notif0_internal_intr_r
            .modify(Notif0IntrT::NotifMbox0CmdAvailSts::SET);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for McuMailbox<'a, A> {
    fn alarm(&self) {
        // Implement alarm callback logic here if needed
    }
}

impl<'a, A: Alarm<'a>> Mailbox<'a> for McuMailbox<'a, A> {
    fn send_request(&self, _command: u32, _request_data: &[u8]) -> Result<(), ErrorCode> {
        unimplemented!("send_request not implemented for McuMailbox");
    }

    /// Writes a response to the mailbox (Receiver mode).
    ///
    /// # Arguments
    ///
    /// * `response_data` - The response payload to write.
    /// * `status` - The status to set for the mailbox.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(ErrorCode)` if the operation fails.
    fn send_response(&self, response_data: &[u8], status: MailboxStatus) -> Result<(), ErrorCode> {
        todo!()
    }

    /// Returns the maximum size (in bytes) of the mailbox SRAM.
    fn max_mbox_sram_size(&self) -> usize {
        self.registers.mcu_mbox0_csr_mbox_sram.len() as usize * 4
    }

    /// Registers a client to receive mailbox event callbacks.
    ///
    /// # Arguments
    ///
    /// * `client` - Reference to an object implementing `MailboxClient`.
    fn set_client(&self, client: &'a dyn MailboxClient<'a>) {
        self.client.set(client);
    }
}
