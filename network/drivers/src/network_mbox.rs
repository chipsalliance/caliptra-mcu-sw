/*++

Licensed under the Apache-2.0 license.

File Name:

    network_mbox.rs

Abstract:

    Network Mailbox driver for the Network Coprocessor.

--*/

use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMailboxClient, NetworkMboxError, NetworkMboxStatus,
    NetworkMboxTargetStatus, Result,
};
use caliptra_mcu_registers_generated::network_mbox::{
    bits::{
        NetworkMboxCmdStatus, NetworkMboxExecute, NetworkMboxHwStatus, NetworkMboxLock,
        NetworkMboxTargetStatus as TargetStatusBits, NetworkMboxTargetUserValid,
    },
    regs::NetworkMbox as NetworkMboxRegs,
    NETWORK_MBOX_CSR_ADDR,
};
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{Readable, Writeable};

use core::cell::Cell;

/// Default StaticRef to the network mailbox registers.
pub const NETWORK_MBOX_REGS: StaticRef<NetworkMboxRegs> =
    unsafe { StaticRef::new(NETWORK_MBOX_CSR_ADDR as *const NetworkMboxRegs) };

/// State machine for the network mailbox driver.
#[derive(Copy, Clone, Debug, PartialEq)]
enum DriverState {
    /// Driver is idle, not processing any request.
    Idle,
    /// Driver is waiting for an incoming request (receiver/target mode).
    RxWait,
    /// A response is being composed/sent (receiver mode).
    TxInProgress,
    /// A request has been sent and we're waiting for the target to respond (sender mode).
    WaitingForTargetDone,
}

/// Network Mailbox driver for the Network Coprocessor.
pub struct NetworkMboxDriver<'a> {
    regs: StaticRef<NetworkMboxRegs>,
    state: Cell<DriverState>,
    client: Cell<Option<&'a dyn NetworkMailboxClient>>,
    sram_ptr: Cell<Option<*mut u32>>,
}

impl NetworkMboxDriver<'_> {
    /// Create a new network mailbox driver using the default peripheral address.
    pub fn new() -> Self {
        Self::from(NETWORK_MBOX_REGS)
    }

    /// Create a new network mailbox driver from a StaticRef to the registers.
    pub fn from(regs: StaticRef<NetworkMboxRegs>) -> Self {
        Self {
            regs,
            state: Cell::new(DriverState::Idle),
            client: Cell::new(None),
            sram_ptr: Cell::new(Some(regs.network_mbox_sram.as_ptr() as *mut u32)),
        }
    }

    pub fn init(&self) {
        self.reset_before_use();
        self.state.set(DriverState::RxWait);
    }

    /// Acquires the lock and releases it with SRAM clearing to ensure a clean
    /// state.
    fn reset_before_use(&self) {
        // Read lock register to acquire (reading 0 means lock acquired).
        let _lock = self.regs.network_mbox_lock.get();

        // Set DLEN to full SRAM size to ensure complete zeroization.
        let sram_size_bytes = self.regs.network_mbox_sram.len() * 4;
        self.regs.network_mbox_dlen.set(sram_size_bytes as u32);

        // Write 0 to execute to release lock and trigger SRAM zeroization.
        self.regs
            .network_mbox_execute
            .write(NetworkMboxExecute::Execute::CLEAR);
    }

    /// Check if the mailbox is currently locked.
    #[allow(dead_code)]
    fn is_locked(&self) -> bool {
        self.regs.network_mbox_lock.is_set(NetworkMboxLock::Lock)
    }

    /// Try to acquire the mailbox lock.
    /// Returns Ok(()) if the lock was acquired, Err if it was already locked.
    fn try_acquire_lock(&self) -> Result<()> {
        // Reading the lock register: 0 means we got the lock, non-zero means locked by someone else.
        let lock_val = self.regs.network_mbox_lock.get();
        if lock_val != 0 {
            Err(NetworkMboxError::Locked)
        } else {
            Ok(())
        }
    }

    /// Read the user register (AXI USER of the agent that acquired the lock).
    fn read_user(&self) -> u32 {
        self.regs.network_mbox_user.get()
    }

    /// Read the command register.
    fn read_cmd(&self) -> u32 {
        self.regs.network_mbox_cmd.get()
    }

    /// Read the data length register (in bytes).
    fn read_dlen(&self) -> usize {
        self.regs.network_mbox_dlen.get() as usize
    }

    /// Check if the execute bit is set.
    fn is_execute_set(&self) -> bool {
        self.regs
            .network_mbox_execute
            .is_set(NetworkMboxExecute::Execute)
    }

    /// Read data from the mailbox SRAM into the provided buffer.
    #[allow(dead_code)]
    fn read_sram_data(&self, buf: &mut [u32], dw_len: usize) {
        for (i, item) in buf.iter_mut().enumerate().take(dw_len) {
            *item = self.regs.network_mbox_sram[i].get();
        }
    }

    /// Write data to the mailbox SRAM from an iterator.
    fn write_sram_data(&self, data: impl Iterator<Item = u32>, dw_len: usize, dlen: usize) {
        for (i, dword) in data.take(dw_len).enumerate() {
            // If this is the last dword and dlen is not 4-byte aligned, mask it.
            if i == dw_len - 1 && dlen % 4 != 0 {
                let mask = (1u32 << (dlen % 4 * 8)) - 1;
                self.regs.network_mbox_sram[i].set(dword & mask);
            } else {
                self.regs.network_mbox_sram[i].set(dword);
            }
        }
    }

    /// Read the hardware status register.
    pub fn hw_status(&self) -> caliptra_mcu_network_hil::network_mbox::NetworkMboxHwStatus {
        let hw_status = self.regs.network_mbox_hw_status.extract();
        caliptra_mcu_network_hil::network_mbox::NetworkMboxHwStatus {
            ecc_single_error: hw_status.is_set(NetworkMboxHwStatus::EccSingleError),
            ecc_double_error: hw_status.is_set(NetworkMboxHwStatus::EccDoubleError),
        }
    }

    /// Read the target status register.
    pub fn read_target_status(&self) -> NetworkMboxTargetStatus {
        let reg = self.regs.network_mbox_target_status.extract();
        let status = match reg.read(TargetStatusBits::Status) {
            0 => NetworkMboxStatus::CmdBusy,
            1 => NetworkMboxStatus::DataReady,
            2 => NetworkMboxStatus::CmdComplete,
            3 => NetworkMboxStatus::CmdFailure,
            _ => NetworkMboxStatus::CmdFailure,
        };
        let done = reg.is_set(TargetStatusBits::Done);
        NetworkMboxTargetStatus { status, done }
    }

    /// Poll for incoming requests or target done events.
    pub fn poll(&self) {
        match self.state.get() {
            DriverState::RxWait => {
                if self.is_execute_set() {
                    self.handle_incoming_request();
                }
            }
            DriverState::WaitingForTargetDone => {
                let target_status = self.read_target_status();
                if target_status.done {
                    self.handle_target_done(target_status);
                }
            }
            _ => {}
        }
    }

    /// Handle an incoming request from an external agent.
    fn handle_incoming_request(&self) {
        if self.try_handle_incoming_request().is_err() {
            self.regs
                .network_mbox_cmd_status
                .write(NetworkMboxCmdStatus::Status::CmdFailure);
            self.state.set(DriverState::RxWait);
        }
    }

    /// Try to process an incoming request, returning Err on any failure.
    fn try_handle_incoming_request(&self) -> Result<()> {
        let command = self.read_cmd();
        let user = self.read_user();
        let dlen = self.read_dlen();
        let dw_len = dlen.div_ceil(4);
        let max_dw = self.regs.network_mbox_sram.len();

        if dw_len > max_dw {
            return Err(NetworkMboxError::DataTooLarge);
        }

        let client = self.client.get().ok_or(NetworkMboxError::Failed)?;
        let sram_ptr = self.sram_ptr.take().ok_or(NetworkMboxError::Failed)?;

        let buf = unsafe { core::slice::from_raw_parts_mut(sram_ptr, max_dw) };

        self.state.set(DriverState::TxInProgress);

        if client.request_received(command, user, buf, dlen).is_err() {
            self.sram_ptr.set(Some(sram_ptr));
            return Err(NetworkMboxError::Failed);
        }

        Ok(())
    }

    /// Handle the target done event (sender mode).
    fn handle_target_done(&self, target_status: NetworkMboxTargetStatus) {
        let dlen = self.read_dlen();
        let max_dw = self.regs.network_mbox_sram.len();

        if let Some(client) = self.client.get() {
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    self.regs.network_mbox_sram.as_ptr() as *mut u32,
                    max_dw,
                )
            };

            self.state.set(DriverState::Idle);
            client.response_received(target_status, buf, dlen);
        }

        // Release the lock by clearing execute (triggers zeroization).
        self.regs
            .network_mbox_execute
            .write(NetworkMboxExecute::Execute::CLEAR);
        self.state.set(DriverState::RxWait);
    }

    /// Convert a HIL status to the register bitfield value for cmd_status.
    fn status_to_cmd_status_field(
        status: NetworkMboxStatus,
    ) -> tock_registers::fields::FieldValue<u32, NetworkMboxCmdStatus::Register> {
        match status {
            NetworkMboxStatus::CmdBusy => NetworkMboxCmdStatus::Status::CmdBusy,
            NetworkMboxStatus::DataReady => NetworkMboxCmdStatus::Status::DataReady,
            NetworkMboxStatus::CmdComplete => NetworkMboxCmdStatus::Status::CmdComplete,
            NetworkMboxStatus::CmdFailure => NetworkMboxCmdStatus::Status::CmdFailure,
        }
    }

    /// Convert a HIL status to the register bitfield value for target_status.
    fn status_to_target_status_field(
        status: NetworkMboxStatus,
    ) -> tock_registers::fields::FieldValue<u32, TargetStatusBits::Register> {
        match status {
            NetworkMboxStatus::CmdBusy => TargetStatusBits::Status::CmdBusy,
            NetworkMboxStatus::DataReady => TargetStatusBits::Status::DataReady,
            NetworkMboxStatus::CmdComplete => TargetStatusBits::Status::CmdComplete,
            NetworkMboxStatus::CmdFailure => TargetStatusBits::Status::CmdFailure,
        }
    }
}

impl Default for NetworkMboxDriver<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NetworkMailbox<'a> for NetworkMboxDriver<'a> {
    fn send_request(
        &self,
        command: u32,
        target_user: u32,
        request_data: impl Iterator<Item = u32>,
        dlen: usize,
    ) -> Result<()> {
        let dw_len = dlen.div_ceil(4);
        let max_dw = self.regs.network_mbox_sram.len();

        if dw_len > max_dw {
            return Err(NetworkMboxError::DataTooLarge);
        }

        // Try to acquire the lock.
        self.try_acquire_lock()?;

        // Set target user and mark it as valid.
        self.regs.network_mbox_target_user.set(target_user);
        self.regs
            .network_mbox_target_user_valid
            .write(NetworkMboxTargetUserValid::Valid::SET);

        // Write command.
        self.regs.network_mbox_cmd.set(command);

        // Write data to SRAM.
        self.write_sram_data(request_data, dw_len, dlen);

        // Set data length.
        self.regs.network_mbox_dlen.set(dlen as u32);

        // Set execute to notify the target.
        self.regs
            .network_mbox_execute
            .write(NetworkMboxExecute::Execute::SET);

        self.state.set(DriverState::WaitingForTargetDone);
        Ok(())
    }

    fn send_response(&self, response_data: impl Iterator<Item = u32>, dlen: usize) -> Result<()> {
        let dw_len = dlen.div_ceil(4);
        let max_dw = self.regs.network_mbox_sram.len();

        if dw_len > max_dw {
            return Err(NetworkMboxError::DataTooLarge);
        }

        if self.state.get() != DriverState::TxInProgress {
            return Err(NetworkMboxError::Failed);
        }

        // Write response data to SRAM.
        self.write_sram_data(response_data, dw_len, dlen);

        // Update data length for the response.
        self.regs.network_mbox_dlen.set(dlen as u32);

        Ok(())
    }

    fn set_target_status(&self, status: NetworkMboxStatus) -> Result<()> {
        // Write target status with done bit set.
        self.regs
            .network_mbox_target_status
            .write(Self::status_to_target_status_field(status) + TargetStatusBits::Done::SET);

        // Transition back to RxWait.
        self.state.set(DriverState::RxWait);
        Ok(())
    }

    fn set_cmd_status(&self, status: NetworkMboxStatus) -> Result<()> {
        self.regs
            .network_mbox_cmd_status
            .write(Self::status_to_cmd_status_field(status));

        // If setting final status (Complete or Failure), transition back to RxWait.
        match status {
            NetworkMboxStatus::CmdComplete | NetworkMboxStatus::CmdFailure => {
                self.state.set(DriverState::RxWait);
            }
            _ => {}
        }
        Ok(())
    }

    fn max_sram_dw_size(&self) -> usize {
        self.regs.network_mbox_sram.len()
    }

    fn restore_rx_buffer(&self, rx_buf: &'static mut [u32]) {
        self.sram_ptr.set(Some(rx_buf.as_mut_ptr()));
    }

    fn enable(&self) {
        self.state.set(DriverState::RxWait);
    }

    fn disable(&self) {
        self.state.set(DriverState::Idle);
    }

    fn set_client(&self, client: &'a dyn NetworkMailboxClient) {
        self.client.set(Some(client));
    }
}
