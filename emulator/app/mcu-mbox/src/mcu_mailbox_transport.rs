// Licensed under the Apache-2.0 license

use emulator_consts::MCU_MAILBOX0_SRAM_SIZE;
use emulator_periph::McuMailbox0External;
use registers_generated::mci::bits::MboxExecute;
use tock_registers::interfaces::Readable;

#[derive(Clone)]
pub struct McuMailboxTransport {
    mbox: McuMailbox0External,
}

impl McuMailboxTransport {
    pub fn new(mbox: McuMailbox0External) -> Self {
        McuMailboxTransport { mbox }
    }

    pub fn execute(&self, cmd: u32, payload: &[u8]) -> Result<(), McuMailboxError> {
        if payload.len() > MCU_MAILBOX0_SRAM_SIZE as usize {
            return Err(McuMailboxError::Overflow);
        }

        // Sender attempts to lock mailbox by reading MBOX_LOCK register
        if self.mbox.regs.lock().unwrap().is_locked() {
            return Err(McuMailboxError::Locked);
        }
        self.mbox.regs.lock().unwrap().lock();

        // Sender writes data to MBOX_SRAM
        for (index, chunk) in payload.chunks(4).enumerate() {
            let mut padded = [0u8; 4];
            padded[..chunk.len()].copy_from_slice(chunk);
            let val = u32::from_le_bytes(padded);
            self.mbox
                .regs
                .lock()
                .unwrap()
                .write_mcu_mbox0_csr_mbox_sram(val, index);
        }

        // Sender writes data length in bytes to MBOX_DLEN
        self.mbox
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_dlen(payload.len() as u32);

        // Sender writes command to MBOX_CMD register
        self.mbox
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_cmd(cmd);

        // Sender writes 1 to MBOX_EXECUTE register
        // This generates MBOX*_CMD_AVAIL interrupt to MCU
        self.mbox
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_execute(caliptra_emu_bus::ReadWriteRegister::new(
                MboxExecute::Execute::SET.value,
            ));

        Ok(())
    }

    pub fn get_execute_response(&self) -> Result<McuMailboxResponse, McuMailboxError> {
        if !self.is_response_available() {
            return Err(McuMailboxError::Busy);
        }

        // Read the status code
        let status_code = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd_status();

        // Read the data from MBOX_SRAM
        let mut data = Vec::new();
        let len = self
            .mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_dlen();

        // Round up to the nearest multiple of 4 for dword alignment
        let dw_len = len.div_ceil(4) as usize;
        for i in 0..dw_len {
            let val = self
                .mbox
                .regs
                .lock()
                .unwrap()
                .read_mcu_mbox0_csr_mbox_sram(i);
            data.extend_from_slice(&val.to_le_bytes());
        }
        // Truncate to the actual data length
        data.truncate(len as usize);

        self.finalize();

        match status_code
            .reg
            .read(registers_generated::mci::bits::MboxCmdStatus::Status)
        {
            val if val
                == registers_generated::mci::bits::MboxCmdStatus::Status::CmdComplete.value =>
            {
                Ok(McuMailboxResponse {
                    status_code: status_code
                        .reg
                        .read(registers_generated::mci::bits::MboxCmdStatus::Status),
                    data,
                })
            }
            _ => {
                Err(McuMailboxError::StatusCode(status_code.reg.read(
                    registers_generated::mci::bits::MboxCmdStatus::Status,
                )))
            }
        }
    }

    pub fn is_response_available(&self) -> bool {
        self.mbox
            .regs
            .lock()
            .unwrap()
            .read_mcu_mbox0_csr_mbox_cmd_status()
            .reg
            .read(registers_generated::mci::bits::MboxCmdStatus::Status)
            != registers_generated::mci::bits::MboxCmdStatus::Status::CmdBusy.value
    }

    pub fn finalize(&self) {
        // Sender writes 0 to MBOX_EXECUTE to release the MBOX
        self.mbox
            .regs
            .lock()
            .unwrap()
            .write_mcu_mbox0_csr_mbox_execute(caliptra_emu_bus::ReadWriteRegister::new(
                MboxExecute::Execute::CLEAR.value,
            ));
    }
}

pub struct McuMailboxResponse {
    pub status_code: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum McuMailboxError {
    Busy,
    Locked,
    Timeout,
    Underflow,
    Overflow,
    NotInitialized,
    StatusCode(u32),
}
