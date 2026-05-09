// Licensed under the Apache-2.0 license

use registers_generated::mci;
use registers_generated::mci::bits::{MboxCmdStatus, MboxExecute, Notif0IntrTrigT};
use romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

const MCU_MAILBOX0_SRAM_SIZE: u32 = 4 * 1024; // MCU Mailbox0 SRAM size is 4KB on FPGA

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

pub struct McuMailboxTransport {
    mci: StaticRef<mci::regs::Mci>,
}

impl McuMailboxTransport {
    pub fn new(mci: StaticRef<mci::regs::Mci>) -> Self {
        McuMailboxTransport { mci }
    }

    pub fn execute(&self, cmd: u32, payload: &[u8]) -> Result<(), McuMailboxError> {
        if payload.len() > MCU_MAILBOX0_SRAM_SIZE as usize {
            return Err(McuMailboxError::Overflow);
        }
        // Wait until the mailbox is unlocked or timeout
        let mut retry = 1000;
        while self.mci.mcu_mbox0_csr_mbox_lock.get() != 0 {
            if retry == 0 {
                println!("Timeout waiting for MCU mailbox lock");
                return Err(McuMailboxError::Locked);
            }
            retry -= 1;
            // Optionally, add a small delay here if needed
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        self.mci.mcu_mbox0_csr_mbox_cmd.set(cmd);
        self.mci.mcu_mbox0_csr_mbox_dlen.set(payload.len() as u32);

        // Write the data to the mailbox SRAM in words
        let len_words = payload.len() / std::mem::size_of::<u32>();
        let word_bytes = &payload[..len_words * std::mem::size_of::<u32>()];
        for (i, word) in word_bytes.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(word.try_into().unwrap());
            self.mci.mcu_mbox0_csr_mbox_sram[i].set(word);
        }

        let remaining = &payload[word_bytes.len()..];
        if !remaining.is_empty() {
            let mut word_bytes = [0u8; 4];
            word_bytes[..remaining.len()].copy_from_slice(remaining);
            let word = u32::from_le_bytes(word_bytes);
            self.mci.mcu_mbox0_csr_mbox_sram[len_words].set(word);
        }

        // Ask the microcontroller to execute this command
        self.mci
            .mcu_mbox0_csr_mbox_execute
            .set(MboxExecute::Execute::SET.value);

        // Manually trigger the interrupt (the HW model doesn't always generate it).
        self.mci
            .intr_block_rf_notif0_intr_trig_r
            .modify(Notif0IntrTrigT::NotifMbox0CmdAvailTrig::SET);

        Ok(())
    }

    pub fn get_execute_response(&self) -> Result<McuMailboxResponse, McuMailboxError> {
        if !self.is_response_available() {
            return Err(McuMailboxError::Busy);
        }

        // Read the status code
        let status_code = self
            .mci
            .mcu_mbox0_csr_mbox_cmd_status
            .read(MboxCmdStatus::Status);
        let mut data = Vec::new();

        if status_code == MboxCmdStatus::Status::CmdComplete.value {
            // Read the data from MBOX_SRAM only if command is completed
            let len = self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize;

            let dw_len = len.div_ceil(4);
            for i in 0..dw_len {
                let val = self.mci.mcu_mbox0_csr_mbox_sram[i].get();
                data.extend_from_slice(&val.to_le_bytes());
            }
            data.truncate(len);
        }

        self.finalize();

        Ok(McuMailboxResponse { status_code, data })
    }

    fn is_response_available(&self) -> bool {
        self.mci
            .mcu_mbox0_csr_mbox_cmd_status
            .read(MboxCmdStatus::Status)
            != MboxCmdStatus::Status::CmdBusy.value
    }

    fn finalize(&self) {
        self.mci
            .mcu_mbox0_csr_mbox_execute
            .set(MboxExecute::Execute::CLEAR.value);
    }
}
