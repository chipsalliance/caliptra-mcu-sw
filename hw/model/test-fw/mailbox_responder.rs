// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

use mcu_config::McuMemoryMap;
use mcu_rom_common::{McuRomBootStatus, RomEnv};
use registers_generated::mci;
use tock_registers::interfaces::{Readable, Writeable};

// re-export these so the common ROM can use it
#[cfg(feature = "fpga_realtime")]
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_fpga::FPGA_MEMORY_MAP;
#[cfg(not(feature = "fpga_realtime"))]
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_emulator::EMULATOR_MEMORY_MAP;

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

#[no_mangle]
pub extern "C" fn main() {
    let env = RomEnv::new();
    let mci = env.mci;

    mci.set_flow_status(McuRomBootStatus::CaliptraBootGoAsserted.into());

    loop {
        let status = &mci.registers.mcu_mbox0_csr_mbox_cmd_status;
        while mci.registers.mcu_mbox0_csr_mbox_execute.get() == 0 {
            // Wait for a request from the SoC.
        }
        let cmd = mci.registers.mcu_mbox0_csr_mbox_cmd.get();

        let dlen = &mci.registers.mcu_mbox0_csr_mbox_dlen;
        let sram = &mci.registers.mcu_mbox0_csr_mbox_sram;
        match cmd {
            // Consumes input, and echoes the request back as the response with
            // the command-id prepended.
            0x1000_0000 => {
                let len = dlen.get();
                let len_words = usize::try_from((len + 3) / 4).unwrap();
                let mut buf = [0u32; 8];
                for i in 0..len_words {
                    buf[i] = sram[i].get();
                }
                dlen.set(len + 4);
                sram[0].set(cmd);
                for i in 0..len_words {
                    sram[i + 1].set(buf[i]);
                }
                status.write(mci::bits::MboxCmdStatus::Status::DataReady);
            }
            // Everything else returns a failure response; doesn't consume input.
            _ => {
                status.write(mci::bits::MboxCmdStatus::Status::CmdFailure);
            }
        }
    }
}
