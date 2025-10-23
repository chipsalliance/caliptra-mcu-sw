// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

use mcu_rom_common::{McuBootMilestones, RomEnv};
use registers_generated::mci;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

// Needed to bring in startup code
#[allow(unused)]
use mcu_test_harness;

fn run() -> ! {
    let env = RomEnv::new();
    let mci = &env.mci;

    mci.registers
        .intr_block_rf_notif0_intr_en_r
        .modify(mci::bits::Notif0IntrEnT::NotifMbox0CmdAvailEn::SET);

    mci.caliptra_boot_go();

    // This is used to tell the hardware model it is ready to start testing
    mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());
    mci.set_flow_milestone(McuBootMilestones::FIRMWARE_BOOT_FLOW_COMPLETE.into());

    let mut replay_buf_len = 0;
    let mut replay_buf = [0u32; 2048];
    loop {
        let status = &mci.registers.mcu_mbox0_csr_mbox_cmd_status;
        let notif0 = &mci.registers.intr_block_rf_notif0_internal_intr_r;
        while notif0.read(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts) == 0 {
            // Wait for a request from the SoC.
        }
        notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
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
            // Returns a response of 7 hard-coded bytes
            0x1000_1000 => {
                dlen.set(7);
                sram[0].set(0x6745_2301);
                sram[1].set(0xefcd_ab89);

                status.write(mci::bits::MboxCmdStatus::Status::DataReady);
            }
            // Returns a response of 0 bytes
            0x1000_2000 => {
                dlen.set(0);
                status.write(mci::bits::MboxCmdStatus::Status::DataReady);
            }
            // Returns a success response
            0x2000_0000 => {
                status.write(mci::bits::MboxCmdStatus::Status::CmdComplete);
            }
            // Store a buf to be returned by 0x3000_0001
            0x3000_0000 => {
                let len = dlen.get();
                let len_words = usize::try_from((len + 3) / 4).unwrap();
                for i in 0..usize::min(len_words, replay_buf.len()) {
                    replay_buf[i] = sram[i].get();
                }
                replay_buf_len = u32::min(len, u32::try_from(replay_buf.len()).unwrap());
                status.write(mci::bits::MboxCmdStatus::Status::CmdComplete);
            }
            0x3000_0001 => {
                dlen.set(replay_buf_len);
                let dlen_words = usize::try_from((replay_buf_len + 3) / 4).unwrap();
                for i in 0..dlen_words {
                    sram[i].set(replay_buf[i]);
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

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
