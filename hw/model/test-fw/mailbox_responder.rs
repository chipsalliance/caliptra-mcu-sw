// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

use mcu_rom_common::{McuBootMilestones, McuRomBootStatus, RomEnv};
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
    // TODO: remove the checkpoints when the HW model supports milestones
    mci.set_flow_checkpoint(McuRomBootStatus::CaliptraBootGoAsserted.into());
    mci.set_flow_checkpoint(McuRomBootStatus::ColdBootFlowComplete.into());
    mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());
    mci.set_flow_milestone(McuBootMilestones::COLD_BOOT_FLOW_COMPLETE.into());

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
