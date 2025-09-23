// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

use mcu_rom_common::{McuRomBootStatus, RomEnv};
use registers_generated::{
    i3c::bits::{
        DeviceStatus0::DevStatus,
        IndirectFifoStatus0::{Empty, Full},
        RecIntfCfg::{self, RecPayloadDone},
        RecoveryCtrl::{self, ActivateRecImg},
        RecoveryStatus::DevRecStatus,
    },
    mci,
};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

// Needed to bring in startup code
#[allow(unused)]
use mcu_test_harness;

/// Enable bit for AXI Bypass
const BYPASS_CFG_AXI_DIRECT: u32 = 0x1;
const RECOVERY_STATUS_SUCCESSFUL: u32 = 0x3;
const TEST_MAGIC_COMPLETE: u32 = 0xABFE;

fn run() -> ! {
    let mut env = RomEnv::new();
    let mci = &env.mci;
    romtime::println!("[mcu-rom] Hello from test");

    env.i3c.configure(0x3a, true);

    // This is used to tell the hardware model it is ready to start testing
    mci.set_flow_status(McuRomBootStatus::CaliptraBootGoAsserted.into());
    mci.set_flow_status(McuRomBootStatus::ColdBootFlowComplete.into());

    mci.caliptra_boot_go();
    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
        env.soc.ready_for_fuses()
    );
    while !env.soc.ready_for_fuses() {}

    env.soc.fuse_write_done();

    romtime::println!("[mcu-rom] Running bypass flow");
    env.i3c_base
        .soc_mgmt_if_rec_intf_cfg
        .modify(RecIntfCfg::RecIntfBypass.val(BYPASS_CFG_AXI_DIRECT));

    romtime::println!("[mcu-rom] Polling device status");
    let mut i = 0;
    loop {
        let device_status = env
            .i3c_base
            .sec_fw_recovery_if_device_status_0
            .read(DevStatus);
        if i % 100000 == 0 {
            romtime::println!("[mcu-rom] still polling");
            romtime::println!("[mcu-rom] Device status: {}", device_status);
        }
        if device_status == 3 {
            romtime::println!("[mcu-rom] Breaking, Device status: {}", device_status);
            break;
        }
        i += 1;
    }

    let mut i = 0;
    loop {
        let recovery_status = env
            .i3c_base
            .sec_fw_recovery_if_recovery_status
            .read(DevRecStatus);
        if i % 100000 == 0 {
            romtime::println!("[mcu-rom] still polling");
            romtime::println!("[mcu-rom] Recovery status: {}", recovery_status);
        }
        if recovery_status == 0x1 {
            romtime::println!("[mcu-rom] Breaking, Recovery status: {}", recovery_status);
            break;
        }
        i += 1;
    }
    env.i3c_base
        .sec_fw_recovery_if_recovery_ctrl
        .set(0x00000000);
    env.i3c_base
        .sec_fw_recovery_if_indirect_fifo_ctrl_0
        .set(0x00000100);
    romtime::println!("[mcu-rom] wrote fifo ctrl0");
    // 4 KiB in words
    let image_size = (4 * 1024) / 4;
    env.i3c_base
        .sec_fw_recovery_if_indirect_fifo_ctrl_1
        .set(image_size);
    let fifo_1 = env.i3c_base.sec_fw_recovery_if_indirect_fifo_ctrl_1.get();
    romtime::println!("[mcu-rom] wrote fifo ctrl1: {}", fifo_1);
    let prot_cap0 = env.i3c_base.sec_fw_recovery_if_prot_cap_0.get();
    romtime::println!("[mcu-rom] prot_cap0: 0x{:x}", prot_cap0);
    if prot_cap0 != 0x2050434f {
        romtime::println!("[mcu-rom] prot_cap0: wrong state");
    } else {
        romtime::println!("[mcu-rom] prot_cap0: OK");
    }
    let prot_cap1 = env.i3c_base.sec_fw_recovery_if_prot_cap_1.get();
    if prot_cap1 != 0x56434552 {
        romtime::println!("[mcu-rom] prot_cap1: wrong state");
    } else {
        romtime::println!("[mcu-rom] prot_cap1: OK");
    }
    romtime::println!("[mcu-rom] prot_cap1: 0x{:x}", prot_cap1);
    let mut i = 0;
    let mut words_written = 0;
    for _ in 0..image_size {
        while env
            .i3c_base
            .sec_fw_recovery_if_indirect_fifo_status_0
            .is_set(Full)
        {
            if i % 100000 == 0 {
                romtime::println!("[mcu-rom] Fifo is full. Wrote {} words", words_written);
            }
            i += 1;
        }
        i = 0;
        words_written += 1;
        env.i3c_base.tti_tx_data_port.set(0xFEEDCAFE);
    }
    romtime::println!("[mcu-rom] Wrote {} words", words_written);
    romtime::println!("[mcu-rom] Setting payload done");
    env.i3c_base.soc_mgmt_if_rec_intf_cfg.write(RecPayloadDone.val(0x01));


   let empty = env
        .i3c_base
        .sec_fw_recovery_if_indirect_fifo_status_0.is_set(Empty);
    if empty {
        romtime::println!("[mcu-rom] FIFO status 0: empty");
    } else {
        romtime::println!("[mcu-rom] FIFO status 0: not empty");
    }

    romtime::println!("[mcu-rom] Done writing bypass");

    let mut i = 0;
    romtime::println!("[mcu-rom] Activating image");
    loop {
        let recovery_status = env.i3c_base.sec_fw_recovery_if_recovery_status.get();
        let device_status = env
            .i3c_base
            .sec_fw_recovery_if_device_status_0
            .read(DevStatus);
        env.i3c_base
            .soc_mgmt_if_rec_intf_reg_w1_c_access
            .set(0x00000F00);
         // env.i3c_base
         //     .sec_fw_recovery_if_recovery_ctrl
         //    .set(0x00000F00);

        if i % 1000000 == 0 {
            romtime::println!("[mcu-rom] still polling");
            romtime::println!("[mcu-rom] Reccovery status: {}", recovery_status);
            romtime::println!("[mcu-rom] Device status: {}", device_status);
        }
        // env.i3c_base
        // .sec_fw_recovery_if_recovery_ctrl
        // .set(0x00000F00);
        // env.i3c_base.sec_fw_recovery_if_recovery_ctrl.write(ActivateRecImg.val(0xF));
        // env.i3c_base
        //     .sec_fw_recovery_if_recovery_ctrl
        //     .modify(RecoveryCtrl::ActivateRecImg.val(0xF));
        // }
        if recovery_status == 3 {
            romtime::println!("[mcu-rom] Breaking, Recovery status: {}", recovery_status);
            break;
        }
        i += 1;
    }
    // assert_eq!(recovery_status, RECOVERY_STATUS_SUCCESSFUL);
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
