// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

use mcu_rom_common::{McuRomBootStatus, RomEnv};
use registers_generated::i3c::bits::{
    DeviceStatus0::DevStatus,
    IndirectFifoCtrl0,
    IndirectFifoStatus0::{Empty, Full},
    RecIntfCfg::{self},
    RecIntfRegW1cAccess,
    RecoveryStatus::DevRecStatus,
};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

// Needed to bring in startup code
#[allow(unused)]
use mcu_test_harness;

// TODO(clundin): These constants should be pushed into library code.
const BYPASS_CFG_AXI_DIRECT: u32 = 0x1;
const DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE: u32 = 0x3;
const RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE: u32 = 0x1;
const RECOVERY_STATUS_SUCCESSFUL: u32 = 0x3;

// Write 16 KiB of data to fill Mailbox SRAM
const IMAGE_SIZE: u32 = 16 * 1024;

fn run() -> ! {
    let mut env = RomEnv::new();
    enable_bypass(&mut env);
    trigger_test_start(&mut env);

    wait_for_recovery_start(&mut env);
    wait_for_ready_for_recovery_image(&mut env);

    clear_recovery_registers(&mut env);

    let image_size_words = IMAGE_SIZE / 4;
    // Set recovery image size
    env.i3c_base
        .sec_fw_recovery_if_indirect_fifo_ctrl_1
        .set(image_size_words);

    let mut words_written = 0;
    for _ in 0..image_size_words {
        if env
            .i3c_base
            .sec_fw_recovery_if_indirect_fifo_status_0
            .is_set(Full)
        {
            // Back off when FIFO fills, otherwise a crash will occur.
            // Let Caliptra drain the FIFO before writing more.
            wait_for_empty_fifo(&mut env);
        }
        words_written += 1;
        env.i3c_base.tti_tx_data_port.set(0xFEEDCAFE);
    }
    // Let Caliptra clear the FIFO before we continue
    wait_for_empty_fifo(&mut env);
    assert_eq!(words_written, image_size_words);

    activate_recovery_image(&mut env);

    assert_eq!(
        wait_for_recovery_status(&mut env),
        RECOVERY_STATUS_SUCCESSFUL
    );
    loop {}
}

/// Enables
fn enable_bypass(env: &mut RomEnv) {
    env.i3c_base
        .soc_mgmt_if_rec_intf_cfg
        .modify(RecIntfCfg::RecIntfBypass.val(BYPASS_CFG_AXI_DIRECT));
}

// TODO(clundin): I imagine this should go in a re-usable place
fn trigger_test_start(env: &mut RomEnv) {
    let mci = &env.mci;

    // This is used to tell the hardware model it is ready to start testing
    mci.set_flow_milestone(McuRomBootStatus::CaliptraBootGoAsserted.into());
    mci.set_flow_milestone(McuRomBootStatus::ColdBootFlowComplete.into());

    mci.caliptra_boot_go();
    while !env.soc.ready_for_fuses() {}

    env.soc.fuse_write_done();
}

fn clear_recovery_registers(env: &mut RomEnv) {
    env.i3c_base
        .sec_fw_recovery_if_recovery_ctrl
        .set(0x00000000);
    env.i3c_base
        .sec_fw_recovery_if_indirect_fifo_ctrl_0
        .write(IndirectFifoCtrl0::Reset.val(0x1));
}

fn wait_for_recovery_start(env: &mut RomEnv) {
    loop {
        let device_status = env
            .i3c_base
            .sec_fw_recovery_if_device_status_0
            .read(DevStatus);
        if device_status == DEVICE_STATUS_READY_TO_ACCEPT_RECOVERY_IMAGE_VALUE {
            break;
        }
    }
}

fn wait_for_ready_for_recovery_image(env: &mut RomEnv) {
    loop {
        let recovery_status = env
            .i3c_base
            .sec_fw_recovery_if_recovery_status
            .read(DevRecStatus);
        if recovery_status == RECOVERY_STATUS_AWAITING_RECOVERY_IMAGE {
            break;
        }
    }
}

fn wait_for_empty_fifo(env: &mut RomEnv) {
    while !env
        .i3c_base
        .sec_fw_recovery_if_indirect_fifo_status_0
        .is_set(Empty)
    {}
}

fn activate_recovery_image(env: &mut RomEnv) {
    env.i3c_base
        .soc_mgmt_if_rec_intf_reg_w1_c_access
        .write(RecIntfRegW1cAccess::RecoveryCtrlActivateRecImg.val(0xF));
}

fn wait_for_recovery_status(env: &mut RomEnv) -> u32 {
    loop {
        let recovery_status = env.i3c_base.sec_fw_recovery_if_recovery_status.get();
        if recovery_status != 0 {
            return recovery_status;
        }
    }
}

#[no_mangle]
pub extern "C" fn main() {
    mcu_test_harness::set_printer();
    run();
}
