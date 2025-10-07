use emulator_mcu_mbox::mm_flash_ctrl::ImaginaryFlashController;
use emulator_periph::McuMailbox0External;
use std::thread;
use std::time::Duration;

use mcu_testing_common::{wait_for_runtime_start, MCU_RUNNING};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::Ordering;
use std::thread::sleep;
use zerocopy::IntoBytes;

pub fn run_mm_flash_ctrl_task(
    mbox: McuMailbox0External,
    file_name: Option<PathBuf>,
    initial_content: Option<&[u8]>,
) {
    let ctrl = ImaginaryFlashController::new(mbox, file_name, initial_content);
    println!("[xs debug]Emulator: entering run_mm_flash_ctrl_task");
    thread::spawn(move || {
        // wait for runtime start
        //wait_for_runtime_start();
        //if !MCU_RUNNING.load(Ordering::Relaxed) {
        //    exit(-1);
        // }
        println!("[xs debug]Emulator: MCU_MBOX_FLASH_CTRL Thread Starting: ");
        loop {
            ctrl.poll_mailbox_and_process();
            thread::sleep(Duration::from_millis(1));
        }
    });
}
