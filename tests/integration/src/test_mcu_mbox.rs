//! Licensed under the Apache-2.0 license

//! This module tests the PLDM Firmware Update

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use std::thread;

    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TEST_LOCK};

    use chrono::Duration as ChronoDuration;
    use std::time::Duration;
    use mcu_hw_model::{McuHwModel, mm_flash_ctrl::ImaginaryFlashController};
    use registers_generated::mci;
    use romtime::StaticRef;

    #[test]
    pub fn test_mcu_mbox0() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(None, Some(65534));

        hw.start_i3c_controller();

        let mci_ptr = hw.base.mci.ptr as u64;

        thread::spawn(move || {
            // wait for runtime start
            //wait_for_runtime_start();
            //if !MCU_RUNNING.load(Ordering::Relaxed) {
            //    exit(-1);
            // }
            let mci_base= unsafe {
                StaticRef::new(mci_ptr as *const mci::regs::Mci)
            };            
          
            let flash_controller = ImaginaryFlashController::new(
                mci_base, Some(std::path::PathBuf::from("imaginary_flash.bin")), None);            
            println!("[xs debug]Emulator: MCU_MBOX_FLASH_CTRL Thread Starting: ");
            loop {
                flash_controller.poll_mailbox_and_process();
                thread::sleep(Duration::from_millis(1));
            }
        });        


        let test = finish_runtime_hw_model(&mut hw);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

}
