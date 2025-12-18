//! Licensed under the Apache-2.0 license

//! This module tests the imaginary flash controller on FPGA.

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
pub mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use mcu_hw_model::{flash_ctrl::ImaginaryFlashController, McuHwModel};
    use mcu_testing_common::wait_for_runtime_start;
    use mcu_testing_common::MCU_RUNNING;
    use random_port::PortPicker;
    use registers_generated::mci;
    use romtime::StaticRef;
    use std::process::exit;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    #[test]
    pub fn test_imaginary_flash_controller() {
        let feature = "test-fpga-flash-ctrl";
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);
        let feature = feature.replace("_", "-");

        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(&feature),
            i3c_port: Some(PortPicker::new().pick().unwrap()),
            ..Default::default()
        });

        hw.start_i3c_controller();

        let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;
        run_imaginary_flash_controller_service(mci_ptr);

        let test = finish_runtime_hw_model(&mut hw);

        MCU_RUNNING.store(false, Ordering::Relaxed);

        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }

    pub fn run_imaginary_flash_controller_service(mci_base: u64) {
        thread::spawn(move || {
            wait_for_runtime_start();
            if !MCU_RUNNING.load(Ordering::Relaxed) {
                exit(-1);
            }
            let mci_base = unsafe { StaticRef::new(mci_base as *const mci::regs::Mci) };

            let flash_controller = ImaginaryFlashController::new(
                mci_base,
                Some(std::path::PathBuf::from("imaginary_flash_test.bin")),
                None,
            );
            println!("Imaginary flash IO processor thread starting");
            loop {
                if !MCU_RUNNING.load(Ordering::Relaxed) {
                    break;
                }
                flash_controller.process_flash_ios();
                thread::sleep(Duration::from_millis(1));
            }
        });
    }
}
