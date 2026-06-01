// Licensed under the Apache-2.0 license

//! FPGA-only userspace integration test for the flash logging capsule.

#[cfg(feature = "fpga_realtime")]
#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams, TEST_LOCK};
    use crate::test_fpga_flash_ctrl::test::run_imaginary_flash_controller_service;
    use caliptra_mcu_hw_model::McuHwModel;
    use caliptra_mcu_testing_common::stop_emulator;
    use random_port::PortPicker;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_log_flash_usermode() {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let feature = "test-log-flash-usermode";
        let mut hw = start_runtime_hw_model(TestParams {
            feature: Some(feature),
            i3c_port: Some(PortPicker::new().random(true).pick().unwrap()),
            ..Default::default()
        });

        // The FPGA flash controller is serviced by a host-side thread over
        // the MCI mailbox; spawn it before userspace logging ops start.
        hw.start_i3c_controller();

        let mci_ptr = hw.base.mmio.mci().unwrap().ptr as u64;
        run_imaginary_flash_controller_service(mci_ptr);

        let test = finish_runtime_hw_model(&mut hw);
        stop_emulator();
        assert_eq!(0, test);

        // force the compiler to keep the lock
        lock.fetch_add(1, Ordering::Relaxed);
    }
}
