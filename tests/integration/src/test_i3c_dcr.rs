// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use caliptra_mcu_rom_common::MCTP_DCR;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_rom_programs_main_i3c_target_mctp_dcr() {
        let lock = TEST_LOCK.lock().unwrap();
        let mut hw = start_runtime_hw_model(TestParams {
            rom_only: true,
            ..Default::default()
        });

        hw.step_until_output_contains("[mcu-rom-i3c] Enable the target transaction interface")
            .expect("ROM did not finish configuring the main I3C target DCR");
        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        let mut mcu = hw.mcu_manager();
        let i3c = mcu.i3c();
        assert_eq!(
            i3c.stdby_ctrl_mode().stby_cr_device_char().read().dcr(),
            u32::from(MCTP_DCR),
            "main I3C target must advertise the MCTP DCR"
        );

        lock.fetch_add(1, Ordering::Relaxed);
    }
}
