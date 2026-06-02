// Licensed under the Apache-2.0 license

#[cfg(test)]
mod test {
    use crate::test::{finish_runtime_hw_model, start_runtime_hw_model, TestParams};
    use caliptra_mcu_hw_model::{
        DeviceLifecycle, LifecycleControllerState, McuHwModel, McuManager,
    };
    use caliptra_mcu_testing_common::MCU_RUNNING;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_raw_lifecycle_boot() {
        // Instantiate hardware model with Caliptra in Raw lifecycle state.
        let mut hw = start_runtime_hw_model(TestParams {
            lifecycle_controller_state: Some(LifecycleControllerState::Raw),
            ..Default::default()
        });

        // Verify the LC state is Raw.
        let lc_state = hw.mcu_manager().with_lc(|lc| lc.lc_state().read().state());
        assert_eq!(
            lc_state,
            LifecycleControllerState::Raw.mnemonic(),
            "LC state should be Raw"
        );

        // Verify the lifecycle state translate to the expected security state
        // in the MCI registers.
        //
        // The lifecycle state is in bits [1:0] of security_state for MCU 2.0
        // Unprovisioned = 0, Manufacturing = 1, Production = 3.
        //
        // When the test completes, it reports the chip is in the Production security state (3)
        // on both the Emulator and FPGA, because the chip security state is latched at reset deassertion
        // and is not unlocked by the SoC (via SS_SOC_DBG_UNLOCK_LEVEL).
        let expected_lifecycle = DeviceLifecycle::Production;

        let security_state = hw.mcu_manager().with_mci(|mci| mci.security_state().read());
        let lifecycle = security_state.device_lifecycle();
        println!("MCI Security State: 0x{:08x}", u32::from(security_state));
        println!("Detected Lifecycle (u32): {}", u32::from(lifecycle));
        assert_eq!(
            u32::from(lifecycle),
            u32::from(expected_lifecycle),
            "Lifecycle should be Production"
        );

        MCU_RUNNING.store(false, Ordering::Relaxed);

        // Exit the test.
        let status = finish_runtime_hw_model(&mut hw);
        assert_eq!(status, 0);
    }
}
