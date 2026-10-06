// Licensed under the Apache-2.0 license

//! Integration tests for the `RomParameters::debug_enablement_masks` ROM
//! parameter.
//!
//! The ROM programs the MCI `SOC_DFT_EN`, `SOC_HW_DEBUG_EN` and
//! `SOC_PROD_DEBUG_STATE` registers during fuse population, before it locks
//! MCI configuration. Both tests boot to the runtime and then read the six
//! words back through the host-accessible MCI register block, which works
//! uniformly on the emulator and the FPGA:
//!
//! 1. The default ROM leaves the parameter `None`, so the registers must hold
//!    `DebugEnablementMasks::REFERENCE` (all eight debug levels enabled).
//! 2. The ROM built with the `test-debug-enablement-masks` feature passes a
//!    distinct value, which must land in the registers unchanged.

#[cfg(test)]
mod test {
    use crate::test::{start_runtime_hw_model, TestParams, TEST_LOCK};
    use caliptra_mcu_hw_model::{McuHwModel, McuManager};
    use std::sync::atomic::Ordering;

    /// `[SOC_DFT_EN, SOC_HW_DEBUG_EN, SOC_PROD_DEBUG_STATE]`, two words each.
    type Masks = [[u32; 2]; 3];

    /// `DebugEnablementMasks::REFERENCE`: all eight levels in every register.
    const REFERENCE_MASKS: Masks = [[0x0000_00FF, 0x0000_0000]; 3];

    /// What the `test-debug-enablement-masks` feature passes in both platform
    /// ROMs (`platforms/{emulator,fpga}/rom/src/riscv.rs`). Keep in sync.
    const FEATURE_MASKS: Masks = [
        [0x0000_0001, 0x0000_0000],
        [0x0000_0003, 0x0000_0000],
        [0x0000_0007, 0x0000_0001],
    ];

    fn read_masks(hw: &mut impl McuHwModel) -> Masks {
        let mut mgr = hw.mcu_manager();
        let mci = mgr.mci();
        [
            [mci.soc_dft_en().at(0).read(), mci.soc_dft_en().at(1).read()],
            [
                mci.soc_hw_debug_en().at(0).read(),
                mci.soc_hw_debug_en().at(1).read(),
            ],
            [
                mci.soc_prod_debug_state().at(0).read(),
                mci.soc_prod_debug_state().at(1).read(),
            ],
        ]
    }

    /// Boots the ROM (built with `rom_feature`, if any) all the way to the
    /// runtime, so fuse population and the MCI configuration lock have both
    /// happened, then returns the mask registers.
    fn boot_and_read_masks(rom_feature: Option<&str>) -> Masks {
        let lock = TEST_LOCK.lock().unwrap();
        lock.fetch_add(1, Ordering::Relaxed);

        let mut hw = start_runtime_hw_model(TestParams {
            rom_feature,
            rom_only: false,
            ..Default::default()
        });
        assert_eq!(hw.mci_fw_fatal_error(), None, "ROM hit fatal error");

        let masks = read_masks(&mut hw);
        println!("debug enablement masks = {masks:08x?}");

        lock.fetch_add(1, Ordering::Relaxed);
        masks
    }

    #[test]
    fn test_debug_enablement_masks_default() {
        assert_eq!(boot_and_read_masks(None), REFERENCE_MASKS);
    }

    #[test]
    fn test_debug_enablement_masks_parameter() {
        assert_eq!(
            boot_and_read_masks(Some("test-debug-enablement-masks")),
            FEATURE_MASKS
        );
    }
}
