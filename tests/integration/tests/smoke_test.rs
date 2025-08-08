// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use mcu_builder::FirmwareBinaries;
use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel, McuManager};

#[test]
fn reg_access_test() {
    let firmware_bundle = FirmwareBinaries::from_env().unwrap();
    let mut hw = DefaultHwModel::new_unbooted(InitParams {
        caliptra_rom: &firmware_bundle.caliptra_rom,
        caliptra_firmware: &firmware_bundle.caliptra_fw,
        mcu_rom: &firmware_bundle.mcu_rom,
        mcu_firmware: &firmware_bundle.mcu_runtime,
        soc_manifest: &firmware_bundle.soc_manifest,
        active_mode: true,
        ..Default::default()
    })
    .unwrap();

    // Check Caliptra reports 2.x
    assert_eq!(
        u32::from(hw.caliptra_soc_manager().soc_ifc().cptra_hw_rev_id().read()),
        2
    );

    let mut mcu_mgr = hw.mcu_manager();

    // // Check the I3C periph reports the right HCI version
    // assert_eq!(mcu_mgr.i3c().i3c_base().hci_version().read(), 0x120);

    // Check the MCU HW generation reports 1.0.0
    assert_eq!(mcu_mgr.mci().hw_rev_id().read().mc_generation(), 0x1000);

    // // Check the MBOX periph reports lock when reading the register
    // assert_eq!(mcu_mgr.mbox0().mbox_lock().read().lock(), false);

    // // Check the MBOX periph reports lock when reading the register
    // assert_eq!(mcu_mgr.mbox1().mbox_lock().read().lock(), false);

    // Check the OTP periph reports idle
    assert!(mcu_mgr.otp_ctrl().status().read().dai_idle());

    // Check the LC periph reports revision 0
    // assert_eq!(u32::from(mcu_mgr.lc_ctrl().hw_revision0().read()), 0x0);
}
