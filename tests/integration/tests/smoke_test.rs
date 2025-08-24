// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use mcu_builder::FirmwareBinaries;
use mcu_hw_model::{new, BootParams, InitParams, McuHwModel, McuManager};

#[test]
fn reg_access_test() {
    let binaries = FirmwareBinaries::from_env().unwrap();
    let mut hw = new(
        InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            caliptra_firmware: &binaries.caliptra_fw,
            mcu_rom: &binaries.mcu_rom,
            mcu_firmware: &binaries.mcu_runtime,
            soc_manifest: &binaries.soc_manifest,
            vendor_pk_hash: binaries.vendor_pk_hash(),
            active_mode: true,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    // Check Caliptra reports 2.x
    assert_eq!(
        u32::from(hw.caliptra_soc_manager().soc_ifc().cptra_hw_rev_id().read()),
        2
    );

    let mut mcu_mgr = hw.mcu_manager();

    // // Check the I3C periph reports the right HCI version
    assert_eq!(mcu_mgr.i3c().i3c_base().hci_version().read(), 0x120);

    // Check the MCU HW generation reports 1.0.0
    assert_eq!(mcu_mgr.mci().hw_rev_id().read().mc_generation(), 0x1000);

    // Check the OTP periph reports idle
    assert!(mcu_mgr.otp_ctrl().status().read().dai_idle());

    // TODO: Check the LC periph reports correct revision
    // assert_eq!(u32::from(mcu_mgr.lc_ctrl().hw_revision0().read()), 0x0);
}
