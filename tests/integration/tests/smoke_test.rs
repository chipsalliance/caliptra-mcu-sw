// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use mcu_hw_model::{DefaultHwModel, InitParams, McuHwModel};

#[test]
fn smoke() {
    let caliptra_rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();
    let mcu_rom = mcu_builder::rom_build(None, "").unwrap();
    let mut hw = DefaultHwModel::new_unbooted(InitParams {
        caliptra_rom: &caliptra_rom,
        mcu_rom: mcu_rom.as_bytes(),
        active_mode: true,
        ..Default::default()
    })
    .unwrap();

    let mut cptra_soc_mgr = hw.caliptra_soc_manager();
    let soc_ifc = cptra_soc_mgr.soc_ifc();

    // Check Caliptra reports 2.x
    assert_eq!(u32::from(soc_ifc.cptra_hw_rev_id().read()), 2);
}
