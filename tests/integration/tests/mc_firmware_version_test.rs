// Licensed under the Apache-2.0 license

use caliptra_hw_model::BootParams;
use mcu_builder::FirmwareBinaries;
use mcu_hw_model::McuManager;
use mcu_hw_model::{new, InitParams, McuHwModel};

#[test]
fn mc_firmware_version_test() {
    #![cfg_attr(not(feature = "fpga_realtime"), ignore)]

    let binaries = FirmwareBinaries::from_env().unwrap();
    let mut hw = new(
        InitParams {
            caliptra_rom: &binaries.caliptra_rom,
            mcu_rom: &binaries.mcu_rom,
            vendor_pk_hash: binaries.vendor_pk_hash(),
            active_mode: true,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&binaries.caliptra_fw),
            soc_manifest: Some(&binaries.soc_manifest),
            mcu_fw_image: Some(&binaries.mcu_runtime),
            ..Default::default()
        },
    )
    .unwrap();

    let mut mcu = hw.mcu_manager();
    let mbox = mcu.mbox0();

    assert_eq!(mbox.mbox_lock().read().lock(), false);
    assert_eq!(mbox.mbox_lock().read().lock(), true);

    mbox.mbox_cmd().write(|_| 0x4D46_5756);
    mbox.mbox_dlen().write(|_| 0);
    mbox.mbox_execute().write(|w| w.execute(true));

    while mbox.mbox_cmd_status().read().status().cmd_busy() {}
    assert_eq!(mbox.mbox_cmd_status().read().status().cmd_complete(), true);
    assert_eq!(mbox.mbox_cmd_status().read().status().cmd_failure(), false);
    assert_eq!(mbox.mbox_cmd_status().read().status().data_ready(), true);
    assert_eq!(mbox.mbox_cmd_status().read().status().cmd_busy(), false);
}
