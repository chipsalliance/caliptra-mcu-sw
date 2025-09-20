// Licensed under the Apache-2.0 license

use anyhow::Result;
use caliptra_hw_model::BootParams;
use caliptra_image_gen::to_hw_format;
use caliptra_image_types::FwVerificationPqcKeyType;
use mcu_builder::{FirmwareBinaries, PROJECT_ROOT};
use mcu_hw_model::{InitParams, McuHwModel, ModelFpgaRealtime};
use std::path::Path;
use std::time::Duration;

pub(crate) fn demo() -> Result<()> {
    if !Path::new("/dev/uio0").exists() {
        crate::fpga::fpga_install_kernel_modules(None)?;
    }

    const SLEEP_BETWEEN_DEMOS_SECS: Duration = Duration::from_secs(30);

    loop {
        println!("Restarting demos");
        std::thread::sleep(Duration::from_secs(5));
        boot_demo()?;
        std::thread::sleep(SLEEP_BETWEEN_DEMOS_SECS);
    }
}

fn boot_demo() -> Result<()> {
    println!("Starting boot demo");
    let zip = Some(PROJECT_ROOT.join("boot-demo.zip"));
    let binaries = FirmwareBinaries::read_from_zip(zip.as_ref().unwrap())?;
    let otp_memory = vec![];
    let steps = 1_000_000;

    let mut model = ModelFpgaRealtime::new_unbooted(InitParams {
        caliptra_rom: &binaries.caliptra_rom,
        caliptra_firmware: &binaries.caliptra_fw,
        mcu_rom: &binaries.mcu_rom,
        mcu_firmware: &binaries.mcu_runtime,
        soc_manifest: &binaries.soc_manifest,
        active_mode: true,
        otp_memory: Some(&otp_memory),
        vendor_pk_hash: binaries.vendor_pk_hash(),
        enable_mcu_uart_log: true,
        ..Default::default()
    })
    .unwrap();
    model.boot(BootParams {
        fuses: caliptra_api_types::Fuses {
            vendor_pk_hash: binaries
                .vendor_pk_hash()
                .map(|h| to_hw_format(&h))
                .unwrap_or([0u32; 12]),
            fuse_pqc_key_type: u8::from(FwVerificationPqcKeyType::LMS).into(),
            ..Default::default()
        },
        fw_image: Some(binaries.caliptra_fw.as_slice()),
        soc_manifest: Some(binaries.soc_manifest.as_slice()),
        mcu_fw_image: Some(binaries.mcu_runtime.as_slice()),
        ..Default::default()
    })?;

    for _ in 0..steps {
        model.step();
    }
    Ok(())
}
