// Licensed under the Apache-2.0 license

mod usb_driver_tests;
mod usb_phy_tests;
mod usb_recovery_tests;
mod usb_rom_recovery_tests;
#[cfg(target_os = "linux")]
mod usbip_tests;

fn test_rom(feature: &str) -> anyhow::Result<Vec<u8>> {
    use anyhow::ensure;
    use caliptra_mcu_builder::{rom_build, CaliptraBuildArgs, FirmwareBinaries};

    let rom = if std::env::var_os("CPTRA_FIRMWARE_BUNDLE").is_some() {
        let binaries = FirmwareBinaries::from_env()?;
        ensure!(
            binaries.has_test_feature_rom(feature),
            "firmware bundle is missing required USB ROM feature {feature}"
        );
        binaries.test_feature_rom(feature)
    } else {
        std::fs::read(rom_build(&CaliptraBuildArgs {
            features: Some(feature),
            ..Default::default()
        })?)?
    };
    ensure!(!rom.is_empty(), "USB ROM feature {feature} is empty");
    Ok(rom)
}
