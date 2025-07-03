// Licensed under the Apache-2.0 license
pub mod flash_boot_cfg;
pub mod flash_drv;

#[cfg(any(
    feature = "test-mcu-rom-flash-access",
    feature = "test-flash-based-boot"
))]
pub mod flash_test;
