// Licensed under the Apache-2.0 license

use mcu_config::flash::FlashPartition;

pub const DRIVER_NUM_EMULATED_FLASH_CTRL: usize = 0x8000_0012;
pub const BLOCK_SIZE: usize = 64 * 1024;

pub const STAGING_PARTITION: FlashPartition = FlashPartition {
    name: "staging_par",
    offset: 0x0000_0000,
    size: (BLOCK_SIZE * 0x200),
    driver_num: DRIVER_NUM_EMULATED_FLASH_CTRL as u32,
};

#[macro_export]
macro_rules! flash_partition_list_imaginary_flash {
    ($macro:ident) => {{
        $macro!(0, staging_par, STAGING_PARTITION);
    }};
}
