// Licensed under the Apache-2.0 license

use caliptra_mcu_config::flash::FlashPartition;

pub const DRIVER_NUM_EMULATED_FLASH_CTRL: usize = 0x8000_0012;
pub const BLOCK_SIZE: usize = 64 * 1024;

pub const STAGING_PARTITION: FlashPartition = FlashPartition {
    name: "staging_par",
    offset: 0x0000_0000,
    size: (BLOCK_SIZE * 0x200),
    driver_num: DRIVER_NUM_EMULATED_FLASH_CTRL as u32,
};

pub const EMULATED_EXT_OTP_PARTITION: FlashPartition = FlashPartition {
    name: "emulated_ext_otp",
    offset: STAGING_PARTITION.offset + STAGING_PARTITION.size,
    size: (BLOCK_SIZE * 0x8),
    driver_num: 0x7000_000B,
};

#[macro_export]
macro_rules! flash_partition_list_imaginary_flash {
    ($macro:ident) => {{
        $macro!(0, staging_par, STAGING_PARTITION);
    }};
}

pub const LOGGING_PARTITION: FlashPartition = FlashPartition {
    name: "logging",
    offset: 0x03FF_8000,
    size: 32 * 1024,
    driver_num: 0x9001_0000,
};

#[cfg(feature = "crash-log")]
pub const CRASH_LOG_PARTITION: FlashPartition = FlashPartition {
    name: "crash_log",
    offset: 0x03FF_0000,
    size: 32 * 1024,
    driver_num: 0x9001_0001,
};

#[macro_export]
macro_rules! logging_flash_list {
    ($macro:ident) => {{
        $macro!(0, logging, LOGGING_PARTITION);
        #[cfg(feature = "crash-log")]
        $macro!(1, crash_log, CRASH_LOG_PARTITION);
    }};
}

// Number of logging-flash instances exposed from logging_flash_list!
pub const LOGGING_FLASH_INSTANCE_COUNT: usize = {
    let mut count: usize = 0;
    macro_rules! __count_logging_flash_entry {
        ($idx:expr, $_var:ident, $name:ident) => {
            count += 1;
        };
    }
    crate::logging_flash_list!(__count_logging_flash_entry);
    count
};

// Driver number for each logging-flash instance, sourced from each partition's driver_num field.
pub const LOGGING_FLASH_DRIVER_NUMS: [u32; LOGGING_FLASH_INSTANCE_COUNT] = {
    let mut nums = [0u32; LOGGING_FLASH_INSTANCE_COUNT];
    macro_rules! __collect_logging_flash_driver_num {
        ($idx:expr, $_var:ident, $partition:ident) => {
            nums[$idx] = $partition.driver_num;
        };
    }
    crate::logging_flash_list!(__collect_logging_flash_driver_num);
    nums
};
