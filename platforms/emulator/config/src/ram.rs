// Licensed under the Apache-2.0 license

pub use caliptra_mcu_config::ram::RamPartition;

pub const LOGGING_PARTITION: RamPartition = RamPartition {
    name: "logging_ram",
    size: 4096,
    driver_num: caliptra_mcu_config::LOGGING_RAM_DRIVER_NUM,
};

#[cfg(feature = "crash-log")]
pub const CRASH_LOG_PARTITION: RamPartition = RamPartition {
    name: "crash_log",
    size: 4096,
    driver_num: 0x9002_0001,
};

#[macro_export]
macro_rules! logging_ram_list {
    ($macro:ident) => {{
        $macro!(0, logging_ram, $crate::ram::LOGGING_PARTITION);
        #[cfg(feature = "crash-log")]
        $macro!(1, crash_log, $crate::ram::CRASH_LOG_PARTITION);
    }};
}

pub const LOGGING_RAM_INSTANCE_COUNT: usize = {
    let mut count: usize = 0;
    macro_rules! __count_logging_ram_entry {
        ($idx:expr, $_var:ident, $partition:path) => {
            count += 1;
        };
    }
    crate::logging_ram_list!(__count_logging_ram_entry);
    count
};

pub const LOGGING_RAM_DRIVER_NUMS: [u32; LOGGING_RAM_INSTANCE_COUNT] = {
    let mut nums = [0u32; LOGGING_RAM_INSTANCE_COUNT];
    macro_rules! __collect_logging_ram_driver_num {
        ($idx:expr, $_var:ident, $partition:path) => {
            nums[$idx] = $partition.driver_num;
        };
    }
    crate::logging_ram_list!(__collect_logging_ram_driver_num);
    nums
};
