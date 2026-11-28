// Licensed under the Apache-2.0 license

use caliptra_mcu_config::ram::RamPartition;

pub const LOGGING_PARTITION: RamPartition = RamPartition {
    name: "logging_ram",
    size: 4096,
    driver_num: caliptra_mcu_config::LOGGING_RAM_DRIVER_NUM,
};
