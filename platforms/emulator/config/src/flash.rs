// Licensed under the Apache-2.0 license

use mcu_config::flash::FlashPartition;

pub use partition_table::{
    prepare_dual_write, parse_partition_table, select_partition_table,
    ChecksumCalculator, PartitionId, PartitionStatus, PartitionTable,
    RollbackEnable, StandAloneChecksumCalculator,
};

pub const FLASH_PARTITIONS_COUNT: usize = 4; // Number of flash partitions

// Allocate driver numbers for flash partitions
pub const DRIVER_NUM_START: usize = 0x7000_0006; // Base driver number for flash partitions
pub const DRIVER_NUM_END: usize = 0x7000_0009; // End driver number for flash partitions

pub const BLOCK_SIZE: usize = 64 * 1024; // Block size for flash partitions

pub const PARTITION_TABLE_COPY_0_OFFSET: usize = 0;
pub const PARTITION_TABLE_COPY_1_OFFSET: usize = BLOCK_SIZE / 2;

pub const PARTITION_TABLE: FlashPartition = FlashPartition {
    name: "partition_table",
    offset: 0x00000000,
    size: BLOCK_SIZE,
    driver_num: 0x7000_0008,
};

pub const IMAGE_A_PARTITION: FlashPartition = FlashPartition {
    name: "image_a",
    offset: BLOCK_SIZE,
    size: (BLOCK_SIZE * 0x20),
    driver_num: 0x7000_0006,
};

pub const IMAGE_B_PARTITION: FlashPartition = FlashPartition {
    name: "image_b",
    offset: 0x00000000,
    size: (BLOCK_SIZE * 0x10),
    driver_num: 0x7000_0007,
};

pub const STAGING_PARTITION: FlashPartition = FlashPartition {
    name: "staging",
    offset: IMAGE_B_PARTITION.offset + IMAGE_B_PARTITION.size,
    size: (BLOCK_SIZE * 0x10),
    driver_num: 0x7000_0009,
};

#[macro_export]
macro_rules! flash_partition_list_primary {
    ($macro:ident) => {{
        $macro!(0, image_a, IMAGE_A_PARTITION);
        $macro!(1, partition_table, PARTITION_TABLE);
    }};
}

#[macro_export]
macro_rules! flash_partition_list_secondary {
    ($macro:ident) => {{
        $macro!(2, image_b, IMAGE_B_PARTITION);
        $macro!(3, staging, STAGING_PARTITION);
    }};
}

/// Map the active partition in a [`PartitionTable`] to the platform-specific
/// [`FlashPartition`] constant.
pub fn get_active_partition(
    pt: &PartitionTable,
) -> (PartitionId, Option<&'static FlashPartition>) {
    let id = pt.get_active_partition_id();
    let partition = match id {
        PartitionId::A => Some(&IMAGE_A_PARTITION),
        PartitionId::B => Some(&IMAGE_B_PARTITION),
        _ => None,
    };
    (id, partition)
}

// Logging flash configuration for emulator platform
#[derive(Debug, Clone, Copy)]
pub struct LoggingFlashConfig {
    pub logging_flash_size: u32,
    pub logging_flash_offset: u32,
    pub base_addr: u32, // Base address of the logging flash.
    pub page_size: u32, // Flash page size in bytes.
}

impl LoggingFlashConfig {
    // 128KB at the end of the 64MB primary flash is reserved for logging.
    // Offset is calculated as: emulator_consts::DIRECT_READ_FLASH_ORG + emulator_consts::DIRECT_READ_FLASH_SIZE - 128 * 1024.
    // This region must not overlap with any other flash partitions.
    pub const fn default() -> Self {
        Self {
            logging_flash_offset: 0x3BFE_0000,
            logging_flash_size: 128 * 1024,
            base_addr: 0x3800_0000,
            page_size: 256,
        }
    }
}

pub const LOGGING_FLASH_CONFIG: LoggingFlashConfig = LoggingFlashConfig::default();
