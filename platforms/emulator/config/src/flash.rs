// Licensed under the Apache-2.0 license

use core::mem::offset_of;
use mcu_config::boot::{PartitionId, PartitionStatus, RollbackEnable};
use mcu_config::flash::FlashPartition;
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const FLASH_PARTITIONS_COUNT: usize = 4; // Number of flash partitions

// Allocate driver numbers for flash partitions
pub const DRIVER_NUM_START: usize = 0x7000_0006; // Base driver number for flash partitions
pub const DRIVER_NUM_END: usize = 0x7000_0009; // End driver number for flash partitions

pub const BLOCK_SIZE: usize = 64 * 1024; // Block size for flash partitions

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

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq, Default)]
#[repr(C, packed)]
pub struct PartitionTable {
    pub active_partition: u32,       // Valid values defined in PartitionId
    pub partition_a_boot_count: u16, // Boot count for partition A
    pub partition_a_status: u16,     // Valid values defined in PartitionStatus
    pub partition_b_boot_count: u16, // Boot count for partition A
    pub partition_b_status: u16,     // Valid values defined in PartitionStatus
    pub rollback_enable: u32,        // Valid values defined in RollbackEnable
    pub reserved: u32,
    pub checksum: u32,
}

impl PartitionTable {
    pub fn new(
        active_partition: PartitionId,
        partition_a_boot_count: u16,
        partition_a_status: PartitionStatus,
        partition_b_boot_count: u16,
        partition_b_status: PartitionStatus,
        rollback_enable: RollbackEnable,
    ) -> Self {
        let reserved = 0; // Reserved field, can be set to zero
        let checksum = 0; // Placeholder for checksum, should be calculated later

        PartitionTable {
            active_partition: active_partition as u32,
            partition_a_boot_count,
            partition_a_status: partition_a_status as u16,
            partition_b_boot_count,
            partition_b_status: partition_b_status as u16,
            rollback_enable: rollback_enable as u32,
            reserved,
            checksum,
        }
    }

    pub fn get_active_partition(&self) -> (PartitionId, Option<&FlashPartition>) {
        let id = PartitionId::try_from(self.active_partition).unwrap_or(PartitionId::None);
        let partition = match id {
            PartitionId::A => Some(&IMAGE_A_PARTITION),
            PartitionId::B => Some(&IMAGE_B_PARTITION),
            _ => None,
        };
        // Make sure the status of the partition is valid
        match self.get_partition_status(id) {
            PartitionStatus::Valid => (id, partition),
            PartitionStatus::BootSuccessful => (id, partition),
            _ => (id, partition),
        }
    }

    pub fn set_active_partition(&mut self, partition: PartitionId) {
        self.active_partition = partition as u32;
    }

    pub fn get_partition_status(&self, partition: PartitionId) -> PartitionStatus {
        match partition {
            PartitionId::A => PartitionStatus::try_from(self.partition_a_status)
                .unwrap_or(PartitionStatus::Invalid),
            PartitionId::B => PartitionStatus::try_from(self.partition_b_status)
                .unwrap_or(PartitionStatus::Invalid),
            _ => PartitionStatus::Invalid,
        }
    }

    pub fn set_partition_status(&mut self, partition: PartitionId, status: PartitionStatus) {
        match partition {
            PartitionId::A => self.partition_a_status = status as u16,
            PartitionId::B => self.partition_b_status = status as u16,
            _ => {}
        }
    }

    pub fn set_active_partition_status(&mut self, status: PartitionStatus) {
        let (active_partition, _) = self.get_active_partition();
        self.set_partition_status(active_partition, status);
    }

    pub fn is_rollback_enabled(&self) -> bool {
        self.rollback_enable == RollbackEnable::Enabled as u32
    }

    pub fn set_rollback_enable(&mut self, enable: RollbackEnable) {
        self.rollback_enable = enable as u32;
    }

    pub fn populate_checksum<C: ChecksumCalculator>(&mut self, calculator: &C) {
        self.checksum = calculator.calc_checksum(&self.as_bytes()[0..offset_of!(Self, checksum)]);
    }

    pub fn verify_checksum<C: ChecksumCalculator>(&self, calculator: &C) -> bool {
        calculator.verify_checksum(
            self.checksum,
            &self.as_bytes()[0..offset_of!(Self, checksum)],
        )
    }
}

pub trait ChecksumCalculator {
    fn calc_checksum(&self, data: &[u8]) -> u32 {
        let mut checksum = 0u32;
        for d in data {
            checksum = checksum.wrapping_add(*d as u32);
        }
        0u32.wrapping_sub(checksum)
    }
    fn verify_checksum(&self, checksum: u32, data: &[u8]) -> bool {
        self.calc_checksum(data) == checksum
    }
}

pub struct StandAloneChecksumCalculator;
impl Default for StandAloneChecksumCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl StandAloneChecksumCalculator {
    pub fn new() -> Self {
        StandAloneChecksumCalculator {}
    }
}
impl ChecksumCalculator for StandAloneChecksumCalculator {}

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
