// Licensed under the Apache-2.0 license
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const FLASH_PARTITIONS_COUNT: usize = 3; // Number of flash partitions

// Allocate driver numbers for flash partitions
pub const DRIVER_NUM_START: usize = 0x8000_0006; // Base driver number for flash partitions
pub const DRIVER_NUM_END: usize = 0x8000_0008; // End driver number for flash partitions

pub const PARTITION_TABLE : FlashPartition = FlashPartition {
    name: "partition_table",
    offset: 0x00000000,
    size: 0x0000_0100, // Size of the partition table
    driver_num: 0x8000_0006, // Driver number for the partition table
}; 

pub const IMAGE_A_PARTITION: FlashPartition = FlashPartition {
    name: "image_a",
    offset: 0x00000100,
    size: 0x200_0000,
    driver_num: 0x8000_0007,
};

pub const IMAGE_B_PARTITION: FlashPartition = FlashPartition {
    name: "image_b",
    offset: 0x00000000,
    size: 0x200_0000,
    driver_num: 0x8000_0008,
};

pub const PRIMARY_FLASH: FlashDeviceConfig = FlashDeviceConfig {
    partitions: &[&PARTITION_TABLE, &IMAGE_A_PARTITION],
};

pub const SECONDARY_FLASH: FlashDeviceConfig = FlashDeviceConfig {
    partitions: &[&IMAGE_B_PARTITION],
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashDeviceConfig {
    pub partitions: &'static [&'static FlashPartition], // partitions on the flash device
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashPartition {
    pub name: &'static str, // name of the partition
    pub offset: usize,      // flash partition offset in bytes
    pub size: usize,        // size in bytes
    pub driver_num: u32,    // driver number for the partition
}

#[derive(Debug, Clone, FromBytes, IntoBytes, Immutable, PartialEq)]
#[repr(C, packed)]
pub struct PartitionTable {
    pub active_partition: u32, // Valid values defined in PartitionId
    pub partition_a_status: u32, // Valid values defined in PartitionStatus
    pub partition_b_status: u32, // Valid values defined in PartitionStatus
    pub rollback_enable: u32, // Valid values defined in RollbackEnable
    pub reserved: u32,
    pub checksum: u32, 
}

impl PartitionTable {
    pub fn new(
        active_partition: PartitionId,
        partition_a_status: PartitionStatus,
        partition_b_status: PartitionStatus,
        rollback_enable: RollbackEnable,
    ) -> Self {
        let reserved = 0; // Reserved field, can be set to zero
        let checksum = 0; // Placeholder for checksum, should be calculated later

        PartitionTable {
            active_partition: active_partition as u32,
            partition_a_status: partition_a_status as u32,
            partition_b_status: partition_b_status as u32,
            rollback_enable: rollback_enable as u32,
            reserved,
            checksum,
        }
    }

    pub fn get_active_partition(&self) -> PartitionId {
        PartitionId::try_from(self.active_partition).unwrap_or(PartitionId::None)
    }

    pub fn set_active_partition(&mut self, partition: PartitionId) {
        self.active_partition = partition as u32;
    }

    pub fn get_partition_status(&self, partition: PartitionId) -> PartitionStatus {
        match partition {
            PartitionId::A => PartitionStatus::try_from(self.partition_a_status).unwrap_or(PartitionStatus::Invalid),
            PartitionId::B => PartitionStatus::try_from(self.partition_b_status).unwrap_or(PartitionStatus::Invalid),
            _ => PartitionStatus::Invalid,
        }
    }

    pub fn set_partition_status(&mut self, partition: PartitionId, status: PartitionStatus) {
        match partition {
            PartitionId::A => self.partition_a_status = status as u32,
            PartitionId::B => self.partition_b_status = status as u32,
            _ => {}
        }
    }

    pub fn is_rollback_enabled(&self) -> bool {
        self.rollback_enable == RollbackEnable::Enabled as u32
    }

    pub fn set_rollback_enable(&mut self, enable: RollbackEnable) {
        self.rollback_enable = enable as u32;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionId {
    None = 0x0000_0000,
    A = 0x0001_0000,
    B = 0x0002_0000,
}

impl core::convert::TryFrom<u32> for PartitionId {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000_0000 => Ok(PartitionId::None),
            0x0001_0000 => Ok(PartitionId::A),
            0x0002_0000 => Ok(PartitionId::B),
            _ => Err(()),
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStatus {
    Invalid = 0x0000_0000,
    Valid = 0x0001_0000,
    BootFailed = 0x0002_0000,
    BootSuccessful = 0x0003_0000,
}

impl core::convert::TryFrom<u32> for PartitionStatus {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000_0000 => Ok(PartitionStatus::Invalid),
            0x0001_0000 => Ok(PartitionStatus::Valid),
            0x0002_0000 => Ok(PartitionStatus::BootFailed),
            0x0003_0000 => Ok(PartitionStatus::BootSuccessful),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackEnable {
    Disabled = 0x0000_0000,
    Enabled = 0x0001_0000,
}