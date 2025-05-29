// Licensed under the Apache-2.0 license

pub const FLASH_PARTITIONS_COUNT: usize = 2; // Number of flash partitions

// Allocate driver numbers for flash partitions
pub const DRIVER_NUM_START: usize = 0x8000_0006; // Base driver number for flash partitions
pub const DRIVER_NUM_END: usize = 0x8000_0008; // End driver number for flash partitions

pub const IMAGE_A_PARTITION: FlashPartition = FlashPartition {
    name: "image_a",
    offset: 0x00000000,
    size: 0x200_0000,
    driver_num: 0x8000_0006,
};

pub const IMAGE_B_PARTITION: FlashPartition = FlashPartition {
    name: "image_b",
    offset: 0x00000000,
    size: 0x200_0000,
    driver_num: 0x8000_0007,
};

pub const PRIMARY_FLASH: FlashDeviceConfig = FlashDeviceConfig {
    partitions: &[&IMAGE_A_PARTITION],
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
