// Licensed under the Apache-2.0 license

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashDeviceConfig {
    pub partitions: &'static [&'static FlashPartition], // partitions on the flash device
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct FlashPartition {
    pub name: &'static str, // name of the partition
    pub offset: usize,      // flash partition offset in bytes
    pub size: usize,        // size in bytes
    pub driver_num: u32,    // driver number for the partition
}
