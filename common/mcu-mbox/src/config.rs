// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

// Dummy firmware version strings for testing purposes.
pub static TEST_FIRMWARE_VERSIONS: [&str; 3] = [
    "Caliptra_Core_v2.0.0", // index 0
    "MCU_RT_v2.0.0",        // index 1
    "SoC_v1.0.1",           // index 2
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TestDeviceId {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
}

// Dummy device ID for testing purposes.
pub static TEST_DEVICE_ID: TestDeviceId = TestDeviceId {
    vendor_id: 0x1414,
    device_id: 0x0010,
    subsystem_vendor_id: 0x0001,
    subsystem_id: 0x0002,
};

// Dummy UID for testing purposes.
pub static TEST_UID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq, FromBytes, IntoBytes, Immutable)]
pub struct TestDeviceCapabilities {
    pub caliptra_rt: [u8; 8],
    pub caliptra_fmc: [u8; 4],
    pub caliptra_rom: [u8; 4],
    pub mcu_rt: [u8; 8],
    pub mcu_rom: [u8; 4],
    pub reserved: [u8; 4],
}

// Dummy device capabilities for testing purposes.
pub static TEST_DEVICE_CAPABILITIES: TestDeviceCapabilities = TestDeviceCapabilities {
    caliptra_rt: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    caliptra_fmc: [0x09, 0x0A, 0x0B, 0x0C],
    caliptra_rom: [0x0D, 0x0E, 0x0F, 0x10],
    mcu_rt: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
    mcu_rom: [0x19, 0x1A, 0x1B, 0x1C],
    reserved: [0x00, 0x00, 0x00, 0x00],
};
