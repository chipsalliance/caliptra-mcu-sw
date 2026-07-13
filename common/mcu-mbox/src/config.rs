// Licensed under the Apache-2.0 license

use zerocopy::{FromBytes, Immutable, IntoBytes};

// Dummy firmware version strings for testing purposes.
pub static TEST_FIRMWARE_VERSIONS: [&str; 4] = [
    "Caliptra_Core_v2.0.0", // index 0
    "MCU_RT_v2.0.0",        // index 1
    "SoC_v1.0.1",           // index 2
    "MCU_ROM_v2.1.0",       // Index 3
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

// Deterministic test fixture for the debug log, host-side seeded into the
// kernel `logging_flash` partition before the firmware starts. Total payload
// is just over the 900-byte MCTP VDM per-call cap (forces multi-call drain)
// and fits the MCU mailbox 4 KiB budget in a single call.
pub static TEST_DEBUG_LOG_ENTRIES: &[&[u8]] = &[
    b"[boot] mcu rom: cold-boot phase complete",
    b"[boot] mcu fmc: control handed off to fmc",
    b"[boot] mcu runtime: tasks spawning",
    b"[mctp] driver: i3c bus configured, eid 0x1d",
    b"[mctp] vdm responder: listening on dst eid",
    b"[mcu_mbox] driver: sram allocated, irq armed",
    b"[mcu_mbox] responder: waiting for caliptra rt",
    b"[spdm] context: versions 1.2/1.3 negotiated",
    b"[spdm] cert store: ldevid through rt-alias loaded",
    b"[caliptra] mailbox: idle, awaiting first command",
    b"[caliptra] runtime: detected, boot phase complete",
    b"[caliptra] dpe: init ok, context table built",
    b"[caliptra] cert: chain ready (ldevid-rt_alias)",
    b"[caliptra] device_id: retrieved from fuses",
    b"[caliptra] firmware_version: 1.2.3 active",
    b"[caliptra] uid: latched from secure storage",
    b"[caliptra] csr: export ready, keys provisioned",
    b"[mctp_vdm] firmware_version: returned v1.2.3",
    b"[mctp_vdm] device_id: canonical id returned",
    b"[mctp_vdm] device_info: uid returned",
    b"[mctp_vdm] device_capabilities: flags reported",
    b"[mcu_mbox] firmware_version: passthrough ok",
    b"[mcu_mbox] device_id: passthrough ok",
    b"[diag] heap: 12% of pool consumed",
];
