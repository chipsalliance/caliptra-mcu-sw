// Licensed under the Apache-2.0 license

use crate::println;
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

/// Magic number for the handoff table ("MCUH" in little-endian).
pub const FHT_MARKER: u32 = 0x4855434D;

/// Major version of the handoff table.
pub const FHT_MAJOR_VERSION: u16 = 1;

/// Minor version of the handoff table.
pub const FHT_MINOR_VERSION: u16 = 3;

/// Minor version that introduced the firmware boot type handoff.
pub const FIRMWARE_BOOT_TYPE_FHT_MINOR_VERSION: u16 = 2;

/// Minor version that introduced the MCU ROM capabilities handoff.
pub const MCU_ROM_CAPABILITIES_FHT_MINOR_VERSION: u16 = 3;

bitflags::bitflags! {
    /// Capabilities implemented by the MCU ROM image.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct McuRomCapabilities: u32 {
        /// MCU ROM supports streaming boot over I3C.
        const STREAMING_BOOT_I3C = 1 << 0;
        /// MCU ROM supports flash boot.
        const FLASH_BOOT = 1 << 1;
        /// MCU ROM supports Device Ownership Transfer firmware manifests.
        const FW_MANIFEST_DOT = 1 << 4;
        /// MCU ROM supports component SVN manifests.
        const COMPONENT_SVN_MANIFEST = 1 << 5;
        /// MCU ROM supports DOT blob authentication during boot.
        const DOT_BOOT = 1 << 7;
        /// MCU ROM has a configured DOT locked-state recovery path.
        const DOT_LOCKED_RECOVERY = 1 << 8;
        /// MCU ROM supports DOT recovery over I3C.
        const I3C_DOT_RECOVERY = 1 << 9;
    }
}

/// Source used to boot the MCU firmware.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FirmwareBootType {
    /// The firmware source is unavailable or invalid.
    #[default]
    Unknown = 0,
    /// Firmware was loaded from flash by MCU ROM.
    Flash = 1,
    /// Firmware used streaming boot.
    Streaming = 2,
}

impl TryFrom<u8> for FirmwareBootType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Unknown as u8 => Ok(Self::Unknown),
            value if value == Self::Flash as u8 => Ok(Self::Flash),
            value if value == Self::Streaming as u8 => Ok(Self::Streaming),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareBootTypeReadError {
    Unsupported,
    Invalid,
}

/// Handoff data produced by ROM.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct RomHandoffTable {
    /// Magic Number marking start of table.
    pub fht_marker: u32,

    /// Major version of FHT.
    pub fht_major_ver: u16,

    /// Minor version of FHT.
    pub fht_minor_ver: u16,

    /// Reserved for compatibility with the version 1.0 table layout.
    pub reserved_hek: [u32; 3], // 12 bytes

    /// Source used to boot the MCU firmware.
    firmware_boot_type: u8,

    /// Reserved for alignment and future byte-sized fields.
    pub reserved: [u8; 3],

    /// Capabilities implemented by this MCU ROM image.
    mcu_rom_capabilities: u32,

    /// Padding to reach 64 bytes total.
    pub padding: [u8; 36],
}

impl Default for RomHandoffTable {
    fn default() -> Self {
        Self {
            fht_marker: FHT_MARKER,
            fht_major_ver: FHT_MAJOR_VERSION,
            fht_minor_ver: FHT_MINOR_VERSION,
            reserved_hek: [0; 3],
            firmware_boot_type: FirmwareBootType::Unknown as u8,
            reserved: [0; 3],
            mcu_rom_capabilities: McuRomCapabilities::empty().bits(),
            padding: [0; 36],
        }
    }
}

/// Handoff data produced or updated by Runtime.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone)]
#[repr(C)]
pub struct RuntimeHandoffTable {
    /// Placeholder for runtime data.
    pub reserved: [u8; 64], // 64 bytes
}

impl Default for RuntimeHandoffTable {
    fn default() -> Self {
        Self { reserved: [0; 64] }
    }
}

/// Top-level handoff structure stored in DCCM.
/// Resident at a well-known location in DCCM.
///
/// SAFETY: This structure MUST NOT exceed the reserved memory region size (1 KB)
/// at the end of DCCM defined in the linker scripts. Exceeding this size will cause
/// memory corruption or linker errors.
///
/// ALIGNMENT: This structure is explicitly 4-byte aligned.
#[derive(Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable, Clone, Default)]
#[repr(C, align(4))]
pub struct HandoffData {
    /// ROM handoff table.
    pub rom: RomHandoffTable,

    /// Runtime handoff table.
    pub runtime: RuntimeHandoffTable,
}

const _: () = assert!(core::mem::size_of::<RomHandoffTable>() == 64);
const _: () = assert!(core::mem::offset_of!(RomHandoffTable, firmware_boot_type) == 20);
const _: () = assert!(core::mem::offset_of!(RomHandoffTable, mcu_rom_capabilities) == 24);
const _: () = assert!(core::mem::size_of::<RuntimeHandoffTable>() == 64);
const _: () = assert!(core::mem::offset_of!(HandoffData, rom) == 0);
const _: () = assert!(core::mem::offset_of!(HandoffData, runtime) == 64);
const _: () = assert!(core::mem::size_of::<HandoffData>() == 128);

// Enforce that the handoff data structure fits within the reserved 1KB region.
const _: () = assert!(core::mem::size_of::<HandoffData>() <= 1024);

// Enforce 4-byte alignment of the data structure.
const _: () = assert!(core::mem::align_of::<HandoffData>() == 4);

/// Arguments for initializing the handoff table.
#[derive(Debug, Default, Clone, Copy)]
pub struct HandoffArgs {
    /// Source used to boot the MCU firmware.
    pub firmware_boot_type: FirmwareBootType,

    /// Capabilities implemented by this MCU ROM image.
    pub mcu_rom_capabilities: McuRomCapabilities,
}

impl HandoffData {
    /// Size of the handoff data structure.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Return the source used to boot the MCU firmware.
    pub fn firmware_boot_type(&self) -> Option<FirmwareBootType> {
        self.read_firmware_boot_type().ok()
    }

    /// Read the MCU firmware boot source with version and encoding validation.
    pub fn read_firmware_boot_type(&self) -> Result<FirmwareBootType, FirmwareBootTypeReadError> {
        if self.rom.fht_minor_ver < FIRMWARE_BOOT_TYPE_FHT_MINOR_VERSION {
            return Err(FirmwareBootTypeReadError::Unsupported);
        }
        FirmwareBootType::try_from(self.rom.firmware_boot_type)
            .map_err(|()| FirmwareBootTypeReadError::Invalid)
    }

    /// Return the capabilities implemented by this MCU ROM image.
    pub fn mcu_rom_capabilities(&self) -> Option<McuRomCapabilities> {
        if self.rom.fht_minor_ver < MCU_ROM_CAPABILITIES_FHT_MINOR_VERSION {
            return None;
        }
        Some(McuRomCapabilities::from_bits_truncate(
            self.rom.mcu_rom_capabilities,
        ))
    }

    /// Return the handoff table when its marker and major version are valid.
    pub fn get() -> Option<&'static Self> {
        // SAFETY: Runtime treats ROM-owned handoff data as read-only.
        let handoff = unsafe { &*core::ptr::addr_of!(HANDOFF) };
        if handoff.rom.fht_marker != FHT_MARKER || handoff.rom.fht_major_ver != FHT_MAJOR_VERSION {
            return None;
        }
        Some(handoff)
    }

    /// Persist handoff data structure from the given arguments.
    pub fn write(args: HandoffArgs) {
        println!(
            "[mcu-rom] Writing handoff table (size {}) to DCCM at {:p}",
            HandoffData::SIZE as u32,
            &raw const HANDOFF
        );

        // SAFETY: Linker must allocate the HANDOFF struct. This is currently the only code writing
        // to the reserved memory section. Should that invariant change there is risk of data
        // corruption / write contention.
        unsafe {
            HANDOFF = Self {
                rom: RomHandoffTable {
                    firmware_boot_type: args.firmware_boot_type as u8,
                    mcu_rom_capabilities: args.mcu_rom_capabilities.bits(),
                    reserved_hek: [0; 3],
                    ..Default::default()
                },
                runtime: RuntimeHandoffTable::default(),
            }
        }
    }

    /// Record the source selected to boot the MCU firmware.
    pub fn write_firmware_boot_type(firmware_boot_type: FirmwareBootType) {
        // SAFETY: ROM owns the handoff table while constructing data for Runtime.
        unsafe {
            let handoff = &raw mut HANDOFF;
            (*handoff).rom.firmware_boot_type = firmware_boot_type as u8;
        }
    }
}

/// Handoff data resident in the .handoff section of DCCM.
/// This section is shared between ROM and Runtime.
#[link_section = ".handoff"]
pub static mut HANDOFF: HandoffData = HandoffData {
    rom: RomHandoffTable {
        fht_marker: 0,
        fht_major_ver: 0,
        fht_minor_ver: 0,
        reserved_hek: [0; 3],
        firmware_boot_type: FirmwareBootType::Unknown as u8,
        reserved: [0; 3],
        mcu_rom_capabilities: McuRomCapabilities::empty().bits(),
        padding: [0; 36],
    },
    runtime: RuntimeHandoffTable { reserved: [0; 64] },
};

/// Return the firmware boot type from a valid handoff table.
pub fn get_firmware_boot_type() -> Result<FirmwareBootType, FirmwareBootTypeReadError> {
    HandoffData::get()
        .ok_or(FirmwareBootTypeReadError::Unsupported)?
        .read_firmware_boot_type()
}

/// Return MCU ROM capabilities from a valid handoff table that supports them.
pub fn get_mcu_rom_capabilities() -> Option<McuRomCapabilities> {
    HandoffData::get()?.mcu_rom_capabilities()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn handoff_layout_is_append_only() {
        assert_eq!(size_of::<RomHandoffTable>(), 64);
        assert_eq!(offset_of!(RomHandoffTable, firmware_boot_type), 20);
        assert_eq!(offset_of!(RomHandoffTable, mcu_rom_capabilities), 24);
        assert_eq!(size_of::<RuntimeHandoffTable>(), 64);
        assert_eq!(offset_of!(HandoffData, rom), 0);
        assert_eq!(offset_of!(HandoffData, runtime), 64);
        assert_eq!(size_of::<HandoffData>(), 128);
    }

    #[test]
    fn firmware_boot_type_requires_supported_version_and_value() {
        let mut handoff = HandoffData::default();
        handoff.rom.firmware_boot_type = FirmwareBootType::Flash as u8;
        assert_eq!(handoff.firmware_boot_type(), Some(FirmwareBootType::Flash));

        handoff.rom.firmware_boot_type = FirmwareBootType::Streaming as u8;
        assert_eq!(
            handoff.firmware_boot_type(),
            Some(FirmwareBootType::Streaming)
        );

        handoff.rom.firmware_boot_type = u8::MAX;
        assert_eq!(handoff.firmware_boot_type(), None);
        assert_eq!(
            handoff.read_firmware_boot_type(),
            Err(FirmwareBootTypeReadError::Invalid)
        );

        handoff.rom.fht_minor_ver = FIRMWARE_BOOT_TYPE_FHT_MINOR_VERSION - 1;
        handoff.rom.firmware_boot_type = FirmwareBootType::Flash as u8;
        assert_eq!(handoff.firmware_boot_type(), None);
        assert_eq!(
            handoff.read_firmware_boot_type(),
            Err(FirmwareBootTypeReadError::Unsupported)
        );
    }

    #[test]
    fn mcu_rom_capabilities_require_supported_version() {
        let mut handoff = HandoffData::default();
        handoff.rom.mcu_rom_capabilities =
            (McuRomCapabilities::STREAMING_BOOT_I3C | McuRomCapabilities::FLASH_BOOT).bits();
        assert_eq!(
            handoff.mcu_rom_capabilities(),
            Some(McuRomCapabilities::STREAMING_BOOT_I3C | McuRomCapabilities::FLASH_BOOT)
        );

        handoff.rom.fht_minor_ver = MCU_ROM_CAPABILITIES_FHT_MINOR_VERSION - 1;
        assert_eq!(handoff.mcu_rom_capabilities(), None);
    }

    #[test]
    fn mcu_rom_capability_assignments_are_stable() {
        assert_eq!(McuRomCapabilities::STREAMING_BOOT_I3C.bits(), 1 << 0);
        assert_eq!(McuRomCapabilities::FLASH_BOOT.bits(), 1 << 1);
        assert_eq!(McuRomCapabilities::FW_MANIFEST_DOT.bits(), 1 << 4);
        assert_eq!(McuRomCapabilities::COMPONENT_SVN_MANIFEST.bits(), 1 << 5);
        assert_eq!(McuRomCapabilities::DOT_BOOT.bits(), 1 << 7);
        assert_eq!(McuRomCapabilities::DOT_LOCKED_RECOVERY.bits(), 1 << 8);
        assert_eq!(McuRomCapabilities::I3C_DOT_RECOVERY.bits(), 1 << 9);
    }
}
