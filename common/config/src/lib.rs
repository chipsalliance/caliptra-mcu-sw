// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod boot;
pub mod capabilities;
pub mod flash;
pub mod version;

/// Userspace flash-partition driver used for the ROM-compatible DOT blob.
pub const DOT_BLOB_STORE_DRIVER_NUM: u32 = 0x8000_0023;
/// Minimum capacity required from a platform's DOT blob store.
pub const DOT_BLOB_STORE_SIZE: usize = 4 * 1024;

/// Configures the memory map for the MCU.
/// These are the defaults that can be overridden and provided to the ROM and runtime builds.
#[repr(C)]
pub struct McuMemoryMap {
    pub rom_offset: u32,
    pub rom_size: u32,
    pub rom_stack_size: u32,
    pub rom_estack_size: u32,
    pub rom_properties: MemoryRegionType,

    pub sram_offset: u32,
    pub sram_size: u32,
    pub sram_properties: MemoryRegionType,

    /// Size in bytes of the persistent storage region reserved at the end of SRAM.
    pub storage_size: u32,

    pub pic_offset: u32,
    pub pic_properties: MemoryRegionType,

    pub dccm_offset: u32,
    pub dccm_size: u32,
    pub dccm_properties: MemoryRegionType,

    pub handoff_offset: u32,
    pub handoff_size: u32,

    pub i3c_offset: u32,
    pub i3c_size: u32,
    pub i3c_properties: MemoryRegionType,

    pub i3c1_offset: u32,
    pub i3c1_size: u32,
    pub i3c1_properties: MemoryRegionType,

    pub mci_offset: u32,
    pub mci_size: u32,
    pub mci_properties: MemoryRegionType,

    pub mbox_offset: u32,
    pub mbox_size: u32,
    pub mbox_properties: MemoryRegionType,

    pub soc_offset: u32,
    pub soc_size: u32,
    pub soc_properties: MemoryRegionType,

    pub otp_offset: u32,
    pub otp_size: u32,
    pub otp_properties: MemoryRegionType,

    pub lc_offset: u32,
    pub lc_size: u32,
    pub lc_properties: MemoryRegionType,

    pub staging_sram_offset: u32,
    pub staging_sram_size: u32,
}

impl Default for McuMemoryMap {
    fn default() -> Self {
        McuMemoryMap {
            rom_offset: 0x8000_0000,
            rom_size: 32 * 1024,
            rom_stack_size: 0x2d00,
            rom_estack_size: 0x200,
            rom_properties: MemoryRegionType::MEMORY,

            dccm_offset: 0x5000_0000,
            dccm_size: 256 * 1024,
            dccm_properties: MemoryRegionType::MEMORY,

            handoff_offset: 0x5000_3C00,
            handoff_size: 1024,

            sram_offset: 0x4000_0000,
            sram_size: 1024 * 1024,
            sram_properties: MemoryRegionType::MEMORY,

            storage_size: 0,

            pic_offset: 0x6000_0000,
            pic_properties: MemoryRegionType::MMIO,

            i3c_offset: 0x2000_4000,
            i3c_size: 0x1000,
            i3c_properties: MemoryRegionType::MMIO,

            i3c1_offset: 0x2000_5000,
            i3c1_size: 0x1000,
            i3c1_properties: MemoryRegionType::MMIO,

            mci_offset: 0x2100_0000,
            mci_size: 0xe0_0000,
            mci_properties: MemoryRegionType::MMIO,

            mbox_offset: 0x3002_0000,
            mbox_size: 0x28,
            mbox_properties: MemoryRegionType::MMIO,

            soc_offset: 0x3003_0000,
            soc_size: 0x5e0,
            soc_properties: MemoryRegionType::MMIO,

            otp_offset: 0x7000_0000,
            otp_size: 0x140,
            otp_properties: MemoryRegionType::MMIO,

            lc_offset: 0x7000_0400,
            lc_size: 0x8c,
            lc_properties: MemoryRegionType::MMIO,

            staging_sram_offset: 0xb00c_0000,
            staging_sram_size: 1024 * 1024,
        }
    }
}

/// Configures other parameters that are expected to be strapped or hardcoded for a platform.
/// These are the defaults that can be overridden and provided to the ROM and runtime builds.
#[repr(C)]
pub struct McuStraps {
    pub i3c_static_addr: u8,
    pub i3c1_static_addr: u8,
    /// Selects which I3C core is used for MCTP transport.
    /// 0 = i3c0 (default), 1 = i3c1.
    pub active_i3c: u8,
    pub cptra_wdt_cfg0: u32,
    pub cptra_wdt_cfg1: u32,
    pub mcu_wdt_cfg0: u32,
    pub mcu_wdt_cfg1: u32,
    pub mcu_wdt_cfg0_manufacturing: u32,
    pub mcu_wdt_cfg1_manufacturing: u32,
    pub mcu_wdt_cfg0_debug: u32,
    pub mcu_wdt_cfg1_debug: u32,
    /// Index of the MCI `generic_input_wires` register that carries the
    /// strap pins (see [`StrapPins`]), or [`STRAP_PINS_NOT_WIRED`] if the
    /// platform does not expose them.
    pub strap_pins_wire_index: u8,
    /// Bit position of [`StrapPins::BOOTMODE0`] within that register; the
    /// six strap pins occupy bits `shift..shift + 6`.
    pub strap_pins_shift: u8,
}

/// Number of strap pin signals (bootmode0..1, strap0..3).
pub const STRAP_PINS_COUNT: u32 = 6;

/// Value of [`McuStraps::strap_pins_wire_index`] for platforms without strap pins.
pub const STRAP_PINS_NOT_WIRED: u8 = 0xff;

bitflags::bitflags! {
    /// Board strap pin signals sampled by MCU firmware.
    ///
    /// Bit `n` of this value maps to bit `strap_pins_shift + n` of
    /// `mci_reg_generic_input_wires[strap_pins_wire_index]`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct StrapPins: u8 {
        const BOOTMODE0 = 1 << 0;
        const BOOTMODE1 = 1 << 1;
        const STRAP0 = 1 << 2;
        const STRAP1 = 1 << 3;
        const STRAP2 = 1 << 4;
        const STRAP3 = 1 << 5;
    }
}

impl StrapPins {
    /// Two-bit boot mode value: `bootmode1:bootmode0`.
    pub const fn bootmode(self) -> u8 {
        self.bits() & 0b11
    }

    /// Four-bit general-purpose strap value: `strap3:strap2:strap1:strap0`.
    pub const fn straps(self) -> u8 {
        (self.bits() >> 2) & 0b1111
    }
}

impl McuStraps {
    /// Decode the strap pins from the MCI generic input wires.
    /// Returns empty pins when the platform does not wire them.
    pub fn strap_pins(&self, generic_input_wires: [u32; 2]) -> StrapPins {
        let Some(&wire) = generic_input_wires.get(self.strap_pins_wire_index as usize) else {
            return StrapPins::empty();
        };
        StrapPins::from_bits_truncate((wire >> self.strap_pins_shift) as u8)
    }

    /// Encode strap pins into a generic input wires value for this platform.
    pub fn strap_pins_to_wires(&self, pins: StrapPins) -> [u32; 2] {
        let mut wires = [0u32; 2];
        if let Some(wire) = wires.get_mut(self.strap_pins_wire_index as usize) {
            *wire = (pins.bits() as u32) << self.strap_pins_shift;
        }
        wires
    }
}

impl McuStraps {
    pub const fn default() -> Self {
        McuStraps {
            i3c_static_addr: 0x3a,
            i3c1_static_addr: 0x3c,
            active_i3c: 0,
            cptra_wdt_cfg0: 100_000_000,
            cptra_wdt_cfg1: 100_000_000,
            mcu_wdt_cfg0: 20_000_000,
            mcu_wdt_cfg1: 1,
            mcu_wdt_cfg0_manufacturing: 80_000_000,
            mcu_wdt_cfg1_manufacturing: 1,
            mcu_wdt_cfg0_debug: 80_000_000,
            mcu_wdt_cfg1_debug: 1,
            strap_pins_wire_index: STRAP_PINS_NOT_WIRED,
            strap_pins_shift: 0,
        }
    }
}

#[cfg(test)]
mod strap_pin_tests {
    use super::*;

    #[test]
    fn strap_pins_round_trip_through_wires() {
        let straps = McuStraps {
            strap_pins_wire_index: 0,
            strap_pins_shift: 16,
            ..McuStraps::default()
        };
        let pins = StrapPins::BOOTMODE1 | StrapPins::STRAP0 | StrapPins::STRAP3;
        let wires = straps.strap_pins_to_wires(pins);
        assert_eq!(wires, [0b10_0110 << 16, 0]);
        assert_eq!(straps.strap_pins(wires), pins);
        assert_eq!(pins.bootmode(), 0b10);
        assert_eq!(pins.straps(), 0b1001);
    }

    #[test]
    fn unwired_platform_reads_no_strap_pins() {
        let straps = McuStraps::default();
        assert_eq!(straps.strap_pins([u32::MAX; 2]), StrapPins::empty());
        assert_eq!(straps.strap_pins_to_wires(StrapPins::all()), [0, 0]);
    }
}

impl Default for McuStraps {
    fn default() -> Self {
        Self::default()
    }
}

/// Represents the properties of a memory region for MRAC computation
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegionType {
    /// Whether the region has side effects (typically true for MMIO)
    pub side_effect: bool,
    /// Whether the region is cacheable (typically true for memory, false for MMIO)
    pub cacheable: bool,
}

impl MemoryRegionType {
    /// Memory regions (cacheable, no side effects)
    pub const MEMORY: Self = Self {
        side_effect: false,
        cacheable: true,
    };
    /// MMIO regions (side effects, not cacheable)
    pub const MMIO: Self = Self {
        side_effect: true,
        cacheable: false,
    };
    /// Default for unmapped regions (side effects, not cacheable)
    pub const UNMAPPED: Self = Self {
        side_effect: true,
        cacheable: false,
    };
}

impl McuMemoryMap {
    /// Size of each MRAC region in bytes (256MB = 0x10000000)
    const MRAC_REGION_SIZE: u32 = 0x1000_0000;

    /// Get the MRAC region index for a given address
    const fn get_mrac_region(address: u32) -> usize {
        (address / Self::MRAC_REGION_SIZE) as usize
    }

    /// Process the specified region, and update the concatenated region types appropriately.
    const fn process_region(
        offset: u32,
        size: u32,
        region_type: MemoryRegionType,
        region_assigned: &mut [bool],
        region_types: &mut [MemoryRegionType],
    ) {
        if size == 0 {
            return;
        }

        let start_region = Self::get_mrac_region(offset);
        let end_address = offset.saturating_add(size).saturating_sub(1);
        let end_region = Self::get_mrac_region(end_address);

        // Apply region type to all affected MRAC regions
        let mut region_idx = start_region;
        while region_idx <= end_region {
            match (
                region_assigned[region_idx],
                region_types[region_idx],
                region_type,
            ) {
                // If region not yet assigned, use the new type
                (false, _, new_type) => {
                    region_types[region_idx] = new_type;
                    region_assigned[region_idx] = true;
                }
                // If current is MEMORY and new is MMIO, convert to MMIO (safety first)
                (true, MemoryRegionType::MEMORY, MemoryRegionType::MMIO) => {
                    region_types[region_idx] = MemoryRegionType::MMIO;
                }
                // If current is MMIO and new is MEMORY, keep MMIO (safety first)
                (true, MemoryRegionType::MMIO, MemoryRegionType::MEMORY) => {
                    // Keep existing MMIO type
                }
                // For any other combination, keep the existing type
                _ => {}
            };

            region_idx += 1;
        }
    }

    /// Compute the MRAC register value based on the memory map
    ///
    /// MRAC is a 32-bit register controlling 16 regions of 256MB each.
    /// Each region uses 2 bits: [side_effect, cacheable]
    /// Bit encoding: 00 = no side effects, not cacheable
    ///               01 = no side effects, cacheable
    ///               10 = side effects, not cacheable
    ///               11 = invalid (prevented by hardware)
    pub const fn compute_mrac(&self) -> u32 {
        // This is hardware defined as the register is 32 bits and each region consumes 2 bits.
        const REGION_COUNT: usize = 16;

        // Track which regions have been assigned and their types
        let mut region_types = [MemoryRegionType::UNMAPPED; REGION_COUNT];
        let mut region_assigned = [false; REGION_COUNT];

        // Helper function to process a memory region

        // Process each memory region directly from the memory map
        Self::process_region(
            self.rom_offset,
            self.rom_size,
            self.rom_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.sram_offset,
            self.sram_size,
            self.sram_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.dccm_offset,
            self.dccm_size,
            self.dccm_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.pic_offset,
            0x1000,
            self.pic_properties,
            &mut region_assigned,
            &mut region_types,
        ); // PIC doesn't have explicit size, use 4KB
        Self::process_region(
            self.i3c_offset,
            self.i3c_size,
            self.i3c_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.i3c1_offset,
            self.i3c1_size,
            self.i3c1_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.mci_offset,
            self.mci_size,
            self.mci_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.mbox_offset,
            self.mbox_size,
            self.mbox_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.soc_offset,
            self.soc_size,
            self.soc_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.otp_offset,
            self.otp_size,
            self.otp_properties,
            &mut region_assigned,
            &mut region_types,
        );
        Self::process_region(
            self.lc_offset,
            self.lc_size,
            self.lc_properties,
            &mut region_assigned,
            &mut region_types,
        );

        // Build the 32-bit MRAC value
        let mut mrac_value = 0u32;
        let mut i = 0;
        while i < REGION_COUNT {
            let region_type = region_types[i];
            let bits = (if region_type.side_effect { 2 } else { 0 })
                | (if region_type.cacheable { 1 } else { 0 });
            mrac_value |= bits << (i * 2);
            i += 1;
        }

        mrac_value
    }

    #[cfg(not(target_arch = "riscv32"))]
    pub fn hash_map(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();

        // Only include variables actually used in linker script templates
        map.insert("ROM_OFFSET".to_string(), format!("0x{:x}", self.rom_offset));
        map.insert("ROM_SIZE".to_string(), format!("0x{:x}", self.rom_size));
        map.insert(
            "ROM_STACK_SIZE".to_string(),
            format!("0x{:x}", self.rom_stack_size),
        );
        map.insert(
            "ROM_ESTACK_SIZE".to_string(),
            format!("0x{:x}", self.rom_estack_size),
        );

        map.insert(
            "DCCM_OFFSET".to_string(),
            format!("0x{:x}", self.dccm_offset),
        );
        map.insert("DCCM_SIZE".to_string(), format!("0x{:x}", self.dccm_size));

        map.insert(
            "HANDOFF_OFFSET".to_string(),
            format!("0x{:x}", self.handoff_offset),
        );
        map.insert(
            "HANDOFF_SIZE".to_string(),
            format!("0x{:x}", self.handoff_size),
        );

        // The computed MRAC value (derived from all memory region properties)
        map.insert(
            "MRAC_VALUE".to_string(),
            format!("0x{:x}", self.compute_mrac()),
        );

        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mrac_computation() {
        let memory_map = McuMemoryMap::default();
        let mrac_value = memory_map.compute_mrac();

        // Print the computed value for debugging
        println!("Computed MRAC value: 0x{:08x}", mrac_value);

        // Verify that the value is reasonable (not zero, not all 1s)
        assert_ne!(mrac_value, 0);
        assert_ne!(mrac_value, 0xffffffff);

        // Test individual region mappings
        assert_eq!(McuMemoryMap::get_mrac_region(0x0000_0000), 0); // Region 0
        assert_eq!(McuMemoryMap::get_mrac_region(0x1000_0000), 1); // Region 1
        assert_eq!(McuMemoryMap::get_mrac_region(0x4000_0000), 4); // Region 4 (SRAM)
        assert_eq!(McuMemoryMap::get_mrac_region(0x5000_0000), 5); // Region 5 (DCCM)
        assert_eq!(McuMemoryMap::get_mrac_region(0x8000_0000), 8); // Region 8 (ROM)

        // Test that the computed MRAC correctly classifies regions by checking bit patterns
        // Extract region 4 (SRAM at 0x4000_0000) - should be cacheable, no side effects (01)
        let region_4_bits = (mrac_value >> (4 * 2)) & 0x3;
        assert_eq!(region_4_bits, 0x1, "SRAM region should be cacheable (01)");

        // Extract region 5 (DCCM at 0x5000_0000) - should be cacheable, no side effects (01)
        let region_5_bits = (mrac_value >> (5 * 2)) & 0x3;
        assert_eq!(region_5_bits, 0x1, "DCCM region should be cacheable (01)");

        // Extract region 8 (ROM at 0x8000_0000) - should be cacheable, no side effects (01)
        let region_8_bits = (mrac_value >> (8 * 2)) & 0x3;
        assert_eq!(region_8_bits, 0x1, "ROM region should be cacheable (01)");

        // Extract region 2 (I3C at 0x2000_4000) - should be side effects, not cacheable (10)
        let region_2_bits = (mrac_value >> (2 * 2)) & 0x3;
        assert_eq!(
            region_2_bits, 0x2,
            "I3C region should have side effects (10)"
        );

        // Print detailed breakdown for debugging
        println!("MRAC breakdown:");
        for i in 0..16 {
            let bits = (mrac_value >> (i * 2)) & 0x3;
            let se = (bits & 0x2) != 0;
            let cache = (bits & 0x1) != 0;
            println!(
                "  Region {:2} (0x{:x}000_0000): SE={}, Cache={} (bits: {:02b})",
                i, i, se, cache, bits
            );
        }
    }

    #[test]
    fn test_mrac_region_mapping() {
        // Test the 256MB region boundaries
        assert_eq!(McuMemoryMap::get_mrac_region(0x0000_0000), 0);
        assert_eq!(McuMemoryMap::get_mrac_region(0x0fff_ffff), 0);
        assert_eq!(McuMemoryMap::get_mrac_region(0x1000_0000), 1);
        assert_eq!(McuMemoryMap::get_mrac_region(0x1fff_ffff), 1);
        assert_eq!(McuMemoryMap::get_mrac_region(0xf000_0000), 15);
        assert_eq!(McuMemoryMap::get_mrac_region(0xffff_ffff), 15);

        // Test that all regions are within bounds (0-15)
        let test_addresses = [
            0x0000_0000,
            0x0fff_ffff, // Region 0
            0x1000_0000,
            0x1fff_ffff, // Region 1
            0x8000_0000,
            0x8fff_ffff, // Region 8
            0xf000_0000,
            0xffff_ffff, // Region 15
        ];

        for &addr in &test_addresses {
            let region = McuMemoryMap::get_mrac_region(addr);
            assert!(
                region < 16,
                "Region {} for address 0x{:08x} is out of bounds",
                region,
                addr
            );
        }
    }
}
