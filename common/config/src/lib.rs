// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

pub mod boot;
pub mod flash;

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

    pub pic_offset: u32,
    pub pic_properties: MemoryRegionType,

    pub dccm_offset: u32,
    pub dccm_size: u32,
    pub dccm_properties: MemoryRegionType,

    pub i3c_offset: u32,
    pub i3c_size: u32,
    pub i3c_properties: MemoryRegionType,

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
}

impl Default for McuMemoryMap {
    fn default() -> Self {
        McuMemoryMap {
            rom_offset: 0x8000_0000,
            rom_size: 32 * 1024,
            rom_stack_size: 0x3000,
            rom_estack_size: 0x800,
            rom_properties: MemoryRegionType::MEMORY,

            dccm_offset: 0x5000_0000,
            dccm_size: 256 * 1024,
            dccm_properties: MemoryRegionType::MEMORY,

            sram_offset: 0x4000_0000,
            sram_size: 512 * 1024,
            sram_properties: MemoryRegionType::MEMORY,

            pic_offset: 0x6000_0000,
            pic_properties: MemoryRegionType::MMIO,

            i3c_offset: 0x2000_4000,
            i3c_size: 0x1000,
            i3c_properties: MemoryRegionType::MMIO,

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
        }
    }
}

/// Configures other parameters that are expected to be strapped or hardcoded for a platform.
/// These are the defaults that can be overridden and provided to the ROM and runtime builds.
#[repr(C)]
pub struct McuStraps {
    pub i3c_static_addr: u8,
    pub axi_user0: u32,
    pub axi_user1: u32,
    pub cptra_wdt_cfg0: u32,
    pub cptra_wdt_cfg1: u32,
    pub mcu_wdt_cfg0: u32,
    pub mcu_wdt_cfg1: u32,
}

impl McuStraps {
    pub const fn default() -> Self {
        McuStraps {
            i3c_static_addr: 0x3a,
            axi_user0: 0xcccc_cccc,
            axi_user1: 0xdddd_dddd,
            cptra_wdt_cfg0: 100_000_000,
            cptra_wdt_cfg1: 100_000_000,
            mcu_wdt_cfg0: 20_000_000,
            mcu_wdt_cfg1: 1,
        }
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
    #[cfg(not(target_arch = "riscv32"))]
    const MRAC_REGION_SIZE: u32 = 0x1000_0000;

    /// Get the MRAC region index for a given address
    #[cfg(not(target_arch = "riscv32"))]
    fn get_mrac_region(address: u32) -> usize {
        let region = (address / Self::MRAC_REGION_SIZE) as usize;
        debug_assert!(
            region < 16,
            "MRAC region index {} out of bounds for address 0x{:08x}",
            region,
            address
        );
        region
    }

    /// Compute the MRAC register value based on the memory map
    ///
    /// MRAC is a 32-bit register controlling 16 regions of 256MB each.
    /// Each region uses 2 bits: [side_effect, cacheable]
    /// Bit encoding: 00 = no side effects, not cacheable
    ///               01 = no side effects, cacheable
    ///               10 = side effects, not cacheable
    ///               11 = invalid (prevented by hardware)
    #[cfg(not(target_arch = "riscv32"))]
    pub fn compute_mrac(&self) -> u32 {
        // Track which regions have been assigned and their types
        let mut region_types = [MemoryRegionType::UNMAPPED; 16];
        let mut region_assigned = [false; 16];

        // Helper function to process a memory region
        let mut process_region = |offset: u32, size: u32, region_type: MemoryRegionType| {
            if size == 0 {
                return;
            }

            let start_region = Self::get_mrac_region(offset);
            let end_address = offset.saturating_add(size).saturating_sub(1);
            let end_region = Self::get_mrac_region(end_address);

            // Apply region type to all affected MRAC regions
            for region_idx in start_region..=end_region.min(15) {
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
                        #[cfg(debug_assertions)]
                        {
                            println!("MRAC WARNING: Region {} (0x{:x}000_0000) has both MEMORY and MMIO - choosing MMIO for safety", region_idx, region_idx);
                        }
                        region_types[region_idx] = MemoryRegionType::MMIO;
                    }
                    // If current is MMIO and new is MEMORY, keep MMIO (safety first)
                    (true, MemoryRegionType::MMIO, MemoryRegionType::MEMORY) => {
                        #[cfg(debug_assertions)]
                        {
                            println!("MRAC WARNING: Region {} (0x{:x}000_0000) has both MMIO and MEMORY - keeping MMIO for safety", region_idx, region_idx);
                        }
                        // Keep existing MMIO type
                    }
                    // For any other combination, keep the existing type
                    _ => {}
                }
            }
        };

        // Process each memory region directly from the memory map
        process_region(self.rom_offset, self.rom_size, self.rom_properties);
        process_region(self.sram_offset, self.sram_size, self.sram_properties);
        process_region(self.dccm_offset, self.dccm_size, self.dccm_properties);
        process_region(self.pic_offset, 0x1000, self.pic_properties); // PIC doesn't have explicit size, use 4KB
        process_region(self.i3c_offset, self.i3c_size, self.i3c_properties);
        process_region(self.mci_offset, self.mci_size, self.mci_properties);
        process_region(self.mbox_offset, self.mbox_size, self.mbox_properties);
        process_region(self.soc_offset, self.soc_size, self.soc_properties);
        process_region(self.otp_offset, self.otp_size, self.otp_properties);
        process_region(self.lc_offset, self.lc_size, self.lc_properties);

        // Build the 32-bit MRAC value
        let mut mrac_value = 0u32;
        for (i, region_type) in region_types.iter().enumerate() {
            let bits = (if region_type.side_effect { 2 } else { 0 })
                | (if region_type.cacheable { 1 } else { 0 });
            mrac_value |= bits << (i * 2);
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
