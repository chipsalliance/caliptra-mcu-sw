// Licensed under the Apache-2.0 license

//! Network Coprocessor Configuration Library
//!
//! This library defines the memory map and configuration for the Network Coprocessor,
//! which handles network boot recovery (DHCP/TFTP client functionality).
//!
//! The Network Coprocessor is a dedicated RISC-V CPU that communicates with the MCU
//! and handles network operations for firmware recovery.

#![cfg_attr(target_arch = "riscv32", no_std)]

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

/// Configures the memory map for the Network Coprocessor.
///
/// The Network Coprocessor has a simpler memory map than the MCU:
/// - ROM: Contains the network boot firmware (DHCP/TFTP client)
/// - ICCM: Instruction Closely Coupled Memory (fast instruction RAM)
/// - DCCM: Data Closely Coupled Memory (fast data RAM for stack/heap)
/// - UART: Debug output
/// - PIC: Interrupt controller
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NetworkMemoryMap {
    /// ROM base address
    pub rom_offset: u32,
    /// ROM size in bytes
    pub rom_size: u32,
    /// Stack size for ROM execution
    pub rom_stack_size: u32,
    /// Exception stack size
    pub rom_estack_size: u32,
    /// ROM memory properties
    pub rom_properties: MemoryRegionType,

    /// ICCM (Instruction Closely Coupled Memory) base address
    pub iccm_offset: u32,
    /// ICCM size in bytes
    pub iccm_size: u32,
    /// ICCM memory properties
    pub iccm_properties: MemoryRegionType,

    /// DCCM (Data Closely Coupled Memory) base address
    pub dccm_offset: u32,
    /// DCCM size in bytes
    pub dccm_size: u32,
    /// DCCM memory properties
    pub dccm_properties: MemoryRegionType,

    /// UART base address (for debug output)
    pub uart_offset: u32,
    /// UART size
    pub uart_size: u32,
    /// UART memory properties
    pub uart_properties: MemoryRegionType,

    /// Emulator control register base address
    pub ctrl_offset: u32,
    /// Emulator control register size
    pub ctrl_size: u32,
    /// Emulator control properties
    pub ctrl_properties: MemoryRegionType,

    /// PIC (Programmable Interrupt Controller) base address
    pub pic_offset: u32,
    /// PIC size
    pub pic_size: u32,
    /// PIC memory properties
    pub pic_properties: MemoryRegionType,

    /// Ethernet peripheral base address (for TAP network interface)
    pub eth_offset: u32,
    /// Ethernet peripheral size
    pub eth_size: u32,
    /// Ethernet peripheral memory properties
    pub eth_properties: MemoryRegionType,
}

impl Default for NetworkMemoryMap {
    fn default() -> Self {
        NetworkMemoryMap {
            // ROM at address 0x0 (64KB)
            rom_offset: 0x0000_0000,
            rom_size: 64 * 1024,
            rom_stack_size: 0x8000, // 32KB stack
            rom_estack_size: 0x200, // 512B exception stack
            rom_properties: MemoryRegionType::MEMORY,

            // ICCM at 0x4000_0000 (128KB)
            iccm_offset: 0x4000_0000,
            iccm_size: 128 * 1024,
            iccm_properties: MemoryRegionType::MEMORY,

            // DCCM at 0x5000_0000 (64KB)
            dccm_offset: 0x5000_0000,
            dccm_size: 64 * 1024,
            dccm_properties: MemoryRegionType::MEMORY,

            // UART for debug output
            uart_offset: 0x1000_1000,
            uart_size: 0x100,
            uart_properties: MemoryRegionType::MMIO,

            // Emulator control register
            ctrl_offset: 0x1000_2000,
            ctrl_size: 0x4,
            ctrl_properties: MemoryRegionType::MMIO,

            // PIC
            pic_offset: 0x6000_0000,
            pic_size: 0x5400,
            pic_properties: MemoryRegionType::MMIO,

            // Ethernet peripheral for TAP network interface
            eth_offset: 0x1000_3000,
            eth_size: 0x1000,
            eth_properties: MemoryRegionType::MMIO,
        }
    }
}

impl NetworkMemoryMap {
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
                        region_types[region_idx] = MemoryRegionType::MMIO;
                    }
                    // If current is MMIO and new is MEMORY, keep MMIO (safety first)
                    (true, MemoryRegionType::MMIO, MemoryRegionType::MEMORY) => {
                        // Keep existing MMIO type
                    }
                    // For any other combination, keep the existing type
                    _ => {}
                }
            }
        };

        // Process each memory region from the memory map
        process_region(self.rom_offset, self.rom_size, self.rom_properties);
        process_region(self.iccm_offset, self.iccm_size, self.iccm_properties);
        process_region(self.dccm_offset, self.dccm_size, self.dccm_properties);
        process_region(self.uart_offset, self.uart_size, self.uart_properties);
        process_region(self.ctrl_offset, self.ctrl_size, self.ctrl_properties);
        process_region(self.pic_offset, self.pic_size, self.pic_properties);
        process_region(self.eth_offset, self.eth_size, self.eth_properties);

        // Build the 32-bit MRAC value
        let mut mrac_value = 0u32;
        for (i, region_type) in region_types.iter().enumerate() {
            let bits = (if region_type.side_effect { 2 } else { 0 })
                | (if region_type.cacheable { 1 } else { 0 });
            mrac_value |= bits << (i * 2);
        }

        mrac_value
    }

    /// Generate a hash map of configuration values for linker script substitution
    #[cfg(not(target_arch = "riscv32"))]
    pub fn hash_map(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();

        // ROM configuration
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

        // ICCM configuration
        map.insert(
            "ICCM_OFFSET".to_string(),
            format!("0x{:x}", self.iccm_offset),
        );
        map.insert("ICCM_SIZE".to_string(), format!("0x{:x}", self.iccm_size));

        // DCCM configuration
        map.insert(
            "DCCM_OFFSET".to_string(),
            format!("0x{:x}", self.dccm_offset),
        );
        map.insert("DCCM_SIZE".to_string(), format!("0x{:x}", self.dccm_size));

        // UART configuration
        map.insert(
            "UART_OFFSET".to_string(),
            format!("0x{:x}", self.uart_offset),
        );
        map.insert("UART_SIZE".to_string(), format!("0x{:x}", self.uart_size));

        // Control register configuration
        map.insert(
            "CTRL_OFFSET".to_string(),
            format!("0x{:x}", self.ctrl_offset),
        );

        // PIC configuration
        map.insert("PIC_OFFSET".to_string(), format!("0x{:x}", self.pic_offset));

        // Ethernet configuration
        map.insert("ETH_OFFSET".to_string(), format!("0x{:x}", self.eth_offset));
        map.insert("ETH_SIZE".to_string(), format!("0x{:x}", self.eth_size));

        // The computed MRAC value
        map.insert(
            "MRAC_VALUE".to_string(),
            format!("0x{:x}", self.compute_mrac()),
        );

        map
    }
}

/// Default Network Coprocessor memory map for the emulator
pub const DEFAULT_NETWORK_MEMORY_MAP: NetworkMemoryMap = NetworkMemoryMap {
    rom_offset: 0x0000_0000,
    rom_size: 64 * 1024,
    rom_stack_size: 0x8000,
    rom_estack_size: 0x200,
    rom_properties: MemoryRegionType::MEMORY,

    iccm_offset: 0x4000_0000,
    iccm_size: 128 * 1024,
    iccm_properties: MemoryRegionType::MEMORY,

    dccm_offset: 0x5000_0000,
    dccm_size: 64 * 1024,
    dccm_properties: MemoryRegionType::MEMORY,

    uart_offset: 0x1000_1000,
    uart_size: 0x100,
    uart_properties: MemoryRegionType::MMIO,

    ctrl_offset: 0x1000_2000,
    ctrl_size: 0x4,
    ctrl_properties: MemoryRegionType::MMIO,

    pic_offset: 0x6000_0000,
    pic_size: 0x5400,
    pic_properties: MemoryRegionType::MMIO,

    eth_offset: 0x1000_3000,
    eth_size: 0x1000,
    eth_properties: MemoryRegionType::MMIO,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_memory_map() {
        let map = NetworkMemoryMap::default();
        assert_eq!(map.rom_offset, 0x0000_0000);
        assert_eq!(map.rom_size, 64 * 1024);
        assert_eq!(map.iccm_offset, 0x4000_0000);
        assert_eq!(map.iccm_size, 128 * 1024);
        assert_eq!(map.dccm_offset, 0x5000_0000);
        assert_eq!(map.dccm_size, 64 * 1024);
    }

    #[test]
    fn test_mrac_computation() {
        let memory_map = NetworkMemoryMap::default();
        let mrac_value = memory_map.compute_mrac();

        // Verify that the value is reasonable
        assert_ne!(mrac_value, 0);
        assert_ne!(mrac_value, 0xffffffff);

        // Region 0 (ROM at 0x0) should be cacheable (01)
        let region_0_bits = mrac_value & 0x3;
        assert_eq!(region_0_bits, 0x1, "ROM region should be cacheable (01)");

        // Region 4 (ICCM at 0x4000_0000) should be cacheable (01)
        let region_4_bits = (mrac_value >> (4 * 2)) & 0x3;
        assert_eq!(region_4_bits, 0x1, "ICCM region should be cacheable (01)");

        // Region 1 (UART at 0x1000_1000) should have side effects (10)
        let region_1_bits = (mrac_value >> 2) & 0x3;
        assert_eq!(
            region_1_bits, 0x2,
            "UART region should have side effects (10)"
        );

        println!("Computed MRAC value: 0x{:08x}", mrac_value);
    }

    #[test]
    fn test_hash_map() {
        let memory_map = NetworkMemoryMap::default();
        let hash_map = memory_map.hash_map();

        assert_eq!(hash_map.get("ROM_OFFSET").unwrap(), "0x0");
        assert_eq!(hash_map.get("ROM_SIZE").unwrap(), "0x10000");
        assert_eq!(hash_map.get("ICCM_OFFSET").unwrap(), "0x40000000");
        assert_eq!(hash_map.get("ICCM_SIZE").unwrap(), "0x20000");
        assert_eq!(hash_map.get("DCCM_OFFSET").unwrap(), "0x50000000");
        assert_eq!(hash_map.get("DCCM_SIZE").unwrap(), "0x10000");
    }
}
