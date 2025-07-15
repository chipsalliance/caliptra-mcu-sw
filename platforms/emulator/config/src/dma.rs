// Licensed under the Apache-2.0 license

/// Convert a local address in MCU SRAM to an AXI address
/// addressable by the DMA controller.
pub fn mcu_sram_to_axi_address(addr: u32) -> u64 {
    const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
    // Convert a local address to an AXI address
    (MCU_SRAM_HI_OFFSET << 32) | (addr as u64)
}
