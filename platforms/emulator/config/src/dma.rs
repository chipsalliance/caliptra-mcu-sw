// Licensed under the Apache-2.0 license

/// Convert a local address in MCU SRAM to an AXI address
/// addressable by the DMA controller.
pub fn mcu_sram_to_axi_address(addr: u32) -> u64 {
    const MCU_SRAM_HI_OFFSET: u64 = 0x1000_0000;
    // Convert a local address to an AXI address
    (MCU_SRAM_HI_OFFSET << 32) | (addr as u64)
}

// Convert Caliptra's AXI address to this device DMA address
pub enum DmaAddrError {
    InvalidAxiAddress,
}

pub fn caliptra_axi_addr_to_dma_addr(addr: u64) -> Result<u64, DmaAddrError> {
    // Caliptra's External SRAM is mapped at 0x0000_0000_8000_0000
    // that is mapped to this device's DMA 0x2000_0000_8000_0000
    const CALIPTRA_EXTERNAL_SRAM_BASE: u64 = 0x0000_0000_8000_0000;
    const DEVICE_EXTERNAL_SRAM_BASE: u64 = 0x2000_0000_0000_0000;
    if addr < CALIPTRA_EXTERNAL_SRAM_BASE {
        return Err(DmaAddrError::InvalidAxiAddress);
    }

    Ok(addr - CALIPTRA_EXTERNAL_SRAM_BASE + DEVICE_EXTERNAL_SRAM_BASE)
}
