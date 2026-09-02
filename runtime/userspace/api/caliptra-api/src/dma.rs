// Licensed under the Apache-2.0 license

//! Caliptra Subsystem AXI DMA address translation utilities.
//!
//! When Caliptra Core responds to DPE or mailbox commands using AXI DMA
//! (for example, transferring large ML-DSA-87 leaf certificates or exported CDIs),
//! it operates as a bus master on the subsystem AXI interconnect.
//!
//! According to the Caliptra Subsystem Integration Specification:
//! - MCI (Microcontroller Interface) base address on the AXI bus: `0xA800_0000`
//! - MCU SRAM offset within MCI: `0x00C0_0000` (12 MiB)
//! - MCU SRAM base address on the AXI bus: `0xA8C0_0000`
//! - MCU SRAM base address in the MCU's local address space: `0x4000_0000`
//!
//! To allow Caliptra Core to DMA directly into a buffer allocated in MCU SRAM,
//! local SRAM addresses must be translated to their subsystem AXI equivalents.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

/// Physical base address of MCU SRAM from the MCU's local memory map.
pub const MCU_SRAM_LOCAL_BASE: u32 = 0x4000_0000;

/// Base address of the MCI on the subsystem AXI bus.
pub const MCI_BASE_AXI_ADDRESS: u32 = 0xA800_0000;

/// Offset of MCU SRAM within MCI address space (12 MiB).
pub const MCU_SRAM_AXI_OFFSET: u32 = 0x00C0_0000;

/// Subsystem AXI bus base address for MCU SRAM as accessed by Caliptra DMA.
pub const MCU_SRAM_AXI_BASE: u32 = MCI_BASE_AXI_ADDRESS + MCU_SRAM_AXI_OFFSET; // 0xA8C0_0000

/// Validated target buffer configuration for Caliptra subsystem AXI DMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxiDmaTarget {
    /// 32-bit AXI address for the start of the buffer.
    pub addr: u32,
    /// Maximum buffer size in bytes available for DMA transfer.
    pub max_size: u32,
}

impl AxiDmaTarget {
    /// Translates an MCU local SRAM buffer into an [`AxiDmaTarget`].
    ///
    /// Returns [`INVARIANT`] if the buffer is not located within MCU local SRAM
    /// (`< MCU_SRAM_LOCAL_BASE`), if pointer arithmetic overflows, or if the buffer
    /// length cannot fit in a `u32`.
    pub fn from_mcu_sram(buf: &[u8]) -> McuResult<Self> {
        Self::from_mcu_sram_ptr(buf.as_ptr(), buf.len())
    }

    /// Translates a raw pointer and length in MCU local SRAM into an [`AxiDmaTarget`].
    pub fn from_mcu_sram_ptr(ptr: *const u8, len: usize) -> McuResult<Self> {
        let local_addr = ptr as u32;
        let sram_offset = local_addr
            .checked_sub(MCU_SRAM_LOCAL_BASE)
            .ok_or(INVARIANT)?;
        let addr = MCU_SRAM_AXI_BASE
            .checked_add(sram_offset)
            .ok_or(INVARIANT)?;
        let max_size = u32::try_from(len).map_err(|_| INVARIANT)?;
        Ok(Self { addr, max_size })
    }

    /// Returns the `(axi_addr, max_size)` tuple format expected by DPE invoke commands.
    #[inline]
    pub fn as_tuple(&self) -> (u32, u32) {
        (self.addr, self.max_size)
    }
}

/// Helper function to translate an MCU local SRAM buffer into an `(axi_addr, max_size)` tuple.
#[inline]
pub fn mcu_sram_to_axi_dma(buf: &[u8]) -> McuResult<(u32, u32)> {
    AxiDmaTarget::from_mcu_sram(buf).map(|t| t.as_tuple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MCU_SRAM_LOCAL_BASE, 0x4000_0000);
        assert_eq!(MCI_BASE_AXI_ADDRESS, 0xA800_0000);
        assert_eq!(MCU_SRAM_AXI_OFFSET, 0x00C0_0000);
        assert_eq!(MCU_SRAM_AXI_BASE, 0xA8C0_0000);
    }

    #[test]
    fn test_valid_sram_translation() {
        let ptr = (MCU_SRAM_LOCAL_BASE + 0x1000) as *const u8;
        let target = AxiDmaTarget::from_mcu_sram_ptr(ptr, 4096).unwrap();
        assert_eq!(target.addr, MCU_SRAM_AXI_BASE + 0x1000);
        assert_eq!(target.max_size, 4096);
        assert_eq!(target.as_tuple(), (0xA8C0_1000, 4096));
    }

    #[test]
    fn test_sram_base_translation() {
        let ptr = MCU_SRAM_LOCAL_BASE as *const u8;
        let target = AxiDmaTarget::from_mcu_sram_ptr(ptr, 0).unwrap();
        assert_eq!(target.addr, MCU_SRAM_AXI_BASE);
        assert_eq!(target.max_size, 0);
        assert_eq!(target.as_tuple(), (0xA8C0_0000, 0));
    }

    #[test]
    fn test_invalid_address_below_sram_base() {
        let ptr = (MCU_SRAM_LOCAL_BASE - 1) as *const u8;
        assert!(AxiDmaTarget::from_mcu_sram_ptr(ptr, 100).is_err());
    }

    #[test]
    fn test_mcu_sram_to_axi_dma_helper() {
        let sim_ptr = (MCU_SRAM_LOCAL_BASE + 0x500) as *const u8;
        let target = AxiDmaTarget::from_mcu_sram_ptr(sim_ptr, 128).unwrap();
        assert_eq!(target.as_tuple(), (0xA8C0_0500, 128));
    }
}
