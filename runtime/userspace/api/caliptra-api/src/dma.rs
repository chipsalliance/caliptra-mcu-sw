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
//!
//! However, the MCU local address space and SRAM size differ depending on the platform:
//! - **Emulator**: Local SRAM base is `0x4000_0000`, size is 1024 KiB (or 512 KiB in release layout).
//! - **FPGA**: Local SRAM base is `0xA8C0_0000`, size is 512 KiB.
//!
//! To allow Caliptra Core to DMA directly into a buffer allocated in MCU SRAM,
//! local SRAM addresses must be validated (alignment, bounds) and translated to their
//! subsystem AXI equivalents.
//!
//! # Note on DMA Abstractions
//! The userspace syscall crate provides [`caliptra_mcu_libsyscall_caliptra::dma::DMAMapping`]
//! for the MCU's internal AXI CDMA controller (`mcu_sram_to_mcu_axi` and `cptra_axi_to_mcu_axi`).
//! In contrast, [`AxiDmaConfig`] and [`AxiDmaTarget`] handle address translation for Caliptra
//! Core's internal DMA engine, which acts as a master on the subsystem AXI interconnect.

use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

/// Base address of the MCI on the subsystem AXI bus.
pub const MCI_BASE_AXI_ADDRESS: u32 = 0xA800_0000;

/// Offset of MCU SRAM within MCI address space (12 MiB).
pub const MCU_SRAM_AXI_OFFSET: u32 = 0x00C0_0000;

/// Subsystem AXI bus base address for MCU SRAM as accessed by Caliptra DMA.
pub const MCU_SRAM_AXI_BASE: u32 = MCI_BASE_AXI_ADDRESS + MCU_SRAM_AXI_OFFSET; // 0xA8C0_0000

/// Hardware memory configuration for Caliptra subsystem AXI DMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxiDmaConfig {
    /// Physical base address of MCU SRAM in the MCU's local address space.
    pub local_sram_base: u32,
    /// Physical base address of MCU SRAM on the Caliptra subsystem AXI bus.
    pub axi_sram_base: u32,
    /// Total size of MCU SRAM in bytes.
    pub sram_size: u32,
}

impl AxiDmaConfig {
    /// Standard configuration for the emulator platform.
    pub const EMULATOR: Self = Self {
        local_sram_base: 0x4000_0000,
        axi_sram_base: MCU_SRAM_AXI_BASE,
        sram_size: 1024 * 1024,
    };

    /// Standard configuration for the FPGA platform.
    pub const FPGA: Self = Self {
        local_sram_base: 0xA8C0_0000,
        axi_sram_base: MCU_SRAM_AXI_BASE,
        sram_size: 512 * 1024,
    };

    /// Default configuration for the active build target.
    #[cfg(feature = "fpga")]
    pub const DEFAULT: Self = Self::FPGA;
    #[cfg(not(feature = "fpga"))]
    pub const DEFAULT: Self = Self::EMULATOR;

    /// Translates an MCU local SRAM buffer into an [`AxiDmaTarget`].
    ///
    /// # Errors
    /// Returns [`INVARIANT`] if:
    /// - `buf.len() == 0` (DMA engine requires non-zero transfer size)
    /// - `buf.as_ptr()` is not 4-byte word aligned
    /// - `buf.len()` is not a multiple of 4 bytes
    /// - `buf` starts before `self.local_sram_base`
    /// - `buf` extends beyond the upper bound of MCU SRAM (`self.sram_size`)
    /// - Address arithmetic overflows
    pub fn translate(&self, buf: &[u8]) -> McuResult<AxiDmaTarget> {
        self.translate_ptr(buf.as_ptr(), buf.len())
    }

    /// Translates a raw pointer and length in MCU local SRAM into an [`AxiDmaTarget`].
    pub fn translate_ptr(&self, ptr: *const u8, len: usize) -> McuResult<AxiDmaTarget> {
        if len == 0 {
            return Err(INVARIANT);
        }

        let local_addr = ptr as u32;

        // The DMA engine requires word alignment for both start address and transfer count.
        if (local_addr % 4 != 0) || (len % 4 != 0) {
            return Err(INVARIANT);
        }

        let sram_offset = local_addr
            .checked_sub(self.local_sram_base)
            .ok_or(INVARIANT)?;

        let max_size = u32::try_from(len).map_err(|_| INVARIANT)?;

        // Ensure buffer does not extend past the upper bound of MCU SRAM.
        let end_offset = sram_offset.checked_add(max_size).ok_or(INVARIANT)?;
        if end_offset > self.sram_size {
            return Err(INVARIANT);
        }

        let addr = self
            .axi_sram_base
            .checked_add(sram_offset)
            .ok_or(INVARIANT)?;

        Ok(AxiDmaTarget { addr, max_size })
    }
}

/// Validated target buffer configuration for Caliptra subsystem AXI DMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxiDmaTarget {
    /// 32-bit AXI address for the start of the buffer.
    pub addr: u32,
    /// Maximum buffer size in bytes available for DMA transfer.
    pub max_size: u32,
}

impl AxiDmaTarget {
    /// Translates an MCU local SRAM buffer into an [`AxiDmaTarget`] using the default platform configuration.
    #[inline]
    pub fn from_mcu_sram(buf: &[u8]) -> McuResult<Self> {
        AxiDmaConfig::DEFAULT.translate(buf)
    }

    /// Translates an MCU local SRAM buffer into an [`AxiDmaTarget`] using an explicit configuration.
    #[inline]
    pub fn from_mcu_sram_with_config(buf: &[u8], config: &AxiDmaConfig) -> McuResult<Self> {
        config.translate(buf)
    }

    /// Returns the `(axi_addr, max_size)` tuple format expected by DPE invoke commands.
    #[inline]
    pub fn as_tuple(&self) -> (u32, u32) {
        (self.addr, self.max_size)
    }
}

/// Helper function to translate an MCU local SRAM buffer into an `(axi_addr, max_size)` tuple
/// using the default platform configuration.
#[inline]
pub fn mcu_sram_to_axi_dma(buf: &[u8]) -> McuResult<(u32, u32)> {
    AxiDmaTarget::from_mcu_sram(buf).map(|t| t.as_tuple())
}

/// Helper function to translate an MCU local SRAM buffer into an `(axi_addr, max_size)` tuple
/// using an explicit configuration.
#[inline]
pub fn mcu_sram_to_axi_dma_with_config(buf: &[u8], config: &AxiDmaConfig) -> McuResult<(u32, u32)> {
    AxiDmaTarget::from_mcu_sram_with_config(buf, config).map(|t| t.as_tuple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MCI_BASE_AXI_ADDRESS, 0xA800_0000);
        assert_eq!(MCU_SRAM_AXI_OFFSET, 0x00C0_0000);
        assert_eq!(MCU_SRAM_AXI_BASE, 0xA8C0_0000);
    }

    #[test]
    fn test_emulator_config_valid_translation() {
        let ptr = (AxiDmaConfig::EMULATOR.local_sram_base + 0x1000) as *const u8;
        let target = AxiDmaConfig::EMULATOR.translate_ptr(ptr, 4096).unwrap();
        assert_eq!(target.addr, MCU_SRAM_AXI_BASE + 0x1000);
        assert_eq!(target.max_size, 4096);
        assert_eq!(target.as_tuple(), (0xA8C0_1000, 4096));
    }

    #[test]
    fn test_fpga_config_valid_translation() {
        let ptr = (AxiDmaConfig::FPGA.local_sram_base + 0x1000) as *const u8;
        let target = AxiDmaConfig::FPGA.translate_ptr(ptr, 4096).unwrap();
        assert_eq!(target.addr, 0xA8C0_1000);
        assert_eq!(target.max_size, 4096);
        assert_eq!(target.as_tuple(), (0xA8C0_1000, 4096));
    }

    #[test]
    fn test_disallow_zero_length() {
        let ptr = AxiDmaConfig::EMULATOR.local_sram_base as *const u8;
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(ptr, 0).is_err());
    }

    #[test]
    fn test_alignment_requirements() {
        let aligned_ptr = AxiDmaConfig::EMULATOR.local_sram_base as *const u8;
        let unaligned_ptr = (AxiDmaConfig::EMULATOR.local_sram_base + 1) as *const u8;

        // Unaligned pointer rejected
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(unaligned_ptr, 4)
            .is_err());
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(unaligned_ptr, 16)
            .is_err());

        // Aligned pointer with unaligned lengths rejected
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(aligned_ptr, 1)
            .is_err());
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(aligned_ptr, 2)
            .is_err());
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(aligned_ptr, 3)
            .is_err());
        assert!(AxiDmaConfig::EMULATOR
            .translate_ptr(aligned_ptr, 5)
            .is_err());

        // Aligned pointer with aligned length accepted
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(aligned_ptr, 4).is_ok());
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(aligned_ptr, 8).is_ok());
    }

    #[test]
    fn test_lower_bound_rejection() {
        let ptr = (AxiDmaConfig::EMULATOR.local_sram_base - 4) as *const u8;
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(ptr, 4).is_err());
    }

    #[test]
    fn test_upper_bound_rejection() {
        let base = AxiDmaConfig::EMULATOR.local_sram_base;
        let sram_size = AxiDmaConfig::EMULATOR.sram_size;

        // Exactly fitting buffer at end of SRAM
        let ptr_last = (base + sram_size - 4) as *const u8;
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(ptr_last, 4).is_ok());

        // Exceeding buffer by 4 bytes
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(ptr_last, 8).is_err());

        // Buffer starting at or beyond end of SRAM
        let ptr_past = (base + sram_size) as *const u8;
        assert!(AxiDmaConfig::EMULATOR.translate_ptr(ptr_past, 4).is_err());
    }

    #[test]
    fn test_with_config_helpers() {
        let ptr = (AxiDmaConfig::FPGA.local_sram_base + 0x2000) as *const u8;
        let target = AxiDmaConfig::FPGA.translate_ptr(ptr, 64).unwrap();
        assert_eq!(target.as_tuple(), (0xA8C0_2000, 64));
    }
}
