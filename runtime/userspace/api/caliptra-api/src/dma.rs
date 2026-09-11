// Licensed under the Apache-2.0 license

//! Caliptra Subsystem AXI DMA address translation utilities.
//!
//! When Caliptra Core responds to DPE or mailbox commands using AXI DMA
//! (for example, transferring large ML-DSA-87 leaf certificates or exported CDIs),
//! it operates as a bus master on the subsystem AXI interconnect.
//!
//! To allow Caliptra Core to DMA directly into a buffer allocated in MCU SRAM,
//! local SRAM addresses must be translated to their subsystem AXI equivalents.
//! The translation, word-alignment verification, and bounds checks are handled
//! by the kernel DMA driver via a syscall, configured at boot time with the
//! platform's memory map.

use caliptra_mcu_libsyscall_caliptra::dma::DMA;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

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
    #[inline]
    pub fn from_mcu_sram(buf: &[u8]) -> McuResult<Self> {
        let (addr, max_size) = mcu_sram_to_axi_dma(buf)?;
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
    DMA::<DefaultSyscalls>::new()
        .mcu_sram_to_cptra_axi(buf)
        .map_err(|_| INVARIANT)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use caliptra_mcu_libtock_unittest::fake;
    use std::rc::Rc;

    #[test]
    fn test_axi_dma_target_translation_success() {
        let kernel = fake::Kernel::new();
        let dma_driver = Rc::new(fake::FakeDMADriver::new());
        kernel.add_driver(&dma_driver);

        let buf = [0u32; 16];
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 4) };

        let target = AxiDmaTarget::from_mcu_sram(bytes).unwrap();
        assert_eq!(target.max_size, 64);
        assert_eq!(target.as_tuple(), (target.addr, 64));
    }

    #[test]
    fn test_axi_dma_target_disallow_zero_length() {
        let kernel = fake::Kernel::new();
        let dma_driver = Rc::new(fake::FakeDMADriver::new());
        kernel.add_driver(&dma_driver);

        let empty: &[u8] = &[];
        assert!(mcu_sram_to_axi_dma(empty).is_err());
    }

    #[test]
    fn test_axi_dma_target_unaligned_length_rejected() {
        let kernel = fake::Kernel::new();
        let dma_driver = Rc::new(fake::FakeDMADriver::new());
        kernel.add_driver(&dma_driver);

        let buf = [0u32; 16];
        let bytes: &[u8] = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, 15) };
        assert!(mcu_sram_to_axi_dma(bytes).is_err());
    }
}
