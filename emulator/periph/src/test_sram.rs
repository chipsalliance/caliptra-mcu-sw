// Licensed under the Apache-2.0 license

//! Test SRAM Peripheral Implementation
//!
//! This module provides a concrete implementation of the TestSramPeripheral trait
//! for emulation purposes. It manages a large SRAM region (1MB) that can be used
//! for testing and validation in the emulator environment.

use caliptra_emu_bus::{Event, Ram};
use caliptra_emu_types::RvData;
use emulator_registers_generated::test_sram::TestSramPeripheral;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::mpsc;

/// Test SRAM implementation providing 1MB of SRAM for testing purposes
///
/// This peripheral implements the TestSramPeripheral trait and provides:
/// - 1MB of addressable SRAM (262,144 32-bit words)
/// - Direct SRAM storage using Vec<RvData>
/// - Event handling for communication with Caliptra and MCU
/// - Proper reset behavior (warm and update resets)
pub struct TestSram {
    /// Optional shared DMA RAM reference
    dma_ram: Option<Rc<RefCell<Ram>>>,
    
    /// Event channels for communication with Caliptra
    events_to_caliptra: Option<mpsc::Sender<Event>>,
    events_from_caliptra: Option<mpsc::Receiver<Event>>,
    
    /// Event channels for communication with MCU
    events_to_mcu: Option<mpsc::Sender<Event>>,
    events_from_mcu: Option<mpsc::Receiver<Event>>,
}

impl TestSram {
    /// Create a new TestSram instance
    pub fn new() -> Self {
        Self {
            dma_ram: None,
            events_to_caliptra: None,
            events_from_caliptra: None,
            events_to_mcu: None,
            events_from_mcu: None,
        }
    }

    /// Get the size of the SRAM in bytes
    pub const fn size_bytes() -> usize {
        262144 * 4 // 262,144 words * 4 bytes per word = 1MB
    }

    /// Get the size of the SRAM in words
    pub const fn size_words() -> usize {
        262144
    }

    /// Clear all SRAM contents (set to zero)
    pub fn clear(&mut self) {
        if let Some(ref dma_ram) = self.dma_ram {
            let mut ram = dma_ram.borrow_mut();
            let data = ram.data_mut();
            data.fill(0);
        }
    }

    /// Fill SRAM with a pattern (useful for testing)
    pub fn fill_pattern(&mut self, pattern: u32) {
        for i in 0..Self::size_words() {
            self.write_sram(pattern.wrapping_add(i as u32), i);
        }
    }

    /// Read a range of SRAM contents
    pub fn read_range(&mut self, start_word: usize, count: usize) -> Vec<u32> {
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let word_index = start_word + i;
            result.push(self.read_sram(word_index));
        }
        result
    }

    /// Write a range of SRAM contents
    pub fn write_range(&mut self, start_word: usize, data: &[u32]) {
        for (i, &value) in data.iter().enumerate() {
            let word_index = start_word + i;
            self.write_sram(value, word_index);
        }
    }
}

impl TestSramPeripheral for TestSram {
    /// Set the DMA RAM reference for potential DMA operations
    fn set_dma_ram(&mut self, ram: Rc<RefCell<Ram>>) {
        self.dma_ram = Some(ram);
    }

    /// Set the DMA ROM SRAM reference for potential DMA operations
    fn set_dma_rom_sram(&mut self, _ram: Rc<RefCell<Ram>>) {
        // Not used in this simple implementation
    }

    /// Get a mutable reference to the generated implementation
    fn generated(&mut self) -> Option<&mut emulator_registers_generated::test_sram::TestSramGenerated> {
        None // We're not using the generated implementation
    }

    /// Register event channels for communication with Caliptra and MCU
    fn register_event_channels(
        &mut self,
        events_to_caliptra: mpsc::Sender<Event>,
        events_from_caliptra: mpsc::Receiver<Event>,
        events_to_mcu: mpsc::Sender<Event>,
        events_from_mcu: mpsc::Receiver<Event>,
    ) {
        self.events_to_caliptra = Some(events_to_caliptra);
        self.events_from_caliptra = Some(events_from_caliptra);
        self.events_to_mcu = Some(events_to_mcu);
        self.events_from_mcu = Some(events_from_mcu);
    }

    /// Poll the peripheral for any pending operations
    fn poll(&mut self) {}

    /// Handle warm reset - typically preserves some state
    fn warm_reset(&mut self) {
        // For test SRAM, we might want to preserve contents during warm reset
        // This matches typical SRAM behavior where contents are preserved
        // unless power is lost
        
        // Reset event channels but preserve SRAM contents
        self.events_to_caliptra = None;
        self.events_from_caliptra = None;
        self.events_to_mcu = None;
        self.events_from_mcu = None;
        
        // Note: SRAM contents are intentionally preserved
    }

    /// Handle update reset - typically clears all state
    fn update_reset(&mut self) {
        // Clear event channels
        self.events_to_caliptra = None;
        self.events_from_caliptra = None;
        self.events_to_mcu = None;
        self.events_from_mcu = None;
        
        // Clear SRAM contents for update reset
        if let Some(ref dma_ram) = self.dma_ram {
            let mut ram = dma_ram.borrow_mut();
            let data = ram.data_mut();
            data.fill(0);
        }
    }

    /// Read a word from SRAM at the specified index
    fn read_sram(&mut self, index: usize) -> RvData {
        if index >= Self::size_words() {
            return 0; // Out of bounds
        }

        if let Some(ref dma_ram) = self.dma_ram {
            let ram = dma_ram.borrow();
            let byte_offset = index * 4;
            
            if byte_offset + 4 <= ram.data().len() {
                // Read 4 bytes and combine into a 32-bit word (little-endian)
                let bytes = &ram.data()[byte_offset..byte_offset + 4];
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            } else {
                0 // Out of bounds
            }
        } else {
            0 // No RAM configured
        }
    }

    /// Write a word to SRAM at the specified index
    fn write_sram(&mut self, val: RvData, index: usize) {
        if index >= Self::size_words() {
            return; // Silently ignore out-of-bounds writes
        }

        if let Some(ref dma_ram) = self.dma_ram {
            let mut ram = dma_ram.borrow_mut();
            let byte_offset = index * 4;
            
            if byte_offset + 4 <= ram.data_mut().len() {
                // Write 4 bytes from the 32-bit word (little-endian)
                let bytes = val.to_le_bytes();
                ram.data_mut()[byte_offset..byte_offset + 4].copy_from_slice(&bytes);
            }
        }
    }
}

impl Default for TestSram {
    fn default() -> Self {
        let mut sram = Self::new();
        // Initialize with a default RAM if none is provided
        sram.dma_ram = Some(Rc::new(RefCell::new(Ram::new(vec![0u8; Self::size_bytes()]))));
        sram
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sram_basic_operations() {
        let mut sram = TestSram::default();

        // Test basic read/write
        sram.write_sram(0xDEADBEEF, 0);
        assert_eq!(sram.read_sram(0), 0xDEADBEEF);

        // Test different addresses
        sram.write_sram(0x12345678, 100);
        assert_eq!(sram.read_sram(100), 0x12345678);
        assert_eq!(sram.read_sram(0), 0xDEADBEEF); // Previous value should remain

        // Test bounds
        assert_eq!(sram.read_sram(TestSram::size_words() + 1), 0); // Out of bounds returns 0
    }

    #[test]
    fn test_sram_clear() {
        let mut sram = TestSram::default();

        // Write some data
        sram.write_sram(0xDEADBEEF, 0);
        sram.write_sram(0x12345678, 100);

        // Clear and verify
        sram.clear();
        assert_eq!(sram.read_sram(0), 0);
        assert_eq!(sram.read_sram(100), 0);
    }

    #[test]
    fn test_sram_fill_pattern() {
        let mut sram = TestSram::default();

        sram.fill_pattern(0x1000);
        assert_eq!(sram.read_sram(0), 0x1000);
        assert_eq!(sram.read_sram(1), 0x1001);
        assert_eq!(sram.read_sram(10), 0x100A);
    }

    #[test]
    fn test_sram_range_operations() {
        let mut sram = TestSram::default();

        let test_data = vec![0x11111111, 0x22222222, 0x33333333, 0x44444444];
        sram.write_range(10, &test_data);

        let read_data = sram.read_range(10, 4);
        assert_eq!(read_data, test_data);
    }

    #[test]
    fn test_sram_resets() {
        let mut sram = TestSram::default();

        // Write some data
        sram.write_sram(0xDEADBEEF, 0);

        // Warm reset should preserve data
        sram.warm_reset();
        assert_eq!(sram.read_sram(0), 0xDEADBEEF);

        // Update reset should clear data
        sram.update_reset();
        assert_eq!(sram.read_sram(0), 0);
    }
}
