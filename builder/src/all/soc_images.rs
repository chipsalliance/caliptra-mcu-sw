// Licensed under the Apache-2.0 license

//! SoC image creation utilities.
//!
//! This module provides utilities for creating default SoC images
//! used in tests that require them.

use crate::ImageCfg;
use std::path::PathBuf;

/// MCI base address for SoC image load addresses.
/// Uses FPGA memory map since the emulator's AXI simulation uses FPGA-like addresses.
const MCI_BASE_AXI_ADDRESS: u64 = mcu_config_fpga::FPGA_MEMORY_MAP.mci_offset as u64;

/// MCU MBOX SRAM1 offset from MCI base.
/// Matches mcu_mbox_driver::MCU_MBOX1_SRAM_OFFSET (0x80_0000).
const MCU_MBOX_SRAM1_OFFSET: u64 = 0x80_0000;

/// Creates default SoC images for tests that require them.
///
/// Creates two simple test images with different patterns (0x55 and 0xAA)
/// that can be used for testing SoC image loading functionality.
///
/// # Returns
///
/// - `(Vec<ImageCfg>, Vec<PathBuf>)`: Tuple of (image configurations, image file paths).
pub fn create_default_soc_images() -> (Vec<ImageCfg>, Vec<PathBuf>) {
    let soc_image_fw_1 = vec![0x55u8; 512];
    let soc_image_fw_2 = vec![0xAAu8; 256];

    let soc_image_path_1 = std::env::temp_dir().join("default-soc-image-1.bin");
    let soc_image_path_2 = std::env::temp_dir().join("default-soc-image-2.bin");

    std::fs::write(&soc_image_path_1, &soc_image_fw_1).expect("Failed to write SoC image 1");
    std::fs::write(&soc_image_path_2, &soc_image_fw_2).expect("Failed to write SoC image 2");

    let soc_images = vec![
        ImageCfg {
            path: soc_image_path_1.clone(),
            load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET,
            image_id: 4096,
            component_id: 4096,
            exec_bit: 5,
            ..Default::default()
        },
        ImageCfg {
            path: soc_image_path_2.clone(),
            load_addr: MCI_BASE_AXI_ADDRESS + MCU_MBOX_SRAM1_OFFSET + soc_image_fw_1.len() as u64,
            image_id: 4097,
            component_id: 4097,
            exec_bit: 6,
            ..Default::default()
        },
    ];

    let soc_images_paths = vec![soc_image_path_1, soc_image_path_2];

    (soc_images, soc_images_paths)
}
