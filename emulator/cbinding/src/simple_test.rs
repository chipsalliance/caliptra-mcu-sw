/*++

Licensed under the Apache-2.0 license.

File Name:

    simple_test.rs

Abstract:

    Simple test to verify the C bindings can be compiled.

--*/

use caliptra_image_types::FwVerificationPqcKeyType;
use emulator::{Emulator, EmulatorArgs};

#[test]
fn test_can_import_emulator() {
    // This test just verifies we can import the emulator types
    let size = std::mem::size_of::<Emulator>();
    let align = std::mem::align_of::<Emulator>();

    println!("Emulator size: {}, alignment: {}", size, align);

    assert!(size > 0);
    assert!(align > 0);
}

#[test]
fn test_emulator_args_creation() {
    // Test that we can create EmulatorArgs
    use std::path::PathBuf;

    let _args = EmulatorArgs {
        rom: PathBuf::from("test_rom.bin"),
        firmware: PathBuf::from("test_firmware.bin"),
        caliptra_rom: PathBuf::from("test_caliptra_rom.bin"),
        caliptra_firmware: PathBuf::from("test_caliptra_firmware.bin"),
        soc_manifest: PathBuf::from("test_soc_manifest.bin"),
        otp: None,
        gdb_port: None,
        log_dir: None,
        trace_instr: false,
        stdin_uart: false,
        _no_stdin_uart: false,
        i3c_port: None,
        manufacturing_mode: false,
        vendor_pk_hash: None,
        vendor_pqc_type: FwVerificationPqcKeyType::LMS,
        owner_pk_hash: None,
        streaming_boot: None,
        primary_flash_image: None,
        secondary_flash_image: None,
        hw_revision: semver::Version::new(2, 0, 0),
        rom_offset: None,
        rom_size: None,
        uart_offset: None,
        uart_size: None,
        ctrl_offset: None,
        ctrl_size: None,
        sram_offset: None,
        sram_size: None,
        pic_offset: None,
        external_test_sram_offset: None,
        external_test_sram_size: None,
        dccm_offset: None,
        dccm_size: None,
        i3c_offset: None,
        i3c_size: None,
        primary_flash_offset: None,
        primary_flash_size: None,
        secondary_flash_offset: None,
        secondary_flash_size: None,
        mci_offset: None,
        mci_size: None,
        dma_offset: None,
        dma_size: None,
        mbox_offset: None,
        mbox_size: None,
        soc_offset: None,
        soc_size: None,
        otp_offset: None,
        otp_size: None,
        lc_offset: None,
        lc_size: None,
        fuse_soc_manifest_max_svn: None,
        fuse_soc_manifest_svn: None,
        fuse_vendor_hashes_prod_partition: None,
    };

    println!("EmulatorArgs created successfully");
}

#[test]
fn test_emulator_get_pc_function_exists() {
    // This test verifies that the emulator_get_pc function exists and can be called
    // We can't actually test it fully without creating a real emulator instance
    // which would require valid ROM/firmware files
    use crate::emulator_get_pc;
    use std::ptr;

    // Test with null pointer should return 0
    let result = unsafe { emulator_get_pc(ptr::null_mut()) };
    assert_eq!(result, 0);

    println!("emulator_get_pc function exists and handles null pointer correctly");
}

#[test]
fn test_offset_size_conversion() {
    // Test the new int64 to Option<u32> conversion logic
    use crate::convert_optional_offset_size;

    // Test -1 returns None (default)
    assert_eq!(convert_optional_offset_size(-1), None);

    // Test valid positive values
    assert_eq!(convert_optional_offset_size(0), Some(0));
    assert_eq!(convert_optional_offset_size(1024), Some(1024));
    assert_eq!(convert_optional_offset_size(0xFFFFFFFF), Some(0xFFFFFFFF));

    // Test negative values (other than -1) return None
    assert_eq!(convert_optional_offset_size(-2), None);
    assert_eq!(convert_optional_offset_size(-100), None);

    // Test values that exceed u32::MAX return None
    assert_eq!(convert_optional_offset_size(0x100000000), None);
    assert_eq!(convert_optional_offset_size(i64::MAX), None);

    println!("Offset/size conversion logic works correctly");
}
