/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

#![allow(unused_imports)]

use crate::io::{EMULATOR_EXITER, EMULATOR_WRITER, FATAL_ERROR_HANDLER};
use core::fmt::Write;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

use crate::flash::flash_boot_cfg::FlashBootCfg;
use crate::flash::flash_drv::{
    EmulatedFlashCtrl, PRIMARY_FLASH_CTRL_BASE, SECONDARY_FLASH_CTRL_BASE,
};
use mcu_config::boot::{BootConfig, BootConfigError, PartitionId, PartitionStatus, RollbackEnable};
use mcu_config::{McuMemoryMap, McuStraps};
use mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
use mcu_rom_common::flash::flash_partition::FlashPartition;
use mcu_rom_common::{fatal_error, RomParameters};
use romtime::HexWord;
use zerocopy::{FromBytes, IntoBytes};

// re-export these so the common ROM can use it
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_emulator::EMULATOR_MEMORY_MAP;

#[no_mangle]
#[used]
pub static MCU_STRAPS: McuStraps = mcu_config_emulator::EMULATOR_MCU_STRAPS;

pub extern "C" fn rom_entry() -> ! {
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut EMULATOR_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_exiter(&mut EMULATOR_EXITER);
    }

    if cfg!(feature = "test-flash-based-boot") {
        // Initialize the flash controller for testing purposes

        let primary_flash_ctrl = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let secondary_flash_ctrl =
            EmulatedFlashCtrl::initialize_flash_ctrl(SECONDARY_FLASH_CTRL_BASE);
        let mut partition_table_driver = FlashPartition::new(
            &primary_flash_ctrl,
            "Partition Table",
            PARTITION_TABLE.offset,
            PARTITION_TABLE.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();

        let boot_cfg = FlashBootCfg::new(&mut partition_table_driver);
        let active_partition = boot_cfg
            .get_active_partition()
            .map_err(|_| {
                fatal_error(1);
            })
            .ok()
            .unwrap();

        let partition_a = FlashPartition::new(
            &primary_flash_ctrl,
            "Image A",
            IMAGE_A_PARTITION.offset,
            IMAGE_A_PARTITION.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();
        let partition_b = FlashPartition::new(
            &secondary_flash_ctrl,
            "Image B",
            IMAGE_B_PARTITION.offset,
            IMAGE_B_PARTITION.size,
        )
        .map_err(|_| {
            fatal_error(1);
        })
        .ok()
        .unwrap();

        let mut flash_image_partition_driver = match active_partition {
            PartitionId::A => {
                romtime::println!("[mcu-rom] Booting from Partition A");
                partition_a
            }
            PartitionId::B => {
                romtime::println!("[mcu-rom] Booting from Partition B");
                partition_b
            }
            _ => fatal_error(1),
        };

        mcu_rom_common::rom_start(RomParameters {
            flash_partition_driver: Some(&mut flash_image_partition_driver),
            ..Default::default()
        });
    } else if cfg!(any(
        feature = "test-mcu-svn-gt-fuse",
        feature = "test-mcu-svn-lt-fuse"
    )) {
        use crate::mcu_image_verifier::McuImageVerifier;
        let mcu_image_verifier = McuImageVerifier;
        let rom_parameters = RomParameters {
            mcu_image_verifier: Some(&mcu_image_verifier),
            mcu_image_header_size: core::mem::size_of::<mcu_image_header::McuImageHeader>(),
            ..Default::default()
        };
        mcu_rom_common::rom_start(rom_parameters);
    } else {
        mcu_rom_common::rom_start(RomParameters::default());
    }

    #[cfg(feature = "test-mcu-rom-flash-access")]
    {
        let primary_flash_ctrl = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let test_par =
            FlashPartition::new(&primary_flash_ctrl, "TestPartition", 0x200_0000, 0x100_0000)
                .unwrap();
        crate::flash::flash_test::test_rom_flash_access(&test_par);
    }

    romtime::println!(
        "[mcu-rom] Jumping to firmware at {}",
        HexWord(MCU_MEMORY_MAP.sram_offset as u32)
    );
    exit_rom();
}

fn exit_rom() -> ! {
    unsafe {
        core::arch::asm! {
                "// Clear the stack
            la a0, STACK_ORIGIN      // dest
            la a1, STACK_SIZE        // len
            add a1, a1, a0
        1:
            sw zero, 0(a0)
            addi a0, a0, 4
            bltu a0, a1, 1b

            // Clear all registers
            li x1,  0; li x2,  0; li x3,  0; li x4,  0;
            li x5,  0; li x6,  0; li x7,  0; li x8,  0;
            li x9,  0; li x10, 0; li x11, 0; li x12, 0;
            li x13, 0; li x14, 0; li x15, 0; li x16, 0;
            li x17, 0; li x18, 0; li x19, 0; li x20, 0;
            li x21, 0; li x22, 0; li x23, 0; li x24, 0;
            li x25, 0; li x26, 0; li x27, 0; li x28, 0;
            li x29, 0; li x30, 0; li x31, 0;

            // jump to runtime
            li a3, 0x40000000
            jr a3",
                options(noreturn),
        }
    }
}
