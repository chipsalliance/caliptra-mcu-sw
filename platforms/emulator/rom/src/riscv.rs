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
use caliptra_mcu_config::boot::{
    BootConfig, BootConfigError, PartitionId, PartitionStatus, RollbackEnable,
};
use caliptra_mcu_config::{McuMemoryMap, McuStraps};
use caliptra_mcu_config_emulator::flash::{
    PartitionTable, StandAloneChecksumCalculator, IMAGE_A_PARTITION, IMAGE_B_PARTITION,
    PARTITION_TABLE,
};
use caliptra_mcu_rom_common::flash::flash_partition::FlashPartition;
use caliptra_mcu_rom_common::hil::FlashStorage;
use caliptra_mcu_rom_common::memory::SimpleFlash;
use caliptra_mcu_rom_common::{fatal_error, RomHooks, RomParameters};
use caliptra_mcu_rom_common::{DotRecoveryHandler, DOT_BLOB_SIZE};
use caliptra_mcu_romtime::HexWord;
use zerocopy::{transmute, FromBytes, IntoBytes};

/// DOT recovery handler using MCI mbox0.
/// Reads a backup DOT blob from offset 2048 in the DOT flash memory region.
struct TestDotRecoveryHandler {
    blob: [u8; DOT_BLOB_SIZE],
}

impl DotRecoveryHandler for TestDotRecoveryHandler {
    fn read_recovery_blob(&self) -> caliptra_mcu_error::McuResult<[u8; DOT_BLOB_SIZE]> {
        Ok(self.blob)
    }
}

/// Example `RomHooks` implementation: prints a distinctive tag for each
/// milestone so external observers (e.g. integration tests) can confirm
/// that the hook fired. Also records which hooks fired as a bitmask in
/// `mci_reg_fw_extended_error_info[0]` so a host-side test can verify
/// completion even when the UART output buffer is drained on boot.
/// Platforms that want to observe the boot flow (for debugging, timing,
/// telemetry, ...) can drop in their own implementation the same way.
struct LoggingRomHooks;

/// Offset of `mci_reg_fw_extended_error_info[0]` within the MCI register
/// block. This register is a writable 32-bit scratch word not touched by
/// the common ROM on a successful boot, so it is safe to repurpose for
/// test instrumentation.
const HOOK_BITMASK_OFFSET: usize = 0x70;

fn record_hook_bit(bit: u32) {
    // Safety: `MCU_MEMORY_MAP.mci_offset` is a linker-provided constant
    // and `fw_extended_error_info[0]` is a normal MMIO register. The
    // read-modify-write is safe because no other code on this core
    // accesses the register concurrently in a single-hart ROM.
    let addr = (MCU_MEMORY_MAP.mci_offset as usize + HOOK_BITMASK_OFFSET) as *mut u32;
    unsafe {
        let cur = core::ptr::read_volatile(addr);
        core::ptr::write_volatile(addr, cur | (1u32 << bit));
    }
}

impl RomHooks for LoggingRomHooks {
    fn pre_cold_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_cold_boot");
        record_hook_bit(0);
    }
    fn post_cold_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_cold_boot");
        record_hook_bit(1);
    }
    fn pre_warm_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_warm_boot");
        record_hook_bit(2);
    }
    fn post_warm_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_warm_boot");
        record_hook_bit(3);
    }
    fn pre_fw_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_fw_boot");
        record_hook_bit(4);
    }
    fn post_fw_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_fw_boot");
        record_hook_bit(5);
    }
    fn pre_fw_hitless_update(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_fw_hitless_update");
        record_hook_bit(6);
    }
    fn post_fw_hitless_update(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_fw_hitless_update");
        record_hook_bit(7);
    }
    fn pre_caliptra_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_caliptra_boot");
        record_hook_bit(8);
    }
    fn post_caliptra_boot(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_caliptra_boot");
        record_hook_bit(9);
    }
    fn pre_populate_fuses_to_caliptra(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_populate_fuses_to_caliptra");
        record_hook_bit(10);
    }
    fn post_populate_fuses_to_caliptra(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_populate_fuses_to_caliptra");
        record_hook_bit(11);
    }
    fn pre_load_firmware(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_load_firmware");
        record_hook_bit(12);
    }
    fn post_load_firmware(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_load_firmware");
        record_hook_bit(13);
    }
}

// re-export these so the common ROM can use it
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;

#[no_mangle]
#[used]
pub static MCU_STRAPS: McuStraps = caliptra_mcu_config_emulator::EMULATOR_MCU_STRAPS;

pub extern "C" fn rom_entry() -> ! {
    unsafe {
        #[allow(static_mut_refs)]
        caliptra_mcu_romtime::set_printer(&mut EMULATOR_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        caliptra_mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        caliptra_mcu_romtime::set_exiter(&mut EMULATOR_EXITER);
    }

    const EMULATOR_DOT_FLASH_ADDR: *mut u8 = 0x8100_0000 as *mut u8;
    const EMULATOR_DOT_FLASH_SIZE: usize = 4 * 1024;

    let raw_dot_flash = unsafe {
        core::slice::from_raw_parts_mut(EMULATOR_DOT_FLASH_ADDR, EMULATOR_DOT_FLASH_SIZE)
    };

    let dot_flash: &dyn FlashStorage = &SimpleFlash::new(raw_dot_flash);

    let axi_user0 = 0xcccc_ccccu32;
    let axi_user1 = 0xdddd_ddddu32;
    let mbox_axi_users = [axi_user0, axi_user1, 0, 0, 0];

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
        .unwrap_or_else(|_| fatal_error(EmulatorError::InitFlashPartitionDriver.into()));

        let boot_cfg = FlashBootCfg::new(&mut partition_table_driver);
        let active_partition = boot_cfg
            .get_active_partition()
            .unwrap_or_else(|_| fatal_error(EmulatorError::InitBootCfg.into()));

        let partition_a = FlashPartition::new(
            &primary_flash_ctrl,
            "Image A",
            IMAGE_A_PARTITION.offset,
            IMAGE_A_PARTITION.size,
        )
        .unwrap_or_else(|_| fatal_error(EmulatorError::InitFlashPartitionA.into()));
        let partition_b = FlashPartition::new(
            &secondary_flash_ctrl,
            "Image B",
            IMAGE_B_PARTITION.offset,
            IMAGE_B_PARTITION.size,
        )
        .unwrap_or_else(|_| fatal_error(EmulatorError::InitFlashPartitionB.into()));

        let mut flash_image_partition_driver = match active_partition {
            PartitionId::A => {
                caliptra_mcu_romtime::println!("[mcu-rom] Booting from Partition A");
                partition_a
            }
            PartitionId::B => {
                caliptra_mcu_romtime::println!("[mcu-rom] Booting from Partition B");
                partition_b
            }
            _ => fatal_error(EmulatorError::InvalidPartitionId.into()),
        };

        caliptra_mcu_rom_common::rom_start(RomParameters {
            flash_partition_driver: Some(&mut flash_image_partition_driver),
            dot_flash: Some(dot_flash),
            request_flash_boot: true,
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
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
            mcu_image_header_size: core::mem::size_of::<caliptra_mcu_image_header::McuImageHeader>(
            ),
            dot_flash: Some(dot_flash),
            otp_enable_integrity_check: true,
            otp_enable_consistency_check: true,
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            ..Default::default()
        };
        caliptra_mcu_rom_common::rom_start(rom_parameters);
    } else if cfg!(feature = "test-fw-manifest-dot") {
        caliptra_mcu_rom_common::rom_start(RomParameters {
            dot_flash: Some(dot_flash),
            fw_manifest_dot_enabled: true,
            otp_enable_integrity_check: true,
            otp_enable_consistency_check: true,
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            ..Default::default()
        });
    } else if cfg!(feature = "hw-2-1") {
        // Simple flash-based boot for hw-2-1 without partition tables.
        // Uses flash image starting at offset 0.
        let primary_flash_ctrl = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);

        // Create a flash partition covering the entire flash for direct access
        let mut flash_partition = FlashPartition::new(
            &primary_flash_ctrl,
            "Primary Flash",
            0, // Start at offset 0
            primary_flash_ctrl.capacity(),
        )
        .unwrap_or_else(|_| fatal_error(EmulatorError::InitFlashPartitionDriver.into()));

        caliptra_mcu_romtime::println!("[mcu-rom] Booting from flash");

        caliptra_mcu_rom_common::rom_start(RomParameters {
            flash_partition_driver: Some(&mut flash_partition),
            dot_flash: Some(dot_flash),
            // Let the generic wire (bit 29 of mci_reg_generic_input_wires[1]) control flash boot
            // request_flash_boot defaults to false - emulator sets the wire when flash boot is requested
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            ..Default::default()
        });
    } else {
        // Read backup blob from DOT flash region
        let recovery_backup_blob = {
            const RECOVERY_BLOB_OFFSET: usize = 2048;
            let mut blob = [0u8; DOT_BLOB_SIZE];
            let mut i = 0;
            while i < blob.len() {
                blob[i] = unsafe { *EMULATOR_DOT_FLASH_ADDR.add(RECOVERY_BLOB_OFFSET + i) };
                i += 1;
            }
            blob
        };
        let recovery_handler = TestDotRecoveryHandler {
            blob: recovery_backup_blob,
        };

        // Create MCI mbox0 transport for DOT recovery/override.
        let recovery_transport = {
            let mci_base: caliptra_mcu_romtime::StaticRef<
                caliptra_mcu_registers_generated::mci::regs::Mci,
            > = unsafe {
                caliptra_mcu_romtime::StaticRef::new(
                    MCU_MEMORY_MAP.mci_offset
                        as *const caliptra_mcu_registers_generated::mci::regs::Mci,
                )
            };
            caliptra_mcu_rom_common::Mbox0RecoveryTransport::new(mci_base)
        };

        let hooks = LoggingRomHooks;

        caliptra_mcu_rom_common::rom_start(RomParameters {
            dot_flash: Some(dot_flash),
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            dot_recovery_handler: if cfg!(feature = "test-dot-recovery") {
                Some(&recovery_handler)
            } else {
                None
            },
            dot_recovery_transport: if cfg!(feature = "test-dot-recovery") {
                Some(&recovery_transport)
            } else {
                None
            },
            i3c_services: if cfg!(feature = "test-i3c-services") {
                Some(caliptra_mcu_rom_common::I3cServicesModes::DOT_RECOVERY)
            } else {
                None
            },
            force_i3c_services: cfg!(feature = "test-i3c-services"),
            hooks: if cfg!(feature = "test-rom-hooks") {
                Some(&hooks)
            } else {
                None
            },
            ..Default::default()
        });
    }

    #[cfg(feature = "test-mcu-rom-flash-access")]
    {
        let primary_flash_ctrl = EmulatedFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);
        let test_par =
            FlashPartition::new(&primary_flash_ctrl, "TestPartition", 0x200_0000, 0x100_0000)
                .unwrap();
        crate::flash::flash_test::test_rom_flash_access(&test_par);
    }

    caliptra_mcu_romtime::println!(
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

enum EmulatorError {
    InitFlashPartitionDriver,
    InitBootCfg,
    InitFlashPartitionA,
    InitFlashPartitionB,
    InvalidPartitionId,
}

impl From<EmulatorError> for caliptra_mcu_error::McuError {
    fn from(err: EmulatorError) -> Self {
        Self::new_vendor(err as u32)
    }
}
