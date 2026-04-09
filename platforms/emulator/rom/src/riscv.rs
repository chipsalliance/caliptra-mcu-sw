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
use mcu_rom_common::hil::FlashStorage;
use mcu_rom_common::memory::SimpleFlash;
use mcu_rom_common::{fatal_error, RomParameters};
use mcu_rom_common::{DotRecoveryHandler, DOT_BLOB_SIZE};
use romtime::HexWord;
use zerocopy::{transmute, FromBytes, IntoBytes};

/// DOT recovery handler using MCI mbox0.
/// Reads a backup DOT blob from offset 2048 in the DOT flash memory region.
struct TestDotRecoveryHandler {
    blob: [u8; DOT_BLOB_SIZE],
}

impl DotRecoveryHandler for TestDotRecoveryHandler {
    fn read_recovery_blob(&self) -> mcu_error::McuResult<[u8; DOT_BLOB_SIZE]> {
        Ok(self.blob)
    }
}

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

    const EMULATOR_DOT_FLASH_ADDR: *mut u8 = 0x8100_0000 as *mut u8;
    const EMULATOR_DOT_FLASH_SIZE: usize = 4 * 1024;

    let raw_dot_flash = unsafe {
        core::slice::from_raw_parts_mut(EMULATOR_DOT_FLASH_ADDR, EMULATOR_DOT_FLASH_SIZE)
    };

    let dot_flash: &dyn FlashStorage = &SimpleFlash::new(raw_dot_flash);

    let axi_user0 = 0xcccc_ccccu32;
    let axi_user1 = 0xdddd_ddddu32;
    let mbox_axi_users = [axi_user0, axi_user1, 0, 0, 0];

    // OTP digest IV and constant for the emulator.
    // These defaults are defined in the caliptra-ss RTL (otp_ctrl_part_pkg.sv).
    #[cfg(feature = "ocp-lock")]
    const EMULATOR_OTP_DIGEST_IV: u64 = 0x90C7F21F6224F027u64;
    #[cfg(feature = "ocp-lock")]
    const EMULATOR_OTP_DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266Fu128;

    #[cfg(feature = "ocp-lock")]
    struct EmulatorOcpPlatform;

    #[cfg(feature = "ocp-lock")]
    fn get_hek_partition(slot: usize) -> registers_generated::fuses::OtpPartitionInfo {
        registers_generated::fuses::OtpPartitionInfo {
            name: "cptra_ss_lock_hek_prod",
            byte_offset: registers_generated::fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET
                + slot * 48,
            byte_size: 40,
            sw_digest: true,
            hw_digest: false,
            digest_offset: None,
        }
    }

    #[cfg(feature = "ocp-lock")]
    impl romtime::ocp_lock::Platform for EmulatorOcpPlatform {
        // This sample implementation hard codes 8 slots.
        fn get_total_slots(&self) -> usize {
            8
        }

        // Sample only supports a subset of `HekSeedState`
        fn get_slot_state(
            &mut self,
            otp: &romtime::otp::Otp,
            perma_bit: &romtime::ocp_lock::PermaBitStatus,
            slot: usize,
            seed: &[u8; 48],
        ) -> Result<romtime::ocp_lock::HekSeedState, romtime::ocp_lock::Error> {
            if *perma_bit == romtime::ocp_lock::PermaBitStatus::Set {
                return Ok(romtime::ocp_lock::HekSeedState::Permanent);
            }
            if seed.iter().all(|&b| b == 0xFF) {
                return Ok(romtime::ocp_lock::HekSeedState::Sanitized);
            }
            if seed.iter().all(|&b| b == 0x0) {
                return Ok(romtime::ocp_lock::HekSeedState::Unused);
            }

            let partition = get_hek_partition(slot);
            let expected_digest: Result<&[u8; 8], _> = seed[32..40].try_into();
            match (
                expected_digest,
                otp.compute_sw_digest(
                    &partition,
                    EMULATOR_OTP_DIGEST_IV,
                    EMULATOR_OTP_DIGEST_CONST,
                ),
            ) {
                (Ok(expected_digest), Ok(computed_digest)) => {
                    let expected_digest = u64::from_le_bytes(*expected_digest);
                    if computed_digest != expected_digest {
                        romtime::println!(
                            "[mcu-rom-otp] HEK software digest mismatch! Slot {}",
                            slot
                        );
                        return Ok(romtime::ocp_lock::HekSeedState::ProgrammedCorrupted);
                    }
                }
                _ => return Err(romtime::ocp_lock::Error::INVALID_HEK_SLOT),
            }

            Ok(romtime::ocp_lock::HekSeedState::Programmed)
        }

        // Simple algorithm to determine the active slot.
        // Returns the first programmed.
        fn get_active_slot(
            &mut self,
            otp: &romtime::otp::Otp,
            perma_bit: &romtime::ocp_lock::PermaBitStatus,
            seeds: &romtime::ocp_lock::HekSeeds,
        ) -> Result<usize, romtime::ocp_lock::Error> {
            if *perma_bit == romtime::ocp_lock::PermaBitStatus::Set {
                // If the permanent bit is set, OCP LOCK spec says the active HEK is fixed.
                // For this emulator, we'll return the last slot.
                return Ok(self.get_total_slots() - 1);
            }

            for i in 0..seeds.len() {
                let buf = seeds
                    .get(i)
                    .ok_or(romtime::ocp_lock::Error::INVALID_HEK_SLOT)?;
                let state = self.get_slot_state(otp, perma_bit, i, buf)?;

                if state == romtime::ocp_lock::HekSeedState::Programmed {
                    return Ok(i);
                }
            }
            Err(romtime::ocp_lock::Error::EXHAUSTED_HEK_SLOTS)
        }
    }

    #[cfg(feature = "ocp-lock")]
    let mut ocp_platform = EmulatorOcpPlatform;

    #[cfg(feature = "ocp-lock")]
    let ocp_lock_config = romtime::ocp_lock::RomConfig {
        platform: Some(&mut ocp_platform),
        ..Default::default()
    };

    let hooks = LoggingRomHooks;

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
                romtime::println!("[mcu-rom] Booting from Partition A");
                partition_a
            }
            PartitionId::B => {
                romtime::println!("[mcu-rom] Booting from Partition B");
                partition_b
            }
            _ => fatal_error(EmulatorError::InvalidPartitionId.into()),
        };

        mcu_rom_common::rom_start(RomParameters {
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
            mcu_image_header_size: core::mem::size_of::<mcu_image_header::McuImageHeader>(),
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
        mcu_rom_common::rom_start(rom_parameters);
    } else if cfg!(any(
        feature = "test-fw-manifest-dot",
        feature = "test-fw-manifest-dot-hitless"
    )) {
        mcu_rom_common::rom_start(RomParameters {
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

        romtime::println!("[mcu-rom] Booting from flash");

        // Read backup blob from DOT flash region for test-dot-recovery feature
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

        // Create MCI mbox0 challenge/response transport for DOT recovery.
        let challenge_transport = {
            let mci_base: romtime::StaticRef<registers_generated::mci::regs::Mci> = unsafe {
                romtime::StaticRef::new(
                    MCU_MEMORY_MAP.mci_offset as *const registers_generated::mci::regs::Mci,
                )
            };
            mcu_rom_common::Mbox0RecoveryTransport::new(mci_base)
        };

        mcu_rom_common::rom_start(RomParameters {
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
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
            dot_recovery_handler: if cfg!(feature = "test-dot-recovery") {
                Some(&recovery_handler)
            } else {
                None
            },
            dot_recovery_transport: if cfg!(feature = "test-dot-recovery") {
                Some(&challenge_transport)
            } else {
                None
            },
            i3c_services: if cfg!(feature = "test-i3c-services") {
                Some(mcu_rom_common::I3cServicesModes::DOT_RECOVERY)
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
            let mci_base: romtime::StaticRef<registers_generated::mci::regs::Mci> = unsafe {
                romtime::StaticRef::new(
                    MCU_MEMORY_MAP.mci_offset as *const registers_generated::mci::regs::Mci,
                )
            };
            mcu_rom_common::Mbox0RecoveryTransport::new(mci_base)
        };

        mcu_rom_common::rom_start(RomParameters {
            dot_flash: Some(dot_flash),
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
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
                Some(mcu_rom_common::I3cServicesModes::DOT_RECOVERY)
            } else {
                None
            },
            force_i3c_services: cfg!(feature = "test-i3c-services"),
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

enum EmulatorError {
    InitFlashPartitionDriver,
    InitBootCfg,
    InitFlashPartitionA,
    InitFlashPartitionB,
    InvalidPartitionId,
}

impl From<EmulatorError> for mcu_error::McuError {
    fn from(err: EmulatorError) -> Self {
        Self::new_vendor(err as u32)
    }
}
