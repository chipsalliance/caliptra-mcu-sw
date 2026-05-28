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

/// Initialize a `MaybeUninit<T>` static via a raw pointer and return a
/// `&'static mut T` to its contents.
///
/// # Safety
///
/// `s` must point to a not-yet-initialized `MaybeUninit<T>`, and the
/// caller must hold exclusive access for the duration of this call.
unsafe fn init_static<T>(s: *mut core::mem::MaybeUninit<T>, value: T) -> &'static mut T {
    (*s).write(value)
}
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
    fn pre_set_ocp_lock_fuses(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_set_ocp_lock_fuses");
        record_hook_bit(14);
    }
    fn post_set_ocp_lock_fuses(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_set_ocp_lock_fuses");
        record_hook_bit(15);
    }
    fn pre_stable_owner_key_derivation(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_stable_owner_key_derivation");
        record_hook_bit(16);
    }
    fn post_stable_owner_key_derivation(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_stable_owner_key_derivation");
        record_hook_bit(17);
    }
    fn pre_encrypted_firmware_decrypt(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] pre_encrypted_firmware_decrypt");
        record_hook_bit(18);
    }
    fn post_encrypted_firmware_decrypt(&self) {
        caliptra_mcu_romtime::println!("[mcu-rom-hook] post_encrypted_firmware_decrypt");
        record_hook_bit(19);
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

    // OTP digest IV and constant for the emulator.
    // These defaults are defined in the caliptra-ss RTL (otp_ctrl_part_pkg.sv).
    #[cfg(feature = "ocp-lock")]
    const EMULATOR_OTP_DIGEST_IV: u64 = 0x90C7F21F6224F027u64;
    #[cfg(feature = "ocp-lock")]
    const EMULATOR_OTP_DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266Fu128;

    #[cfg(feature = "ocp-lock")]
    struct EmulatorOcpPlatform;

    #[cfg(feature = "ocp-lock")]
    fn get_hek_partition(slot: usize) -> caliptra_mcu_registers_generated::fuses::OtpPartitionInfo {
        caliptra_mcu_registers_generated::fuses::OtpPartitionInfo {
            name: "cptra_ss_lock_hek_prod",
            byte_offset:
                caliptra_mcu_registers_generated::fuses::CPTRA_SS_LOCK_HEK_PROD_0_BYTE_OFFSET
                    + slot * 48,
            byte_size: 40,
            sw_digest: true,
            hw_digest: false,
            digest_offset: None,
        }
    }

    #[cfg(feature = "ocp-lock")]
    impl caliptra_mcu_romtime::ocp_lock::Platform for EmulatorOcpPlatform {
        fn get_total_slots(&self) -> usize {
            8
        }

        fn is_perma_bit_set(
            &self,
            otp: &caliptra_mcu_romtime::otp::Otp,
        ) -> Result<bool, caliptra_mcu_romtime::ocp_lock::Error> {
            otp.read_entry(&caliptra_mcu_registers_generated::fuses::PERMA_HEK_EN)
                .map(|val| val != 0)
                .map_err(|_| caliptra_mcu_romtime::ocp_lock::Error::INVALID_HEK_SLOT)
        }

        fn get_slot_state(
            &mut self,
            otp: &caliptra_mcu_romtime::otp::Otp,
            perma_bit: &caliptra_mcu_romtime::ocp_lock::PermaBitStatus,
            slot: usize,
            seed: &[u8; 48],
        ) -> Result<
            caliptra_mcu_romtime::ocp_lock::HekSeedState,
            caliptra_mcu_romtime::ocp_lock::Error,
        > {
            if *perma_bit == caliptra_mcu_romtime::ocp_lock::PermaBitStatus::Set {
                return Ok(caliptra_mcu_romtime::ocp_lock::HekSeedState::Permanent);
            }
            if seed.iter().all(|&b| b == 0xFF) {
                return Ok(caliptra_mcu_romtime::ocp_lock::HekSeedState::Sanitized);
            }
            if seed.iter().all(|&b| b == 0x0) {
                return Ok(caliptra_mcu_romtime::ocp_lock::HekSeedState::Unused);
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
                        caliptra_mcu_romtime::println!(
                            "[mcu-rom-otp] HEK software digest mismatch! Slot {}",
                            slot
                        );
                        return Ok(
                            caliptra_mcu_romtime::ocp_lock::HekSeedState::ProgrammedCorrupted,
                        );
                    }
                }
                _ => return Err(caliptra_mcu_romtime::ocp_lock::Error::INVALID_HEK_SLOT),
            }

            Ok(caliptra_mcu_romtime::ocp_lock::HekSeedState::Programmed)
        }

        fn get_active_slot(
            &mut self,
            otp: &caliptra_mcu_romtime::otp::Otp,
            perma_bit: &caliptra_mcu_romtime::ocp_lock::PermaBitStatus,
            seeds: &caliptra_mcu_romtime::ocp_lock::HekSeeds,
        ) -> Result<usize, caliptra_mcu_romtime::ocp_lock::Error> {
            if *perma_bit == caliptra_mcu_romtime::ocp_lock::PermaBitStatus::Set {
                return Ok(self.get_total_slots() - 1);
            }

            for i in 0..seeds.len() {
                let buf = seeds
                    .get(i)
                    .ok_or(caliptra_mcu_romtime::ocp_lock::Error::INVALID_HEK_SLOT)?;
                let state = self.get_slot_state(otp, perma_bit, i, buf)?;

                if state == caliptra_mcu_romtime::ocp_lock::HekSeedState::Programmed {
                    return Ok(i);
                }
            }
            Err(caliptra_mcu_romtime::ocp_lock::Error::EXHAUSTED_HEK_SLOTS)
        }
    }

    #[cfg(feature = "ocp-lock")]
    let mut ocp_platform = EmulatorOcpPlatform;

    #[cfg(feature = "ocp-lock")]
    let ocp_lock_config = caliptra_mcu_romtime::ocp_lock::RomConfig {
        platform: Some(&mut ocp_platform),
        ..Default::default()
    };

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

        use caliptra_mcu_rom_common::recovery::flash::FlashImageProvider;
        use caliptra_mcu_rom_common::recovery::{
            ErrorPolicy, ImageProviderEntry, ImageProviderManager,
        };

        let mut flash_provider = FlashImageProvider::new(&mut flash_image_partition_driver);
        let mut entries = [ImageProviderEntry {
            provider: &mut flash_provider,
            policy: ErrorPolicy::Continue,
        }];
        let manager = ImageProviderManager::new(&mut entries);

        caliptra_mcu_rom_common::rom_start(RomParameters {
            image_provider_manager: Some(manager),
            dot_flash: Some(dot_flash),
            request_recovery_boot: true,
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
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
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
            ..Default::default()
        };
        caliptra_mcu_rom_common::rom_start(rom_parameters);
    } else if cfg!(any(
        feature = "test-fw-manifest-dot",
        feature = "test-fw-manifest-dot-hitless"
    )) {
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
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
            ..Default::default()
        });
    } else if cfg!(feature = "test-usb-ocp-recovery") {
        #[cfg(feature = "test-usb-ocp-recovery")]
        {
            use caliptra_mcu_ocp::cms::slice_fifo::SliceFifoRegion;
            use caliptra_mcu_ocp::cms::slice_indirect::SliceIndirectRegion;
            use caliptra_mcu_ocp::cms::{FifoCmsRegion, IndirectCmsRegion};
            use caliptra_mcu_ocp::interface::{RecoveryDeviceConfig, RecoveryStateMachine};
            use caliptra_mcu_ocp::protocol::device_id::{
                DeviceDescriptor, DeviceId, PciVendorDescriptor,
            };
            use caliptra_mcu_ocp::protocol::indirect_fifo_status::FifoCmsRegionType;
            use caliptra_mcu_ocp::protocol::indirect_status::CmsRegionType;
            use caliptra_mcu_ocp::vendor::NoopVendorHandler;
            use caliptra_mcu_registers_generated::usbdev;
            use caliptra_mcu_usb_emulator::ExamplarUsbDriver;

            caliptra_mcu_romtime::println!("[mcu-rom] USB OCP Recovery boot path");

            let usb_regs = unsafe {
                caliptra_mcu_romtime::StaticRef::new(
                    usbdev::USBDEV_ADDR as *const usbdev::regs::Usbdev,
                )
            };
            let mut usb_driver = ExamplarUsbDriver::new(usb_regs);

            // CMS 0: Indirect CodeSpace backed by MCI staging SRAM (required by spec).
            let indirect_buf = unsafe {
                core::slice::from_raw_parts_mut(
                    MCU_MEMORY_MAP.staging_sram_offset as *mut u8,
                    MCU_MEMORY_MAP.staging_sram_size as usize,
                )
            };

            fn ocp_setup_failed() -> ! {
                fatal_error(
                    caliptra_mcu_error::McuError::ROM_COLD_BOOT_RECOVERY_NOT_CONFIGURED_ERROR,
                );
            }
            let mut indirect = SliceIndirectRegion::new(indirect_buf, CmsRegionType::CodeSpace)
                .ok()
                .unwrap_or_else(|| ocp_setup_failed());
            let mut indirect_regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut indirect)];

            // CMS 1: FIFO CodeSpace for streaming recovery data.
            let mut fifo_buf = [0u8; 4096];
            let mut fifo = SliceFifoRegion::new(&mut fifo_buf, FifoCmsRegionType::CodeSpace, 256)
                .ok()
                .unwrap_or_else(|| ocp_setup_failed());
            let mut fifo_regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(1, &mut fifo)];

            let desc =
                DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0x1209, 0x0001, 0, 0, 0));
            let config = RecoveryDeviceConfig {
                device_id: DeviceId::new(desc, &[])
                    .ok()
                    .unwrap_or_else(|| ocp_setup_failed()),
                major_version: 1,
                minor_version: 1,
                max_response_time: 17,
                heartbeat_period: 0,
                local_c_image_support: false,
            };

            let sm = RecoveryStateMachine::new(
                config,
                &mut usb_driver,
                &mut indirect_regions,
                &mut fifo_regions,
                NoopVendorHandler,
            )
            .ok()
            .unwrap_or_else(|| ocp_setup_failed());

            use caliptra_mcu_rom_common::recovery::ocp::OcpImageProvider;
            use caliptra_mcu_rom_common::recovery::{
                ErrorPolicy, ImageProviderEntry, ImageProviderManager,
            };

            let mut ocp_provider = OcpImageProvider::new(sm);
            let mut entries = [ImageProviderEntry {
                provider: &mut ocp_provider,
                policy: ErrorPolicy::RetryForever,
            }];
            let manager = ImageProviderManager::new(&mut entries);

            caliptra_mcu_rom_common::rom_start(RomParameters {
                image_provider_manager: Some(manager),
                dot_flash: Some(dot_flash),
                cptra_mbox_axi_users: mbox_axi_users,
                cptra_fuse_axi_user: axi_user0,
                cptra_trng_axi_user: axi_user0,
                cptra_dma_axi_user: axi_user0,
                mci_mbox0_axi_users: mbox_axi_users,
                mci_mbox1_axi_users: mbox_axi_users,
                #[cfg(feature = "ocp-lock")]
                ocp_lock_config,
                ..Default::default()
            });
        }
    } else if cfg!(feature = "test-svn-manifest") {
        caliptra_mcu_rom_common::rom_start(RomParameters {
            dot_flash: Some(dot_flash),
            svn_manifest_enabled: true,
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
    } else if cfg!(feature = "hw-2-1")
        && !cfg!(any(
            feature = "test-dot-recovery",
            feature = "test-i3c-services",
            feature = "test-rom-hooks",
            feature = "test-svn-manifest",
            feature = "test-usb-ocp-recovery",
        ))
    {
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

        use caliptra_mcu_rom_common::recovery::flash::FlashImageProvider;
        use caliptra_mcu_rom_common::recovery::{
            ErrorPolicy, ImageProviderEntry, ImageProviderManager,
        };

        let mut flash_provider = FlashImageProvider::new(&mut flash_partition);
        let mut entries = [ImageProviderEntry {
            provider: &mut flash_provider,
            policy: ErrorPolicy::Continue,
        }];
        let manager = ImageProviderManager::new(&mut entries);

        caliptra_mcu_rom_common::rom_start(RomParameters {
            image_provider_manager: Some(manager),
            dot_flash: Some(dot_flash),
            // Let the generic wire (bit 29 of mci_reg_generic_input_wires[1]) control flash boot
            // request_recovery_boot defaults to false - emulator sets the wire when flash boot is requested
            cptra_mbox_axi_users: mbox_axi_users,
            cptra_fuse_axi_user: axi_user0,
            cptra_trng_axi_user: axi_user0,
            cptra_dma_axi_user: axi_user0,
            mci_mbox0_axi_users: mbox_axi_users,
            mci_mbox1_axi_users: mbox_axi_users,
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
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

        // Store recovery handler and transport in statics so the
        // DotLockedRecoveryHandler wrappers can reference them with
        // 'static lifetime.
        static mut RECOVERY_HANDLER: core::mem::MaybeUninit<TestDotRecoveryHandler> =
            core::mem::MaybeUninit::uninit();
        let recovery_handler = unsafe {
            init_static(
                &raw mut RECOVERY_HANDLER,
                TestDotRecoveryHandler {
                    blob: recovery_backup_blob,
                },
            )
        };

        let mci_base: caliptra_mcu_romtime::StaticRef<
            caliptra_mcu_registers_generated::mci::regs::Mci,
        > = unsafe {
            caliptra_mcu_romtime::StaticRef::new(
                MCU_MEMORY_MAP.mci_offset
                    as *const caliptra_mcu_registers_generated::mci::regs::Mci,
            )
        };
        static mut RECOVERY_TRANSPORT: core::mem::MaybeUninit<
            caliptra_mcu_rom_common::Mbox0RecoveryTransport,
        > = core::mem::MaybeUninit::uninit();
        let recovery_transport = unsafe {
            init_static(
                &raw mut RECOVERY_TRANSPORT,
                caliptra_mcu_rom_common::Mbox0RecoveryTransport::new(mci_base),
            )
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
                Some(&*recovery_handler)
            } else {
                None
            },
            dot_recovery_transport: if cfg!(feature = "test-dot-recovery") {
                Some(&*recovery_transport)
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
            dot_locked_recovery_handlers: if cfg!(feature = "test-dot-recovery") {
                static mut BLOB_HANDLER: core::mem::MaybeUninit<
                    caliptra_mcu_rom_common::BackupBlobRecoveryHandler<'static>,
                > = core::mem::MaybeUninit::uninit();
                let blob_h = unsafe {
                    init_static(
                        &raw mut BLOB_HANDLER,
                        caliptra_mcu_rom_common::BackupBlobRecoveryHandler {
                            recovery_handler: &*recovery_handler,
                        },
                    )
                };
                static mut OVERRIDE_HANDLER: core::mem::MaybeUninit<
                    caliptra_mcu_rom_common::OverrideChallengeRecoveryHandler<'static>,
                > = core::mem::MaybeUninit::uninit();
                let override_h = unsafe {
                    init_static(
                        &raw mut OVERRIDE_HANDLER,
                        caliptra_mcu_rom_common::OverrideChallengeRecoveryHandler {
                            transport: &*recovery_transport,
                            wdt_timeout: 0,
                        },
                    )
                };
                static mut HANDLER_ENTRIES: core::mem::MaybeUninit<
                    [caliptra_mcu_rom_common::DotLockedRecoveryEntry<'static>; 2],
                > = core::mem::MaybeUninit::uninit();
                unsafe {
                    init_static(
                        &raw mut HANDLER_ENTRIES,
                        [
                            caliptra_mcu_rom_common::DotLockedRecoveryEntry {
                                handler: blob_h,
                                policy:
                                    caliptra_mcu_rom_common::DotLockedRecoveryErrorPolicy::Continue,
                            },
                            caliptra_mcu_rom_common::DotLockedRecoveryEntry {
                                handler: override_h,
                                policy:
                                    caliptra_mcu_rom_common::DotLockedRecoveryErrorPolicy::Continue,
                            },
                        ],
                    )
                    .as_slice()
                }
            } else if cfg!(feature = "test-i3c-services") {
                let i3c_base = unsafe {
                    caliptra_mcu_romtime::StaticRef::new(
                        MCU_MEMORY_MAP.i3c_offset
                            as *const caliptra_mcu_registers_generated::i3c::regs::I3c,
                    )
                };
                static mut I3C_HANDLER: core::mem::MaybeUninit<
                    caliptra_mcu_rom_common::I3cDotLockedRecoveryHandler,
                > = core::mem::MaybeUninit::uninit();
                let handler = unsafe {
                    init_static(
                        &raw mut I3C_HANDLER,
                        caliptra_mcu_rom_common::I3cDotLockedRecoveryHandler {
                            i3c_base,
                            services: caliptra_mcu_rom_common::I3cServicesModes::DOT_RECOVERY,
                            i3c_target_addr: 0x5a,
                        },
                    )
                };
                static mut HANDLER_ENTRIES: core::mem::MaybeUninit<
                    [caliptra_mcu_rom_common::DotLockedRecoveryEntry<'static>; 1],
                > = core::mem::MaybeUninit::uninit();
                unsafe {
                    init_static(
                        &raw mut HANDLER_ENTRIES,
                        [caliptra_mcu_rom_common::DotLockedRecoveryEntry {
                            handler,
                            policy: caliptra_mcu_rom_common::DotLockedRecoveryErrorPolicy::Continue,
                        }],
                    )
                    .as_slice()
                }
            } else {
                &[]
            },
            #[cfg(feature = "ocp-lock")]
            ocp_lock_config,
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
        HexWord(MCU_MEMORY_MAP.sram_offset)
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
