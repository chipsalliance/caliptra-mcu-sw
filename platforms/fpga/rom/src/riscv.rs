/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::flash::flash_drv::{FpgaFlashCtrl, PRIMARY_FLASH_CTRL_BASE};
use crate::io::{print_to_console, EXITER, FATAL_ERROR_HANDLER, FPGA_WRITER};
use core::fmt::Write;

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

use mcu_config::{McuMemoryMap, McuStraps};
use mcu_rom_common::flash::flash_partition::FlashPartition;
use mcu_rom_common::recovery::flash::FlashImageProvider;
use mcu_rom_common::recovery::{ErrorPolicy, ImageProviderEntry, ImageProviderManager};
use mcu_rom_common::{RomHooks, RomParameters};
use romtime::{LifecycleControllerState, LifecycleHashedToken, LifecycleToken};

/// Example `RomHooks` implementation for the FPGA platform. Emits a
/// distinctive tagged log line for each milestone and records which
/// hooks fired as a bitmask in `mci_reg_fw_extended_error_info[0]` so a
/// host-side test can verify completion even after full-runtime boot.
/// Attached via the `test-rom-hooks` cargo feature.
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
        romtime::println!("[mcu-rom-hook] pre_cold_boot");
        record_hook_bit(0);
    }
    fn post_cold_boot(&self) {
        romtime::println!("[mcu-rom-hook] post_cold_boot");
        record_hook_bit(1);
    }
    fn pre_warm_boot(&self) {
        romtime::println!("[mcu-rom-hook] pre_warm_boot");
        record_hook_bit(2);
    }
    fn post_warm_boot(&self) {
        romtime::println!("[mcu-rom-hook] post_warm_boot");
        record_hook_bit(3);
    }
    fn pre_fw_boot(&self) {
        romtime::println!("[mcu-rom-hook] pre_fw_boot");
        record_hook_bit(4);
    }
    fn post_fw_boot(&self) {
        romtime::println!("[mcu-rom-hook] post_fw_boot");
        record_hook_bit(5);
    }
    fn pre_fw_hitless_update(&self) {
        romtime::println!("[mcu-rom-hook] pre_fw_hitless_update");
        record_hook_bit(6);
    }
    fn post_fw_hitless_update(&self) {
        romtime::println!("[mcu-rom-hook] post_fw_hitless_update");
        record_hook_bit(7);
    }
    fn pre_caliptra_boot(&self) {
        romtime::println!("[mcu-rom-hook] pre_caliptra_boot");
        record_hook_bit(8);
    }
    fn post_caliptra_boot(&self) {
        romtime::println!("[mcu-rom-hook] post_caliptra_boot");
        record_hook_bit(9);
    }
    fn pre_populate_fuses_to_caliptra(&self) {
        romtime::println!("[mcu-rom-hook] pre_populate_fuses_to_caliptra");
        record_hook_bit(10);
    }
    fn post_populate_fuses_to_caliptra(&self) {
        romtime::println!("[mcu-rom-hook] post_populate_fuses_to_caliptra");
        record_hook_bit(11);
    }
    fn pre_load_firmware(&self) {
        romtime::println!("[mcu-rom-hook] pre_load_firmware");
        record_hook_bit(12);
    }
    fn post_load_firmware(&self) {
        romtime::println!("[mcu-rom-hook] post_load_firmware");
        record_hook_bit(13);
    }
}

// re-export these so the common ROM and runtime can use them
#[no_mangle]
#[used]
pub static MCU_MEMORY_MAP: McuMemoryMap = mcu_config_fpga::FPGA_MEMORY_MAP;

#[no_mangle]
#[used]
pub static MCU_STRAPS: McuStraps = mcu_config_fpga::FPGA_MCU_STRAPS;

pub extern "C" fn rom_entry() -> ! {
    print_to_console("FPGA MCU ROM\n");
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_printer(&mut FPGA_WRITER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        mcu_rom_common::set_fatal_error_handler(&mut FATAL_ERROR_HANDLER);
    }
    unsafe {
        #[allow(static_mut_refs)]
        romtime::set_exiter(&mut EXITER);
    }

    romtime::println!("[mcu-rom] Starting FPGA MCU ROM");

    // Initialize the primary flash controller
    let primary_flash_ctrl = FpgaFlashCtrl::initialize_flash_ctrl(PRIMARY_FLASH_CTRL_BASE);

    // Create a flash partition covering the entire flash
    // The partition starts at offset 0 and uses the full flash capacity
    let mut flash_partition = FlashPartition::new(
        &primary_flash_ctrl,
        "primary",
        0,
        primary_flash_ctrl.capacity(),
    )
    .expect("Failed to create flash partition");

    // This token is fixed in the FPGA RTL and is specified in LE order.
    let unlock_token: LifecycleToken = 0xF12A5911421748A2ADFC9693EF1FADEAu128.to_le_bytes().into();

    // This is a random token is created by us.
    let burn_raw_token: LifecycleToken =
        0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes().into();

    // This is cSHAKE128(burn_raw_token, "LC_CTRL", 256) in LE order.
    // You can generate it with the following Python script if you have PyCryptodome installed:
    // ```python
    // from Crypto.Hash import cSHAKE128
    // value = 0x05edb8c608fcc830de181732cfd65e57
    // data = value.to_bytes(16, byteorder="little")
    // custom = "LC_CTRL".encode("UTF-8")
    // shake = cSHAKE128.new(data=data, custom=custom)
    // digest = int.from_bytes(shake.read(16), byteorder="little")
    // print(hex(digest))
    let burn_hashed_token: LifecycleHashedToken =
        0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes().into();

    // Use these to change the ROM flow.
    // TODO: use generic input wires or other mechanism for host to communicate these.
    let transition_unlocked = false;
    let burn_tokens = false;
    let transition_manufacturing = false;
    let transition_production = false;
    let program_field_entropy = false;

    // For now, we use the same tokens for all lifecycle transitions.
    let burn_lifecycle_tokens = if burn_tokens {
        Some(romtime::LifecycleHashedTokens {
            test_unlock: [burn_hashed_token; 7],
            manuf: burn_hashed_token,
            manuf_to_prod: burn_hashed_token,
            prod_to_prod_end: burn_hashed_token,
            rma: burn_hashed_token,
        })
    } else {
        None
    };

    let lifecycle_transition = if transition_manufacturing {
        Some((
            LifecycleControllerState::Dev, // alias for manufacturing
            burn_raw_token,
        ))
    } else if transition_production {
        Some((
            LifecycleControllerState::Prod, // alias for manufacturing
            burn_raw_token,
        ))
    } else if transition_unlocked {
        Some((LifecycleControllerState::TestUnlocked0, unlock_token))
    } else {
        None
    };

    let axi_user0 = 1;
    let axi_user1 = 2;
    let mbox_axi_users = [axi_user0, axi_user1, 0, 0, 0];

    let hooks = LoggingRomHooks;

    let mut flash_provider = FlashImageProvider::new(&mut flash_partition);
    let mut entries = [ImageProviderEntry {
        provider: &mut flash_provider,
        policy: ErrorPolicy::Continue,
    }];
    let manager = ImageProviderManager::new(&mut entries);

    #[cfg(feature = "ocp-lock")]
    const OTP_DIGEST_IV: u64 = 0x90C7F21F6224F027u64;
    #[cfg(feature = "ocp-lock")]
    const OTP_DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266Fu128;

    #[cfg(feature = "ocp-lock")]
    struct FpgaOcpPlatform;

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
    impl romtime::ocp_lock::Platform for FpgaOcpPlatform {
        fn get_total_slots(&self) -> usize {
            8
        }

        fn get_slot_state(
            &mut self,
            otp: &romtime::otp::Otp,
            perma_bit: &romtime::ocp_lock::PermaBitStatus,
            slot: usize,
            seed: &[u8; 48],
        ) -> Result<romtime::ocp_lock::HekSeedState, romtime::ocp_lock::Error> {
            if *perma_bit == romtime::ocp_lock::PermaBitStatus::Set && !cfg!(feature = "core_test")
            {
                return Ok(romtime::ocp_lock::HekSeedState::Permanent);
            }
            if seed.iter().all(|&b| b == 0xFF) {
                return Ok(romtime::ocp_lock::HekSeedState::Sanitized);
            }
            if seed.iter().all(|&b| b == 0x0) {
                return Ok(romtime::ocp_lock::HekSeedState::Unused);
            }

            if cfg!(feature = "core_test") {
                if slot == 0 && !seed.iter().all(|&b| b == 0) && !seed.iter().all(|&b| b == 0xFF) {
                    return Ok(romtime::ocp_lock::HekSeedState::Programmed);
                }
            }

            let partition = get_hek_partition(slot);
            let expected_digest: Result<&[u8; 8], _> = seed[32..40].try_into();
            match (
                expected_digest,
                otp.compute_sw_digest(&partition, OTP_DIGEST_IV, OTP_DIGEST_CONST),
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

        fn get_active_slot(
            &mut self,
            otp: &romtime::otp::Otp,
            perma_bit: &romtime::ocp_lock::PermaBitStatus,
            seeds: &romtime::ocp_lock::HekSeeds,
        ) -> Result<usize, romtime::ocp_lock::Error> {
            if *perma_bit == romtime::ocp_lock::PermaBitStatus::Set && !cfg!(feature = "core_test")
            {
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
    let mut ocp_platform = FpgaOcpPlatform;

    #[cfg(feature = "ocp-lock")]
    let ocp_lock_config = romtime::ocp_lock::RomConfig {
        platform: Some(&mut ocp_platform),
        key_release_addr: 0xA401_0200,
        ..Default::default()
    };

    mcu_rom_common::rom_start(RomParameters {
        lifecycle_transition,
        burn_lifecycle_tokens,
        program_field_entropy: [program_field_entropy; 4],
        otp_enable_integrity_check: true,
        otp_enable_consistency_check: true,
        image_provider_manager: Some(manager),
        cptra_mbox_axi_users: mbox_axi_users,
        cptra_fuse_axi_user: axi_user0,
        cptra_trng_axi_user: axi_user0,
        cptra_dma_axi_user: axi_user0,
        mci_mbox0_axi_users: mbox_axi_users,
        mci_mbox1_axi_users: mbox_axi_users,
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

        #[cfg(feature = "ocp-lock")]
        ocp_lock_config,
        ..Default::default()
    });

    let addr = MCU_MEMORY_MAP.sram_offset;
    romtime::println!("[mcu-rom] Jumping to firmware at {:08x}", addr);
    exit_rom(addr);
}

fn exit_rom(addr: u32) -> ! {
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
            li x14, 0; li x15, 0; li x16, 0;
            li x17, 0; li x18, 0; li x19, 0; li x20, 0;
            li x21, 0; li x22, 0; li x23, 0; li x24, 0;
            li x25, 0; li x26, 0; li x27, 0; li x28, 0;
            li x29, 0; li x30, 0; li x31, 0;

            // jump to runtime
            jr a3",
                in("a3") addr,
                options(noreturn),
        }
    }
}
