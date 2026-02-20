/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_boot.rs

Abstract:

    Warm Boot Flow - Handles warm boot when MCU powers on

--*/

#![allow(clippy::empty_loop)]

use crate::{
    configure_mcu_mbox_axi_users, fatal_error, verify_mcu_mbox_axi_users, AxiUsers, BootFlow,
    McuBootMilestones, McuRomBootStatus, RomEnv, RomParameters, MCU_MEMORY_MAP,
};
use caliptra_api_types::{DeviceLifecycle, SecurityState};
use core::{fmt::Write, ops::Deref};
use mcu_error::McuError;

pub struct WarmBoot {}

impl BootFlow for WarmBoot {
    fn run(env: &mut RomEnv, params: RomParameters) -> ! {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::WarmResetFlowStarted.into());
        romtime::println!("[mcu-rom] Starting warm boot flow");

        // Create local references to minimize code changes
        let mci = &env.mci;
        let soc = &env.soc;
        let straps = env.straps.deref();

        romtime::println!("[mcu-rom] Setting Caliptra boot go");
        mci.caliptra_boot_go();
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraBootGoAsserted.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED.into());

        romtime::println!(
            "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
            soc.ready_for_fuses()
        );
        while !soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::CaliptraReadyForFuses.into());

        // Configure watchdog timers
        soc.set_cptra_wdt_cfg(0, straps.cptra_wdt_cfg0);
        soc.set_cptra_wdt_cfg(1, straps.cptra_wdt_cfg1);

        mci.set_nmi_vector(unsafe { MCU_MEMORY_MAP.rom_offset });

        let state = SecurityState::from(mci.security_state());
        let lifecycle = state.device_lifecycle();
        match (state.debug_locked(), lifecycle) {
            (false, _) => mci.configure_wdt(
                straps.mcu_wdt_cfg0_debug.into(),
                straps.mcu_wdt_cfg1_debug.into(),
            ),
            (true, DeviceLifecycle::Manufacturing) => {
                mci.configure_wdt(
                    straps.mcu_wdt_cfg0_manufacturing.into(),
                    straps.mcu_wdt_cfg1_manufacturing.into(),
                );
            }
            (true, _) => {
                mci.configure_wdt(straps.mcu_wdt_cfg0.into(), straps.mcu_wdt_cfg1.into());
            }
        }
        mci.set_flow_checkpoint(McuRomBootStatus::WatchdogConfigured.into());

        soc.set_axi_users(AxiUsers {
            mbox_users: params
                .cptra_mbox_axi_users
                .map(|u| if u != 0 { Some(u) } else { None }),
            fuse_user: params.cptra_fuse_axi_user,
            trng_user: params.cptra_trng_axi_user,
            dma_user: params.cptra_dma_axi_user,
        });
        mci.set_flow_checkpoint(McuRomBootStatus::AxiUsersConfigured.into());

        // Configure MCU mailbox AXI users before locking
        romtime::println!("[mcu-rom] Configuring MCU mailbox AXI users");
        let mcu_mbox_config = configure_mcu_mbox_axi_users(
            mci,
            &params.mci_mbox0_axi_users,
            &params.mci_mbox1_axi_users,
        );
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersConfigured.into());

        // Set SS_CONFIG_DONE_STICKY to lock MCI configuration registers
        romtime::println!("[mcu-rom] Setting SS_CONFIG_DONE_STICKY to lock configuration");
        mci.set_ss_config_done_sticky();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneStickySet.into());

        // Set SS_CONFIG_DONE to lock MCI configuration registers until warm reset
        romtime::println!("[mcu-rom] Setting SS_CONFIG_DONE");
        mci.set_ss_config_done();
        mci.set_flow_checkpoint(McuRomBootStatus::SsConfigDoneSet.into());

        // Verify that SS_CONFIG_DONE_STICKY and SS_CONFIG_DONE are actually set
        if !mci.is_ss_config_done_sticky() || !mci.is_ss_config_done() {
            romtime::println!("[mcu-rom] SS_CONFIG_DONE verification failed");
            fatal_error(McuError::ROM_SOC_SS_CONFIG_DONE_VERIFY_FAILED);
        }

        // Verify MCU mailbox AXI users haven't been tampered with after locking
        romtime::println!("[mcu-rom] Verifying MCU mailbox AXI users");
        if let Err(err) = verify_mcu_mbox_axi_users(mci, &mcu_mbox_config) {
            romtime::println!("[mcu-rom] MCU mailbox AXI user verification failed");
            fatal_error(err);
        }
        mci.set_flow_checkpoint(McuRomBootStatus::McuMboxAxiUsersVerified.into());

        // According to https://github.com/chipsalliance/caliptra-rtl/blob/main/docs/CaliptraIntegrationSpecification.md#fuses
        // we still need to write the fuse write done bit even though fuses can't be changed on a
        // warm reset.

        romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
        soc.fuse_write_done();
        while soc.ready_for_fuses() {}
        mci.set_flow_checkpoint(McuRomBootStatus::FuseWriteComplete.into());
        mci.set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());

        romtime::println!("[mcu-rom] Waiting for MCU firmware to be ready");
        soc.wait_for_firmware_ready(mci);
        romtime::println!("[mcu-rom] Firmware is ready");

        // Check that the firmware was actually loaded before jumping to it
        let firmware_ptr = unsafe {
            (MCU_MEMORY_MAP.sram_offset + params.mcu_image_header_size as u32) as *const u32
        };
        // Safety: this address is valid
        if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
            romtime::println!("Invalid firmware detected; halting");
            fatal_error(McuError::ROM_WARM_BOOT_INVALID_FIRMWARE);
        }

        // Reset so FirmwareBootReset can jump to firmware
        romtime::println!("[mcu-rom] Resetting to boot firmware");
        mci.set_flow_checkpoint(McuRomBootStatus::WarmResetFlowComplete.into());
        mci.set_flow_milestone(McuBootMilestones::WARM_RESET_FLOW_COMPLETE.into());
        mci.trigger_warm_reset();
        romtime::println!("[mcu-rom] ERROR: Still running after reset request!");
        fatal_error(McuError::ROM_WARM_BOOT_RESET_ERROR);
    }
}
