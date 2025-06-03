/*++

Licensed under the Apache-2.0 license.

File Name:

    riscv.rs

Abstract:

    File contains the common RISC-V code for MCU ROM

--*/

#![allow(unused)]

use crate::fatal_error;
use crate::fuses::Otp;
use caliptra_api::mailbox::CommandId;
use caliptra_api::CaliptraApiError;
use caliptra_api::SocManager;
use core::{fmt::Write, hint::black_box, ptr::addr_of};
use registers_generated::{fuses::Fuses, i3c, mbox, mci, otp_ctrl, soc};
use romtime::{HexWord, Mci, StaticRef};
use tock_registers::interfaces::{Readable, Writeable};

extern "C" {
    pub static MCU_MEMORY_MAP: mcu_config::McuMemoryMap;
}

pub struct Soc {
    registers: StaticRef<soc::regs::Soc>,
}

impl Soc {
    pub const fn new(registers: StaticRef<soc::regs::Soc>) -> Self {
        Soc { registers }
    }

    pub fn flow_status(&self) -> u32 {
        self.registers.cptra_flow_status.get()
    }

    pub fn ready_for_mbox(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForMbProcessing)
    }

    pub fn ready_for_fuses(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForFuses)
    }

    pub fn populate_fuses(&self, fuses: &Fuses) {
        // secret fuses are populated by a hardware state machine, so we can skip those

        // TODO[cap2]: the OTP map doesn't have this value yet, so we hardcode it for now
        self.registers.fuse_pqc_key_type.set(3); // LMS

        // TODO: vendor-specific fuses when those are supported
        self.registers
            .fuse_fmc_key_manifest_svn
            .set(u32::from_le_bytes(
                fuses.cptra_core_fmc_key_manifest_svn().try_into().unwrap(),
            ));

        romtime::print!("[mcu-fuse-write] Writing fuse key vendor PK hash: ");
        if fuses.cptra_core_vendor_pk_hash_0().len() != self.registers.fuse_vendor_pk_hash.len() * 4
        {
            romtime::println!("[mcu-fuse-write] Key manifest PK hash length mismatch");
            fatal_error(1);
        }
        for i in 0..fuses.cptra_core_vendor_pk_hash_0().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_core_vendor_pk_hash_0()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            romtime::print!("{}", HexWord(word));
            self.registers.fuse_vendor_pk_hash[i].set(word);
        }
        romtime::println!("");

        // TODO: this seems to not exist any more
        // self.registers.fuse_key_manifest_pk_hash_mask[0].set(fuses.key_manifest_pk_hash_mask());
        // if fuses.owner_pk_hash().len() != self.registers.cptra_owner_pk_hash.len() {
        //     romtime::println!("[mcu-fuse-write] Owner PK hash length mismatch");
        //     fatal_error();
        // }
        //romtime::println!("");
        if fuses.cptra_core_runtime_svn().len() != self.registers.fuse_runtime_svn.len() * 4 {
            romtime::println!("[mcu-fuse-write] Runtime SVN length mismatch");
            fatal_error(1);
        }
        for i in 0..fuses.cptra_core_runtime_svn().len() / 4 {
            let word = u32::from_le_bytes(
                fuses.cptra_core_runtime_svn()[i * 4..i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            self.registers.fuse_runtime_svn[i].set(word);
        }
        // TODO
        // self.registers
        //     .fuse_anti_rollback_disable
        //     .set(fuses.anti_rollback_disable());
        // TODO: fix these
        // for i in 0..self.registers.fuse_idevid_cert_attr.len() {
        //     self.registers.fuse_idevid_cert_attr[i].set(fuses.cptra_core_idevid_cert_idevid_attr()[i]);
        // }
        // for i in 0..self.registers.fuse_idevid_manuf_hsm_id.len() {
        //     self.registers.fuse_idevid_manuf_hsm_id[i].set(fuses.idevid_manuf_hsm_id()[i]);
        // }
        // TODO: read the lifecycle partition from the lifecycle controller
        // self.registers
        //     .fuse_life_cycle
        //     .write(soc::bits::FuseLifeCycle::LifeCycle.val(..));
        // self.registers.fuse_lms_revocation.set(u32::from_le_bytes(
        //     fuses.cptra_core_lms_revocation_0().try_into().unwrap(),
        // ));
        // TODO
        //self.registers.fuse_mldsa_revocation.set(fuses.mldsa_revocation());
        let soc_stepping_id =
            u16::from_le_bytes(fuses.cptra_core_soc_stepping_id()[0..2].try_into().unwrap()) as u32;
        self.registers
            .fuse_soc_stepping_id
            .write(soc::bits::FuseSocSteppingId::SocSteppingId.val(soc_stepping_id));
        // TODO: debug unlock / rma token?
    }

    pub fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }
}

pub fn rom_start() {
    romtime::println!("[mcu-rom] Hello from ROM");

    let otp_base: StaticRef<otp_ctrl::regs::OtpCtrl> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.otp_offset as *const otp_ctrl::regs::OtpCtrl) };
    let i3c_base: StaticRef<i3c::regs::I3c> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.i3c_offset as *const i3c::regs::I3c) };
    let soc_base: StaticRef<soc::regs::Soc> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.soc_offset as *const soc::regs::Soc) };
    let mci_base: StaticRef<mci::regs::Mci> =
        unsafe { StaticRef::new(MCU_MEMORY_MAP.mci_offset as *const mci::regs::Mci) };

    let mut soc_manager = romtime::CaliptraSoC::new(
        Some(unsafe { MCU_MEMORY_MAP.soc_offset }),
        Some(unsafe { MCU_MEMORY_MAP.soc_offset }),
        Some(unsafe { MCU_MEMORY_MAP.mbox_offset }),
    );
    let soc = Soc::new(soc_base);

    // De-assert caliptra reset
    let mut mci = Mci::new(mci_base);
    romtime::println!("[mcu-rom] Setting Caliptra boot go");
    mci.caliptra_boot_go();

    // only do these on the emulator for now
    let fuses = if unsafe { MCU_MEMORY_MAP.rom_offset } == 0x8000_0000 {
        let otp = Otp::new(otp_base);
        if let Err(err) = otp.init() {
            romtime::println!("Error initializing OTP: {}", HexWord(err as u32));
            fatal_error(1);
        }
        match otp.read_fuses() {
            Ok(fuses) => fuses,
            Err(e) => {
                romtime::println!("Error reading fuses: {}", HexWord(e as u32));
                fatal_error(1);
            }
        }
    } else {
        Fuses::default()
    };

    let flow_status = soc.flow_status();
    romtime::println!("[mcu-rom] Caliptra flow status {}", HexWord(flow_status));

    // TODO: pass these in as parameters
    soc.registers.cptra_wdt_cfg[0].set(100_000_000);
    soc.registers.cptra_wdt_cfg[1].set(100_000_000);

    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
        soc.ready_for_fuses()
    );
    while !soc.ready_for_fuses() {}
    romtime::println!("[mcu-rom] Writing fuses to Caliptra");
    soc.populate_fuses(&fuses);
    soc.fuse_write_done();
    while soc.ready_for_fuses() {}

    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for mbox: {}",
        soc.ready_for_mbox()
    );
    while !soc.ready_for_mbox() {}

    // tell Caliptra to download firmware from the recovery interface
    romtime::println!(
        "[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command: status {}",
        HexWord(u32::from(
            soc_manager.soc_mbox().status().read().mbox_fsm_ps()
        ))
    );
    if let Err(err) =
        soc_manager.start_mailbox_req(CommandId::RI_DOWNLOAD_FIRMWARE.into(), 0, [].into_iter())
    {
        match err {
            CaliptraApiError::MailboxCmdFailed(code) => {
                romtime::println!("[mcu-rom] Error sending mailbox command: {}", HexWord(code));
            }
            _ => {
                romtime::println!("[mcu-rom] Error sending mailbox command");
            }
        }
        fatal_error(4);
    }
    romtime::println!(
        "[mcu-rom] Done sending RI_DOWNLOAD_FIRMWARE command: status {}",
        HexWord(u32::from(
            soc_manager.soc_mbox().status().read().mbox_fsm_ps()
        ))
    );
    {
        // drop this to release the lock
        if let Err(err) = soc_manager.finish_mailbox_resp(8, 8) {
            match err {
                CaliptraApiError::MailboxCmdFailed(code) => {
                    romtime::println!(
                        "[mcu-rom] Error finishing mailbox command: {}",
                        HexWord(code)
                    );
                }
                _ => {
                    romtime::println!("[mcu-rom] Error finishing mailbox command");
                }
            }
            fatal_error(5);
        }
    };

    romtime::println!("[mcu-rom] Starting recovery flow");
    let mut i3c = I3c::new(i3c_base);
    recovery_flow(&mut mci, &mut i3c);
    romtime::println!("[mcu-rom] Recovery flow complete");

    // Check that the firmware was actually loaded before jumping to it
    let firmware_ptr = unsafe { (MCU_MEMORY_MAP.sram_offset + 0x80) as *const u32 };
    // Safety: this address is valid
    if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
        romtime::println!("Invalid firmware detected; halting");
        fatal_error(1);
    }
    romtime::println!("[mcu-rom] Finished common initialization");
}

pub struct I3c {
    registers: StaticRef<i3c::regs::I3c>,
}

impl I3c {
    pub const fn new(registers: StaticRef<i3c::regs::I3c>) -> Self {
        I3c { registers }
    }
}

pub fn recovery_flow(mci: &mut Mci, i3c: &mut I3c) {
    // TODO: implement Caliptra boot flow

    // TODO: read this value from the fuses (according to the spec)?
    romtime::println!("[mcu-rom] Initialize I3C");
    i3c.registers.sec_fw_recovery_if_device_id_0.set(0x3a); // placeholder address for now
    i3c.registers.stdby_ctrl_mode_stby_cr_device_addr.set(0x3a);

    romtime::println!("[mcu-rom] MCI flow status: {}", HexWord(mci.flow_status()));

    // TODO: what value are we looking for
    romtime::println!("[mcu-rom] Waiting for firmware to be loaded");
    let firmware_ptr = unsafe { (MCU_MEMORY_MAP.sram_offset + 0xfff0) as *const u32 };
    while unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {}
    romtime::println!("[mcu-rom] Firmware load detected");
}
