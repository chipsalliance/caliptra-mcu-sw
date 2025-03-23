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
use core::fmt::Write;
use registers_generated::{fuses::Fuses, i3c, mbox, mci, otp_ctrl, soc};
use romtime::{HexWord, Mci, StaticRef, MCI_BASE};
use tock_registers::interfaces::{Readable, Writeable};

pub const SOC_BASE: StaticRef<soc::regs::Soc> =
    unsafe { StaticRef::new(soc::SOC_IFC_REG_ADDR as *const soc::regs::Soc) };

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
            .set(fuses.fmc_key_manifest_svn());

        romtime::print!("[mcu-fuse-write] Writing fuse key vendor PK hash: ");
        if fuses.key_manifest_pk_hash().len() != self.registers.fuse_vendor_pk_hash.len() {
            romtime::println!("[mcu-fuse-write] Key manifest PK hash length mismatch");
            fatal_error(1);
        }
        for i in 0..fuses.key_manifest_pk_hash().len() {
            romtime::print!("{}", HexWord(fuses.key_manifest_pk_hash()[i]));
            self.registers.fuse_vendor_pk_hash[i].set(fuses.key_manifest_pk_hash()[i]);
        }
        romtime::println!("");

        // TODO: this seems to not exist any more
        // self.registers.fuse_key_manifest_pk_hash_mask[0].set(fuses.key_manifest_pk_hash_mask());
        // if fuses.owner_pk_hash().len() != self.registers.cptra_owner_pk_hash.len() {
        //     romtime::println!("[mcu-fuse-write] Owner PK hash length mismatch");
        //     fatal_error();
        // }
        romtime::print!("[mcu-fuse-write] Writing Owner PK hash from fuses: ");
        for (i, f) in fuses.owner_pk_hash().iter().enumerate() {
            romtime::print!("{}", HexWord(*f));
            self.registers.cptra_owner_pk_hash[i].set(*f);
        }
        romtime::println!("");
        if fuses.runtime_svn().len() != self.registers.fuse_runtime_svn.len() {
            romtime::println!("[mcu-fuse-write] Runtime SVN length mismatch");
            fatal_error(1);
        }
        for i in 0..fuses.runtime_svn().len() {
            self.registers.fuse_runtime_svn[i].set(fuses.runtime_svn()[i]);
        }
        // TODO
        // self.registers
        //     .fuse_anti_rollback_disable
        //     .set(fuses.anti_rollback_disable());
        for i in 0..self.registers.fuse_idevid_cert_attr.len() {
            self.registers.fuse_idevid_cert_attr[i].set(fuses.idevid_cert_attr()[i]);
        }
        for i in 0..self.registers.fuse_idevid_manuf_hsm_id.len() {
            self.registers.fuse_idevid_manuf_hsm_id[i].set(fuses.idevid_manuf_hsm_id()[i]);
        }
        // TODO: read the lifecycle partition from the lifecycle controller
        // self.registers
        //     .fuse_life_cycle
        //     .write(soc::bits::FuseLifeCycle::LifeCycle.val(..));
        self.registers
            .fuse_lms_revocation
            .set(fuses.lms_revocation());
        // TODO
        //self.registers.fuse_mldsa_revocation.set(fuses.mldsa_revocation());
        self.registers
            .fuse_soc_stepping_id
            .write(soc::bits::FuseSocSteppingId::SocSteppingId.val(fuses.soc_stepping_id()));
        // TODO: debug unlock / rma token?
    }

    pub fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }
}

pub const OTP_BASE: StaticRef<otp_ctrl::regs::OtpCtrl> =
    unsafe { StaticRef::new(otp_ctrl::CALIPTRA_OTP_CTRL_ADDR as *const otp_ctrl::regs::OtpCtrl) };

pub const I3C_BASE: StaticRef<i3c::regs::I3c> =
    unsafe { StaticRef::new(i3c::I3C_CSR_ADDR as *const i3c::regs::I3c) };

pub fn rom_start() {
    romtime::println!("[mcu-rom] Hello from ROM");

    let otp = Otp::new(OTP_BASE);
    if let Err(err) = otp.init() {
        romtime::println!("Error initializing OTP: {}", HexWord(err as u32));
        fatal_error(1);
    }
    let fuses = match otp.read_fuses() {
        Ok(fuses) => fuses,
        Err(e) => {
            romtime::println!("Error reading fuses: {}", HexWord(e as u32));
            fatal_error(1);
        }
    };

    let soc = Soc::new(SOC_BASE);
    let flow_status = soc.flow_status();
    romtime::println!("[mcu-rom] Caliptra flow status {}", HexWord(flow_status));
    if flow_status == 0 {
        romtime::println!("Caliptra not detected; skipping common Caliptra boot flow");
        return;
    }

    romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for fuses");
    while !soc.ready_for_fuses() {}
    romtime::println!("[mcu-rom] Writing fuses to Caliptra");
    soc.populate_fuses(&fuses);
    soc.fuse_write_done();
    while soc.ready_for_fuses() {}

    romtime::println!("[mcu-rom] Fuses written to Caliptra");

    // De-assert caliptra reset
    let mut mci = Mci::new(MCI_BASE);
    mci.caliptra_boot_go();

    // tell Caliptra to download firmware from the recovery interface

    romtime::println!("[mcu-rom] Starting recovery flow");
    recovery_flow(&mut mci);
    romtime::println!("[mcu-rom] Recovery flow complete");

    // Check that the firmware was actually loaded before jumping to it
    let firmware_ptr = 0x4000_0080u32 as *const u32;
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

pub fn recovery_flow(_mci: &mut Mci) {
    // TODO: implement Caliptra boot flow
    let i3c = I3c::new(I3C_BASE);

    // TODO: read this value from the fuses (according to the spec)?
    i3c.registers.sec_fw_recovery_if_device_id_0.set(0x3a); // placeholder address for now
    i3c.registers.stdby_ctrl_mode_stby_cr_device_addr.set(0x3a);

    // TODO: what value are we looking for
    // while mci.flow_status() != 123 {
    //     // wait for us to get the signal to boot
    // }
    // hack until we have MCI hooked up: just look for a non-zero firmware value somewhere
    while unsafe { core::ptr::read_volatile(0x4000_fff0 as *const u32) } == 0 {}
}
