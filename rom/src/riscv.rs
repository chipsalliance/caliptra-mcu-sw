/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::{fuses::Otp, static_ref::StaticRef};
use core::fmt::Write;
use registers_generated::{fuses::Fuses, i3c, otp_ctrl, soc};
use tock_registers::interfaces::{Readable, Writeable};

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("start.s"));

pub const SOC_BASE: StaticRef<soc::regs::Soc> =
    unsafe { StaticRef::new(soc::SOC_IFC_REG_ADDR as *const soc::regs::Soc) };

struct Soc {
    registers: StaticRef<soc::regs::Soc>,
}

impl Soc {
    pub const fn new(registers: StaticRef<soc::regs::Soc>) -> Self {
        Soc { registers }
    }

    fn flow_status(&self) -> u32 {
        self.registers.cptra_flow_status.get()
    }

    fn ready_for_fuses(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForFuses)
    }

    fn populate_fuses(&self, fuses: &Fuses) {
        // secret fuses are populated by a hardware state machine, so we can skip those

        // TODO: vendor-specific fuses when those are supported
        self.registers
            .fuse_fmc_key_manifest_svn
            .set(fuses.fmc_key_manifest_svn());
        // TODO: this seems to be bigger in the SoC registers than in the fuses
        self.registers.fuse_key_manifest_pk_hash_mask[0].set(fuses.key_manifest_pk_hash_mask());
        for i in 0..self.registers.cptra_owner_pk_hash.len() {
            self.registers.cptra_owner_pk_hash[i].set(fuses.owner_pk_hash()[i]);
        }
        for i in 0..self.registers.fuse_runtime_svn.len() {
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

    fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }
}

pub const OTP_BASE: StaticRef<otp_ctrl::regs::OtpCtrl> =
    unsafe { StaticRef::new(otp_ctrl::CALIPTRA_OTP_CTRL_ADDR as *const otp_ctrl::regs::OtpCtrl) };

pub const I3C_BASE: StaticRef<i3c::regs::I3c> =
    unsafe { StaticRef::new(i3c::I3C_CSR_ADDR as *const i3c::regs::I3c) };

pub extern "C" fn rom_entry() -> ! {
    romtime::println!("Hello from ROM");

    let otp = Otp::new(OTP_BASE);
    if let Err(err) = otp.init() {
        panic!("Error initializing OTP: {:x}", err as u32);
    }
    let fuses = match otp.read_fuses() {
        Ok(fuses) => fuses,
        Err(e) => panic!("Error reading fuses: {:x}", e as u32),
    };

    let soc = Soc::new(SOC_BASE);
    let flow_status = soc.flow_status();
    romtime::println!("Caliptra flow status {:x}", flow_status);
    if flow_status == 0 {
        romtime::println!("Caliptra not detected; skipping Caliptra boot flow");
        exit_rom();
    }

    romtime::println!("Waiting for Caliptra to be ready for fuses");
    while !soc.ready_for_fuses() {}
    romtime::println!("Writing fuses to Caliptra");
    soc.populate_fuses(&fuses);
    soc.fuse_write_done();
    while soc.ready_for_fuses() {}

    romtime::println!("Fuses written to Caliptra");

    // TODO(MCI): de-assert caliptra reset

    romtime::println!("Starting recovery flow");
    recovery_flow();
    romtime::println!("Recovery flow complete");

    // TODO: verify MCU firmware is valid

    exit_rom();
}

struct I3c {
    registers: StaticRef<i3c::regs::I3c>,
}

impl I3c {
    pub const fn new(registers: StaticRef<i3c::regs::I3c>) -> Self {
        I3c { registers }
    }
}

fn recovery_flow() {
    // TODO: implement Caliptra boot flow
    let i3c = I3c::new(I3C_BASE);

    // TODO: read this value from the fuses (according to the spec)?
    i3c.registers.sec_fw_recovery_if_device_id_0.set(0x3a); // placeholder address for now
    i3c.registers.stdby_ctrl_mode_stby_cr_device_addr.set(0x3a);
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
            li a3, 0x40000080
            jr a3",
                options(noreturn),
        }
    }
}
