/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main RISC-V entry point for MCU ROM

--*/

use crate::io::HexWord;
use crate::{fatal_error, fuses::Otp, static_ref::StaticRef};
use core::fmt::Write;
use registers_generated::{fuses::Fuses, i3c, mbox, mci, otp_ctrl, soc};
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

        romtime::print!("[mcu-fuse-write] Writing fuse key manifest PK hash: ");
        if fuses.key_manifest_pk_hash().len() != self.registers.fuse_key_manifest_pk_hash.len() {
            romtime::println!("[mcu-fuse-write] Key manifest PK hash length mismatch");
            fatal_error();
        }
        for i in 0..fuses.key_manifest_pk_hash().len() {
            romtime::print!("{}", HexWord(fuses.key_manifest_pk_hash()[i]));
            self.registers.fuse_key_manifest_pk_hash[i].set(fuses.key_manifest_pk_hash()[i]);
        }
        romtime::println!("");

        // TODO: this seems to be bigger in the SoC registers than in the fuses
        self.registers.fuse_key_manifest_pk_hash_mask[0].set(fuses.key_manifest_pk_hash_mask());
        if fuses.owner_pk_hash().len() != self.registers.cptra_owner_pk_hash.len() {
            romtime::println!("[mcu-fuse-write] Owner PK hash length mismatch");
            fatal_error();
        }
        romtime::print!("[mcu-fuse-write] Writing Owner PK hash from fuses: ");
        for (i, f) in fuses.owner_pk_hash().iter().enumerate() {
            romtime::print!("{}", HexWord(*f));
            self.registers.cptra_owner_pk_hash[i].set(*f);
        }
        romtime::println!("");
        if fuses.runtime_svn().len() != self.registers.fuse_runtime_svn.len() {
            romtime::println!("[mcu-fuse-write] Runtime SVN length mismatch");
            fatal_error();
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

    fn fuse_write_done(&self) {
        self.registers.cptra_fuse_wr_done.set(1);
    }
}

pub const OTP_BASE: StaticRef<otp_ctrl::regs::OtpCtrl> =
    unsafe { StaticRef::new(otp_ctrl::CALIPTRA_OTP_CTRL_ADDR as *const otp_ctrl::regs::OtpCtrl) };

pub const I3C_BASE: StaticRef<i3c::regs::I3c> =
    unsafe { StaticRef::new(i3c::I3C_CSR_ADDR as *const i3c::regs::I3c) };

pub const MCI_BASE: StaticRef<mci::regs::Mci> =
    unsafe { StaticRef::new(mci::MCI_REG_ADDR as *const mci::regs::Mci) };

#[allow(dead_code)]
pub const MBOX_BASE: StaticRef<mbox::regs::Mbox> =
    unsafe { StaticRef::new(mbox::MBOX_CSR_ADDR as *const mbox::regs::Mbox) };

#[allow(dead_code)]
struct Mailbox {
    registers: StaticRef<mbox::regs::Mbox>,
}

impl Mailbox {}

struct Mci {
    registers: StaticRef<mci::regs::Mci>,
}

impl Mci {
    pub const fn new(registers: StaticRef<mci::regs::Mci>) -> Self {
        Mci { registers }
    }

    fn caliptra_boot_go(&self) {
        self.registers.caliptra_boot_go.set(1);
    }

    #[allow(dead_code)]
    fn flow_status(&self) -> u32 {
        self.registers
            .flow_status
            .read(mci::bits::FlowStatus::Status)
    }
}

pub extern "C" fn rom_entry() -> ! {
    romtime::println!("[mcu-rom] Hello from ROM");

    let otp = Otp::new(OTP_BASE);
    if let Err(err) = otp.init() {
        romtime::println!("Error initializing OTP: {}", HexWord(err as u32));
        fatal_error();
    }
    let fuses = match otp.read_fuses() {
        Ok(fuses) => fuses,
        Err(e) => {
            romtime::println!("Error reading fuses: {}", HexWord(e as u32));
            fatal_error()
        }
    };

    let soc = Soc::new(SOC_BASE);
    let flow_status = soc.flow_status();
    romtime::println!("[mcu-rom] Caliptra flow status {}", HexWord(flow_status));
    if flow_status == 0 {
        romtime::println!("Caliptra not detected; skipping Caliptra boot flow");
        exit_rom();
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
        exit_emulator(1);
    }
    romtime::println!("[mcu-rom] Jumping to firmware");

    exit_rom();
}

/// Exit the emulator
pub fn exit_emulator(exit_code: u32) -> ! {
    // Safety: This is a safe memory address to write to for exiting the emulator.
    unsafe {
        // By writing to this address we can exit the emulator.
        core::ptr::write_volatile(0x1000_2000 as *mut u32, exit_code);
    }
    loop {}
}

struct I3c {
    registers: StaticRef<i3c::regs::I3c>,
}

impl I3c {
    pub const fn new(registers: StaticRef<i3c::regs::I3c>) -> Self {
        I3c { registers }
    }
}

fn recovery_flow(_mci: &mut Mci) {
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
    while unsafe { core::ptr::read_volatile(0x4000_ffff as *const u32) } == 0 {}
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
