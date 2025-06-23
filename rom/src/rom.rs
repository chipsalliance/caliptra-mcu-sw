/*++

Licensed under the Apache-2.0 license.

File Name:

    riscv.rs

Abstract:

    File contains the common RISC-V code for MCU ROM

--*/

use crate::fatal_error;
use crate::fuses::Otp;
use crate::i3c::I3c;
use caliptra_api::mailbox::CommandId;
use caliptra_api::CaliptraApiError;
use caliptra_api::SocManager;
use core::fmt::Write;
use registers_generated::{fuses::Fuses, i3c, mci, otp_ctrl, soc};
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

    pub fn ready_for_runtime(&self) -> bool {
        self.registers
            .cptra_flow_status
            .is_set(soc::bits::CptraFlowStatus::ReadyForRuntime)
    }

    pub fn fw_ready(&self) -> bool {
        self.registers.ss_generic_fw_exec_ctrl[0].get() & (1 << 2) != 0
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

#[cfg(target_arch = "riscv32")]
fn configure_mrac() {
    // defined in VeeR spec: https://chipsalliance.github.io/Cores-VeeR-EL2/html/main/docs_rendered/html/memory-map.html#region-access-control-register-mrac
    const MRAC_CSR: usize = 0x7c0;
    // Set all memory to side effects and cacheable.
    // The LSU of the VeeR core is set to 64 bits, which translates all
    // memory access to 64 bits by default, even though the core is 32 bits.
    // If we set side effects to true everywhere, then all accesses are instead
    // translated to 32 bits, so we waste less latency and bandwidth.
    // We only have I-Cache (no D-Cache), so it is safe to set all memory to cacheable.
    let mrac = riscv_csr::csr::ReadWriteRiscvCsr::<usize, (), MRAC_CSR>::new();
    mrac.set(0xaaaa_aaaa);
}

#[cfg(not(target_arch = "riscv32"))]
fn configure_mrac() {}

pub fn rom_start() {
    configure_mrac();

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
    let mci = Mci::new(mci_base);
    romtime::println!("[mcu-rom] Setting Caliptra boot go");
    mci.caliptra_boot_go();

    romtime::println!("[mcu-rom] Initializing I3C");
    let mut i3c = I3c::new(i3c_base);
    i3c.configure(0x3a, true);

    // only do these on the emulator for now
    // let otp = Otp::new(otp_base);
    // let otp_status = otp.status();
    // romtime::println!("[mcu-rom] OTP status: {}", HexWord(otp_status));

    // let lc_status =
    //     unsafe { core::ptr::read_volatile((MCU_MEMORY_MAP.lc_offset + 0x4) as *const u32) };
    // romtime::println!("[mcu-rom] LC status: {}", HexWord(lc_status));

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
        let mut vendor = [
            0xb1, 0x7c, 0xa8, 0x77, 0x66, 0x66, 0x57, 0xcc, 0xd1, 0x00, 0xe6, 0x92, 0x6c, 0x72,
            0x06, 0xb6, 0x0c, 0x99, 0x5c, 0xb6, 0x89, 0x92, 0xc6, 0xc9, 0xba, 0xef, 0xce, 0x72,
            0x8a, 0xf0, 0x54, 0x41, 0xde, 0xe1, 0xff, 0x41, 0x5a, 0xdf, 0xc1, 0x87, 0xe1, 0xe4,
            0xed, 0xb4, 0xd3, 0xb2, 0xd9, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // swizzle
        for i in (0..64).step_by(4) {
            let a = vendor[i];
            let b = vendor[i + 1];
            let c = vendor[i + 2];
            let d = vendor[i + 3];
            vendor[i] = d;
            vendor[i + 1] = c;
            vendor[i + 2] = b;
            vendor[i + 3] = a;
        }

        Fuses {
            vendor_hashes_manuf_partition: vendor,
            ..Default::default()
        }
    };

    // TODO: pass these in as parameters
    soc.registers.cptra_wdt_cfg[0].set(100_000_000);
    soc.registers.cptra_wdt_cfg[1].set(100_000_000);

    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for fuses: {}",
        soc.ready_for_fuses()
    );
    while !soc.ready_for_fuses() {}

    romtime::println!("[mcu-rom] Writing fuses to Caliptra");
    romtime::println!("[mcu-rom] Setting Caliptra mailbox user 0 to CCCCCCCC");

    // TODO: read this value from somewhere
    soc.registers.cptra_mbox_valid_axi_user[0].set(0xcccc_cccc);
    romtime::println!("[mcu-rom] Locking Caliptra mailbox user 0");
    soc.registers.cptra_mbox_axi_user_lock[0].set(1);

    romtime::println!("[mcu-rom] Setting TRNG user");
    soc.registers.cptra_trng_valid_axi_user.set(0xcccc_cccc);
    romtime::println!("[mcu-rom] Locking TRNG user");
    soc.registers.cptra_trng_axi_user_lock.set(1);
    romtime::println!("[mcu-rom] Setting DMA user");
    soc.registers.ss_caliptra_dma_axi_user.set(0xcccc_cccc);

    soc.populate_fuses(&fuses);
    romtime::println!("[mcu-rom] Setting Caliptra fuse write done");
    soc.fuse_write_done();
    while soc.ready_for_fuses() {}

    romtime::println!("[mcu-rom] Waiting for Caliptra to be ready for mbox",);
    while !soc.ready_for_mbox() {}
    romtime::println!("[mcu-rom] Caliptra is ready for mailbox commands",);

    // tell Caliptra to download firmware from the recovery interface
    romtime::println!("[mcu-rom] Sending RI_DOWNLOAD_FIRMWARE command",);
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

    romtime::println!("[mcu-rom] Waiting for firmware to be ready");
    while !soc.fw_ready() {}

    // Check that the firmware was actually loaded before jumping to it
    let firmware_ptr = unsafe { MCU_MEMORY_MAP.sram_offset as *const u32 };
    // Safety: this address is valid
    if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
        romtime::println!("Invalid firmware detected; halting");
        fatal_error(1);
    }
    romtime::println!("[mcu-rom] Firmware load detected");

    // wait for the Caliptra RT to be ready
    // this is a busy loop, but it should be very short
    romtime::println!("[mcu-rom] Waiting for Caliptra RT to be ready for runtime mailbox commands");
    while !soc.ready_for_runtime() {}

    romtime::println!("[mcu-rom] Finished common initialization");
}
