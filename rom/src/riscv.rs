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
use registers_generated::i3c::bits::DeviceStatus0;
use registers_generated::i3c::bits::HcControl::BusEnable;
use registers_generated::i3c::bits::HcControl::ModeSelector;
use registers_generated::i3c::bits::IndirectFifoCtrl0;
use registers_generated::i3c::bits::ProtCap2;
use registers_generated::i3c::bits::ProtCap3;
use registers_generated::i3c::bits::QueueThldCtrl;
use registers_generated::i3c::bits::RingHeadersSectionOffset;
use registers_generated::i3c::bits::StbyCrCapabilities;
use registers_generated::i3c::bits::StbyCrCapabilities::TargetXactSupport;
use registers_generated::i3c::bits::StbyCrControl;
use registers_generated::i3c::bits::StbyCrControl::AcrFsmOpSelect;
use registers_generated::i3c::bits::StbyCrControl::DaaEntdaaEnable;
use registers_generated::i3c::bits::StbyCrControl::DaaSetdasaEnable;
use registers_generated::i3c::bits::StbyCrControl::PrimeAcceptGetacccr;
use registers_generated::i3c::bits::StbyCrControl::TargetXactEnable;
use registers_generated::i3c::bits::StbyCrDeviceAddr;
use registers_generated::i3c::bits::StbyCrDeviceAddr::StaticAddrValid;
use registers_generated::i3c::bits::StbyCrVirtDeviceAddr;
use registers_generated::i3c::bits::StbyCrVirtDeviceAddr::VirtStaticAddrValid;
use registers_generated::i3c::bits::TtiQueueThldCtrl;
use registers_generated::{fuses::Fuses, i3c, mbox, mci, otp_ctrl, soc};
use riscv_csr::csr::ReadWriteRiscvCsr;
use romtime::{HexWord, Mci, StaticRef};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

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

// defined in VeeR spec: https://chipsalliance.github.io/Cores-VeeR-EL2/html/main/docs_rendered/html/memory-map.html#region-access-control-register-mrac
const MRAC_CSR: usize = 0x7c0;

pub fn rom_start() {
    // Set all memory to side effects and cacheable.
    // The LSU of the VeeR core is set to 64 bits, which translates all
    // memory access to 64 bits by default, even though the core is 32 bits.
    // If we set side effects to true everywhere, then all accesses are instead
    // translated to 32 bits, so we waste less latency and bandwidth.
    // We only have I-Cache (no D-Cache), so it is safe to set all memory to cacheable.
    let mrac = ReadWriteRiscvCsr::<usize, (), MRAC_CSR>::new();
    mrac.set(0xaaaa_aaaa);

    romtime::println!("[mcu-rom] Hello from ROM");
    let val = 0x01020304u32;
    let addr = unsafe { 0xa8c0_0000u32 as *mut u32 };
    romtime::println!("[mcu-rom] Write {:08x} <= {:08x}", addr as u32, val);
    unsafe {
        core::ptr::write_volatile(addr, val);
    }
    romtime::println!("[mcu-rom] Read {:08x} => {:02x}", addr as u32, unsafe {
        core::ptr::read_volatile(addr as *const u8)
    });

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

    romtime::println!("[mcu-rom] Initialize I3C");
    let mut i3c = I3c::new(i3c_base);
    configure_i3c(&mut i3c, 0x3a, true);

    soc.populate_fuses(&fuses);
    soc.fuse_write_done();
    while soc.ready_for_fuses() {}

    romtime::println!(
        "[mcu-rom] Waiting for Caliptra to be ready for mbox: {}",
        HexWord(soc.flow_status())
    );
    while !soc.ready_for_mbox() {}
    romtime::println!(
        "[mcu-rom] Caliptra is ready for mailbox commands, addr = {}",
        HexWord(unsafe { MCU_MEMORY_MAP.mbox_offset + 0x18 })
    );

    let status =
        unsafe { core::ptr::read_volatile((MCU_MEMORY_MAP.mbox_offset + 0x08) as *mut u32) };

    let status =
        unsafe { core::ptr::read_volatile((MCU_MEMORY_MAP.mbox_offset + 0x18) as *mut u32) };

    romtime::println!("Direct Status {}", HexWord(status));

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
    recovery_flow(&soc, &mut mci, &mut i3c);
    romtime::println!("[mcu-rom] Recovery flow complete");

    // Check that the firmware was actually loaded before jumping to it
    let firmware_ptr = unsafe { (MCU_MEMORY_MAP.sram_offset + 0) as *const u32 };
    for i in 0..8 {
        romtime::println!("Bytes from SRAM: {}: {:02x}", i, unsafe {
            core::ptr::read_volatile((firmware_ptr as *const u8).offset(i))
        });
    }
    // Safety: this address is valid
    if unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {
        romtime::println!("Invalid firmware detected; halting");
        fatal_error(1);
    }

    // wait for the Caliptra RT to be ready
    // this is a busy loop, but it should be very short
    while !soc.ready_for_runtime() {}

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

pub fn recovery_flow(soc: &Soc, mci: &mut Mci, i3c: &mut I3c) {
    // TODO: implement Caliptra boot flow

    // TODO: read this value from the fuses (according to the spec)?
    // i3c.registers.sec_fw_recovery_if_device_id_0.set(0x3a); // placeholder address for now
    // i3c.registers.stdby_ctrl_mode_stby_cr_device_addr.set(0x3a);

    romtime::println!("[mcu-rom] MCI flow status: {}", HexWord(mci.flow_status()));

    // TODO: what value are we looking for
    romtime::println!("[mcu-rom] Waiting for firmware to be ready");
    while !soc.fw_ready() {}
    let firmware_ptr = unsafe { MCU_MEMORY_MAP.sram_offset as *const u32 };
    //while unsafe { core::ptr::read_volatile(firmware_ptr) } == 0 {}
    romtime::println!("[mcu-rom] Firmware load detected");
    //for i in 0..4 {
    //    unsafe { romtime::println!("SRAM: {:02x}", core::ptr::read_volatile((MCU_MEMORY_MAP.sram_offset as *const u8).offset(i))); }
    //}
}

fn configure_i3c(i3c: &mut I3c, addr: u8, recovery_enabled: bool) {
    let regs = i3c.registers;
    romtime::println!("I3C HCI version: {:x}", regs.i3c_base_hci_version.get());

    romtime::println!("Set TTI RESET_CONTROL");
    regs.tti_tti_reset_control.set(0x3f);
    romtime::println!("TTI RESET_CONTROL: {:x}", regs.tti_tti_reset_control.get());

    // Evaluate RING_HEADERS_SECTION_OFFSET, the SECTION_OFFSET should read 0x0 as this controller doesn’t support the DMA mode
    romtime::println!("Check ring headers section offset");
    let rhso = regs
        .i3c_base_ring_headers_section_offset
        .read(RingHeadersSectionOffset::SectionOffset);
    if rhso != 0 {
        panic!("RING_HEADERS_SECTION_OFFSET is not 0");
    }

    romtime::println!("TTI QUEUE_SIZE: {:x}", regs.tti_tti_queue_size.get());

    // Set PROT_CAP early so that the BMC won't abort the recovery flow.
    // if recovery_enabled {
    //     romtime::println!("Enabling recovery interface prot cap");
    //     regs.sec_fw_recovery_if_prot_cap_2.write(
    //         ProtCap2::RecProtVersion.val(0x101)
    //             + ProtCap2::AgentCaps.val(
    //                 (1 << 0) | // device id
    //             (1 << 4) | // device status
    //             (1 << 5) | // indirect ctrl
    //             (1 << 7), // push c-image support
    //             ),
    //     );
    //     regs.sec_fw_recovery_if_prot_cap_3.write(
    //         ProtCap3::NumOfCmsRegions.val(1) + ProtCap3::MaxRespTime.val(20), // 1.048576 second maximum response time
    //     );
    // }

    // initialize timing registers
    romtime::println!("Initialize timing registers");

    // AXI clock is ~200 MHz, I3C clock is 12.5 MHz
    // values of all of these set to 0-5 seem to work for receiving data correctly
    // 6-7 gets corrupted data but will ACK
    // 8+ will fail to ACK
    //
    let clocks = 0;
    regs.soc_mgmt_if_t_r_reg.set(clocks); // rise time of both SDA and SCL in clock units
    regs.soc_mgmt_if_t_f_reg.set(clocks); // rise time of both SDA and SCL in clock units

    // if this is set to 6+ then ACKs start failing
    regs.soc_mgmt_if_t_hd_dat_reg.set(clocks); // data hold time in clock units
    regs.soc_mgmt_if_t_su_dat_reg.set(clocks); // data setup time in clock units

    regs.soc_mgmt_if_t_high_reg.set(clocks); // High period of the SCL in clock units
    regs.soc_mgmt_if_t_low_reg.set(clocks); // Low period of the SCL in clock units
    regs.soc_mgmt_if_t_hd_sta_reg.set(clocks); // Hold time for (repeated) START in clock units
    regs.soc_mgmt_if_t_su_sta_reg.set(clocks); // Setup time for repeated START in clock units
    regs.soc_mgmt_if_t_su_sto_reg.set(clocks); // Setup time for STOP in clock units

    // set this to 1 microsecond
    regs.soc_mgmt_if_t_free_reg.set(200); // Bus free time in clock units before doing IBI

    romtime::println!(
            "Timing register t_r: {}, t_f: {}, t_hd_dat: {}, t_su_dat: {}, t_high: {}, t_low: {}, t_hd_sta: {}, t_su_sta: {}, t_su_sto: {}, t_free: {}",
            regs.soc_mgmt_if_t_r_reg.get(),
            regs.soc_mgmt_if_t_f_reg.get(),
            regs.soc_mgmt_if_t_hd_dat_reg.get(),
            regs.soc_mgmt_if_t_su_dat_reg.get(),
            regs.soc_mgmt_if_t_high_reg.get(),
            regs.soc_mgmt_if_t_low_reg.get(),
            regs.soc_mgmt_if_t_hd_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sta_reg.get(),
            regs.soc_mgmt_if_t_su_sto_reg.get(),
            regs.soc_mgmt_if_t_free_reg.get(),
        );

    // Setup the threshold for the HCI queues (in the internal/private software data structures):
    romtime::println!("Setup HCI queue thresholds");
    regs.piocontrol_queue_thld_ctrl.modify(
        QueueThldCtrl::CmdEmptyBufThld.val(0)
            + QueueThldCtrl::RespBufThld.val(1)
            + QueueThldCtrl::IbiStatusThld.val(1),
    );

    romtime::println!("Enable the target transaction interface");
    regs.stdby_ctrl_mode_stby_cr_control.modify(
        StbyCrControl::StbyCrEnableInit.val(2) // enable the standby controller
                + StbyCrControl::TargetXactEnable::SET // enable Target Transaction Interface
                + StbyCrControl::DaaEntdaaEnable::SET // enable ENTDAA dynamic address assignment
                + StbyCrControl::DaaSetdasaEnable::SET // enable SETDASA dynamic address assignment
                + StbyCrControl::BastCccIbiRing.val(0) // Set the IBI to use ring buffer 0
                + StbyCrControl::PrimeAcceptGetacccr::CLEAR // // don't auto-accept primary controller role
                + StbyCrControl::AcrFsmOpSelect::CLEAR, // don't become the active controller and set us as not the bus owner
    );

    romtime::println!(
        "STBY_CR_CONTROL: {:x}",
        regs.stdby_ctrl_mode_stby_cr_control.get()
    );

    regs.stdby_ctrl_mode_stby_cr_capabilities
        .write(StbyCrCapabilities::TargetXactSupport::SET);
    romtime::println!(
        "STBY_CR_CAPABILITIES: {:x}",
        regs.stdby_ctrl_mode_stby_cr_capabilities.get()
    );
    if !regs
        .stdby_ctrl_mode_stby_cr_capabilities
        .is_set(StbyCrCapabilities::TargetXactSupport)
    {
        panic!("I3C target transaction support is not enabled");
    }

    // program a static address
    romtime::println!("Setting static address to {:x}", addr);
    regs.stdby_ctrl_mode_stby_cr_device_addr.write(
        StbyCrDeviceAddr::StaticAddrValid::SET + StbyCrDeviceAddr::StaticAddr.val(addr as u32),
    );
    if recovery_enabled {
        romtime::println!("Setting virtual device static address to {:x}", addr + 1);
        regs.stdby_ctrl_mode_stby_cr_virt_device_addr.write(
            StbyCrVirtDeviceAddr::VirtStaticAddrValid::SET
                + StbyCrVirtDeviceAddr::VirtStaticAddr.val((addr + 1) as u32),
        );
    }

    romtime::println!("Set TTI queue thresholds");
    // set TTI queue thresholds
    regs.tti_tti_queue_thld_ctrl.modify(
        TtiQueueThldCtrl::IbiThld.val(1)
            + TtiQueueThldCtrl::RxDescThld.val(1)
            + TtiQueueThldCtrl::TxDescThld.val(1),
    );
    romtime::println!(
        "TTI queue thresholds: {:x}",
        regs.tti_tti_queue_thld_ctrl.get()
    );

    romtime::println!(
        "TTI data buffer thresholds ctrl: {:x}",
        regs.tti_tti_data_buffer_thld_ctrl.get()
    );

    // reset the FIFO as there might be junk in it
    regs.sec_fw_recovery_if_indirect_fifo_ctrl_0
        .write(IndirectFifoCtrl0::Reset.val(1));
    regs.sec_fw_recovery_if_indirect_fifo_ctrl_1.set(0);

    romtime::println!("Enable PHY to the bus");
    // enable the PHY connection to the bus
    regs.i3c_base_hc_control
        .modify(ModeSelector::SET + BusEnable::CLEAR); // clear is enabled, set is suspended

    romtime::println!("Enabling interrupts");
    // regs.tti_interrupt_enable.modify(
    //     InterruptEnable::IbiThldStatEn::SET
    //         + InterruptEnable::RxDescThldStatEn::SET
    //         + InterruptEnable::TxDescThldStatEn::SET
    //         + InterruptEnable::RxDataThldStatEn::SET
    //         + InterruptEnable::TxDataThldStatEn::SET,
    // );
    // regs.tti_interrupt_enable.set(0xffff_ffff);
    // romtime::println!(
    //     "I3C target interrupt enable {:x}",
    //     regs.tti_interrupt_enable.get()
    // );

    romtime::println!(
        "I3C target status {:x}, interrupt status {:x}",
        regs.tti_status.get(),
        regs.tti_interrupt_status.get()
    );

    // if recovery_enabled {
    // regs.sec_fw_recovery_if_device_status_0
    //     .write(DeviceStatus0::DevStatus.val(0x3)); // ready to accept recovery image
    //}

    // romtime::println!(
    //     "I3C recovery prot_cap 2 and 3: {:08x} {:08x}",
    //     regs.sec_fw_recovery_if_prot_cap_2.get(),
    //     regs.sec_fw_recovery_if_prot_cap_3.get(),
    // );
    // romtime::println!(
    //     "I3C recovery device status: {:x}",
    //     regs.sec_fw_recovery_if_device_status_0
    //         .read(DeviceStatus0::DevStatus)
    // );
}
