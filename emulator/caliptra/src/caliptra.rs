/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_api_types::{DeviceLifecycle, SecurityState};
use caliptra_emu_bus::{Bus, BusMmio, Clock};
use caliptra_emu_cpu::{Cpu, CpuArgs, Pic};
use caliptra_emu_periph::dma::axi_root_bus::SubsystemAddresses;
use caliptra_emu_periph::soc_reg::DebugManufService;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, MailboxInternal, MailboxRequester,
    Mci, ReadyForFwCb, SocToCaliptraBus, TbServicesCb, UploadUpdateFwCb,
};
use caliptra_emu_types::RvSize;
use caliptra_hw_model_types::DEFAULT_UDS_SEED;
#[cfg(test)]
use std::cell::Cell;
use std::io::{self, ErrorKind, Write};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

/// Mailbox user for accessing Caliptra mailbox.
const MAILBOX_USER: MailboxRequester = MailboxRequester::SocUser(1);

#[derive(Debug)]
pub enum BytesOrPath {
    Bytes(Vec<u8>),
    Path(PathBuf),
}

impl Default for BytesOrPath {
    fn default() -> Self {
        BytesOrPath::Bytes(Vec::new())
    }
}

impl BytesOrPath {
    fn exists(&self) -> bool {
        match self {
            BytesOrPath::Bytes(_) => true,
            BytesOrPath::Path(p) => p.exists(),
        }
    }

    fn read(&self) -> io::Result<Vec<u8>> {
        match self {
            BytesOrPath::Bytes(b) => Ok(b.clone()),
            BytesOrPath::Path(p) => std::fs::read(p),
        }
    }
}

#[derive(Default)]
pub struct StartCaliptraArgs<'a> {
    pub rom: BytesOrPath,
    pub req_idevid_csr: Option<bool>,
    pub device_lifecycle: Option<String>,
    pub cptra_hw_config: Option<u32>,
    pub prod_dbg_unlock_pk_hashes_offset: Option<u32>,
    pub num_prod_dbg_unlock_pk_hashes: Option<u32>,
    pub ss_strap_generic_0: Option<u32>,
    pub ss_strap_generic_1: Option<u32>,
    pub use_mcu_recovery_interface: bool,
    pub extra_soc_bus: Option<u32>,
    pub debug_intent: bool,
    pub prod_dbg_unlock_keypairs: Vec<(&'a [u8; 96], &'a [u8; 2592])>,
    pub cptra_obf_key: [u32; 8],
    pub ss_caliptra_dma_axi_user: Option<u32>,
}

register_bitfields! [
    u32,
    IDevIdCertAttrFlags [
        KEY_ID_ALGO OFFSET(0) NUMBITS(2) [
            SHA1 = 0b00,
            SHA256 = 0b01,
            SHA384 = 0b10,
            FUSE = 0b11,
        ],
        RESERVED OFFSET(2) NUMBITS(30) [],
    ],
];

/// Creates and returns an initialized a Caliptra emulator CPU.
pub fn start_caliptra(
    args: &StartCaliptraArgs<'_>,
) -> io::Result<(
    Cpu<CaliptraRootBus>,
    SocToCaliptraBus,
    Option<SocToCaliptraBus>,
    Mci,
)> {
    let tmp = PathBuf::from("/tmp");
    let args_log_dir = &tmp;
    let args_idevid_key_id_algo = "sha1";
    let args_ueid = u128::MAX;
    let unprovisioned = String::from("unprovisioned");
    let args_device_lifecycle = args.device_lifecycle.as_ref().unwrap_or(&unprovisioned);
    let args_use_mcu_recovery_interface = args.use_mcu_recovery_interface;
    if !args.rom.exists() {
        Err(io::Error::new(
            ErrorKind::NotFound,
            format!("ROM File {:?} does not exist", &args.rom),
        ))?;
    }

    let req_idevid_csr = args.req_idevid_csr.unwrap_or(false);
    let rom_buffer = args.rom.read()?;

    if rom_buffer.len() > CaliptraRootBus::ROM_SIZE {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "ROM File Size must not exceed {} bytes",
                CaliptraRootBus::ROM_SIZE
            ),
        ))?;
    }

    let log_dir = Rc::new(args_log_dir.to_path_buf());

    let clock = Rc::new(Clock::new());
    let pic = Rc::new(Pic::new());

    let mut security_state = SecurityState::default();
    let requested_lifecycle = match args_device_lifecycle.to_ascii_lowercase().as_str() {
        "manufacturing" => DeviceLifecycle::Manufacturing,
        "production" => DeviceLifecycle::Production,
        "unprovisioned" | "" => DeviceLifecycle::Unprovisioned,
        other => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Unknown device lifecycle {:?}", other),
        ))?,
    };

    // If debug intent is not set or unlock level 0 is not set, then the security state
    // should be latched as production.
    // In the emulator, we don't easily have access to the register state before Caliptra starts.
    // However, we can simulate the latching logic by defaulting to Production unless
    // specifically overridden by a mechanism that represents "unlocked".

    // For now, we follow the RTL logic: it is unlocked if (debug_intent AND SS_SOC_DBG_UNLOCK_LEVEL[0])
    // OR ss_dbg_manuf_enable.
    // Since we don't have registers yet, we'll assume it's locked unless debug_intent is set
    // AND some other condition we can pass in.
    // But the user said "if the debug_intent and SS_SOC_DBG_UNLOCK_LEVEL are not set ... report the correct security state"
    // This implies that if they ARE set, it should NOT be Production.

    // Since we are at reset deassertion, SS_SOC_DBG_UNLOCK_LEVEL is 0.
    // So it should ALWAYS be locked at reset deassertion.
    let is_unlocked = false;

    if !is_unlocked {
        security_state.set_device_lifecycle(DeviceLifecycle::Production);
    } else {
        security_state.set_device_lifecycle(requested_lifecycle);
    }
    // in active mode, we don't upload the firmware here, as MCU ROM will trigger it
    let ready_for_fw_cb = ReadyForFwCb::new(|_| {});
    // in active mode, we don't update firmware here, as MCU will trigger it
    let upload_update_fw = UploadUpdateFwCb::new(|_| {});

    let bus_args = CaliptraRootBusArgs {
        clock: clock.clone(),
        pic: pic.clone(),
        rom: rom_buffer,
        log_dir: args_log_dir.clone(),
        tb_services_cb: TbServicesCb::new(move |val| match val {
            0x01 => exit(0xFF),
            0xFF => exit(0x00),
            _ => print!("{}", val as char),
        }),
        ready_for_fw_cb,
        security_state,
        upload_update_fw,
        download_idevid_csr_cb: DownloadIdevidCsrCb::new(
            move |mailbox: &mut MailboxInternal,
                  cptra_dbg_manuf_service_reg: &mut InMemoryRegister<
                u32,
                DebugManufService::Register,
            >| {
                download_idev_id_csr(mailbox, log_dir.clone(), cptra_dbg_manuf_service_reg);
            },
        ),
        subsystem_mode: true,
        use_mcu_recovery_interface: args_use_mcu_recovery_interface,
        enable_external_soc_dma: args.extra_soc_bus.is_some(),
        subsystem_addresses: Some(SubsystemAddresses {
            caliptra: 0x3000_0000,
            mci: 0xA800_0000,
            recovery: 0x0006_0100,
            otp_fc: 0x0005_0000,
            uds_seed: 0x0000_0048,
        }),
        debug_intent: args.debug_intent,
        prod_dbg_unlock_keypairs: args.prod_dbg_unlock_keypairs.clone(),
        cptra_obf_key: args.cptra_obf_key,
        ..Default::default()
    };

    let mut root_bus = CaliptraRootBus::new(bus_args);
    if let Some(hw_config) = args.cptra_hw_config {
        root_bus.soc_reg.set_hw_config(hw_config.into());
    }
    if let (Some(hash_offset), Some(hash_count)) = (
        args.prod_dbg_unlock_pk_hashes_offset,
        args.num_prod_dbg_unlock_pk_hashes,
    ) {
        root_bus
            .soc_reg
            .set_prod_debug_unlock_config(hash_offset, hash_count);
    }
    if args.ss_strap_generic_0.is_some() || args.ss_strap_generic_1.is_some() {
        root_bus.soc_reg.set_strap_generic(&[
            args.ss_strap_generic_0.unwrap_or_default(),
            args.ss_strap_generic_1.unwrap_or_default(),
            0,
            0,
        ]);
    }
    // Set UDS seed directly — matches the caliptra-sw standalone emulator
    // behavior where fuse_uds_seed = DEFAULT_UDS_SEED (via SocRegistersImpl::UDS default).
    root_bus.soc_reg.set_uds_seed(&DEFAULT_UDS_SEED);
    if let Some(val) = args.ss_caliptra_dma_axi_user {
        if val != 0 {
            root_bus
                .soc_reg
                .write(RvSize::Word, 0x534, val)
                .expect("SS_CALIPTRA_DMA_AXI_USER register must be writable");
        }
    }
    let soc_ifc = unsafe {
        caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
            0x3003_0000 as *mut u32,
            BusMmio::new(root_bus.soc_to_caliptra_bus(MAILBOX_USER)),
        )
    };
    let ext_mci = root_bus.mci_external_regs();

    {
        ext_mci.regs.borrow_mut().security_state = security_state.into();
    }

    // Populate DBG_MANUF_SERVICE_REG
    soc_ifc
        .cptra_dbg_manuf_service_reg()
        .write(|_| if req_idevid_csr { 1 } else { 0 });

    // Populate fuse_idevid_cert_attr
    {
        // Determine the Algorithm used for IDEVID Certificate Subject Key Identifier
        let algo = match args_idevid_key_id_algo.to_ascii_lowercase().as_str() {
            "" | "sha1" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA1,
            "sha256" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA256,
            "sha384" => IDevIdCertAttrFlags::KEY_ID_ALGO::SHA384,
            "fuse" => IDevIdCertAttrFlags::KEY_ID_ALGO::FUSE,
            _ => panic!("Unknown idev_key_id_algo {:?}", args_idevid_key_id_algo),
        };

        let flags: InMemoryRegister<u32, IDevIdCertAttrFlags::Register> = InMemoryRegister::new(0);
        flags.write(algo);
        let mut cert = [0u32; 24];
        // DWORD 00 - Flags
        cert[0] = flags.get();
        // DWORD 01 - 05 - IDEVID Subject Key Identifier (all zeroes)
        cert[6] = 1; // UEID Type
                     // DWORD 07 - 10 - UEID / Manufacturer Serial Number
        cert[7] = args_ueid as u32;
        cert[8] = (args_ueid >> 32) as u32;
        cert[9] = (args_ueid >> 64) as u32;
        cert[10] = (args_ueid >> 96) as u32;

        soc_ifc.fuse_idevid_cert_attr().write(&cert);
    }

    let ext_soc_ifc = root_bus.soc_to_caliptra_bus(MAILBOX_USER);
    let extra_soc_ifc = args
        .extra_soc_bus
        .map(|user| root_bus.soc_to_caliptra_bus(MailboxRequester::SocUser(user)));

    Ok((
        Cpu::new(root_bus, clock.clone(), pic.clone(), CpuArgs::default()),
        ext_soc_ifc,
        extra_soc_ifc,
        ext_mci,
    ))
}

fn download_idev_id_csr(
    mailbox: &mut MailboxInternal,
    path: Rc<PathBuf>,
    cptra_dbg_manuf_service_reg: &mut InMemoryRegister<u32, DebugManufService::Register>,
) {
    let mut path = path.to_path_buf();
    path.push("caliptra_ldevid_cert.der");

    let mut file = std::fs::File::create(path).unwrap();

    let soc_mbox = mailbox.as_external(MAILBOX_USER).regs();

    let byte_count = soc_mbox.dlen().read() as usize;
    let remainder = byte_count % core::mem::size_of::<u32>();
    let n = byte_count - remainder;

    for _ in (0..n).step_by(core::mem::size_of::<u32>()) {
        let buf = soc_mbox.dataout().read();
        file.write_all(&buf.to_le_bytes()).unwrap();
    }

    if remainder > 0 {
        let part = soc_mbox.dataout().read();
        for idx in 0..remainder {
            let byte = ((part >> (idx << 3)) & 0xFF) as u8;
            file.write_all(&[byte]).unwrap();
        }
    }

    // Complete the mailbox command.
    soc_mbox.status().write(|w| w.status(|w| w.cmd_complete()));

    // Clear the Idevid CSR requested bit.
    cptra_dbg_manuf_service_reg.modify(DebugManufService::REQ_IDEVID_CSR::CLEAR);
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::BusError;
    use caliptra_emu_types::{RvAddr, RvData};
    use caliptra_mcu_emulator_periph::CaliptraToExtBus;
    use caliptra_mcu_emulator_registers_generated::root_bus::{AutoRootBus, AutoRootBusOffsets};

    struct UnclaimedBus;

    impl Bus for UnclaimedBus {
        fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, BusError> {
            Err(BusError::LoadAccessFault)
        }

        fn write(&mut self, _size: RvSize, _addr: RvAddr, _value: RvData) -> Result<(), BusError> {
            Err(BusError::StoreAccessFault)
        }
    }

    #[test]
    fn subsystem_soc_register_values_match_rtl() {
        let (_, mut soc, _, _) = start_caliptra(&StartCaliptraArgs {
            debug_intent: true,
            cptra_hw_config: Some(0x31),
            prod_dbg_unlock_pk_hashes_offset: Some(0x000d_0120),
            num_prod_dbg_unlock_pk_hashes: Some(1),
            ss_strap_generic_0: Some(0x0015_0010),
            ss_strap_generic_1: Some(0x0005_005c),
            ss_caliptra_dma_axi_user: Some(0x10),
            ..Default::default()
        })
        .unwrap();

        let expected = [
            (0x3003_0044, 0x0000_0003),
            (0x3003_0070, 0xffff_ffff),
            (0x3003_00d4, 0x0000_0302),
            (0x3003_00e0, 0x31),
            (0x3003_0500, 0x3000_0000),
            (0x3003_0504, 0),
            (0x3003_0508, 0xA800_0000),
            (0x3003_050c, 0),
            (0x3003_0510, 0x0006_0100),
            (0x3003_0514, 0),
            (0x3003_0518, 0x0005_0000),
            (0x3003_051c, 0),
            (0x3003_0520, 0x0000_0048),
            (0x3003_0524, 0),
            (0x3003_0528, 0x000d_0120),
            (0x3003_052c, 1),
            (0x3003_0530, 1),
            (0x3003_0534, 0x10),
            (0x3003_05a0, 0x0015_0010),
            (0x3003_05a4, 0x0005_005c),
        ];
        for (address, value) in expected {
            assert_eq!(soc.read(RvSize::Word, address), Ok(value), "{address:#x}");
        }

        let reserved_ranges = [
            (0x3003_0134, 3),
            (0x3003_0174, 35),
            (0x3003_0294, 8),
            (0x3003_033c, 1),
            (0x3003_03a4, 87),
            (0x3003_0538, 26),
            (0x3003_05b0, 4),
        ];
        for (start, word_count) in reserved_ranges {
            for address in (start..start + word_count * 4).step_by(4) {
                assert_eq!(soc.read(RvSize::Word, address), Ok(0), "{address:#x}");
                assert_eq!(
                    soc.write(RvSize::Word, address, u32::MAX),
                    Ok(()),
                    "{address:#x}"
                );
                assert_eq!(soc.read(RvSize::Word, address), Ok(0), "{address:#x}");
            }
        }
    }

    #[test]
    fn subsystem_straps_can_be_configured_independently() {
        for (strap_0, strap_1, expected_0, expected_1) in [
            (Some(0x0015_0010), None, 0x0015_0010, 0),
            (None, Some(0x0005_005c), 0, 0x0005_005c),
        ] {
            let (_, mut soc, _, _) = start_caliptra(&StartCaliptraArgs {
                ss_strap_generic_0: strap_0,
                ss_strap_generic_1: strap_1,
                ..Default::default()
            })
            .unwrap();

            assert_eq!(soc.read(RvSize::Word, 0x3003_05a0), Ok(expected_0));
            assert_eq!(soc.read(RvSize::Word, 0x3003_05a4), Ok(expected_1));
        }
    }

    #[test]
    fn soc_reserved_read_does_not_reach_external_bus() {
        let (_, soc_to_caliptra, _, _) = start_caliptra(&StartCaliptraArgs::default()).unwrap();
        let external_read_called = Rc::new(Cell::new(false));
        let callback_flag = external_read_called.clone();
        let mut caliptra_to_ext = CaliptraToExtBus::new();
        caliptra_to_ext.set_read_callback(move |_, _, _| {
            callback_flag.set(true);
            false
        });

        let delegates: Vec<Box<dyn Bus>> = vec![
            Box::new(UnclaimedBus),
            Box::new(soc_to_caliptra),
            Box::new(caliptra_to_ext),
        ];
        let mut offsets = AutoRootBusOffsets::default();
        offsets.soc_offset = 0x3002_0000;
        offsets.soc_size = 0x2_0000;
        let mut root_bus = AutoRootBus::new(
            delegates,
            Some(offsets),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(root_bus.read(RvSize::Word, 0x3003_033c), Ok(0));
        assert!(!external_read_called.get());
    }
}
