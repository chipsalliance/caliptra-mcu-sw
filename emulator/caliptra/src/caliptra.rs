/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_api_types::{DeviceLifecycle, SecurityState};
use caliptra_emu_bus::{BusMmio, Clock};
use caliptra_emu_cpu::{Cpu, CpuArgs, Pic};
use caliptra_emu_periph::soc_reg::DebugManufService;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, MailboxInternal, MailboxRequester,
    Mci, ReadyForFwCb, SocToCaliptraBus, TbServicesCb, UploadUpdateFwCb,
};
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
pub struct StartCaliptraArgs {
    pub rom: BytesOrPath,
    pub req_idevid_csr: Option<bool>,
    pub device_lifecycle: Option<String>,
    pub use_mcu_recovery_interface: bool,
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
    args: &StartCaliptraArgs,
) -> io::Result<(Cpu<CaliptraRootBus>, SocToCaliptraBus, Mci)> {
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
    security_state.set_device_lifecycle(
        match args_device_lifecycle.to_ascii_lowercase().as_str() {
            "manufacturing" => DeviceLifecycle::Manufacturing,
            "production" => DeviceLifecycle::Production,
            "unprovisioned" | "" => DeviceLifecycle::Unprovisioned,
            other => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown device lifecycle {:?}", other),
            ))?,
        },
    );

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
        ..Default::default()
    };

    let root_bus = CaliptraRootBus::new(bus_args);
    let soc_ifc = unsafe {
        caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
            0x3003_0000 as *mut u32,
            BusMmio::new(root_bus.soc_to_caliptra_bus(MAILBOX_USER)),
        )
    };
    let ext_mci = root_bus.mci_external_regs();

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

    Ok((
        Cpu::new(root_bus, clock.clone(), pic.clone(), CpuArgs::default()),
        ext_soc_ifc,
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
