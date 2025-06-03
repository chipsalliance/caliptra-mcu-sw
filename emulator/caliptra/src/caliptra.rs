/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

use caliptra_api_types::{DeviceLifecycle, SecurityState};
use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::{Cpu, CpuArgs, Pic};
use caliptra_emu_periph::soc_reg::DebugManufService;
use caliptra_emu_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, MailboxInternal, MailboxRequester,
    ReadyForFwCb, SocToCaliptraBus, TbServicesCb, UploadUpdateFwCb,
};
use caliptra_hw_model::BusMmio;
use std::fs::File;
use std::io::{self, ErrorKind};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;
/// Mailbox user for accessing Caliptra mailbox.
const MAILBOX_USER: MailboxRequester = MailboxRequester::SocUser(1);

/// The number of CPU clock cycles it takes to write the firmware to the mailbox.
const FW_WRITE_TICKS: u64 = 1000;

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles

fn words_from_bytes_le(arr: &[u8; 48]) -> [u32; 12] {
    let mut result = [0u32; 12];
    for i in 0..result.len() {
        result[i] = u32::from_le_bytes(arr[i * 4..][..4].try_into().unwrap())
    }
    result
}

#[derive(Default)]
pub struct StartCaliptraArgs {
    pub rom: Option<PathBuf>,
    pub active_mode: bool,
    pub firmware: Option<PathBuf>,
    pub update_firmware: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    pub ueid: Option<u128>,
    pub idevid_key_id_algo: Option<String>,
    pub req_idevid_csr: Option<bool>,
    pub req_ldevid_cert: Option<bool>,
    pub mfg_pk_hash: Option<String>,
    pub owner_pk_hash: Option<String>,
    pub device_lifecycle: Option<String>,
    pub wdt_timeout: Option<u64>,
}

/// Creates and returns an initialized a Caliptra emulator CPU.
pub fn start_caliptra(
    args: &StartCaliptraArgs,
) -> io::Result<(Option<Cpu<CaliptraRootBus>>, SocToCaliptraBus)> {
    let args_rom = &args.rom;
    let args_current_fw = &args.firmware;
    let args_update_fw = &args.update_firmware;
    let tmp = PathBuf::from("/tmp");
    let args_log_dir = args.log_dir.as_ref().unwrap_or(&tmp);
    let args_idevid_key_id_algo = args.idevid_key_id_algo.as_deref().unwrap_or("sha1");
    let args_ueid = args.ueid.unwrap_or(u128::MAX);
    let wdt_timeout = args
        .wdt_timeout
        .unwrap_or(EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES);
    let mut mfg_pk_hash = match hex::decode(args.mfg_pk_hash.as_ref().unwrap_or(&String::new())) {
        Ok(mfg_pk_hash) => mfg_pk_hash,
        Err(_) => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Manufacturer public keys hash format is incorrect",
            ));
        }
    };
    let mut owner_pk_hash = match hex::decode(args.owner_pk_hash.as_ref().unwrap_or(&String::new()))
    {
        Ok(owner_pk_hash) => owner_pk_hash,
        Err(_) => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Owner public key hash format is incorrect",
            ));
        }
    };
    let unprovisioned = String::from("unprovisioned");
    let args_device_lifecycle = args.device_lifecycle.as_ref().unwrap_or(&unprovisioned);
    if let Some(args_rom) = args_rom.as_ref() {
        if !Path::new(args_rom).exists() {
            Err(io::Error::new(
                ErrorKind::NotFound,
                format!("ROM File {:?} does not exist", args_rom),
            ))?;
        }
    }

    if (!mfg_pk_hash.is_empty() && mfg_pk_hash.len() != 48)
        || (!owner_pk_hash.is_empty() && owner_pk_hash.len() != 48)
    {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Incorrect mfg_pk_hash: {} and/or owner_pk_hash: {} length",
                mfg_pk_hash.len(),
                owner_pk_hash.len()
            ),
        ))?;
    }
    change_dword_endianess(&mut mfg_pk_hash);
    change_dword_endianess(&mut owner_pk_hash);
    let req_idevid_csr = args.req_idevid_csr.unwrap_or(false);
    let req_ldevid_cert = args.req_ldevid_cert.unwrap_or(false);

    let mut rom_buffer = Vec::new();
    if let Some(args_rom) = args_rom {
        let mut rom = File::open(args_rom)?;
        rom.read_to_end(&mut rom_buffer)?;
    }

    if rom_buffer.len() > CaliptraRootBus::ROM_SIZE {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "ROM File Size must not exceed {} bytes",
                CaliptraRootBus::ROM_SIZE
            ),
        ))?;
    }

    let mut current_fw_buf = Vec::new();
    if let Some(path) = args_current_fw {
        if !Path::new(path).exists() {
            Err(io::Error::new(
                ErrorKind::NotFound,
                format!("Current firmware file {:?} does not exist", path),
            ))?;
        }
        let mut firmware = File::open(path)?;
        firmware.read_to_end(&mut current_fw_buf)?;
    }
    let current_fw_buf = Rc::new(current_fw_buf);

    let mut update_fw_buf = Vec::new();
    if let Some(path) = args_update_fw {
        Err(io::Error::new(
            ErrorKind::NotFound,
            format!("Update firmware file {:?} does not exist", args_update_fw),
        ))?;
        let mut firmware = File::open(path)?;
        firmware.read_to_end(&mut update_fw_buf)?;
    }
    let update_fw_buf = Rc::new(update_fw_buf);

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

    let ready_for_fw_cb = if args.active_mode {
        // in active mode, we don't upload the firmware here, as MCU ROM will trigger it
        ReadyForFwCb::new(|_| {})
    } else {
        ReadyForFwCb::new(move |args| {
            let firmware_buffer = current_fw_buf.clone();
            args.schedule_later(FW_WRITE_TICKS, move |mailbox: &mut MailboxInternal| {
                upload_fw_to_mailbox(mailbox, firmware_buffer);
            });
        })
    };

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
        upload_update_fw: UploadUpdateFwCb::new(move |mailbox: &mut MailboxInternal| {
            upload_fw_to_mailbox(mailbox, update_fw_buf.clone());
        }),
        download_idevid_csr_cb: DownloadIdevidCsrCb::new(
            move |mailbox: &mut MailboxInternal,
                  cptra_dbg_manuf_service_reg: &mut InMemoryRegister<
                u32,
                DebugManufService::Register,
            >| {
                download_idev_id_csr(mailbox, log_dir.clone(), cptra_dbg_manuf_service_reg);
            },
        ),
        subsystem_mode: args.active_mode,
        ..Default::default()
    };

    let root_bus = CaliptraRootBus::new(bus_args);
    let soc_ifc = unsafe {
        caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
            0x3003_0000 as *mut u32,
            BusMmio::new(root_bus.soc_to_caliptra_bus(MAILBOX_USER)),
        )
    };

    if !mfg_pk_hash.is_empty() {
        let mfg_pk_hash = words_from_bytes_le(
            &mfg_pk_hash
                .try_into()
                .expect("mfg_pk_hash must be 48 bytes"),
        );
        soc_ifc.fuse_vendor_pk_hash().write(&mfg_pk_hash);
    }

    if !owner_pk_hash.is_empty() {
        let owner_pk_hash = words_from_bytes_le(
            &owner_pk_hash
                .try_into()
                .expect("owner_pk_hash must be 48 bytes"),
        );
        soc_ifc.cptra_owner_pk_hash().write(&owner_pk_hash);
    }

    // Populate DBG_MANUF_SERVICE_REG
    {
        const GEN_IDEVID_CSR_FLAG: u32 = 1 << 0;
        const GEN_LDEVID_CSR_FLAG: u32 = 1 << 1;

        let mut val = 0;
        if req_idevid_csr {
            val |= GEN_IDEVID_CSR_FLAG;
        }
        if req_ldevid_cert {
            val |= GEN_LDEVID_CSR_FLAG;
        }
        soc_ifc.cptra_dbg_manuf_service_reg().write(|_| val);
    }

    // Populate fuse_idevid_cert_attr
    {
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

    // Populate cptra_wdt_cfg
    {
        soc_ifc.cptra_wdt_cfg().at(0).write(|_| wdt_timeout as u32);
        soc_ifc
            .cptra_wdt_cfg()
            .at(1)
            .write(|_| (wdt_timeout >> 32) as u32);
    }

    let ext_soc_ifc = root_bus.soc_to_caliptra_bus(MAILBOX_USER);

    // only return a full CPU if we have a firmware to run
    if args_rom.is_some() {
        Ok((
            Some(Cpu::new(
                root_bus,
                clock.clone(),
                pic.clone(),
                CpuArgs::default(),
            )),
            ext_soc_ifc,
        ))
    } else {
        Ok((None, ext_soc_ifc))
    }
}

fn change_dword_endianess(data: &mut [u8]) {
    for idx in (0..data.len()).step_by(4) {
        data.swap(idx, idx + 3);
        data.swap(idx + 1, idx + 2);
    }
}

fn upload_fw_to_mailbox(mailbox: &mut MailboxInternal, firmware_buffer: Rc<Vec<u8>>) {
    let soc_mbox = mailbox.as_external(MAILBOX_USER).regs();
    // Write the cmd to mailbox.

    assert!(!soc_mbox.lock().read().lock());

    soc_mbox.cmd().write(|_| FW_LOAD_CMD_OPCODE);
    soc_mbox.dlen().write(|_| firmware_buffer.len() as u32);

    //
    // Write firmware image.
    //
    let word_size = std::mem::size_of::<u32>();
    let remainder = firmware_buffer.len() % word_size;
    let n = firmware_buffer.len() - remainder;

    for idx in (0..n).step_by(word_size) {
        soc_mbox.datain().write(|_| {
            u32::from_le_bytes(firmware_buffer[idx..idx + word_size].try_into().unwrap())
        });
    }

    // Handle the remainder bytes.
    if remainder > 0 {
        let mut last_word = firmware_buffer[n] as u32;
        for idx in 1..remainder {
            last_word |= (firmware_buffer[n + idx] as u32) << (idx << 3);
        }
        soc_mbox.datain().write(|_| last_word);
    }

    // Set the execute register.
    soc_mbox.execute().write(|w| w.execute(true));
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
