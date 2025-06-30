/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra MCU Emulator.

--*/

mod dis;
mod dis_test;
mod doe_mbox_fsm;
mod elf;
mod gdb;
mod i3c_socket;
mod mctp_transport;
mod tests;

use crate::i3c_socket::start_i3c_socket;
use caliptra_emu_bus::{Bus, Clock, Timer};
use caliptra_emu_cpu::{Cpu, Pic, RvInstr, StepAction};
use caliptra_emu_cpu::{Cpu as CaliptraMainCpu, StepAction as CaliptraMainStepAction};
use caliptra_emu_periph::CaliptraRootBus as CaliptraMainRootBus;
use clap::{ArgAction, Parser};
use clap_num::maybe_hex;
use crossterm::event::{Event, KeyCode, KeyEvent};
use emulator_bmc::Bmc;
use emulator_caliptra::{start_caliptra, StartCaliptraArgs};
use emulator_consts::DEFAULT_CPU_ARGS;
use emulator_consts::{RAM_ORG, ROM_SIZE};
use emulator_periph::{
    DoeMboxPeriph, DummyDoeMbox, DummyFlashCtrl, I3c, I3cController, Mci, McuRootBus,
    McuRootBusArgs, McuRootBusOffsets, Otp,
};
use emulator_registers_generated::dma::DmaPeripheral;
use emulator_registers_generated::root_bus::{AutoRootBus, AutoRootBusOffsets};
use gdb::gdb_state;
use gdb::gdb_target::GdbTarget;
use mctp_transport::MctpTransport;
use pldm_fw_pkg::FirmwareManifest;
use pldm_ua::daemon::PldmDaemon;
use pldm_ua::transport::{EndpointId, PldmTransport};
use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tests::mctp_util::base_protocol::LOCAL_TEST_ENDPOINT_EID;
use tests::pldm_request_response_test::PldmRequestResponseTest;

#[derive(Parser)]
#[command(version, about, long_about = None, name = "Caliptra MCU Emulator")]
struct Emulator {
    /// ROM binary path
    #[arg(short, long)]
    rom: PathBuf,

    #[arg(short, long)]
    firmware: Option<PathBuf>,

    /// Optional file to store OTP / fuses between runs.
    #[arg(short, long)]
    otp: Option<PathBuf>,

    /// GDB Debugger Port
    #[arg(short, long)]
    gdb_port: Option<u16>,

    /// Directory in which to log execution artifacts.
    #[arg(short, long)]
    log_dir: Option<PathBuf>,

    /// Trace instructions.
    #[arg(short, long, default_value_t = false)]
    trace_instr: bool,

    // These look backwards, but this is necessary so that the default is to capture stdin.
    /// Pass stdin to the MCU UART Rx.
    #[arg(long = "no-stdin-uart", action = ArgAction::SetFalse)]
    stdin_uart: bool,

    // this is used only to set stdin_uart to false
    #[arg(long = "stdin-uart", overrides_with = "stdin_uart")]
    _no_stdin_uart: bool,

    /// Start a Caliptra CPU as well and connect to the MCU.
    #[arg(short, long, default_value_t = false)]
    caliptra: bool,

    /// The ROM path for the Caliptra CPU.
    #[arg(long)]
    caliptra_rom: Option<PathBuf>,

    /// The Firmware path for the Caliptra CPU.
    #[arg(long)]
    caliptra_firmware: Option<PathBuf>,

    #[arg(long)]
    soc_manifest: Option<PathBuf>,

    #[arg(long)]
    i3c_port: Option<u16>,

    /// Boot active mode (MCU firmware will need to be loaded by Caliptra Core)
    #[arg(long)]
    active_mode: bool,

    /// This is only needed if the IDevID CSR needed to be generated in the Caliptra Core.
    #[arg(long)]
    manufacturing_mode: bool,

    #[arg(long)]
    vendor_pk_hash: Option<String>,

    #[arg(long)]
    owner_pk_hash: Option<String>,

    /// Path to the streaming boot PLDM firmware package
    #[arg(long)]
    streaming_boot: Option<PathBuf>,

    #[arg(long)]
    primary_flash_image: Option<PathBuf>,

    #[arg(long)]
    secondary_flash_image: Option<PathBuf>,

    /// Override ROM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    rom_offset: Option<u32>,
    /// Override ROM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    rom_size: Option<u32>,
    /// Override UART offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    uart_offset: Option<u32>,
    /// Override UART size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    uart_size: Option<u32>,
    /// Override emulator control offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    ctrl_offset: Option<u32>,
    /// Override emulator control size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    ctrl_size: Option<u32>,
    /// Override SPI offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    spi_offset: Option<u32>,
    /// Override SPI size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    spi_size: Option<u32>,
    /// Override SRAM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    sram_offset: Option<u32>,
    /// Override SRAM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    sram_size: Option<u32>,
    /// Override PIC offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    pic_offset: Option<u32>,
    /// Override external test SRAM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    external_test_sram_offset: Option<u32>,
    /// Override external test SRAM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    external_test_sram_size: Option<u32>,
    /// Override DCCM offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    dccm_offset: Option<u32>,
    /// Override DCCM size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    dccm_size: Option<u32>,
    /// Override I3C offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    i3c_offset: Option<u32>,
    /// Override I3C size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    i3c_size: Option<u32>,
    /// Override primary flash offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    primary_flash_offset: Option<u32>,
    /// Override primary flash size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    primary_flash_size: Option<u32>,
    /// Override secondary flash offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    secondary_flash_offset: Option<u32>,
    /// Override secondary flash size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    secondary_flash_size: Option<u32>,
    /// Override MCI offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    mci_offset: Option<u32>,
    /// Override MCI size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    mci_size: Option<u32>,
    /// Override DMA offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    dma_offset: Option<u32>,
    /// Override DMA size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    dma_size: Option<u32>,
    /// Override Caliptra mailbox offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    mbox_offset: Option<u32>,
    /// Override Caliptra mailbox size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    mbox_size: Option<u32>,
    /// Override Caliptra SoC interface offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    soc_offset: Option<u32>,
    /// Override Caliptra SoC interface size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    soc_size: Option<u32>,
    /// Override OTP offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    otp_offset: Option<u32>,
    /// Override OTP size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    otp_size: Option<u32>,
    /// Override LC offset
    #[arg(long, value_parser=maybe_hex::<u32>)]
    lc_offset: Option<u32>,
    /// Override LC size
    #[arg(long, value_parser=maybe_hex::<u32>)]
    lc_size: Option<u32>,
}

fn disassemble(pc: u32, instr: u32) -> String {
    let mut out = vec![];
    // TODO: we should replace this with something more efficient.
    let dis = dis::disasm_inst(dis::RvIsa::Rv32, pc as u64, instr as u64);
    write!(&mut out, "0x{:08x}   {}", pc, dis).unwrap();

    String::from_utf8(out).unwrap()
}

fn read_console(running: Arc<AtomicBool>, stdin_uart: Option<Arc<Mutex<Option<u8>>>>) {
    let mut buffer = vec![];
    if let Some(ref stdin_uart) = stdin_uart {
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if buffer.is_empty() {
                match crossterm::event::read() {
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Char(ch),
                        ..
                    })) => {
                        buffer.extend_from_slice(ch.to_string().as_bytes());
                    }
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Enter,
                        ..
                    })) => {
                        buffer.push(b'\n');
                    }
                    Ok(Event::Key(KeyEvent {
                        code: KeyCode::Backspace,
                        ..
                    })) => {
                        if !buffer.is_empty() {
                            buffer.pop();
                        } else {
                            buffer.push(8);
                        }
                    }
                    _ => {} // ignore other keys
                }
            } else {
                let mut stdin_uart = stdin_uart.lock().unwrap();
                if stdin_uart.is_none() {
                    *stdin_uart = Some(buffer.remove(0));
                }
            }
            std::thread::yield_now();
        }
    }
}

// CPU Main Loop (free_run no GDB)
fn free_run(
    running: Arc<AtomicBool>,
    mut mcu_cpu: Cpu<AutoRootBus>,
    mut caliptra_cpu: Option<CaliptraMainCpu<CaliptraMainRootBus>>,
    trace_path: Option<PathBuf>,
    stdin_uart: Option<Arc<Mutex<Option<u8>>>>,
    mut bmc: Option<Bmc>,
) {
    // read from the console in a separate thread to prevent blocking
    let running_clone = running.clone();
    let stdin_uart_clone = stdin_uart.clone();
    std::thread::spawn(move || read_console(running_clone, stdin_uart_clone));

    let timer = Timer::new(&mcu_cpu.clock.clone());
    if let Some(path) = trace_path {
        let mut f = File::create(path).unwrap();
        let trace_fn: &mut dyn FnMut(u32, RvInstr) = &mut |pc, instr| match instr {
            RvInstr::Instr32(instr32) => {
                let _ = writeln!(&mut f, "{}", disassemble(pc, instr32));
                println!("{{mcu cpu}}      {}", disassemble(pc, instr32));
            }
            RvInstr::Instr16(instr16) => {
                let _ = writeln!(&mut f, "{}", disassemble(pc, instr16 as u32));
                println!("{{mcu cpu}}      {}", disassemble(pc, instr16 as u32));
            }
        };

        // we don't put the caliptra trace in the file
        let caliptra_trace_fn: &mut dyn FnMut(u32, caliptra_emu_cpu::RvInstr) =
            &mut |pc, instr| match instr {
                caliptra_emu_cpu::RvInstr::Instr32(instr32) => {
                    println!("{{caliptra cpu}} {}", disassemble(pc, instr32));
                }
                caliptra_emu_cpu::RvInstr::Instr16(instr16) => {
                    println!("{{caliptra cpu}} {}", disassemble(pc, instr16 as u32));
                }
            };

        // Need to have the loop in the same scope as trace_fn to prevent borrowing rules violation
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref stdin_uart) = stdin_uart {
                if stdin_uart.lock().unwrap().is_some() {
                    timer.schedule_poll_in(1);
                }
            }
            let action = mcu_cpu.step(Some(trace_fn));
            if action != StepAction::Continue {
                break;
            }
            match caliptra_cpu
                .as_mut()
                .map(|cpu| cpu.step(Some(caliptra_trace_fn)))
            {
                Some(CaliptraMainStepAction::Continue) | None => {}
                _ => {
                    println!("Caliptra CPU Halted");
                    caliptra_cpu = None;
                }
            }
            if let Some(bmc) = bmc.as_mut() {
                bmc.step();
            }
        }
    } else {
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref stdin_uart) = stdin_uart {
                if stdin_uart.lock().unwrap().is_some() {
                    timer.schedule_poll_in(1);
                }
            }
            let action = mcu_cpu.step(None);
            if action != StepAction::Continue {
                break;
            }
            match caliptra_cpu.as_mut().map(|cpu| cpu.step(None)) {
                Some(CaliptraMainStepAction::Continue) | None => {}
                _ => {
                    println!("Caliptra CPU Halted");
                    caliptra_cpu = None;
                }
            }
            if let Some(bmc) = bmc.as_mut() {
                bmc.step();
            }
        }
    };
}

fn main() -> io::Result<()> {
    let cli = Emulator::parse();
    run(cli, false).map(|_| ())
}

fn read_binary(path: &PathBuf, expect_load_addr: u32) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Check if this is an ELF
    if buffer.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        println!("Loading ELF executable {}", path.display());
        let elf = elf::ElfExecutable::new(&buffer).unwrap();
        if elf.load_addr() != expect_load_addr {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ELF executable has non-0x{:x} load address, which is not supported (got 0x{:x})",
                    expect_load_addr, elf.load_addr()
                ),
            ))?;
        }
        // TBF files have an entry point offset by 0x20
        if elf.entry_point() != expect_load_addr && elf.entry_point() != elf.load_addr() + 0x20 {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ELF executable has non-0x{:x} entry point, which is not supported (got 0x{:x})", expect_load_addr, elf.entry_point()),
            ))?;
        }
        buffer = elf.content().clone();
    }

    Ok(buffer)
}

fn run(cli: Emulator, capture_uart_output: bool) -> io::Result<Vec<u8>> {
    // exit cleanly on Ctrl-C so that we save any state.
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    if io::stdout().is_terminal() {
        ctrlc::set_handler(move || {
            running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        })
        .unwrap();
    }
    let active_mode = cli.active_mode;
    let args_rom = &cli.rom;
    let args_log_dir = &cli.log_dir.unwrap_or_else(|| PathBuf::from("/tmp"));

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

    let (mut caliptra_cpu, soc_to_caliptra) = if cli.caliptra {
        if cli.gdb_port.is_some() {
            println!("Caliptra CPU cannot be started with GDB enabled");
            exit(-1);
        }
        if cli.caliptra_rom.is_none() {
            println!("Caliptra ROM File is required if Caliptra is enabled");
            exit(-1);
        }

        let device_lifecycle: Option<String> = if cli.manufacturing_mode {
            Some("manufacturing".into())
        } else {
            Some("production".into())
        };

        let req_idevid_csr: Option<bool> = if cli.manufacturing_mode {
            Some(true)
        } else {
            None
        };

        let (caliptra_cpu, soc_to_caliptra) = start_caliptra(&StartCaliptraArgs {
            rom: cli.caliptra_rom,
            device_lifecycle,
            req_idevid_csr,
            active_mode,
            firmware: if active_mode {
                None
            } else {
                cli.caliptra_firmware.clone()
            },
            ..Default::default()
        })
        .expect("Failed to start Caliptra CPU");
        assert!(caliptra_cpu.is_some());
        (caliptra_cpu, soc_to_caliptra)
    } else {
        // still create the external bus for the mailbox and SoC interfaces
        let (caliptra_cpu, soc_to_caliptra) = start_caliptra(&StartCaliptraArgs {
            ..Default::default()
        })
        .expect("Failed to start Caliptra CPU");
        assert!(caliptra_cpu.is_none());
        (None, soc_to_caliptra)
    };

    let rom_buffer = read_binary(args_rom, 0)?;
    if rom_buffer.len() > ROM_SIZE as usize {
        println!("ROM File Size must not exceed {} bytes", ROM_SIZE);
        exit(-1);
    }
    println!(
        "Loaded ROM File {:?} of size {}",
        args_rom,
        rom_buffer.len(),
    );

    if active_mode && cli.firmware.is_none() {
        println!("Active mode requires an MCU firmware file to be passed");
        exit(-1);
    }

    let mcu_firmware = if let Some(firmware_path) = cli.firmware {
        read_binary(&firmware_path, 0x4000_0080)?
    } else {
        // this just immediately exits
        vec![0xb7, 0xf6, 0x00, 0x20, 0x94, 0xc2]
    };

    let clock = Rc::new(Clock::new());

    let uart_output = if capture_uart_output {
        Some(Rc::new(RefCell::new(Vec::new())))
    } else {
        None
    };

    let stdin_uart = if cli.stdin_uart && std::io::stdin().is_terminal() {
        Some(Arc::new(Mutex::new(None)))
    } else {
        None
    };
    let pic = Rc::new(Pic::new());

    let mut mcu_root_bus_offsets = McuRootBusOffsets::default();
    let mut auto_root_bus_offsets = AutoRootBusOffsets::default();

    if let Some(rom_offset) = cli.rom_offset {
        mcu_root_bus_offsets.rom_offset = rom_offset;
    }
    if let Some(rom_size) = cli.rom_size {
        mcu_root_bus_offsets.rom_size = rom_size;
    }
    if let Some(sram_offset) = cli.sram_offset {
        mcu_root_bus_offsets.ram_offset = sram_offset;
    }
    if let Some(uart_offset) = cli.uart_offset {
        mcu_root_bus_offsets.uart_offset = uart_offset;
    }
    if let Some(uart_size) = cli.uart_size {
        mcu_root_bus_offsets.uart_size = uart_size;
    }
    if let Some(ctrl_offset) = cli.ctrl_offset {
        mcu_root_bus_offsets.ctrl_offset = ctrl_offset;
    }
    if let Some(ctrl_size) = cli.ctrl_size {
        mcu_root_bus_offsets.ctrl_size = ctrl_size;
    }
    if let Some(spi_offset) = cli.spi_offset {
        mcu_root_bus_offsets.spi_offset = spi_offset;
    }
    if let Some(spi_size) = cli.spi_size {
        mcu_root_bus_offsets.spi_size = spi_size;
    }
    if let Some(pic_offset) = cli.pic_offset {
        mcu_root_bus_offsets.pic_offset = pic_offset;
        auto_root_bus_offsets.el2_pic_offset = pic_offset;
    }
    if let Some(external_test_sram_offset) = cli.external_test_sram_offset {
        mcu_root_bus_offsets.external_test_sram_offset = external_test_sram_offset;
    }
    if let Some(external_test_sram_size) = cli.external_test_sram_size {
        mcu_root_bus_offsets.external_test_sram_size = external_test_sram_size;
    }
    if let Some(sram_size) = cli.sram_size {
        mcu_root_bus_offsets.ram_size = sram_size;
    }

    // Don't override default DCCM offset and size when the ROM flash driver feature is enabled.
    #[cfg(not(feature = "test-mcu-rom-flash-access"))]
    {
        if let Some(dccm_offset) = cli.dccm_offset {
            mcu_root_bus_offsets.rom_dedicated_ram_offset = dccm_offset;
        }
        if let Some(dccm_size) = cli.dccm_size {
            mcu_root_bus_offsets.rom_dedicated_ram_size = dccm_size;
        }
    }

    if let Some(i3c_offset) = cli.i3c_offset {
        auto_root_bus_offsets.i3c_offset = i3c_offset;
    }
    if let Some(i3c_size) = cli.i3c_size {
        auto_root_bus_offsets.i3c_size = i3c_size;
    }
    if let Some(primary_flash_offset) = cli.primary_flash_offset {
        auto_root_bus_offsets.primary_flash_offset = primary_flash_offset;
    }
    if let Some(primary_flash_size) = cli.primary_flash_size {
        auto_root_bus_offsets.primary_flash_size = primary_flash_size;
    }
    if let Some(secondary_flash_offset) = cli.secondary_flash_offset {
        auto_root_bus_offsets.secondary_flash_offset = secondary_flash_offset;
    }
    if let Some(secondary_flash_size) = cli.secondary_flash_size {
        auto_root_bus_offsets.secondary_flash_size = secondary_flash_size;
    }
    if let Some(mci_offset) = cli.mci_offset {
        auto_root_bus_offsets.mci_offset = mci_offset;
    }
    if let Some(mci_size) = cli.mci_size {
        auto_root_bus_offsets.mci_size = mci_size;
    }
    if let Some(dma_offset) = cli.dma_offset {
        auto_root_bus_offsets.dma_offset = dma_offset;
    }
    if let Some(dma_size) = cli.dma_size {
        auto_root_bus_offsets.dma_size = dma_size;
    }
    if let Some(mbox_offset) = cli.mbox_offset {
        auto_root_bus_offsets.mbox_offset = mbox_offset;
    }
    if let Some(mbox_size) = cli.mbox_size {
        auto_root_bus_offsets.mbox_size = mbox_size;
    }
    if let Some(soc_offset) = cli.soc_offset {
        auto_root_bus_offsets.soc_offset = soc_offset;
    }
    if let Some(soc_size) = cli.soc_size {
        auto_root_bus_offsets.soc_size = soc_size;
    }
    if let Some(otp_offset) = cli.otp_offset {
        auto_root_bus_offsets.otp_offset = otp_offset;
    }
    if let Some(otp_size) = cli.otp_size {
        auto_root_bus_offsets.otp_size = otp_size;
    }
    if let Some(lc_offset) = cli.lc_offset {
        auto_root_bus_offsets.lc_offset = lc_offset;
    }
    if let Some(lc_size) = cli.lc_size {
        auto_root_bus_offsets.lc_size = lc_size;
    }

    let bus_args = McuRootBusArgs {
        offsets: mcu_root_bus_offsets.clone(),
        rom: rom_buffer,
        log_dir: args_log_dir.clone(),
        uart_output: uart_output.clone(),
        uart_rx: stdin_uart.clone(),
        pic: pic.clone(),
        clock: clock.clone(),
    };
    let mut root_bus = McuRootBus::new(bus_args).unwrap();

    if !active_mode {
        root_bus.load_ram(0x80, &mcu_firmware);
    }

    let dma_ram = root_bus.ram.clone();
    let dma_rom_sram = root_bus.rom_sram.clone();

    let i3c_error_irq = pic.register_irq(McuRootBus::I3C_ERROR_IRQ);
    let i3c_notif_irq = pic.register_irq(McuRootBus::I3C_NOTIF_IRQ);

    println!("Starting I3C Socket, port {}", cli.i3c_port.unwrap_or(0));

    let mut i3c_controller = if let Some(i3c_port) = cli.i3c_port {
        let (rx, tx) = start_i3c_socket(running.clone(), i3c_port);
        I3cController::new(rx, tx)
    } else {
        I3cController::default()
    };
    let i3c = I3c::new(
        &clock.clone(),
        &mut i3c_controller,
        i3c_error_irq,
        i3c_notif_irq,
    );
    let i3c_dynamic_address = i3c.get_dynamic_address().unwrap();

    let doe_event_irq = pic.register_irq(McuRootBus::DOE_MBOX_EVENT_IRQ);
    let doe_mbox_periph = DoeMboxPeriph::default();

    let mut doe_mbox_fsm = doe_mbox_fsm::DoeMboxFsm::new(doe_mbox_periph.clone());

    let doe_mbox = DummyDoeMbox::new(&clock.clone(), doe_event_irq, doe_mbox_periph);

    println!("Starting DOE mailbox transport thread");

    if cfg!(feature = "test-doe-transport-loopback") {
        let (test_rx, test_tx) = doe_mbox_fsm.start(running.clone());
        println!("Starting DOE transport loopback test thread");
        let tests = tests::doe_transport_loopback::generate_tests();
        doe_mbox_fsm::run_doe_transport_tests(running.clone(), test_tx, test_rx, tests);
    } else if cfg!(feature = "test-doe-discovery") {
        let (test_rx, test_tx) = doe_mbox_fsm.start(running.clone());
        println!("Starting DOE discovery test thread");
        let tests = tests::doe_discovery::DoeDiscoveryTest::generate_tests();
        doe_mbox_fsm::run_doe_transport_tests(running.clone(), test_tx, test_rx, tests);
    } else if cfg!(feature = "test-mctp-ctrl-cmds") {
        i3c_controller.start();
        println!(
            "Starting test-mctp-ctrl-cmds test thread for testing target {:?}",
            i3c.get_dynamic_address().unwrap()
        );

        let tests = tests::mctp_ctrl_cmd::MCTPCtrlCmdTests::generate_tests();
        i3c_socket::run_tests(
            running.clone(),
            cli.i3c_port.unwrap(),
            i3c.get_dynamic_address().unwrap(),
            tests,
            None,
        );
    } else if cfg!(feature = "test-mctp-capsule-loopback") {
        i3c_controller.start();
        println!(
            "Starting loopback test thread for testing target {:?}",
            i3c.get_dynamic_address().unwrap()
        );

        let tests = tests::mctp_loopback::generate_tests();
        i3c_socket::run_tests(
            running.clone(),
            cli.i3c_port.unwrap(),
            i3c.get_dynamic_address().unwrap(),
            tests,
            None,
        );
    } else if cfg!(feature = "test-mctp-user-loopback") {
        i3c_controller.start();
        println!(
            "Starting loopback test thread for testing target {:?}",
            i3c.get_dynamic_address().unwrap()
        );

        let spdm_loopback_tests = tests::mctp_user_loopback::MctpUserAppTests::generate_tests(
            tests::mctp_util::base_protocol::MctpMsgType::Caliptra as u8,
        );

        i3c_socket::run_tests(
            running.clone(),
            cli.i3c_port.unwrap(),
            i3c.get_dynamic_address().unwrap(),
            spdm_loopback_tests,
            None,
        );
    } else if cfg!(feature = "test-spdm-validator") {
        if std::env::var("SPDM_VALIDATOR_DIR").is_err() {
            println!("SPDM_VALIDATOR_DIR environment variable is not set. Skipping test");
            exit(0);
        }
        i3c_controller.start();
        let spdm_validator_tests = tests::spdm_validator::generate_tests();
        i3c_socket::run_tests(
            running.clone(),
            cli.i3c_port.unwrap(),
            i3c.get_dynamic_address().unwrap(),
            spdm_validator_tests,
            Some(std::time::Duration::from_secs(3000)), // timeout in seconds
        );
    }

    if cfg!(any(
        feature = "test-pldm-request-response",
        feature = "test-pldm-discovery",
        feature = "test-pldm-fw-update",
    )) {
        i3c_controller.start();
        let pldm_transport =
            MctpTransport::new(cli.i3c_port.unwrap(), i3c.get_dynamic_address().unwrap());
        let pldm_socket = pldm_transport
            .create_socket(EndpointId(0), EndpointId(1))
            .unwrap();
        PldmRequestResponseTest::run(pldm_socket, running.clone());
    }

    if cfg!(feature = "test-pldm-fw-update-e2e") {
        i3c_controller.start();
        let pldm_transport =
            MctpTransport::new(cli.i3c_port.unwrap(), i3c.get_dynamic_address().unwrap());
        let pldm_socket = pldm_transport
            .create_socket(EndpointId(8), EndpointId(0))
            .unwrap();
        tests::pldm_fw_update_test::PldmFwUpdateTest::run(pldm_socket, running.clone());
    }

    let create_flash_controller =
        |default_path: &str, error_irq: u8, event_irq: u8, initial_content: Option<&[u8]>| {
            // Use a temporary file for flash storage if we're running a test
            let flash_file = if cfg!(any(
                feature = "test-flash-ctrl-init",
                feature = "test-flash-ctrl-read-write-page",
                feature = "test-flash-ctrl-erase-page",
                feature = "test-flash-storage-read-write",
                feature = "test-flash-storage-erase",
                feature = "test-flash-usermode",
                feature = "test-mcu-rom-flash-access",
            )) {
                Some(
                    tempfile::NamedTempFile::new()
                        .unwrap()
                        .into_temp_path()
                        .to_path_buf(),
                )
            } else {
                Some(PathBuf::from(default_path))
            };

            DummyFlashCtrl::new(
                &clock.clone(),
                flash_file,
                pic.register_irq(error_irq),
                pic.register_irq(event_irq),
                initial_content,
            )
            .unwrap()
        };

    let primary_flash_initial_content = if cli.primary_flash_image.is_some() {
        let flash_image_path = cli.primary_flash_image.as_ref().unwrap();
        println!("Loading flash image from {}", flash_image_path.display());
        const FLASH_SIZE: usize = DummyFlashCtrl::PAGE_SIZE * DummyFlashCtrl::MAX_PAGES as usize;
        let mut flash_image = vec![0; FLASH_SIZE];
        let mut file = File::open(flash_image_path)?;
        let bytes_read = file.read(&mut flash_image)?;
        if bytes_read > FLASH_SIZE {
            println!("Flash image size exceeds {} bytes", FLASH_SIZE);
            exit(-1);
        }

        Some(flash_image[..bytes_read].to_vec())
    } else {
        None
    };

    let primary_flash_controller = create_flash_controller(
        "primary_flash",
        McuRootBus::PRIMARY_FLASH_CTRL_ERROR_IRQ,
        McuRootBus::PRIMARY_FLASH_CTRL_EVENT_IRQ,
        primary_flash_initial_content.as_deref(),
    );

    let secondary_flash_initial_content = if cli.secondary_flash_image.is_some() {
        let flash_image_path = cli.secondary_flash_image.as_ref().unwrap();
        const FLASH_SIZE: usize = DummyFlashCtrl::PAGE_SIZE * DummyFlashCtrl::MAX_PAGES as usize;
        let mut flash_image = vec![0; FLASH_SIZE];
        let mut file = File::open(flash_image_path)?;
        let bytes_read = file.read(&mut flash_image)?;
        if bytes_read > FLASH_SIZE {
            println!("Flash image size exceeds {} bytes", FLASH_SIZE);
            exit(-1);
        }

        Some(flash_image[..bytes_read].to_vec())
    } else {
        None
    };

    let secondary_flash_controller = create_flash_controller(
        "secondary_flash",
        McuRootBus::SECONDARY_FLASH_CTRL_ERROR_IRQ,
        McuRootBus::SECONDARY_FLASH_CTRL_EVENT_IRQ,
        secondary_flash_initial_content.as_deref(),
    );

    let mut dma_ctrl = emulator_periph::DummyDmaCtrl::new(
        &clock.clone(),
        pic.register_irq(McuRootBus::DMA_ERROR_IRQ),
        pic.register_irq(McuRootBus::DMA_EVENT_IRQ),
        Some(root_bus.external_test_sram.clone()),
    )
    .unwrap();

    emulator_periph::DummyDmaCtrl::set_dma_ram(&mut dma_ctrl, dma_ram.clone());

    let delegates: Vec<Box<dyn Bus>> = vec![Box::new(root_bus), Box::new(soc_to_caliptra)];

    let vendor_pk_hash = cli.vendor_pk_hash.map(|hash| {
        let v = hex::decode(hash).unwrap();
        v.try_into().unwrap()
    });
    let owner_pk_hash = cli.owner_pk_hash.map(|hash| {
        let v = hex::decode(hash).unwrap();
        v.try_into().unwrap()
    });

    let otp = Otp::new(&clock.clone(), cli.otp, owner_pk_hash, vendor_pk_hash)?;
    let mci = Mci::new(&clock.clone());
    let mut auto_root_bus = AutoRootBus::new(
        delegates,
        Some(auto_root_bus_offsets),
        Some(Box::new(i3c)),
        Some(Box::new(primary_flash_controller)),
        Some(Box::new(secondary_flash_controller)),
        Some(Box::new(mci)),
        Some(Box::new(doe_mbox)),
        Some(Box::new(dma_ctrl)),
        None,
        Some(Box::new(otp)),
        None,
        None,
        None,
        None,
    );

    // Set the DMA RAM for Primary Flash Controller
    auto_root_bus
        .primary_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_ram(dma_ram.clone());

    // Set DMA RAM for ROM access to Primary Flash Controller
    auto_root_bus
        .primary_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_rom_sram(dma_rom_sram.clone());

    // Set the DMA RAM for Secondary Flash Controller
    auto_root_bus
        .secondary_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_ram(dma_ram);

    // Set the DMA RAM for ROM access to Secondary Flash Controller
    auto_root_bus
        .secondary_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_rom_sram(dma_rom_sram.clone());

    let cpu_args = DEFAULT_CPU_ARGS;

    let mut cpu = Cpu::new(auto_root_bus, clock, pic, cpu_args);
    cpu.write_pc(mcu_root_bus_offsets.rom_offset);
    cpu.register_events();

    let mut bmc = match caliptra_cpu.as_mut() {
        Some(caliptra_cpu) => {
            println!("Initializing recovery interface");
            let (caliptra_event_sender, caliptra_event_receiver) = caliptra_cpu.register_events();
            let (mcu_event_sender, mcu_event_reciever) = cpu.register_events();
            let bmc = Bmc::new(
                caliptra_event_sender,
                caliptra_event_receiver,
                mcu_event_sender,
                mcu_event_reciever,
            );
            Some(bmc)
        }
        _ => None,
    };

    // prepare the BMC recovery interface emulator
    if active_mode {
        if bmc.is_none() {
            println!("Active mode is only supported when Caliptra CPU is enabled");
            exit(-1);
        }
        let bmc = bmc.as_mut().unwrap();

        // load the firmware images and SoC manifest into the recovery interface emulator
        // TODO: support reading these from firmware bundle as well
        let Some(caliptra_firmware) = cli.caliptra_firmware else {
            println!("Caliptra firmware file is required in active mode");
            exit(-1);
        };
        let Some(soc_manifest) = cli.soc_manifest else {
            println!("SoC manifest file is required in active mode");
            exit(-1);
        };
        let caliptra_firmware = read_binary(&caliptra_firmware, RAM_ORG).unwrap();
        let soc_manifest = read_binary(&soc_manifest, 0).unwrap();
        bmc.push_recovery_image(caliptra_firmware);
        bmc.push_recovery_image(soc_manifest);
        bmc.push_recovery_image(mcu_firmware);
        println!("Active mode enabled with 3 recovery images");
        // TODO: set caliptra SoC registers if active mode
    }

    if cli.streaming_boot.is_some() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Debug)
            .init();
        let pldm_fw_pkg_path = cli.streaming_boot.as_ref().unwrap();
        println!(
            "Starting streaming boot using PLDM package {}",
            pldm_fw_pkg_path.display()
        );

        // Parse PLDM Firmware Package
        let pldm_fw_pkg = FirmwareManifest::decode_firmware_package(
            &pldm_fw_pkg_path.to_str().unwrap().to_string(),
            None,
        );
        if pldm_fw_pkg.is_err() {
            println!("Failed to parse PLDM firmware package");
            exit(-1);
        }

        // Start the PLDM Daemon
        i3c_controller.start();
        let pldm_transport = MctpTransport::new(cli.i3c_port.unwrap(), i3c_dynamic_address);
        let pldm_socket = pldm_transport
            .create_socket(EndpointId(LOCAL_TEST_ENDPOINT_EID), EndpointId(1))
            .unwrap();
        if cfg!(feature = "test-pldm-streaming-boot") {
            // If we are running the PLDM daemon from an integration test,
            // we need to set the update state machine to exit on error
            let _ = PldmDaemon::run(
                pldm_socket,
                pldm_ua::daemon::Options {
                    pldm_fw_pkg: Some(pldm_fw_pkg.unwrap()),
                    discovery_sm_actions: pldm_ua::discovery_sm::DefaultActions {},
                    update_sm_actions: pldm_ua::update_sm::DefaultActionsExitOnError {},
                    fd_tid: 0x01,
                },
            );
        } else {
            let _ = PldmDaemon::run(
                pldm_socket,
                pldm_ua::daemon::Options {
                    pldm_fw_pkg: Some(pldm_fw_pkg.unwrap()),
                    discovery_sm_actions: pldm_ua::discovery_sm::DefaultActions {},
                    update_sm_actions: pldm_ua::update_sm::DefaultActions {},
                    fd_tid: 0x01,
                },
            );
        };
    }

    // Check if Optional GDB Port is passed
    match cli.gdb_port {
        Some(port) => {
            // Create GDB Target Instance
            let mut gdb_target = GdbTarget::new(cpu);

            // Execute CPU through GDB State Machine
            gdb_state::wait_for_gdb_run(&mut gdb_target, port);
        }
        _ => {
            let instr_trace = if cli.trace_instr {
                Some(args_log_dir.join("caliptra_instr_trace.txt"))
            } else {
                None
            };

            // If no GDB Port is passed, Free Run
            free_run(
                running.clone(),
                cpu,
                caliptra_cpu,
                instr_trace,
                stdin_uart,
                bmc,
            );
        }
    }

    Ok(uart_output.map(|o| o.borrow().clone()).unwrap_or_default())
}
