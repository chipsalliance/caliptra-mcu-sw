/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra MCU Emulator.

--*/

mod dis;
mod dis_test;
mod elf;
mod gdb;
mod i3c_socket;
mod tests;

use crate::i3c_socket::start_i3c_socket;
use caliptra_emu_cpu::{Cpu as CaliptraMainCpu, StepAction as CaliptraMainStepAction};
use caliptra_emu_periph::CaliptraRootBus as CaliptraMainRootBus;
use clap::{ArgAction, Parser};
use crossterm::event::{Event, KeyCode, KeyEvent};
use emulator_bmc::Bmc;
use emulator_bus::{Bus, BusConverter, Clock, Timer};
use emulator_caliptra::{start_caliptra, StartCaliptraArgs};
use emulator_cpu::{Cpu, Pic, RvInstr, StepAction};
use emulator_periph::{
    CaliptraRootBus, CaliptraRootBusArgs, DummyFlashCtrl, I3c, I3cController, Mci, Otp,
};
use emulator_registers_generated::root_bus::AutoRootBus;
use emulator_registers_generated::soc::SocPeripheral;
use emulator_types::ROM_SIZE;
use gdb::gdb_state;
use gdb::gdb_target::GdbTarget;
use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

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

    #[arg(long)]
    vendor_pk_hash: Option<String>,

    #[arg(long)]
    owner_pk_hash: Option<String>,
}

//const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles

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
        let (caliptra_cpu, soc_to_caliptra) = start_caliptra(&StartCaliptraArgs {
            rom: cli.caliptra_rom.unwrap(),
            device_lifecycle: Some("production".into()),
            active_mode,
            ..Default::default()
        })
        .expect("Failed to start Caliptra CPU");
        (Some(caliptra_cpu), Some(soc_to_caliptra))
    } else {
        (None, None)
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

    let bus_args = CaliptraRootBusArgs {
        rom: rom_buffer,
        log_dir: args_log_dir.clone(),
        uart_output: uart_output.clone(),
        uart_rx: stdin_uart.clone(),
        pic: pic.clone(),
        clock: clock.clone(),
    };
    let mut root_bus = CaliptraRootBus::new(bus_args).unwrap();

    if !active_mode {
        root_bus.load_ram(0x80, &mcu_firmware);
    }

    let dma_ram = root_bus.ram.clone();

    let i3c_error_irq = pic.register_irq(CaliptraRootBus::I3C_ERROR_IRQ);
    let i3c_notif_irq = pic.register_irq(CaliptraRootBus::I3C_NOTIF_IRQ);

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

    if cfg!(feature = "test-mctp-ctrl-cmds") {
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
        );
    } else if cfg!(feature = "test-spdm-validator") {
        i3c_controller.start();
        let spdm_validator_tests = tests::spdm_validator::generate_tests();
        i3c_socket::run_tests(
            running.clone(),
            cli.i3c_port.unwrap(),
            i3c.get_dynamic_address().unwrap(),
            spdm_validator_tests,
        );
    }

    let create_flash_controller = |default_path: &str, error_irq: u8, event_irq: u8| {
        // Use a temporary file for flash storage if we're running a test
        let flash_file = if cfg!(any(
            feature = "test-flash-ctrl-init",
            feature = "test-flash-ctrl-read-write-page",
            feature = "test-flash-ctrl-erase-page",
            feature = "test-flash-storage-read-write",
            feature = "test-flash-storage-erase",
            feature = "test-flash-usermode",
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
        )
        .unwrap()
    };

    let main_flash_controller = create_flash_controller(
        "main_flash",
        CaliptraRootBus::MAIN_FLASH_CTRL_ERROR_IRQ,
        CaliptraRootBus::MAIN_FLASH_CTRL_EVENT_IRQ,
    );

    let recovery_flash_controller = create_flash_controller(
        "recovery_flash",
        CaliptraRootBus::RECOVERY_FLASH_CTRL_ERROR_IRQ,
        CaliptraRootBus::RECOVERY_FLASH_CTRL_EVENT_IRQ,
    );

    let mut delegates: Vec<Box<dyn Bus>> = vec![Box::new(root_bus)];
    let soc_periph = if let Some(soc_to_caliptra) = soc_to_caliptra {
        delegates.push(Box::new(BusConverter::new(Box::new(soc_to_caliptra))));
        None
    } else {
        // pass an empty SoC interface that returns 0 for everything
        Some(Box::new(FakeSoc {}) as Box<dyn SocPeripheral>)
    };

    let vendor_pk_hash = cli.vendor_pk_hash.map(|hash| {
        let v = hex::decode(hash).unwrap();
        v.try_into().unwrap()
    });
    let owner_pk_hash = cli.owner_pk_hash.map(|hash| {
        let v = hex::decode(hash).unwrap();
        v.try_into().unwrap()
    });

    let otp = Otp::new(&clock.clone(), cli.otp, owner_pk_hash, vendor_pk_hash)?;
    let mci = Mci::default();
    let mut auto_root_bus = AutoRootBus::new(
        delegates,
        Some(Box::new(i3c)),
        Some(Box::new(main_flash_controller)),
        Some(Box::new(recovery_flash_controller)),
        Some(Box::new(otp)),
        Some(Box::new(mci)),
        None,
        None,
        soc_periph,
        None,
    );

    // Set the DMA RAM for Main Flash Controller
    auto_root_bus
        .main_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_ram(dma_ram.clone());

    // Set the DMA RAM for Recovery Flash Controller
    auto_root_bus
        .recovery_flash_periph
        .as_mut()
        .unwrap()
        .periph
        .set_dma_ram(dma_ram);

    let mut cpu = Cpu::new(auto_root_bus, clock, pic);
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
        let caliptra_firmware = read_binary(&caliptra_firmware, 0x4000_0000).unwrap();
        let soc_manifest = read_binary(&soc_manifest, 0).unwrap();
        bmc.push_recovery_image(caliptra_firmware);
        bmc.push_recovery_image(soc_manifest);
        bmc.push_recovery_image(mcu_firmware);
        println!("Active mode enabled with 3 recovery images");
        // TODO: set caliptra SoC registers if active mode
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

struct FakeSoc {}

impl SocPeripheral for FakeSoc {}
