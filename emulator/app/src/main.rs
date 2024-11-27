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

use crate::i3c_socket::start_i3c_socket;
use caliptra_emu_cpu::{Cpu as CaliptraMainCpu, StepAction as CaliptraMainStepAction};
use caliptra_emu_periph::CaliptraRootBus as CaliptraMainRootBus;
use clap::{ArgAction, Parser};
use crossterm::event::{Event, KeyCode, KeyEvent};
use emulator_bus::{Clock, Timer};
use emulator_caliptra::{start_caliptra, StartCaliptraArgs};
use emulator_cpu::{Cpu, Pic, RvInstr, StepAction};
use emulator_periph::{CaliptraRootBus, CaliptraRootBusArgs, DummyFlashCtrl, I3c, I3cController};
use emulator_registers_generated::root_bus::AutoRootBus;
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
    i3c_port: Option<u16>,
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
                println!("{}", disassemble(pc, instr32));
            }
            RvInstr::Instr16(instr16) => {
                let _ = writeln!(&mut f, "{}", disassemble(pc, instr16 as u32));
                println!("{}", disassemble(pc, instr16 as u32));
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
            match caliptra_cpu.as_mut().map(|cpu| cpu.step(None)) {
                Some(CaliptraMainStepAction::Continue) | None => {}
                _ => {
                    println!("Caliptra CPU Halted");
                    caliptra_cpu = None;
                }
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

    let args_rom = &cli.rom;
    let args_log_dir = &cli.log_dir.unwrap_or_else(|| PathBuf::from("/tmp"));

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

    let caliptra_cpu = if cli.caliptra {
        if cli.gdb_port.is_some() {
            println!("Caliptra CPU cannot be started with GDB enabled");
            exit(-1);
        }
        if cli.caliptra_rom.is_none() {
            println!("Caliptra ROM File is required if Caliptra is enabled");
            exit(-1);
        }
        if cli.caliptra_firmware.is_none() {
            println!("Caliptra ROM File is required if Caliptra is enabled");
            exit(-1);
        }
        Some(
            start_caliptra(&StartCaliptraArgs {
                rom: cli.caliptra_rom.unwrap(),
                firmware: cli.caliptra_firmware,
                ..Default::default()
            })
            .expect("Failed to start Caliptra CPU"),
        )
    } else {
        None
    };

    let rom_buffer = read_binary(args_rom, 0)?;
    if rom_buffer.len() > CaliptraRootBus::ROM_SIZE {
        println!(
            "ROM File Size must not exceed {} bytes",
            CaliptraRootBus::ROM_SIZE
        );
        exit(-1);
    }
    println!(
        "Loaded ROM File {:?} of size {}",
        args_rom,
        rom_buffer.len(),
    );

    let firmware_buffer = if let Some(firmware_path) = cli.firmware {
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
        firmware: firmware_buffer,
        log_dir: args_log_dir.clone(),
        uart_output: uart_output.clone(),
        otp_file: cli.otp,
        uart_rx: stdin_uart.clone(),
        pic: pic.clone(),
        clock: clock.clone(),
    };
    let root_bus = CaliptraRootBus::new(bus_args).unwrap();
    let i3c_error_irq = pic.register_irq(CaliptraRootBus::I3C_ERROR_IRQ);
    let i3c_notif_irq = pic.register_irq(CaliptraRootBus::I3C_NOTIF_IRQ);

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

    let flash_ctrl_error_irq = pic.register_irq(CaliptraRootBus::FLASH_CTRL_ERROR_IRQ);
    let flash_ctrl_event_irq = pic.register_irq(CaliptraRootBus::FLASH_CTRL_EVENT_IRQ);
    let flash_controller = DummyFlashCtrl::new(
        &clock.clone(),
        None,
        flash_ctrl_error_irq,
        flash_ctrl_event_irq,
    )
    .unwrap();

    let auto_root_bus = AutoRootBus::new(
        Some(Box::new(root_bus)),
        Some(Box::new(i3c)),
        Some(Box::new(flash_controller)),
        None,
        None,
        None,
        None,
    );

    let cpu = Cpu::new(auto_root_bus, clock, pic);

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
            free_run(running.clone(), cpu, caliptra_cpu, instr_trace, stdin_uart);
        }
    }

    Ok(uart_output.map(|o| o.borrow().clone()).unwrap_or_default())
}
