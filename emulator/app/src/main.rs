/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra Emulator.

--*/

mod dis;
mod dis_test;
mod elf;
mod gdb;
mod tbf;

use clap::{Parser, Subcommand};
use console::{Key, Term};
use emulator_bus::{Bus, Clock, Timer};
use emulator_cpu::{Cpu, Pic, RvInstr, StepAction};
use emulator_periph::{CaliptraRootBus, CaliptraRootBusArgs};
use emulator_registers_generated::root_bus::AutoRootBus;
use gdb::gdb_state;
use gdb::gdb_target::GdbTarget;
use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
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

    #[arg(short, long)]
    apps: Option<Vec<PathBuf>>,

    /// Optional file to store OTP / fuses between runs.
    #[arg(short, long)]
    otp: Option<PathBuf>,

    /// GDB Debugger Port
    #[arg(short, long)]
    gdb_port: Option<u16>,

    /// Directory in which to log execution artifacts.
    #[arg(short, long)]
    log_dir: Option<PathBuf>,

    #[arg(short, long, default_value_t = false)]
    trace_instr: bool,

    #[arg(short, long, default_value_t = true)]
    stdin_uart: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Build Tock image
    Tock,
    /// Run clippy on all targets
    Clippy,
    /// Check that all files are formatted
    Format,
    /// Run pre-check-in checks
    Precheckin,
    /// Check cargo lock
    CargoLock,
    /// Check files for Apache license header
    HeaderCheck,
    /// Add Apache license header to files where it is missing
    HeaderFix,
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
    let term = Term::stdout();
    let mut buffer = vec![];
    if let Some(ref stdin_uart) = stdin_uart {
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if buffer.is_empty() {
                match term.read_key() {
                    Ok(Key::Char(ch)) => buffer.extend_from_slice(ch.to_string().as_bytes()),
                    Ok(Key::Enter) => {
                        buffer.push(b'\n');
                    }
                    Ok(Key::Backspace) => {
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
fn free_run<T: Bus>(
    running: Arc<AtomicBool>,
    mut cpu: Cpu<T>,
    trace_path: Option<PathBuf>,
    stdin_uart: Option<Arc<Mutex<Option<u8>>>>,
) {
    // read from the console in a separate thread to prevent blocking
    let running_clone = running.clone();
    let stdin_uart_clone = stdin_uart.clone();
    std::thread::spawn(move || read_console(running_clone, stdin_uart_clone));

    let timer = Timer::new(&cpu.clock.clone());
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
            let action = cpu.step(Some(trace_fn));
            if action != StepAction::Continue {
                break;
            }
        }
    } else {
        while running.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref stdin_uart) = stdin_uart {
                if stdin_uart.lock().unwrap().is_some() {
                    timer.schedule_poll_in(1);
                }
            }
            let action = cpu.step(None);
            if action != StepAction::Continue {
                break;
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
    if atty::is(atty::Stream::Stdout) {
        ctrlc::set_handler(move || {
            running_clone.store(false, std::sync::atomic::Ordering::Relaxed);
            Term::stdout().clear_line().unwrap();
            Term::stdout().show_cursor().unwrap();
            println!("Terminal might be in a bad state. Run \"stty sane && reset\" to fix it.");
        })
        .unwrap();
    }

    let args_rom = &cli.rom;
    let args_log_dir = &cli.log_dir.unwrap_or_else(|| PathBuf::from("/tmp"));

    if !Path::new(&args_rom).exists() {
        println!("ROM File {:?} does not exist", args_rom);
        exit(-1);
    }

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

    let apps = cli.apps.unwrap_or_default();
    let apps_binary = if !apps.is_empty() {
        if apps.len() > 1 {
            println!("Only one app is supported right now");
            exit(-1);
        }
        let app_raw_binary = read_binary(&apps[0], 0x4002_0000 + 0x60)?;
        tbf::make_tbf(app_raw_binary)
    } else {
        vec![]
    };

    let clock = Rc::new(Clock::new());

    let uart_output = if capture_uart_output {
        Some(Rc::new(RefCell::new(Vec::new())))
    } else {
        None
    };

    let stdin_uart = if cli.stdin_uart && atty::is(atty::Stream::Stdin) {
        Some(Arc::new(Mutex::new(None)))
    } else {
        None
    };
    let pic = Rc::new(Pic::new());

    let bus_args = CaliptraRootBusArgs {
        rom: rom_buffer,
        firmware: firmware_buffer,
        apps: apps_binary,
        log_dir: args_log_dir.clone(),
        uart_output: uart_output.clone(),
        otp_file: cli.otp,
        uart_rx: stdin_uart.clone(),
        pic: pic.clone(),
        clock: clock.clone(),
    };
    let root_bus = CaliptraRootBus::new(bus_args).unwrap();
    let auto_root_bus = AutoRootBus::new(Some(Box::new(root_bus)), None, None, None, None, None);

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
            free_run(running.clone(), cpu, instr_trace, stdin_uart);
        }
    }

    Ok(uart_output.map(|o| o.borrow().clone()).unwrap_or_default())
}
