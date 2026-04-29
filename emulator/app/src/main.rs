/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entrypoint for Caliptra MCU Emulator.

--*/

use caliptra_emu_cpu::StepAction;
use caliptra_mcu_emulator::{gdb, Emulator, EmulatorArgs};
use caliptra_mcu_testing_common::MCU_RUNNING;
use clap::Parser;
use std::cell::RefCell;
use std::io;
use std::io::IsTerminal;
use std::rc::Rc;

// CPU Main Loop (free_run no GDB)
fn free_run(mut emulator: Emulator) {
    while caliptra_mcu_testing_common::is_emulator_running() {
        match emulator.step() {
            StepAction::Break => break,
            StepAction::Fatal => break,
            _ => {}
        }
    }
}

fn main() -> io::Result<()> {
    let cli = EmulatorArgs::parse();
    run(cli, false).map(|_| ())
}

fn run(cli: EmulatorArgs, capture_uart_output: bool) -> io::Result<Vec<u8>> {
    let uart_output = if capture_uart_output {
        Some(Rc::new(RefCell::new(Vec::new())))
    } else {
        None
    };

    let emulator = Emulator::from_args(cli.clone(), capture_uart_output)?;

    // exit cleanly on Ctrl-C so that we save any state.
    // Sets both per-instance and global state.
    if io::stdout().is_terminal() {
        let state = emulator.state.clone();
        ctrlc::set_handler(move || {
            state
                .running
                .store(false, std::sync::atomic::Ordering::Relaxed);
            MCU_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
        })
        .unwrap();
    }

    // Check if Optional GDB Port is passed
    match cli.gdb_port {
        Some(port) => {
            // Create GDB Target Instance
            let mut gdb_target = gdb::gdb_target::GdbTarget::new(emulator);

            // Execute CPU through GDB State Machine
            gdb::gdb_state::wait_for_gdb_run(&mut gdb_target, port);
        }
        _ => {
            // Create the emulator with all the setup
            free_run(emulator);
        }
    }

    Ok(uart_output.map(|o| o.borrow().clone()).unwrap_or_default())
}
