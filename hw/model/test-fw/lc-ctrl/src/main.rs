// Licensed under the Apache-2.0 license

//! Parameterized test ROM for LC state transitions.
//!
//! Reads the target state and token selector from MCI generic input wires:
//!   - wires[0] bit 0:       go-bit (wait until set)
//!   - wires[0] bits [12:8]: target LC state index (0-21)
//!   - wires[0] bits [16:15]: token type (0=zero, 1=raw unlock, 2=default)
//!   - wires[0] bit 17:     expect error (1 = expect transition to fail)
//!
//! Prints "PASS" on expected outcome, "FAIL: <reason>" otherwise.

#![no_main]
#![no_std]

use mcu_rom_common::{LifecycleControllerState, LifecycleToken, McuBootMilestones, RomEnv};
use tock_registers::interfaces::Readable;

const GO_BIT: u32 = 1 << 0;

const RAW_UNLOCK_TOKEN: [u8; 16] = [
    0xca, 0xa0, 0x32, 0xb5, 0x87, 0x96, 0xce, 0x74, 0x9a, 0xef, 0xec, 0xa2, 0x65, 0xbe, 0x41, 0x61,
];

const DEFAULT_TOKEN: u128 = 0x05edb8c608fcc830de181732cfd65e57;

fn run() -> ! {
    let env = RomEnv::new();

    // Set boot milestone so the host's warm_reset() can proceed.
    env.mci
        .set_flow_milestone(McuBootMilestones::CPTRA_FUSES_WRITTEN.into());

    // Wait for go-bit.
    while env.mci.registers.mci_reg_generic_input_wires[0].get() & GO_BIT == 0 {}

    let wires = env.mci.registers.mci_reg_generic_input_wires[0].get();
    let target_index = ((wires >> 8) & 0x1F) as u8;
    let token_type = (wires >> 15) & 0x3;
    let expect_error = (wires >> 17) & 1 != 0;

    // Initialize LC controller (waits for ready).
    env.lc.init().unwrap();

    let target = LifecycleControllerState::from(target_index);
    let token = match token_type {
        1 => LifecycleToken(RAW_UNLOCK_TOKEN),
        2 => LifecycleToken(DEFAULT_TOKEN.to_le_bytes()),
        _ => LifecycleToken([0u8; 16]),
    };

    let result = env.lc.transition(target, &token);

    match (result.is_ok(), expect_error) {
        (true, false) | (false, true) => romtime::println!("PASS"),
        (true, true) => romtime::println!("FAIL: expected error but succeeded"),
        (false, false) => romtime::println!("FAIL: unexpected transition error"),
    }

    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
extern "C" fn main() -> ! {
    mcu_test_harness::set_printer();
    run()
}
