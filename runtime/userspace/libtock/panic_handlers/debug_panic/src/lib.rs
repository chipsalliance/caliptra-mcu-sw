#![no_std]
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_low_level_debug::{AlertCode, LowLevelDebug};
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtock_runtime::TockSyscalls;
use core::fmt::Write;

/// This handler requires some 0x400 bytes of stack
#[allow(dead_code)]
#[cfg_attr(target_arch = "riscv32", panic_handler)]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    // Signal a panic using the LowLevelDebug capsule (if available).
    LowLevelDebug::<TockSyscalls>::print_alert_code(AlertCode::Panic);

    let mut writer = Console::<TockSyscalls>::writer();
    // If this printing fails, we can't panic harder, and we can't print it either.
    let _ = writeln!(writer, "{}", info);
    // Exit with a non-zero exit code to indicate failure.
    TockSyscalls::exit_terminate(ErrorCode::Fail as u32);
}
