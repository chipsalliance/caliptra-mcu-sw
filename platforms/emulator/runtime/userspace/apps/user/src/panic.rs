// Licensed under the Apache-2.0 license

//! User-app panic handler: record the panic reason via `defmt` and flush staged
//! frames to flash (when `userspace-log` is enabled) before terminating.

use caliptra_mcu_libtock_low_level_debug::{AlertCode, LowLevelDebug};
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtock_runtime::TockSyscalls;

/// Requires roughly 0x400 bytes of stack.
#[panic_handler]
#[cfg_attr(
    all(not(feature = "userspace-log"), not(debug_assertions)),
    allow(unused_variables)
)]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    // Point of no return: record the reason and flush staged frames to flash.
    #[cfg(feature = "userspace-log")]
    {
        defmt::error!("panic: {}", defmt::Display2Format(info));
        defmt::flush();
    }

    // Cheap debug-channel signal; works even when the console is disabled.
    LowLevelDebug::<TockSyscalls>::print_alert_code(AlertCode::Panic);

    // Dev-only human-readable echo; the console is disabled in release.
    #[cfg(debug_assertions)]
    {
        use caliptra_mcu_libtock_console::Console;
        use core::fmt::Write;
        let mut writer = Console::<TockSyscalls>::writer();
        let _ = writeln!(writer, "{}", info);
    }

    TockSyscalls::exit_terminate(ErrorCode::Fail as u32);
}
