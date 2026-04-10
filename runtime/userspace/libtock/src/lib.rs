#![forbid(unsafe_code)]
#![no_std]

#[cfg(debug_assertions)]
extern crate caliptra_mcu_libtock_debug_panic;
#[cfg(not(debug_assertions))]
extern crate caliptra_mcu_libtock_small_panic;

pub use caliptra_mcu_libtock_platform as platform;
pub use caliptra_mcu_libtock_runtime as runtime;

pub mod alarm {
    use caliptra_mcu_libtock_alarm as alarm;
    pub type Alarm = alarm::Alarm<super::runtime::TockSyscalls>;
    pub use alarm::{Convert, Hz, Milliseconds, Ticks};
}
pub mod console {
    use caliptra_mcu_libtock_console as console;
    pub type Console = console::Console<super::runtime::TockSyscalls>;
    pub use console::ConsoleWriter;
}
pub mod low_level_debug {
    use caliptra_mcu_libtock_low_level_debug as lldb;
    pub type LowLevelDebug = lldb::LowLevelDebug<super::runtime::TockSyscalls>;
    pub use lldb::AlertCode;
}
pub mod rng {
    use caliptra_mcu_libtock_rng as rng;
    pub type Rng = rng::Rng<super::runtime::TockSyscalls>;
    pub use rng::RngListener;
}
