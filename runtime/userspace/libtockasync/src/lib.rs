// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

extern crate alloc;

mod future;
pub use future::TockSubscribe;
mod tock_executor;
pub use tock_executor::TockExecutor;

use critical_section::RawRestoreState;
use embassy_executor::{SpawnToken, Spawner};

// copied from libtock-rs/demos/st7789-slint/src/main.rs
struct NullCriticalSection;
critical_section::set_impl!(NullCriticalSection);

// Safety: there is no code here.
unsafe impl critical_section::Impl for NullCriticalSection {
    unsafe fn acquire() -> RawRestoreState {
        // Tock is single threaded, so this can only be preempted by interrupts
        // The kernel won't schedule anything from our app unless we yield
        // so as long as we don't yield we won't concurrently run with
        // other critical sections from our app.
        // The kernel might schedule itself or other applications, but there
        // is nothing we can do about that.
    }
    unsafe fn release(_token: RawRestoreState) {}
}

pub fn init<S>(spawner: Spawner, main: SpawnToken<S>) {
    spawner.spawn(main).unwrap();
}

pub fn start_async<S>(main: SpawnToken<S>) -> ! {
    // Safety: we are upgrading the lifetime of this executor. This is safe because main() lives forever
    // and never returns, so the executor is never dropped.
    let mut executor = TockExecutor::new();
    let executor: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor) };
    executor.run(|spawner: Spawner| init(spawner, main));
}
