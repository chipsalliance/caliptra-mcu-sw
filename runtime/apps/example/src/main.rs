// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]
#![feature(impl_trait_in_assoc_type)]
#![allow(static_mut_refs)]

use core::fmt::Write;
use libtock::alarm::*;
use libtock_console::Console;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtockasync::TockSubscribe;

#[cfg(target_arch = "riscv32")]
mod riscv;

#[cfg(not(target_arch = "riscv32"))]
pub(crate) fn kernel() -> libtock_unittest::fake::Kernel {
    use libtock_unittest::fake;
    let kernel = fake::Kernel::new();
    let alarm = fake::Alarm::new(1_000_000);
    let console = fake::Console::new();
    kernel.add_driver(&alarm);
    kernel.add_driver(&console);
    kernel
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    // build a fake kernel so that the app will at least start without Tock
    let _kernel = kernel();
    // call the main function
    libtockasync::start_async(start());
}

#[cfg(target_arch = "riscv32")]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_runtime::TockSyscalls>().await;
}

#[cfg(not(target_arch = "riscv32"))]
#[embassy_executor::task]
async fn start() {
    async_main::<libtock_unittest::fake::Syscalls>().await;
}

pub(crate) async fn async_main<S: Syscalls>() {
    let mut console_writer = Console::<S>::writer();
    writeln!(console_writer, "Hello async world!").unwrap();
    writeln!(
        console_writer,
        "Timer frequency: {}",
        AsyncAlarm::<S>::get_frequency().unwrap().0
    )
    .unwrap();

    match AsyncAlarm::<S>::exists() {
        Ok(()) => {}
        Err(e) => {
            writeln!(
                console_writer,
                "Alarm capsule not available, so skipping sleep loop: {:?}",
                e
            )
            .unwrap();
            return;
        }
    };

    for _ in 0..5 {
        writeln!(console_writer, "Sleeping for 1 millisecond").unwrap();
        sleep::<S>(Milliseconds(1)).await;
        writeln!(console_writer, "async sleeper woke").unwrap();
    }
    writeln!(console_writer, "app finished").unwrap();
}

// -----------------------------------------------------------------------------
// Driver number and command IDs
// -----------------------------------------------------------------------------

const DRIVER_NUM: u32 = 0;

// Command IDs
#[allow(unused)]
mod command {
    pub const EXISTS: u32 = 0;
    pub const FREQUENCY: u32 = 1;
    pub const TIME: u32 = 2;
    pub const STOP: u32 = 3;

    pub const SET_RELATIVE: u32 = 5;
    pub const SET_ABSOLUTE: u32 = 6;
}

#[allow(unused)]
mod subscribe {
    pub const CALLBACK: u32 = 0;
}

pub(crate) async fn sleep<S: Syscalls>(time: Milliseconds) {
    let x = AsyncAlarm::<S>::sleep_for(time).await;
    writeln!(Console::<S>::writer(), "Async sleep done {:?}", x).unwrap();
}

pub struct AsyncAlarm<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config> AsyncAlarm<S, C> {
    /// Run a check against the console capsule to ensure it is present.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).to_result()
    }

    pub fn get_frequency() -> Result<Hz, ErrorCode> {
        S::command(DRIVER_NUM, command::FREQUENCY, 0, 0)
            .to_result()
            .map(Hz)
    }

    #[allow(dead_code)]
    pub fn get_ticks() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::TIME, 0, 0).to_result()
    }

    #[allow(dead_code)]
    pub fn get_milliseconds() -> Result<u64, ErrorCode> {
        let ticks = Self::get_ticks()? as u64;
        let freq = (Self::get_frequency()?).0 as u64;

        Ok(ticks.saturating_div(freq / 1000))
    }

    pub async fn sleep_for<T: Convert>(time: T) -> Result<(), ErrorCode> {
        let freq = Self::get_frequency()?;
        let ticks = time.to_ticks(freq).0;
        writeln!(Console::<S>::writer(), "Sleeping for {} ticks", ticks).unwrap();
        let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, 0);
        S::command(DRIVER_NUM, command::SET_RELATIVE, ticks, 0)
            .to_result()
            .map(|_when: u32| ())?;
        sub.await.map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use super::{command, kernel, sleep};
    use libtock_alarm::Milliseconds;
    use libtock_unittest::fake;
    use libtock_unittest::fake::Alarm;
    use libtockasync::TockExecutor;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{LazyLock, Mutex};

    #[test]
    fn test_frequency() {
        use fake::SyscallDriver;
        let alarm = Alarm::new(10);

        assert_eq!(
            alarm.command(command::FREQUENCY, 1, 2).get_success_u32(),
            Some(10)
        );
    }

    static SLEEP_COUNTER: LazyLock<Mutex<AtomicU32>> =
        LazyLock::new(|| Mutex::new(AtomicU32::new(0)));

    #[embassy_executor::task]
    async fn run_sleep() {
        sleep::<fake::Syscalls>(Milliseconds(1)).await;
        SLEEP_COUNTER
            .lock()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
        // ensure there is always an upcall scheduled
        loop {
            sleep::<fake::Syscalls>(Milliseconds(1)).await;
        }
    }

    #[test]
    fn test_async_sleep() {
        let kernel = kernel();
        let mut executor = TockExecutor::new();
        // Safety: we are upgrading the executor for the lifetime of the test only.
        // This needs to be in the same scope as the test for the static upgrade to work.
        let executor: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor) };

        executor.spawner().spawn(run_sleep()).unwrap();
        for _ in 0..10 {
            executor.poll();
        }
        assert_eq!(SLEEP_COUNTER.lock().unwrap().load(Ordering::Relaxed), 1);
        drop(kernel);
    }
}