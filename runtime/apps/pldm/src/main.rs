// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]
#![no_main]
#![allow(static_mut_refs)]

#[macro_use]
extern crate cfg_if;

cfg_if! {
    if #[cfg(target_arch = "riscv32")] {

extern crate alloc;
use alloc::boxed::Box;
use core::cell::Cell;
use core::fmt::Write;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use critical_section::RawRestoreState;
use embassy_executor::Spawner;
use embedded_alloc::Heap;
use libtock::alarm::*;
use libtock::console::Console;
use libtock::runtime::{set_main, stack_size};
use libtock_platform::exit_on_drop::ExitOnDrop;
use libtock_platform::*;
use libtock_platform::{self as platform};
use libtock_platform::{DefaultConfig, ErrorCode, Syscalls};
use libtock_runtime::TockSyscalls;

mod tock_executor;
use tock_executor::TockExecutor;

const HEAP_SIZE: usize = 0x40;
#[global_allocator]
static HEAP: Heap = Heap::empty();

stack_size! {0x1000}
set_main! {main}

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

fn main() {
    // setup the global allocator for futures
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // Safety: HEAP_MEM is a valid array of MaybeUninit, so we can safely initialize it.
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }

    let mut console_writer = Console::writer();
    writeln!(console_writer, "Hello world! from main\r").unwrap();
    // Safety: we are upgrading the lifetime of this executor. This is safe because main() lives forever
    // and never returns, so the executor is never dropped.
    let mut executor = TockExecutor::new();
    let executor: &'static mut TockExecutor = unsafe { core::mem::transmute(&mut executor) };
    executor.run(init);
}

fn init(spawner: Spawner) {
    spawner.spawn(async_main()).unwrap();
}

#[embassy_executor::task]
async fn async_main() {
    let mut console_writer = Console::writer();
    writeln!(console_writer, "Hello async world!\r").unwrap();

    for _ in 0..20 {
        writeln!(console_writer, "Sleeping for 10 millisecond\r").unwrap();
        sleep(Milliseconds(10)).await;
        writeln!(console_writer, "async sleeper woke\r").unwrap();
    }
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

async fn sleep(time: Milliseconds) {
    let x = AsyncAlarm::<TockSyscalls>::sleep_for(time).await;
    writeln!(Console::writer(), "Async sleep done {:?}\r", x).unwrap();
}

pub struct AsyncAlarm<S: Syscalls, C: platform::subscribe::Config = DefaultConfig>(S, C);

impl<S: Syscalls, C: platform::subscribe::Config> AsyncAlarm<S, C> {
    /// Run a check against the console capsule to ensure it is present.
    #[inline(always)]
    pub fn exists() -> Result<(), ErrorCode> {
        S::command(DRIVER_NUM, command::EXISTS, 0, 0).to_result()
    }

    pub fn get_frequency() -> Result<Hz, ErrorCode> {
        S::command(DRIVER_NUM, command::FREQUENCY, 0, 0)
            .to_result()
            .map(Hz)
    }

    pub fn get_ticks() -> Result<u32, ErrorCode> {
        S::command(DRIVER_NUM, command::TIME, 0, 0).to_result()
    }

    pub fn get_milliseconds() -> Result<u64, ErrorCode> {
        let ticks = Self::get_ticks()? as u64;
        let freq = (Self::get_frequency()?).0 as u64;

        Ok(ticks.saturating_div(freq / 1000))
    }

    pub async fn sleep_for<T: Convert>(time: T) -> Result<(), ErrorCode> {
        let freq = Self::get_frequency()?;
        let ticks = time.to_ticks(freq);
        let sub = TockSubscribe::subscribe::<S>(DRIVER_NUM, 0);
        S::command(DRIVER_NUM, command::SET_RELATIVE, ticks.0, 0)
            .to_result()
            .map(|_when: u32| ())?;
        sub.await.map(|_| ())
    }
}

/// TockSubscribe is a future implementation that performs a Tock subscribe call and
/// is ready when the subscribe upcall happens.
///
/// When the future is ready, it will contain arguments the upcall was called with.
///
/// Use like: `TockSubscribe::<TockSyscalls>::subscribe(driver_num, subscribe_num).await`.
pub struct TockSubscribe {
    result: Cell<Option<(u32, u32, u32)>>,
    waker: Cell<Option<Waker>>,
    error: Option<ErrorCode>,
}

impl TockSubscribe {
    fn new() -> TockSubscribe {
        TockSubscribe {
            result: Cell::new(None),
            waker: Cell::new(None),
            error: None,
        }
    }

    fn set_err(&mut self, err: ErrorCode) {
        self.error = Some(err);
    }

    pub fn subscribe<S: Syscalls>(
        driver_num: u32,
        subscribe_num: u32,
    ) -> impl Future<Output = Result<(u32, u32, u32), ErrorCode>> {
        // Pinning is necessary since we are passing a pointer to the TockSubscribe to the kernel.
        let mut f = Pin::new(Box::new(TockSubscribe::new()));
        let upcall_fcn = (kernel_upcall::<S> as *const ()) as u32;
        let upcall_data = (&*f as *const TockSubscribe) as u32;

        // Safety: we are passing in a fixed (safe) function pointer and a pointer to a pinned instance.
        // If the instance is dropped before the upcall comes in, then we panic in the Drop impl.
        let [r0, r1, _, _] = unsafe {
            S::syscall4::<{ syscall_class::SUBSCRIBE }>([
                driver_num.into(),
                subscribe_num.into(),
                upcall_fcn.into(),
                upcall_data.into(),
            ])
        };
        let return_variant: ReturnVariant = r0.as_u32().into();
        match return_variant {
            return_variant::SUCCESS_2_U32 => {}
            return_variant::FAILURE_2_U32 => {
                f.set_err(r1.as_u32().try_into().unwrap_or(ErrorCode::Fail));
            }
            _ => {
                f.set_err(ErrorCode::Fail);
            }
        }
        f
    }
}

extern "C" fn kernel_upcall<S: Syscalls>(arg0: u32, arg1: u32, arg2: u32, data: Register) {
    let exit: ExitOnDrop<S> = Default::default();
    let upcall: *mut TockSubscribe = data.into();
    // Safety: we set the pointer to a pinned TockSubscribe instance in the subscribe.
    // If the subscribe call had failed, then the error would have been set this upcall
    // will never be called.
    // If the reference to the TockSubscribe is dropped before the upcall, then we panic
    // in the Drop instead of dereferencing into an invalid pointer.
    unsafe { (*upcall).result.set(Some((arg0, arg1, arg2))) };
    if let Some(waker) = unsafe { (*upcall).waker.take() } {
        waker.wake();
    }
    core::mem::forget(exit);
}

impl Future for TockSubscribe {
    type Output = Result<(u32, u32, u32), ErrorCode>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(err) = self.error {
            return Poll::Ready(Err(err));
        }
        if let Some(ret) = self.result.get() {
            Poll::Ready(Ok(ret))
        } else {
            // set ourselves to wake when the upcall happens
            self.waker.replace(Some(cx.waker().clone()));
            // we don't call yield ourself, but let the executor call yield
            Poll::Pending
        }
    }
}

impl Drop for TockSubscribe {
    fn drop(&mut self) {
        if self.result.get().is_none() && self.error.is_none() {
            writeln!(
                Console::writer(),
                "PANIC: The TockSubscribe future was dropped before the upcall happened.\r"
            )
            .unwrap();
            panic!("The TockSubscribe future was dropped before the upcall happened.");
        }
    }
}
    } else {
        #[no_mangle]
        pub extern "C" fn main() {
            // no-op on x86 just to keep the build clean
        }
    }
}
