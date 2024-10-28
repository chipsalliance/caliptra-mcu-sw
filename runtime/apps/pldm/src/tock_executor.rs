// Licensed under the Apache-2.0 license

// Based almost entirely on the Embassy RISC-V executor (which is also licensed Apache 2.0).

use core::marker::PhantomData;
use embassy_executor::{raw, Spawner};
use portable_atomic::{AtomicBool, Ordering};

/// global atomic used to keep track of whether there is work to do since sev() is not available on RISCV
static SIGNAL_WORK_THREAD_MODE: AtomicBool = AtomicBool::new(false);

#[export_name = "__pender"]
fn __pender(_context: *mut ()) {
    SIGNAL_WORK_THREAD_MODE.store(true, Ordering::SeqCst);
}

/// RISCV32 Tock Executor
pub struct TockExecutor {
    inner: raw::Executor,
    not_send: PhantomData<*mut ()>,
}

impl TockExecutor {
    /// Create a new Executor.
    pub fn new() -> Self {
        Self {
            inner: raw::Executor::new(core::ptr::null_mut()),
            not_send: PhantomData,
        }
    }

    /// Run the executor.
    ///
    /// The `init` closure is called with a [`Spawner`] that spawns tasks on
    /// this executor. Use it to spawn the initial task(s). After `init` returns,
    /// the executor starts running the tasks.
    ///
    /// To spawn more tasks later, you may keep copies of the [`Spawner`] (it is `Copy`),
    /// for example by passing it as an argument to the initial tasks.
    ///
    /// This function requires `&'static mut self`. This means you have to store the
    /// Executor instance in a place where it'll live forever and grants you mutable
    /// access. There's a few ways to do this:
    ///
    /// - a [StaticCell](https://docs.rs/static_cell/latest/static_cell/) (safe)
    /// - a `static mut` (unsafe)
    /// - a local variable in a function you know never returns (like `fn main() -> !`), upgrading its lifetime with `transmute`. (unsafe)
    ///
    /// This function never returns.
    pub fn run(&'static mut self, init: impl FnOnce(Spawner)) -> ! {
        init(self.inner.spawner());

        loop {
            unsafe {
                self.inner.poll();
                // we do not care about race conditions between the load and store operations, interrupts
                // will only set this value to true.
                critical_section::with(|_| {
                    // if there is work to do, loop back to polling
                    // TODO can we relax this?
                    if SIGNAL_WORK_THREAD_MODE.load(Ordering::SeqCst) {
                        SIGNAL_WORK_THREAD_MODE.store(false, Ordering::SeqCst);
                    }
                    // if not, yield and wait for OS upcall
                    else {
                        // Safety: yield-wait does not return a value, which satisfies yield1's
                        // requirement. The yield-wait system call cannot trigger undefined
                        // behavior on its own in any other way.
                        yield1(1);
                    }
                });
            }
        }
    }
}

unsafe fn yield1(r0: u32) {
    // Safety: This matches the invariants required by the documentation on
    // RawSyscalls::yield1

    use core::arch::asm;
    unsafe {
        asm!("ecall",
                // x0 is the zero register.
                lateout("x1") _, // Return address
                // x2-x4 are stack, global, and thread pointers. sp is
                // callee-saved.
                lateout("x5") _, // t0
                lateout("x6") _, // t1
                lateout("x7") _, // t2
                // x8 and x9 are s0 and s1 and are callee-saved.
                inlateout("x10") r0 => _, // a0
                lateout("x11") _,         // a1
                lateout("x12") _,         // a2
                lateout("x13") _,         // a3
                inlateout("x14") 0 => _,  // a4
                lateout("x15") _,         // a5
                lateout("x16") _,         // a6
                lateout("x17") _,         // a7
                // x18-27 are s2-s11 and are callee-saved
                lateout("x28") _, // t3
                lateout("x29") _, // t4
                lateout("x30") _, // t5
                lateout("x31") _, // t6
        );
    }
}
