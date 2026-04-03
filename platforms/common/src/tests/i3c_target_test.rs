// Licensed under the Apache-2.0 license.

use core::cell::Cell;
use core::fmt::Write;
use i3c_driver::{
    core::I3CCore,
    hil::{I3CTarget, RxClient},
};
use kernel::{
    debug_flush_queue,
    deferred_call::{DeferredCall, DeferredCallClient},
    static_buf, static_init,
    utilities::cells::{OptionalCell, TakeCell},
};
use mcu_tock_veer::chip::{VeeR, VeeRDefaultPeripherals};
use mcu_tock_veer::timers::InternalTimers;
use romtime::println;

fn success() -> ! {
    debug_flush_queue!();
    romtime::test_exit(0);
}

#[allow(dead_code)]
fn fail() -> ! {
    debug_flush_queue!();
    romtime::test_exit(1);
}

/// A simple test that just enables and disables the I3C driver.
pub fn test_i3c_simple(
    chip: &'static VeeR<'static, VeeRDefaultPeripherals<'static>>,
) -> Option<u32> {
    chip.peripherals.i3c.enable();
    // check that we have a dynamic address from the driver
    if chip
        .peripherals
        .i3c
        .get_device_info()
        .dynamic_addr
        .is_none()
    {
        println!(
            "Failed to get address: dynamic {:?} static {:?}",
            chip.peripherals.i3c.get_device_info().dynamic_addr,
            chip.peripherals.i3c.get_device_info().static_addr,
        );
        fail();
    }
    chip.peripherals.i3c.disable();
    success();
}

/// Tests that writes are handled properly
pub fn test_i3c_constant_writes(
    chip: &'static VeeR<'static, VeeRDefaultPeripherals<'static>>,
) -> Option<u32> {
    println!("initializing test");
    let i3c = &chip.peripherals.i3c;
    // Safety: this buffer is only used by one function at a time, and only once.
    let const_writes_buf = unsafe { static_buf!([u8; 128]) };
    let const_writes_buf = const_writes_buf.write([0u8; 128]) as &'static mut [u8];
    let tester = unsafe { static_init!(I3CConstantWritesTest, I3CConstantWritesTest::new()) };
    tester.buf.replace(const_writes_buf);
    tester.i3c.set(i3c);
    tester.register();
    tester.deferred_call.set();
    i3c.set_rx_client(tester);
    i3c.enable();
    None
}

struct I3CConstantWritesTest<'a> {
    deferred_call: DeferredCall,
    count: Cell<usize>,
    buf: TakeCell<'static, [u8]>,
    i3c: OptionalCell<&'a I3CCore<'static, InternalTimers<'static>>>,
    deferred_calls: Cell<usize>,
}

impl<'a> I3CConstantWritesTest<'a> {
    pub fn new() -> I3CConstantWritesTest<'a> {
        I3CConstantWritesTest {
            deferred_call: DeferredCall::new(),
            count: Cell::new(0),
            buf: TakeCell::empty(),
            i3c: OptionalCell::empty(),
            deferred_calls: Cell::new(0),
        }
    }
}

impl<'a> DeferredCallClient for I3CConstantWritesTest<'a> {
    fn handle_deferred_call(&self) {
        if self.count.get() >= 10 {
            println!("Passed");
            success();
        }
        let iter = self.deferred_calls.get();
        self.deferred_calls.set(iter + 1);
        if iter > 10000 {
            println!(
                "Too many deferred calls; failing test; only got {}",
                self.count.get()
            );
            fail();
        }
        // try again in the next kernel loop
        self.deferred_call.set();
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}

impl<'a> RxClient for I3CConstantWritesTest<'a> {
    fn receive_write(&self, rx_buffer: &'static mut [u8], _len: usize) {
        self.buf.replace(rx_buffer);
        self.count.set(self.count.get() + 1);
    }

    fn write_expected(&self) {
        self.i3c
            .get()
            .unwrap()
            .set_rx_buffer(self.buf.take().unwrap());
    }
}
