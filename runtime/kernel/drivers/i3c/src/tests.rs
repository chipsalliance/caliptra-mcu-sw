// Licensed under the Apache-2.0 license

//! Memory-backed MMIO tests of driver state and buffer ownership. These registers
//! do not model FIFO pops, read-to-clear status, or the full sequence of writes
//! to a port; those behaviors need emulator component/integration tests.

use super::*;
use crate::hil::I3CTarget;
use kernel::hil::time::{Frequency, Ticks, Ticks32};
use std::sync::{Mutex, MutexGuard};
use tock_registers::registers::ReadWrite;

// Tock's deferred-call registry is global and single-threaded. Serialize all
// tests, including construction, and keep the total number of instances < 32.
static TEST_LOCK: Mutex<()> = Mutex::new(());

struct TestFrequency;
impl Frequency for TestFrequency {
    fn frequency() -> u32 {
        1_000_000
    }
}

struct TestAlarm {
    now: Cell<Ticks32>,
    deadline: Cell<Ticks32>,
    armed: Cell<bool>,
    client: OptionalCell<&'static dyn AlarmClient>,
}

impl TestAlarm {
    fn new() -> Self {
        Self {
            now: Cell::new(0.into()),
            deadline: Cell::new(0.into()),
            armed: Cell::new(false),
            client: OptionalCell::empty(),
        }
    }

    fn fire(&self) {
        assert!(self.armed.replace(false));
        self.now.set(self.deadline.get());
        self.client.get().unwrap().alarm();
    }
}

impl Time for TestAlarm {
    type Frequency = TestFrequency;
    type Ticks = Ticks32;

    fn now(&self) -> Ticks32 {
        self.now.get()
    }
}

impl Alarm<'static> for TestAlarm {
    fn set_alarm_client(&self, client: &'static dyn AlarmClient) {
        self.client.set(client);
    }

    fn set_alarm(&self, reference: Ticks32, dt: Ticks32) {
        self.deadline.set(reference.wrapping_add(dt));
        self.armed.set(true);
    }

    fn get_alarm(&self) -> Ticks32 {
        self.deadline.get()
    }

    fn disarm(&self) -> Result<(), ErrorCode> {
        self.armed.set(false);
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed.get()
    }

    fn minimum_dt(&self) -> Ticks32 {
        1.into()
    }
}

#[derive(Clone, Copy)]
struct Registers(usize);

impl Registers {
    fn new() -> Self {
        // Leaked, aligned storage lives as long as the driver's StaticRef.
        Self(Box::leak(Box::new([0u32; 0x1000 / 4])).as_ptr() as usize)
    }

    fn port(&self, offset: usize) -> &ReadWrite<u32> {
        assert!(offset < 0x1000 && offset.is_multiple_of(4));
        // Safety: only test RAM, not real MMIO, is accessed. The aligned backing
        // allocation is permanent. Tock register wrappers provide interior
        // mutability, including simulated hardware writes to ReadOnly ports.
        unsafe { &*((self.0 + offset) as *const ReadWrite<u32>) }
    }

    fn base(&self) -> StaticRef<I3c> {
        // Safety: this permanent, aligned allocation covers the register block.
        unsafe { StaticRef::new(self.0 as *const I3c) }
    }
}

type Driver = I3CCore<'static, TestAlarm>;

struct TxRecorder {
    driver: &'static Driver,
    calls: Cell<usize>,
    buffer: TakeCell<'static, [u8]>,
    next: TakeCell<'static, [u8]>,
}

impl TxClient for TxRecorder {
    fn send_done(&self, buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        assert_eq!(result, Ok(()));
        self.calls.set(self.calls.get() + 1);
        self.buffer.replace(buffer);
        if let Some(next) = self.next.take() {
            self.driver.transmit_read(next, 4).unwrap();
        }
    }
}

struct RxRecorder {
    driver: &'static Driver,
    requested: Cell<usize>,
    calls: Cell<usize>,
    len: Cell<usize>,
    available: TakeCell<'static, [u8]>,
    received: TakeCell<'static, [u8]>,
}

impl RxClient for RxRecorder {
    fn write_expected(&self) {
        self.requested.set(self.requested.get() + 1);
        if let Some(buffer) = self.available.take() {
            self.driver.set_rx_buffer(buffer);
        }
    }

    fn receive_write(&self, buffer: &'static mut [u8], len: usize) {
        self.calls.set(self.calls.get() + 1);
        self.len.set(len);
        self.received.replace(buffer);
        // A real FIFO pop deasserts RxDescStat. Test RAM has no read side effects.
        self.driver.registers.tti_interrupt_status.set(0);
    }
}

struct Harness {
    _guard: MutexGuard<'static, ()>,
    registers: Registers,
    driver: &'static Driver,
    alarm: &'static TestAlarm,
    tx: &'static TxRecorder,
    rx: &'static RxRecorder,
}

impl Harness {
    fn new() -> Self {
        let guard = TEST_LOCK.lock().unwrap();
        assert!(!DeferredCall::has_tasks());
        let registers = Registers::new();
        let alarm = Box::leak(Box::new(TestAlarm::new()));
        let mux = Box::leak(Box::new(MuxAlarm::new(alarm)));
        alarm.set_alarm_client(mux);
        let driver = Box::leak(Box::new(Driver::new(registers.base(), mux)));
        driver.init();
        DeferredCall::verify_setup();
        let tx = Box::leak(Box::new(TxRecorder {
            driver,
            calls: Cell::new(0),
            buffer: TakeCell::empty(),
            next: TakeCell::empty(),
        }));
        let rx = Box::leak(Box::new(RxRecorder {
            driver,
            requested: Cell::new(0),
            calls: Cell::new(0),
            len: Cell::new(0),
            available: TakeCell::empty(),
            received: TakeCell::empty(),
        }));
        driver.set_tx_client(tx);
        driver.set_rx_client(rx);
        Self {
            _guard: guard,
            registers,
            driver,
            alarm,
            tx,
            rx,
        }
    }

    fn ibi_done(&self, status: u32) {
        self.registers
            .port(0x208)
            .set(Status::LastIbiStatus.val(status).value);
        self.driver
            .registers
            .tti_interrupt_status
            .write(InterruptStatus::IbiDone::SET);
        self.driver.handle_interrupt();
        self.driver.registers.tti_interrupt_status.set(0);
    }

    fn receive(&self, len: usize, error: u32) {
        self.registers
            .port(0x270)
            .set((RxDesc::DataLength.val(len as u32) + RxDesc::Error.val(error)).value);
        self.registers.port(0x274).set(0x44332211);
    }

    fn private_read_done(&self) {
        self.driver
            .registers
            .tti_interrupt_status
            .write(InterruptStatus::TxDescComplete::SET);
        self.driver.handle_interrupt();
        self.driver.registers.tti_interrupt_status.set(0);
    }

    fn complete_tx(&self) {
        self.ibi_done(0);
        assert!(!DeferredCall::has_tasks());
        self.private_read_done();
        assert!(DeferredCall::service_next_pending().is_some());
        assert!(!DeferredCall::has_tasks());
    }
}

fn buffer(len: usize) -> &'static mut [u8] {
    Box::leak(vec![0xcc; len].into_boxed_slice())
}

#[test]
fn tx_bounds_and_word_padding() {
    let h = Harness::new();
    for (capacity, len, valid) in [
        (8, 0, false),
        (8, 1, true),
        (8, 3, true),
        (8, 4, true),
        (8, 5, true),
        (250, 249, true),
        (250, 250, true),
        (255, 255, true),
        (256, 256, true),
        (257, 257, false),
        (4, 5, false),
    ] {
        h.registers.port(0x278).set(0);
        h.registers.port(0x27c).set(0);
        h.registers.port(0x280).set(0);
        let buf = buffer(capacity);
        let ptr = buf.as_ptr();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let result = h.driver.transmit_read(buf, len);
        if valid {
            assert!(result.is_ok());
            assert_eq!(h.registers.port(0x278).get(), len as u32);
            let start = (len - 1) / 4 * 4;
            let expected = (start..len)
                .enumerate()
                .fold(0, |word, (i, byte)| word | ((byte as u8 as u32) << (8 * i)));
            assert_eq!(h.registers.port(0x27c).get(), expected);
            assert_eq!(
                h.registers.port(0x280).get(),
                (len as u16).swap_bytes() as u32
            );
            h.complete_tx();
            assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), ptr);
        } else {
            let (error, returned) = result.unwrap_err();
            assert_eq!(error, ErrorCode::SIZE);
            assert_eq!(returned.as_ptr(), ptr);
            assert_eq!(h.registers.port(0x278).get(), 0);
            assert_eq!(h.registers.port(0x27c).get(), 0);
            assert_eq!(h.registers.port(0x280).get(), 0);
            assert!(h.driver.tx_buffer.is_none());
            assert!(h.driver.pending_ibi.is_none());
        }
    }
}

#[test]
fn tx_busy_until_deferred_completion_and_callback_can_send_next() {
    let h = Harness::new();
    let first = buffer(4);
    let first_ptr = first.as_ptr();
    h.driver.transmit_read(first, 4).unwrap();
    let second = buffer(4);
    let second_ptr = second.as_ptr();
    for acked in [false, true] {
        if acked {
            h.ibi_done(0);
        }
        let busy = buffer(4);
        let busy_ptr = busy.as_ptr();
        let (error, returned) = h.driver.transmit_read(busy, 4).unwrap_err();
        assert_eq!(error, ErrorCode::BUSY);
        assert_eq!(returned.as_ptr(), busy_ptr);
        assert_eq!(h.tx.calls.get(), 0);
    }
    assert!(!DeferredCall::has_tasks());
    let (error, _) = h.driver.transmit_read(buffer(0), 0).unwrap_err();
    assert_eq!(error, ErrorCode::BUSY);
    h.private_read_done();
    h.tx.next.replace(second);
    assert!(DeferredCall::service_next_pending().is_some());
    assert_eq!(h.tx.calls.get(), 1);
    assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), first_ptr);
    assert_eq!(h.driver.pending_ibi.get(), Some((MDB_PENDING_READ_MCTP, 4)));
    h.complete_tx();
    assert_eq!(h.tx.calls.get(), 2);
    assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), second_ptr);
}

#[test]
fn private_read_before_ibi_keeps_buffer_until_both_complete() {
    let h = Harness::new();
    let buf = buffer(4);
    let ptr = buf.as_ptr();
    h.driver.transmit_read(buf, 4).unwrap();
    h.private_read_done();
    assert!(!DeferredCall::has_tasks());
    assert_eq!(h.tx.calls.get(), 0);
    assert!(h.driver.tx_buffer.is_some());
    h.ibi_done(0);
    assert!(DeferredCall::service_next_pending().is_some());
    assert_eq!(h.tx.calls.get(), 1);
    assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), ptr);
}

#[test]
fn configured_read_and_write_limits_are_enforced() {
    let h = Harness::new();
    h.driver.set_max_read_len(4);
    h.driver.set_max_write_len(3);
    let info = h.driver.get_device_info();
    assert_eq!(info.max_read_len, 4);
    assert_eq!(info.max_write_len, 3);
    let tx = buffer(5);
    let ptr = tx.as_ptr();
    let (error, tx) = h.driver.transmit_read(tx, 5).unwrap_err();
    assert_eq!(error, ErrorCode::SIZE);
    assert_eq!(tx.as_ptr(), ptr);
    h.driver.transmit_read(tx, 4).unwrap();
    h.complete_tx();
    assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), ptr);
    h.driver.set_rx_buffer(buffer(8));
    h.receive(4, 0);
    assert!(h.driver.handle_incoming_write());
    assert_eq!(h.rx.calls.get(), 0);
    h.receive(3, 0);
    assert!(h.driver.handle_incoming_write());
    assert_eq!(h.rx.calls.get(), 1);
    assert_eq!(h.rx.len.get(), 3);
}

#[test]
fn failed_ibi_resends_without_completing_or_releasing_buffer() {
    let h = Harness::new();
    let buf = buffer(5);
    let ptr = buf.as_ptr();
    h.driver.transmit_read(buf, 5).unwrap();
    for status in 1..=4 {
        h.registers.port(0x280).set(0);
        h.ibi_done(status);
        assert_eq!(h.registers.port(0x280).get(), 5u16.swap_bytes() as u32);
        assert_eq!(h.driver.pending_ibi.get(), Some((MDB_PENDING_READ_MCTP, 5)));
        assert_eq!(h.tx.calls.get(), 0);
        assert!(!DeferredCall::has_tasks());
        let busy = buffer(4);
        let busy_ptr = busy.as_ptr();
        let (error, returned) = h.driver.transmit_read(busy, 4).unwrap_err();
        assert_eq!(error, ErrorCode::BUSY);
        assert_eq!(returned.as_ptr(), busy_ptr);
    }
    h.complete_tx();
    assert_eq!(h.tx.calls.get(), 1);
    assert_eq!(h.tx.buffer.take().unwrap().as_ptr(), ptr);
}

#[test]
fn spurious_ibi_does_not_complete_twice() {
    let h = Harness::new();
    h.ibi_done(0);
    assert!(!DeferredCall::has_tasks());
    assert_eq!(h.registers.port(0x280).get(), 0);
    h.driver.transmit_read(buffer(4), 4).unwrap();
    // An empty interrupt must not release a still-pending IBI.
    h.driver.handle_interrupt();
    assert_eq!(h.tx.calls.get(), 0);
    assert!(!DeferredCall::has_tasks());
    h.complete_tx();
    h.ibi_done(0);
    assert!(!DeferredCall::has_tasks());
    assert_eq!(h.tx.calls.get(), 1);
}

#[test]
fn rx_exact_length_and_padding_leave_unused_buffer_unchanged() {
    let h = Harness::new();
    for len in [1, 3, 4, 5, 249, 250, 255, 256] {
        let buf = buffer(256);
        let ptr = buf.as_ptr();
        h.driver.set_rx_buffer(buf);
        h.receive(len, 0);
        assert!(h.driver.handle_incoming_write());
        assert_eq!(h.rx.len.get(), len);
        let received = h.rx.received.take().unwrap();
        assert_eq!(received.as_ptr(), ptr);
        for (i, byte) in received[..len].iter().enumerate() {
            assert_eq!(*byte, [0x11, 0x22, 0x33, 0x44][i % 4]);
        }
        assert!(received[len..].iter().all(|&byte| byte == 0xcc));
    }
}

#[test]
fn rx_rejects_error_and_overflow_then_accepts_next_packet() {
    let h = Harness::new();
    let buf = buffer(250);
    let ptr = buf.as_ptr();
    h.driver.set_rx_buffer(buf);
    for (len, error) in [(5, 1), (251, 0), (257, 0)] {
        h.receive(len, error);
        assert!(h.driver.handle_incoming_write());
        assert_eq!(h.rx.calls.get(), 0);
        h.driver.rx_buffer.map(|buf| {
            assert_eq!(buf.as_ptr(), ptr);
            assert!(buf.iter().all(|&byte| byte == 0xcc));
        });
    }
    h.receive(4, 0);
    assert!(h.driver.handle_incoming_write());
    assert_eq!(h.rx.calls.get(), 1);
    assert_eq!(h.rx.received.take().unwrap().as_ptr(), ptr);

    h.driver.set_rx_buffer(buffer(4));
    h.receive(5, 0);
    assert!(h.driver.handle_incoming_write());
    assert_eq!(h.rx.calls.get(), 1);
    assert!(h.driver.rx_buffer.is_some());
}

#[test]
fn rx_waits_for_buffer_and_retries_through_alarm() {
    let h = Harness::new();
    h.receive(4, 0);
    h.driver
        .registers
        .tti_interrupt_status
        .write(InterruptStatus::RxDescStat::SET);
    h.driver.handle_interrupt();
    assert_eq!(h.rx.requested.get(), 1);
    assert!(h.driver.retry_incoming_write.get());
    assert_eq!(h.alarm.get_alarm().into_u32(), Driver::RETRY_WAIT_TICKS);
    h.alarm.fire();
    assert_eq!(h.rx.requested.get(), 2);
    assert!(h.alarm.is_armed());
    h.rx.available.replace(buffer(4));
    h.alarm.fire();
    assert_eq!(h.rx.calls.get(), 1);
    assert_eq!(h.rx.requested.get(), 3);
    assert!(!h.driver.retry_incoming_write.get());
    assert!(!h.alarm.is_armed());
}

#[test]
fn zero_length_rx_keeps_buffer_and_empty_tx_retries() {
    let h = Harness::new();
    h.driver.set_rx_buffer(buffer(4));
    h.receive(0, 0);
    assert!(!h.driver.handle_incoming_write());
    assert!(h.driver.rx_buffer.is_some());
    assert_eq!(h.rx.calls.get(), 0);
    h.driver.handle_outgoing_read();
    assert!(h.driver.retry_outgoing_read.get());
    h.alarm.fire();
    assert!(h.driver.retry_outgoing_read.get());
    assert!(h.alarm.is_armed());
    h.driver.transmit_read(buffer(4), 4).unwrap();
    assert!(!h.driver.retry_outgoing_read.get());
    h.complete_tx();
}

#[test]
fn address_validity_and_interrupt_enable_disable() {
    let h = Harness::new();
    for (dynamic_valid, static_valid) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        h.driver
            .registers
            .stdby_ctrl_mode_stby_cr_device_addr
            .write(
                StbyCrDeviceAddr::DynamicAddr.val(0x22)
                    + StbyCrDeviceAddr::DynamicAddrValid.val(dynamic_valid as u32)
                    + StbyCrDeviceAddr::StaticAddr.val(0x33)
                    + StbyCrDeviceAddr::StaticAddrValid.val(static_valid as u32),
            );
        let info = h.driver.get_device_info();
        assert_eq!(info.dynamic_addr, dynamic_valid.then_some(0x22));
        assert_eq!(info.static_addr, static_valid.then_some(0x33));
        assert_eq!(info.max_read_len, MAX_READ_WRITE_SIZE);
        assert_eq!(info.max_write_len, MAX_READ_WRITE_SIZE);
    }
    h.driver.enable();
    assert!(h
        .driver
        .registers
        .tti_interrupt_enable
        .is_set(InterruptEnable::RxDescStatEn));
    assert!(h
        .driver
        .registers
        .tti_interrupt_enable
        .is_set(InterruptEnable::IbiDoneEn));
    h.driver.disable();
    assert_eq!(h.driver.registers.tti_interrupt_enable.get(), 0);
}
