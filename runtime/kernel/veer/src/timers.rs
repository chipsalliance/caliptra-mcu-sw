// Licensed under the Apache-2.0 license.

// Based on Tock CLINT code, which is
// Copyright Tock Contributors 2022.

//! Create a timer using the VeeR EL2 Internal Timer registers.

use crate::chip::TIMER_FREQUENCY_HZ;
use core::cell::Cell;
use kernel::hil::time::{self, Alarm, ConvertTicks, Frequency, Ticks, Ticks64, Time};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::registers::register_bitfields;
use kernel::ErrorCode;
use riscv_csr::csr::ReadWriteRiscvCsr;

register_bitfields![usize,
    /// Internal Timer Counter 0
    mitcnt0 [
        counter OFFSET(0) NUMBITS(riscv::XLEN) []
    ],
    /// Internal Timer Counter 1
    mitcnt1 [
        counter OFFSET(0) NUMBITS(riscv::XLEN) []
    ],
    /// Internal Timer Bound 1
    mitb0 [
        bound OFFSET(0) NUMBITS(riscv::XLEN) []
    ],
    /// Internal Timer Bound 1
    mitb1 [
        bound OFFSET(0) NUMBITS(riscv::XLEN) []
    ],
    /// Internal Timer Control 0
    mitctl0 [
        enable OFFSET(0) NUMBITS(1) [],
        cascade OFFSET(3) NUMBITS(1) [],
    ],
    /// Internal Timer Control 1
    mitctl1 [
        enable OFFSET(0) NUMBITS(1) [],
        cascade OFFSET(3) NUMBITS(1) [],
    ],
    value [
        value OFFSET(0) NUMBITS(32) [],
    ],
];

pub struct InternalTimers<'a> {
    client: OptionalCell<&'a dyn time::AlarmClient>,
    saved: Cell<TimerInterrupts>,
    mitcnt0: ReadWriteRiscvCsr<usize, mitcnt0::Register, 0x7D2>,
    #[allow(dead_code)]
    mitcnt1: ReadWriteRiscvCsr<usize, mitcnt1::Register, 0x7D5>,
    mitb0: ReadWriteRiscvCsr<usize, mitb0::Register, 0x7D3>,
    #[allow(dead_code)]
    mitb1: ReadWriteRiscvCsr<usize, mitb0::Register, 0x7D6>,
    mitctl0: ReadWriteRiscvCsr<usize, mitctl0::Register, 0x7D4>,
    mitctl1: ReadWriteRiscvCsr<usize, mitctl1::Register, 0x7D5>,
    mcycle: ReadWriteRiscvCsr<usize, value::Register, { riscv_csr::csr::MCYCLE }>,
    mcycleh: ReadWriteRiscvCsr<usize, value::Register, { riscv_csr::csr::MCYCLEH }>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TimerInterrupts {
    None,
    Timer0,
    Timer1,
    Timer0AndTimer1,
}

impl<'a> Default for InternalTimers<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> InternalTimers<'a> {
    pub const fn new() -> Self {
        Self {
            client: OptionalCell::empty(),
            saved: Cell::new(TimerInterrupts::None),
            mitcnt0: ReadWriteRiscvCsr::new(),
            mitcnt1: ReadWriteRiscvCsr::new(),
            mitb0: ReadWriteRiscvCsr::new(),
            mitb1: ReadWriteRiscvCsr::new(),
            mitctl0: ReadWriteRiscvCsr::new(),
            mitctl1: ReadWriteRiscvCsr::new(),
            mcycle: ReadWriteRiscvCsr::new(),
            mcycleh: ReadWriteRiscvCsr::new(),
        }
    }

    pub fn disable_timers(&self) {
        self.disable_timer0();
        self.disable_timer1();
    }

    pub fn enable_timer0(&self) {
        self.mitctl0
            .read_and_set_bits(mitctl0::enable.mask << mitctl0::enable.shift);
    }

    fn disable_timer0(&self) {
        self.mitctl0
            .read_and_clear_bits(mitctl0::enable.mask << mitctl0::enable.shift);
    }

    fn disable_timer1(&self) {
        self.mitctl1
            .read_and_clear_bits(mitctl1::enable.mask << mitctl1::enable.shift);
    }

    pub fn get_saved_interrupts(&self) -> TimerInterrupts {
        self.saved.get()
    }

    pub fn save_interrupt(&self, i: u8) {
        self.saved.set(match (self.saved.get(), i) {
            (TimerInterrupts::None, 0) => TimerInterrupts::Timer0,
            (TimerInterrupts::None, 1) => TimerInterrupts::Timer1,
            (TimerInterrupts::Timer0, 0) => TimerInterrupts::Timer0,
            (TimerInterrupts::Timer0, 1) => TimerInterrupts::Timer0AndTimer1,
            (TimerInterrupts::Timer1, 0) => TimerInterrupts::Timer0AndTimer1,
            (TimerInterrupts::Timer1, 1) => TimerInterrupts::Timer1,
            (TimerInterrupts::Timer0AndTimer1, _) => TimerInterrupts::Timer0AndTimer1,
            _ => unreachable!(),
        });
    }

    pub fn service_interrupts(&self) {
        let saved = self.saved.replace(TimerInterrupts::None);
        match saved {
            TimerInterrupts::None => {}
            _ => {
                self.disable_timers();
                self.client.map(|client| {
                    client.alarm();
                });
            }
        }
    }
}

/// Platform-specific frequency for the internal timers.
#[derive(Debug)]
pub enum FreqPlatform {}
impl Frequency for FreqPlatform {
    fn frequency() -> u32 {
        // Safety: This is a constant defined in the platform.
        unsafe { TIMER_FREQUENCY_HZ }
    }
}

impl Time for InternalTimers<'_> {
    type Frequency = FreqPlatform;
    type Ticks = Ticks64;

    fn now(&self) -> Ticks64 {
        (((self.mcycleh.get() as u64) << 32) | (self.mcycle.get() as u64)).into()
    }
}

impl<'a> time::Alarm<'a> for InternalTimers<'a> {
    fn set_alarm_client(&self, client: &'a dyn time::AlarmClient) {
        self.client.set(client);
    }

    fn set_alarm(&self, reference: Self::Ticks, dt: Self::Ticks) {
        // This does not handle the 64-bit wraparound case.
        // TODO: support cascade to support larger time ranges
        let now = self.now();
        let expire = reference.wrapping_add(dt);
        let dt = if now.within_range(reference, expire) {
            expire.wrapping_sub(now)
        } else {
            // expire immediately
            1u64.into()
        };
        let val = (dt.into_u64() & 0xffff_ffff) as usize;
        // Set the start as 0 and the bound as the delta.
        self.mitcnt0.set(0);
        self.mitb0.set(val);
        self.enable_timer0();
    }

    fn get_alarm(&self) -> Self::Ticks {
        let bound = self.mitb0.read(mitb0::bound) as u64;
        let now = self.now().into_u64();
        (now + bound).into()
    }

    fn disarm(&self) -> Result<(), ErrorCode> {
        self.mitctl0.modify(mitctl0::enable::CLEAR);
        self.mitctl1.modify(mitctl1::enable::CLEAR);
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.mitctl0.read(mitctl0::enable) == 1
    }

    fn minimum_dt(&self) -> Self::Ticks {
        Ticks64::from(1u64)
    }
}

impl kernel::platform::scheduler_timer::SchedulerTimer for InternalTimers<'_> {
    fn start(&self, us: u32) {
        let now = self.now();
        let tics = self.ticks_from_us(us);
        self.set_alarm(now, tics);
    }

    fn get_remaining_us(&self) -> Option<u32> {
        // We need to convert from native ticks to us, multiplication could overflow in 32-bit
        // arithmetic. So we convert to 64-bit.
        let diff = self.get_alarm().wrapping_sub(self.now()).into_u64();

        // If next alarm is more than one second away from now, alarm must have expired.
        // Use this formulation to protect against errors when the alarm has passed.
        // 1 second was chosen because it is significantly greater than the 400ms max value allowed
        // by start(), and requires no computational overhead (e.g. using 500ms would require
        // dividing the returned ticks by 2)
        // However, if the alarm frequency is slow enough relative to the cpu frequency, it is
        // possible this will be evaluated while now() == get_alarm(), so we special case that
        // result where the alarm has fired but the subtraction has not overflowed
        if diff >= <Self as Time>::Frequency::frequency() as u64 || diff == 0 {
            None
        } else {
            let hertz = <Self as Time>::Frequency::frequency() as u64;
            Some(((diff * 1_000_000) / hertz) as u32)
        }
    }

    fn reset(&self) {
        self.disable_timers()
    }

    fn arm(&self) {
        // Arm and disarm are optional, but controlling the interrupts
        // should be re-enabled if Tock moves to a design that allows direct control of
        // interrupt enables
    }

    fn disarm(&self) {}
}
