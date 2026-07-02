// Licensed under the Apache-2.0 license.
//
// Caliptra-specific virtual alarm multiplexer.
#![no_std]
//
// This is a replacement for Tock's `capsules_core::virtualizers::virtual_alarm`
// that removes the `within_range` + `next_tick_vals` optimization which fails
// on VeeR EL2 FPGA (stale timer state after disable/re-enable cycles).
//
// API-compatible drop-in replacement: same types, same trait implementations.

use core::cell::Cell;

use kernel::collections::list::{List, ListLink, ListNode};
use kernel::hil::time::{self, Alarm, Ticks, Time};
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

#[derive(Copy, Clone)]
struct TickDtReference<T: Ticks> {
    reference: T,
    dt: T,
    extended: bool,
}

impl<T: Ticks> TickDtReference<T> {
    #[inline]
    fn reference_plus_dt(&self) -> T {
        self.reference.wrapping_add(self.dt)
    }
}

/// Virtual alarm node — drop-in replacement for `capsules_core::VirtualMuxAlarm`.
pub struct VirtualMuxAlarm<'a, A: Alarm<'a>> {
    mux: &'a MuxAlarm<'a, A>,
    dt_reference: Cell<TickDtReference<A::Ticks>>,
    armed: Cell<bool>,
    next: ListLink<'a, VirtualMuxAlarm<'a, A>>,
    client: OptionalCell<&'a dyn time::AlarmClient>,
}

impl<'a, A: Alarm<'a>> ListNode<'a, VirtualMuxAlarm<'a, A>> for VirtualMuxAlarm<'a, A> {
    fn next(&self) -> &'a ListLink<VirtualMuxAlarm<'a, A>> {
        &self.next
    }
}

impl<'a, A: Alarm<'a>> VirtualMuxAlarm<'a, A> {
    pub fn new(mux_alarm: &'a MuxAlarm<'a, A>) -> VirtualMuxAlarm<'a, A> {
        let zero = A::Ticks::from(0);
        VirtualMuxAlarm {
            mux: mux_alarm,
            dt_reference: Cell::new(TickDtReference {
                reference: zero,
                dt: zero,
                extended: false,
            }),
            armed: Cell::new(false),
            next: ListLink::empty(),
            client: OptionalCell::empty(),
        }
    }

    pub fn setup(&'a self) {
        self.mux.virtual_alarms.push_head(self);
    }
}

impl<'a, A: Alarm<'a>> Time for VirtualMuxAlarm<'a, A> {
    type Frequency = A::Frequency;
    type Ticks = A::Ticks;

    fn now(&self) -> Self::Ticks {
        self.mux.alarm.now()
    }
}

impl<'a, A: Alarm<'a>> Alarm<'a> for VirtualMuxAlarm<'a, A> {
    fn set_alarm_client(&self, client: &'a dyn time::AlarmClient) {
        self.client.set(client);
    }

    fn disarm(&self) -> Result<(), ErrorCode> {
        if !self.armed.get() {
            return Ok(());
        }

        self.armed.set(false);

        let enabled = self.mux.enabled.get() - 1;
        self.mux.enabled.set(enabled);

        if enabled == 0 {
            let _ = self.mux.alarm.disarm();
        }
        Ok(())
    }

    fn is_armed(&self) -> bool {
        self.armed.get()
    }

    fn set_alarm(&self, reference: Self::Ticks, dt: Self::Ticks) {
        let enabled = self.mux.enabled.get();
        let half_max = Self::Ticks::half_max_value();

        // Split large dt into two parts to handle wraparound correctly.
        let dt_reference = if dt > half_max.wrapping_add(self.minimum_dt()) {
            TickDtReference {
                reference,
                dt: dt.wrapping_sub(half_max),
                extended: true,
            }
        } else {
            TickDtReference {
                reference,
                dt,
                extended: false,
            }
        };
        self.dt_reference.set(dt_reference);
        let dt = dt_reference.dt;

        if !self.armed.get() {
            self.mux.enabled.set(enabled + 1);
            self.armed.set(true);
        }

        // First alarm: always program hardware.
        if enabled == 0 {
            self.mux.set_alarm(reference, dt);
        } else if !self.mux.firing.get() {
            // FIX: Always reprogram the hardware timer.
            //
            // Tock's original code has a within_range + next_tick_vals guard
            // here that skips reprogramming when it believes the current alarm
            // fires sooner. This optimization fails on VeeR EL2 because:
            //   - get_alarm() returns stale values after timer disable/re-enable
            //   - next_tick_vals goes stale after alarm expiry
            //
            // By always reprogramming, we ensure our alarm's deadline is met.
            // Earlier alarms that get "overwritten" are still caught in
            // MuxAlarm::alarm()'s expired-alarm scan.
            self.mux.set_alarm(reference, dt);
        }
        // If firing is true, MuxAlarm::alarm() will rescan and reprogram
        // for the soonest alarm after all callbacks complete.
    }

    fn get_alarm(&self) -> Self::Ticks {
        let dt_reference = self.dt_reference.get();
        let extension = if dt_reference.extended {
            Self::Ticks::half_max_value()
        } else {
            Self::Ticks::from(0)
        };
        dt_reference.reference_plus_dt().wrapping_add(extension)
    }

    fn minimum_dt(&self) -> Self::Ticks {
        self.mux.alarm.minimum_dt()
    }
}

impl<'a, A: Alarm<'a>> time::AlarmClient for VirtualMuxAlarm<'a, A> {
    fn alarm(&self) {
        self.client.map(|client| client.alarm());
    }
}

/// Alarm multiplexer — drop-in replacement for `capsules_core::MuxAlarm`.
pub struct MuxAlarm<'a, A: Alarm<'a>> {
    virtual_alarms: List<'a, VirtualMuxAlarm<'a, A>>,
    enabled: Cell<usize>,
    alarm: &'a A,
    firing: Cell<bool>,
}

impl<'a, A: Alarm<'a>> MuxAlarm<'a, A> {
    pub const fn new(alarm: &'a A) -> MuxAlarm<'a, A> {
        MuxAlarm {
            virtual_alarms: List::new(),
            enabled: Cell::new(0),
            alarm,
            firing: Cell::new(false),
        }
    }

    fn set_alarm(&self, reference: A::Ticks, dt: A::Ticks) {
        self.alarm.set_alarm(reference, dt);
    }

    fn disarm(&self) {
        let _ = self.alarm.disarm();
    }
}

impl<'a, A: Alarm<'a>> time::AlarmClient for MuxAlarm<'a, A> {
    fn alarm(&self) {
        self.firing.set(true);

        // Fire all expired alarms.
        self.virtual_alarms
            .iter()
            .filter(|cur| {
                let dt_ref = cur.dt_reference.get();
                let now = self.alarm.now();
                cur.armed.get() && !now.within_range(dt_ref.reference, dt_ref.reference_plus_dt())
            })
            .for_each(|cur| {
                let dt_ref = cur.dt_reference.get();
                if dt_ref.extended {
                    // First half of extended alarm fired; set up second half.
                    cur.dt_reference.set(TickDtReference {
                        reference: dt_ref.reference_plus_dt(),
                        dt: A::Ticks::half_max_value(),
                        extended: false,
                    });
                } else {
                    // Alarm fully expired.
                    cur.armed.set(false);
                    self.enabled.set(self.enabled.get() - 1);
                    cur.alarm();
                }
            });

        self.firing.set(false);

        // Find the soonest remaining alarm and reprogram hardware.
        let now = self.alarm.now();
        let next = self
            .virtual_alarms
            .iter()
            .filter(|cur| cur.armed.get())
            .min_by_key(|cur| {
                let when = cur.dt_reference.get();
                if !now.within_range(when.reference, when.reference_plus_dt()) {
                    A::Ticks::from(0u32)
                } else {
                    when.reference_plus_dt().wrapping_sub(now)
                }
            });

        if let Some(valrm) = next {
            let dt_reference = valrm.dt_reference.get();
            self.set_alarm(dt_reference.reference, dt_reference.dt);
        } else {
            self.disarm();
        }
    }
}
