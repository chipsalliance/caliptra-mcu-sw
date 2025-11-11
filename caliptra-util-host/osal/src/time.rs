// Licensed under the Apache-2.0 license

//! Time and timer abstraction

use crate::error::OsalResult;

#[cfg(feature = "std")]
use std::time as std_time;

/// Duration type that works in no_std
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    nanos: u64,
}

impl Duration {
    pub const fn new(secs: u64, nanos: u32) -> Self {
        Self {
            nanos: secs * 1_000_000_000 + nanos as u64,
        }
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self::new(secs, 0)
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self::new(millis / 1000, ((millis % 1000) * 1_000_000) as u32)
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self::new(micros / 1_000_000, ((micros % 1_000_000) * 1000) as u32)
    }

    pub const fn from_nanos(nanos: u64) -> Self {
        Self::new(nanos / 1_000_000_000, (nanos % 1_000_000_000) as u32)
    }

    pub const fn as_secs(&self) -> u64 {
        self.nanos / 1_000_000_000
    }

    pub const fn as_millis(&self) -> u64 {
        self.nanos / 1_000_000
    }

    pub const fn as_micros(&self) -> u64 {
        self.nanos / 1000
    }

    pub const fn as_nanos(&self) -> u64 {
        self.nanos
    }

    pub const fn subsec_nanos(&self) -> u32 {
        (self.nanos % 1_000_000_000) as u32
    }

    pub const fn subsec_millis(&self) -> u32 {
        (self.nanos % 1_000_000_000 / 1_000_000) as u32
    }

    pub const fn subsec_micros(&self) -> u32 {
        (self.nanos % 1_000_000_000 / 1000) as u32
    }
}

#[cfg(feature = "std")]
impl From<std_time::Duration> for Duration {
    fn from(std_dur: std_time::Duration) -> Self {
        Self::new(std_dur.as_secs(), std_dur.subsec_nanos())
    }
}

#[cfg(feature = "std")]
impl From<Duration> for std_time::Duration {
    fn from(dur: Duration) -> Self {
        std_time::Duration::new(dur.as_secs(), dur.subsec_nanos())
    }
}

/// Instant type that works in no_std
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    nanos: u64,
}

impl Instant {
    /// Get current time
    pub fn now() -> Self {
        #[cfg(feature = "std")]
        {
            let std_instant = std_time::SystemTime::now()
                .duration_since(std_time::UNIX_EPOCH)
                .unwrap_or_default();
            Self {
                nanos: std_instant.as_nanos() as u64,
            }
        }

        #[cfg(not(feature = "std"))]
        {
            // In no_std, you would need to implement platform-specific time reading
            // For now, return a placeholder
            Self { nanos: 0 }
        }
    }

    /// Get duration since another instant
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Get elapsed time since this instant
    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    /// Add duration to instant
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.nanos
            .checked_add(duration.as_nanos())
            .map(|nanos| Self { nanos })
    }

    /// Subtract duration from instant
    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        self.nanos
            .checked_sub(duration.as_nanos())
            .map(|nanos| Self { nanos })
    }
}

/// Timer trait for scheduling callbacks
pub trait Timer: Send + Sync {
    /// Schedule a one-shot timer
    fn schedule_once(
        &self,
        duration: Duration,
        callback: Box<dyn FnOnce() + Send>,
    ) -> OsalResult<TimerHandle>;

    /// Schedule a repeating timer
    fn schedule_repeat(
        &self,
        duration: Duration,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> OsalResult<TimerHandle>;

    /// Cancel a timer
    fn cancel(&self, handle: TimerHandle) -> OsalResult<()>;
}

/// Handle to a scheduled timer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerHandle(pub u32);

/// Standard library timer implementation
#[cfg(feature = "std")]
pub struct StdTimer {
    next_handle: core::sync::atomic::AtomicU32,
}

#[cfg(feature = "std")]
impl Default for StdTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl StdTimer {
    pub fn new() -> Self {
        Self {
            next_handle: core::sync::atomic::AtomicU32::new(1),
        }
    }

    fn next_handle(&self) -> TimerHandle {
        let handle = self
            .next_handle
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        TimerHandle(handle)
    }
}

#[cfg(feature = "std")]
impl Timer for StdTimer {
    fn schedule_once(
        &self,
        duration: Duration,
        callback: Box<dyn FnOnce() + Send>,
    ) -> OsalResult<TimerHandle> {
        let handle = self.next_handle();
        let std_duration: std_time::Duration = duration.into();

        std::thread::spawn(move || {
            std::thread::sleep(std_duration);
            callback();
        });

        Ok(handle)
    }

    fn schedule_repeat(
        &self,
        duration: Duration,
        callback: Box<dyn Fn() + Send + Sync>,
    ) -> OsalResult<TimerHandle> {
        let handle = self.next_handle();
        let std_duration: std_time::Duration = duration.into();

        std::thread::spawn(move || loop {
            std::thread::sleep(std_duration);
            callback();
        });

        Ok(handle)
    }

    fn cancel(&self, _handle: TimerHandle) -> OsalResult<()> {
        // For simplicity, we don't support cancellation in this implementation
        // A real implementation would track timer threads and signal them to stop
        Ok(())
    }
}

static mut TIMER: Option<&'static dyn Timer> = None;

/// Initialize time subsystem
pub fn init(_resolution_us: u64) -> OsalResult<()> {
    #[cfg(feature = "std")]
    {
        static STD_TIMER: StdTimer = StdTimer {
            next_handle: core::sync::atomic::AtomicU32::new(1),
        };
        unsafe {
            TIMER = Some(&STD_TIMER as &(dyn Timer));
        }
    }

    #[cfg(not(feature = "std"))]
    {
        use crate::error::OsalError;
        // In no_std, you would initialize your platform-specific timer here
        return Err(OsalError::ResourceUnavailable);
    }

    Ok(())
}

/// Cleanup time subsystem
pub fn cleanup() -> OsalResult<()> {
    unsafe {
        TIMER = None;
    }
    Ok(())
}

/// Get the current timer
fn get_timer() -> &'static dyn Timer {
    unsafe { TIMER.expect("Time subsystem not initialized") }
}

/// Sleep for specified duration
pub fn sleep(duration: Duration) -> OsalResult<()> {
    #[cfg(feature = "std")]
    {
        let std_duration: std_time::Duration = duration.into();
        std::thread::sleep(std_duration);
        Ok(())
    }

    #[cfg(not(feature = "std"))]
    {
        use crate::error::OsalError;
        // In no_std, you would implement platform-specific sleep
        Err(OsalError::ResourceUnavailable)
    }
}

/// Schedule a one-shot timer
pub fn schedule_once<F>(duration: Duration, callback: F) -> OsalResult<TimerHandle>
where
    F: FnOnce() + Send + 'static,
{
    get_timer().schedule_once(duration, Box::new(callback))
}

/// Schedule a repeating timer
pub fn schedule_repeat<F>(duration: Duration, callback: F) -> OsalResult<TimerHandle>
where
    F: Fn() + Send + Sync + 'static,
{
    get_timer().schedule_repeat(duration, Box::new(callback))
}

/// Cancel a timer
pub fn cancel_timer(handle: TimerHandle) -> OsalResult<()> {
    get_timer().cancel(handle)
}
