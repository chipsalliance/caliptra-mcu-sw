// Licensed under the Apache-2.0 license

//! Synchronization primitives abstraction

use crate::error::{OsalError, OsalResult};

#[cfg(feature = "std")]
use std::sync as std_sync;

/// Mutex abstraction
pub struct Mutex<T> {
    #[cfg(feature = "std")]
    inner: std_sync::Mutex<T>,
    #[cfg(not(feature = "std"))]
    inner: nb::Mutex<T>,
}

impl<T> Mutex<T> {
    pub fn new(value: T) -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std_sync::Mutex::new(value),
            #[cfg(not(feature = "std"))]
            inner: nb::Mutex::new(value),
        }
    }

    #[cfg(feature = "std")]
    pub fn lock(&self) -> OsalResult<std_sync::MutexGuard<'_, T>> {
        self.inner
            .lock()
            .map_err(|_| OsalError::ResourceUnavailable)
    }

    #[cfg(not(feature = "std"))]
    pub fn try_lock(&self) -> OsalResult<&T> {
        self.inner.try_lock().map_err(|_| OsalError::WouldBlock)
    }
}

/// RwLock abstraction  
pub struct RwLock<T> {
    #[cfg(feature = "std")]
    inner: std_sync::RwLock<T>,
    #[cfg(not(feature = "std"))]
    inner: T, // Simplified for no_std
}

impl<T> RwLock<T> {
    pub fn new(value: T) -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std_sync::RwLock::new(value),
            #[cfg(not(feature = "std"))]
            inner: value,
        }
    }

    #[cfg(feature = "std")]
    pub fn read(&self) -> OsalResult<std_sync::RwLockReadGuard<'_, T>> {
        self.inner
            .read()
            .map_err(|_| OsalError::ResourceUnavailable)
    }

    #[cfg(feature = "std")]
    pub fn write(&self) -> OsalResult<std_sync::RwLockWriteGuard<'_, T>> {
        self.inner
            .write()
            .map_err(|_| OsalError::ResourceUnavailable)
    }
}

/// Condition variable abstraction
pub struct Condvar {
    #[cfg(feature = "std")]
    inner: std_sync::Condvar,
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

impl Condvar {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std_sync::Condvar::new(),
        }
    }

    #[cfg(feature = "std")]
    pub fn wait<'a, T>(
        &self,
        guard: std_sync::MutexGuard<'a, T>,
    ) -> OsalResult<std_sync::MutexGuard<'a, T>> {
        self.inner
            .wait(guard)
            .map_err(|_| OsalError::ResourceUnavailable)
    }

    #[cfg(feature = "std")]
    pub fn notify_one(&self) {
        self.inner.notify_one();
    }

    #[cfg(feature = "std")]
    pub fn notify_all(&self) {
        self.inner.notify_all();
    }
}

/// Atomic u32
pub struct AtomicU32 {
    inner: core::sync::atomic::AtomicU32,
}

impl AtomicU32 {
    pub fn new(value: u32) -> Self {
        Self {
            inner: core::sync::atomic::AtomicU32::new(value),
        }
    }

    pub fn load(&self, ordering: core::sync::atomic::Ordering) -> u32 {
        self.inner.load(ordering)
    }

    pub fn store(&self, value: u32, ordering: core::sync::atomic::Ordering) {
        self.inner.store(value, ordering);
    }

    pub fn fetch_add(&self, value: u32, ordering: core::sync::atomic::Ordering) -> u32 {
        self.inner.fetch_add(value, ordering)
    }

    pub fn compare_exchange(
        &self,
        current: u32,
        new: u32,
        success: core::sync::atomic::Ordering,
        failure: core::sync::atomic::Ordering,
    ) -> Result<u32, u32> {
        self.inner.compare_exchange(current, new, success, failure)
    }
}

/// Atomic bool
pub struct AtomicBool {
    inner: core::sync::atomic::AtomicBool,
}

impl AtomicBool {
    pub fn new(value: bool) -> Self {
        Self {
            inner: core::sync::atomic::AtomicBool::new(value),
        }
    }

    pub fn load(&self, ordering: core::sync::atomic::Ordering) -> bool {
        self.inner.load(ordering)
    }

    pub fn store(&self, value: bool, ordering: core::sync::atomic::Ordering) {
        self.inner.store(value, ordering);
    }

    pub fn compare_exchange(
        &self,
        current: bool,
        new: bool,
        success: core::sync::atomic::Ordering,
        failure: core::sync::atomic::Ordering,
    ) -> Result<bool, bool> {
        self.inner.compare_exchange(current, new, success, failure)
    }
}
