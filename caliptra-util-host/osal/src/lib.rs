// Licensed under the Apache-2.0 license

//! OS Abstraction Layer (OSAL) for Caliptra Utility Host Library
//!
//! This layer provides a uniform interface for OS-specific functionality,
//! allowing the library to be portable across different operating systems
//! and embedded environments (including no_std).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;

pub mod error;
pub mod io;
pub mod memory;
pub mod sync;
pub mod thread;
pub mod time;

// Re-export core types
pub use error::{OsalError, OsalResult};
pub use io::{AsyncReader, AsyncWriter, Reader, Writer};
pub use memory::{Allocator, Buffer};
pub use sync::{AtomicBool, AtomicU32, Condvar, Mutex, RwLock};
pub use thread::{Thread, ThreadBuilder, ThreadHandle};
pub use time::{Duration, Instant, Timer};

/// OSAL configuration
#[derive(Debug, Clone)]
pub struct OsalConfig {
    pub max_threads: usize,
    pub default_stack_size: usize,
    pub timer_resolution_us: u64,
    pub memory_pool_size: usize,
}

impl Default for OsalConfig {
    fn default() -> Self {
        Self {
            max_threads: 16,
            default_stack_size: 64 * 1024, // 64KB
            timer_resolution_us: 1000,     // 1ms
            memory_pool_size: 1024 * 1024, // 1MB
        }
    }
}

/// Initialize the OSAL with configuration
pub fn init(config: OsalConfig) -> OsalResult<()> {
    memory::init(config.memory_pool_size)?;
    time::init(config.timer_resolution_us)?;
    thread::init(config.max_threads, config.default_stack_size)?;
    Ok(())
}

/// Cleanup OSAL resources
pub fn cleanup() -> OsalResult<()> {
    thread::cleanup()?;
    time::cleanup()?;
    memory::cleanup()?;
    Ok(())
}

/// Get OSAL version information
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Platform-specific information
pub struct PlatformInfo {
    pub os_name: &'static str,
    pub arch: &'static str,
    pub has_std: bool,
    pub has_alloc: bool,
}

pub fn platform_info() -> PlatformInfo {
    PlatformInfo {
        #[cfg(feature = "std")]
        os_name: std::env::consts::OS,
        #[cfg(not(feature = "std"))]
        os_name: "unknown",

        #[cfg(feature = "std")]
        arch: std::env::consts::ARCH,
        #[cfg(not(feature = "std"))]
        arch: "unknown",

        has_std: cfg!(feature = "std"),
        has_alloc: cfg!(feature = "alloc"),
    }
}
