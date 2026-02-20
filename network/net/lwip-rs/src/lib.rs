// Licensed under the Apache-2.0 license

//! lwip-rs: Rust bindings for lwIP (Lightweight IP stack)
//!
//! Provides safe Rust wrappers for network stack functionality
//! including DHCP and TFTP.
//!
//! ## Features
//!
//! - `alloc` - Enable heap-allocated wrappers (NetIf, DhcpClient)
//! - `baremetal` - Enable bare-metal port (no OS, static storage, custom netif)
//! - `ipv4`, `ipv6` - IP version support
//! - `dhcp`, `dhcp6` - DHCP client support
//! - `tftp` - TFTP client support

#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::ffi::CStr;
use core::ffi::{c_char, c_int, c_void};

pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(clippy::all)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod error;
pub mod ip;

#[cfg(all(feature = "alloc", not(feature = "baremetal")))]
pub mod netif;

#[cfg(all(feature = "alloc", not(feature = "baremetal")))]
pub mod dhcp;

#[cfg(feature = "baremetal")]
pub mod netif_baremetal;

#[cfg(feature = "tftp")]
pub mod tftp;

#[cfg(feature = "baremetal-tftp")]
pub mod tftp_baremetal;

pub mod sys;

pub use error::LwipError;
pub use ip::Ipv4Addr;

#[cfg(any(not(feature = "baremetal"), feature = "baremetal-ipv6"))]
pub use ip::Ipv6Addr;

#[cfg(all(feature = "alloc", not(feature = "baremetal")))]
pub use netif::NetIf;

#[cfg(all(feature = "alloc", not(feature = "baremetal")))]
pub use dhcp::DhcpClient;

#[cfg(feature = "baremetal")]
pub use netif_baremetal::BaremetalNetIf;

#[cfg(feature = "tftp")]
pub use tftp::{TftpClient, TftpStorageOps};

#[cfg(feature = "baremetal-tftp")]
pub use tftp_baremetal::{BaremetalTftpClient, BaremetalTftpOps};

/// Initialize the lwIP stack. Must be called before any other lwIP functions.
pub fn init() {
    unsafe {
        ffi::lwip_init();
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn lwip_platform_assert(msg: *const c_char, line: c_int, file: *const c_char) {
    let msg_str = if msg.is_null() {
        "unknown"
    } else {
        unsafe { CStr::from_ptr(msg).to_str().unwrap_or("invalid utf8") }
    };
    let file_str = if file.is_null() {
        "unknown"
    } else {
        unsafe { CStr::from_ptr(file).to_str().unwrap_or("invalid utf8") }
    };
    panic!(
        "lwIP assertion failed: {} at {}:{}",
        msg_str, file_str, line
    );
}

// ============================================================================
// Bare-metal port: provide sys_now, sys_init, sys_arch_protect/unprotect,
// and lwip_baremetal_rand as extern "C" functions that lwIP C code calls.
//
// All callbacks are registered by the upper-layer application via
// `register_sys_callbacks()` before calling `init()`.
// ============================================================================

#[cfg(feature = "baremetal")]
mod baremetal_sys {
    /// Callbacks for lwIP bare-metal system functions.
    ///
    /// The upper-layer application provides these function pointers to control
    /// how lwIP interacts with the platform (timekeeping, critical sections,
    /// randomness, etc.).
    ///
    /// Must be registered via [`register_sys_callbacks()`](super::register_sys_callbacks)
    /// before calling [`init()`](super::init).
    pub struct BaremetalSysCallbacks {
        /// Return the current system time in milliseconds.
        ///
        /// lwIP uses this for timeout management (DHCP retransmissions, ARP,
        /// TCP timers, etc.). The value should be monotonically increasing.
        pub sys_now: fn() -> u32,

        /// System initialization hook (called once during `lwip_init()`).
        ///
        /// Typically a no-op for bare-metal `NO_SYS=1` configurations.
        pub sys_init: fn(),

        /// Enter a critical section. Returns an opaque value passed to `sys_arch_unprotect`.
        ///
        /// On single-core bare-metal without interrupts, this can be a no-op
        /// returning 0. On platforms with interrupts, this should disable them.
        pub sys_arch_protect: fn() -> u32,

        /// Exit a critical section. Receives the value returned by `sys_arch_protect`.
        pub sys_arch_unprotect: fn(u32),

        /// Return a random `u32` value.
        ///
        /// Used by lwIP for port randomization, DHCP transaction IDs, etc.
        pub rand: fn() -> u32,
    }

    /// Stored callbacks. `None` until `register_sys_callbacks()` is called.
    static mut CALLBACKS: Option<BaremetalSysCallbacks> = None;

    /// Register the bare-metal system callbacks.
    ///
    /// Must be called before `lwip_rs::init()` or any lwIP operations.
    pub fn register_sys_callbacks(callbacks: BaremetalSysCallbacks) {
        unsafe {
            CALLBACKS = Some(callbacks);
        }
    }

    // ========================================================================
    // extern "C" trampolines — called by lwIP C code, delegate to callbacks
    // ========================================================================

    #[no_mangle]
    pub extern "C" fn sys_now() -> u32 {
        unsafe {
            match CALLBACKS {
                Some(ref cb) => (cb.sys_now)(),
                None => 0,
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn sys_init() {
        unsafe {
            if let Some(ref cb) = CALLBACKS {
                (cb.sys_init)();
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn sys_arch_protect() -> u32 {
        unsafe {
            match CALLBACKS {
                Some(ref cb) => (cb.sys_arch_protect)(),
                None => 0,
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn sys_arch_unprotect(val: u32) {
        unsafe {
            if let Some(ref cb) = CALLBACKS {
                (cb.sys_arch_unprotect)(val);
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn lwip_baremetal_rand() -> u32 {
        unsafe {
            match CALLBACKS {
                Some(ref cb) => (cb.rand)(),
                None => 0,
            }
        }
    }
}

#[cfg(feature = "baremetal")]
pub use baremetal_sys::{register_sys_callbacks, BaremetalSysCallbacks};
