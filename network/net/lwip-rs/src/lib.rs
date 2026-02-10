// Licensed under the Apache-2.0 license

//! lwip-rs: Rust bindings for lwIP (Lightweight IP stack)
//!
//! Provides safe Rust wrappers for network stack functionality
//! including DHCP and TFTP.

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

#[cfg(feature = "alloc")]
pub mod netif;

#[cfg(feature = "alloc")]
pub mod dhcp;

#[cfg(feature = "tftp")]
pub mod tftp;

pub mod sys;

pub use error::LwipError;
pub use ip::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "alloc")]
pub use netif::NetIf;

#[cfg(feature = "alloc")]
pub use dhcp::DhcpClient;

#[cfg(feature = "tftp")]
pub use tftp::{TftpClient, TftpStorageOps};

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
