// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

#[cfg(target_arch = "riscv32")]
pub mod pmp_config;

#[macro_export]
macro_rules! read_volatile_at {
    ($slice:expr, $index:expr) => {{
        let ptr = unsafe { $slice.as_ptr().add($index) };
        unsafe { core::ptr::read_volatile(ptr) }
    }};
}

#[macro_export]
macro_rules! read_volatile_slice {
    ($slice:expr, $index:expr, $buf:expr) => {{
        for (i, b) in $buf.iter_mut().enumerate() {
            let ptr = unsafe { $slice.as_ptr().add($index + i) };
            *b = unsafe { core::ptr::read_volatile(ptr) };
        }
    }};
}
