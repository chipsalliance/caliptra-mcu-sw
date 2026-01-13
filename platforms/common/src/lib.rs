// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

#[cfg(target_arch = "riscv32")]
pub mod pmp_config;

#[cfg(target_arch = "riscv32")]
pub mod tests;

#[macro_export]
macro_rules! read_volatile_at {
    ($slice:expr, $index:expr) => {{
        assert!(
            $index < $slice.len(),
            "Index out of bounds in read_volatile_at: {} >= {}",
            $index,
            $slice.len()
        );
        let ptr = unsafe { $slice.as_ptr().add($index) };
        unsafe { core::ptr::read_volatile(ptr) }
    }};
}

#[macro_export]
macro_rules! read_volatile_slice {
    ($slice:expr, $index:expr, $buf:expr) => {{
        assert!(
            $index + $buf.len() <= $slice.len(),
            "Slice out of bounds in read_volatile_slice: {} + {} > {}",
            $index,
            $buf.len(),
            $slice.len()
        );
        for (i, b) in $buf.iter_mut().enumerate() {
            let ptr = unsafe { $slice.as_ptr().add($index + i) };
            *b = unsafe { core::ptr::read_volatile(ptr) };
        }
    }};
}
