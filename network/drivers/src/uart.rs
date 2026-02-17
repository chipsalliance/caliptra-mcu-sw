/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    UART driver and print utilities for Network Coprocessor.

    Provides basic UART output functionality and print macros for
    no_std environments.

--*/

use network_config::DEFAULT_NETWORK_MEMORY_MAP;

/// UART TX data register address for Network Coprocessor
/// This is UART offset + TX register offset (0x41)
const UART_TX_ADDR: u32 = DEFAULT_NETWORK_MEMORY_MAP.uart_offset + 0x41;

/// Print a single character to the UART
#[inline(never)]
pub fn print_char(c: u8) {
    unsafe {
        core::ptr::write_volatile(UART_TX_ADDR as *mut u8, c);
    }
}

/// Print a string to the UART
pub fn print_str(s: &str) {
    for b in s.bytes() {
        print_char(b);
    }
}

/// UART writer that implements core::fmt::Write
pub struct UartWriter;

impl core::fmt::Write for UartWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print_str(s);
        Ok(())
    }
}

/// Print macro - supports format arguments like std::print!
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::uart::UartWriter, $($arg)*);
    }};
}

/// Println macro - supports format arguments like std::println!
#[macro_export]
macro_rules! println {
    () => {
        $crate::uart::print_str("\r\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::uart::UartWriter, $($arg)*);
        $crate::uart::print_str("\r\n");
    }};
}

/// Wrapper for displaying an IP address (4 bytes)
pub struct IpAddr<'a>(pub &'a [u8; 4]);

impl core::fmt::Display for IpAddr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// Wrapper for displaying a MAC address (6 bytes)
pub struct MacAddr<'a>(pub &'a [u8; 6]);

impl core::fmt::Display for MacAddr<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
