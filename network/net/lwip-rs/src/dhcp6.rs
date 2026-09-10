// Licensed under the Apache-2.0 license

//! DHCPv6 stateful client wrapper

use core::mem::MaybeUninit;

use alloc::boxed::Box;

use crate::error::{check_err, Result};
use crate::ffi;
use crate::ip::Ipv6Addr;
use crate::netif::NetIf;

/// DHCPv6 stateful client
///
/// Enables stateful DHCPv6 address acquisition (RFC 8415).
/// The client waits for a Router Advertisement with the M flag set,
/// then performs the Solicit→Advertise→Request→Reply exchange.
pub struct Dhcp6Client {
    inner: Box<ffi::dhcp6>,
    netif: *mut ffi::netif,
    started: bool,
}

impl Dhcp6Client {
    pub fn new(netif: &mut NetIf) -> Self {
        let inner = Box::new(unsafe { MaybeUninit::<ffi::dhcp6>::zeroed().assume_init() });
        Dhcp6Client {
            inner,
            netif: netif.as_mut_ptr(),
            started: false,
        }
    }

    /// Start stateful DHCPv6 on the network interface.
    ///
    /// The client will wait for a Router Advertisement with the Managed Address
    /// Configuration (M) flag set, then perform a 4-message exchange to acquire
    /// an IPv6 address.
    pub fn start(&mut self) -> Result<()> {
        unsafe {
            ffi::dhcp6_set_struct(self.netif, self.inner.as_mut());
            let err = ffi::dhcp6_enable_stateful(self.netif);
            check_err(err)?;
            self.started = true;
            Ok(())
        }
    }

    /// Stop DHCPv6 on the network interface.
    pub fn stop(&mut self) {
        if self.started {
            unsafe {
                ffi::dhcp6_disable(self.netif);
            }
            self.started = false;
        }
    }

    /// Check if a global (non-link-local) IPv6 address has been assigned.
    ///
    /// Scans address slots 1..N (slot 0 is typically link-local) for a
    /// valid, non-link-local address.
    pub fn has_address(&self, netif: &NetIf) -> bool {
        for i in 1..ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            if netif.ipv6_addr_valid(i) {
                if let Some(addr) = netif.ipv6_addr(i) {
                    if !addr.is_link_local() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Get the first valid global (non-link-local) IPv6 address assigned via DHCPv6.
    pub fn global_address(&self, netif: &NetIf) -> Option<Ipv6Addr> {
        for i in 1..ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            if netif.ipv6_addr_valid(i) {
                if let Some(addr) = netif.ipv6_addr(i) {
                    if !addr.is_link_local() {
                        return Some(addr);
                    }
                }
            }
        }
        None
    }

    /// Get the Boot File URL from DHCPv6 Option 59 (RFC 5970).
    ///
    /// Returns the raw URL string (e.g. "tftp://[fd00::1]/boot.bin") if the
    /// server provided it, or `None` if the option was not received.
    pub fn boot_file_url(&self) -> Option<&str> {
        let len = self.inner.boot_file_url_len as usize;
        if len == 0 {
            return None;
        }
        let bytes = &self.inner.boot_file_url[..len];
        // Safety: the C layer null-terminates and copies valid UTF-8 URL text
        let s = core::str::from_utf8(unsafe {
            core::slice::from_raw_parts(bytes.as_ptr() as *const u8, len)
        })
        .ok()?;
        Some(s)
    }

    /// Parse the Boot File URL (Option 59) into a server IPv6 address and file path.
    ///
    /// Expects format: `tftp://[<ipv6-addr>]/<path>`
    /// Returns `(Ipv6Addr, &str)` where the string is the file path (without leading `/`).
    pub fn parse_boot_file_url(&self) -> Option<(Ipv6Addr, &str)> {
        let url = self.boot_file_url()?;

        // Strip "tftp://" prefix
        let rest = url
            .strip_prefix("tftp://[")
            .or_else(|| url.strip_prefix("tftp://["))?;

        // Find the closing ']'
        let bracket_end = rest.find(']')?;
        let addr_str = &rest[..bracket_end];
        let after_bracket = &rest[bracket_end + 1..];

        // Parse the IPv6 address from the bracket content
        let server_addr = parse_ipv6_addr(addr_str)?;

        // The path follows: "/path" or "]/path"
        let path = after_bracket.strip_prefix('/').unwrap_or(after_bracket);

        Some((server_addr, path))
    }
}

impl Drop for Dhcp6Client {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Parse a standard IPv6 address string (e.g. "fd00:1234:5678::1") into an Ipv6Addr.
/// Supports `::` shorthand.
fn parse_ipv6_addr(s: &str) -> Option<Ipv6Addr> {
    let mut segments = [0u16; 8];

    if let Some((left, right)) = s.split_once("::") {
        let left_parts: alloc::vec::Vec<&str> = if left.is_empty() {
            alloc::vec::Vec::new()
        } else {
            left.split(':').collect()
        };
        let right_parts: alloc::vec::Vec<&str> = if right.is_empty() {
            alloc::vec::Vec::new()
        } else {
            right.split(':').collect()
        };

        if left_parts.len() + right_parts.len() > 8 {
            return None;
        }

        for (i, part) in left_parts.iter().enumerate() {
            segments[i] = u16::from_str_radix(part, 16).ok()?;
        }
        let right_start = 8 - right_parts.len();
        for (i, part) in right_parts.iter().enumerate() {
            segments[right_start + i] = u16::from_str_radix(part, 16).ok()?;
        }
    } else {
        let parts: alloc::vec::Vec<&str> = s.split(':').collect();
        if parts.len() != 8 {
            return None;
        }
        for (i, part) in parts.iter().enumerate() {
            segments[i] = u16::from_str_radix(part, 16).ok()?;
        }
    }

    Some(Ipv6Addr::new(segments))
}
