// Licensed under the Apache-2.0 license

//! IP address types

use core::fmt;

use crate::ffi;

/// IPv4 address wrapper
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Ipv4Addr(pub(crate) ffi::ip4_addr_t);

impl Ipv4Addr {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        let addr = ((d as u32) << 24) | ((c as u32) << 16) | ((b as u32) << 8) | (a as u32);
        Ipv4Addr(ffi::ip4_addr_t { addr })
    }

    pub fn any() -> Self {
        Ipv4Addr(ffi::ip4_addr_t { addr: 0 })
    }

    pub fn is_any(&self) -> bool {
        self.0.addr == 0
    }

    pub fn raw(&self) -> u32 {
        self.0.addr
    }

    pub fn as_ptr(&self) -> *const ffi::ip4_addr_t {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::ip4_addr_t {
        &mut self.0
    }

    pub fn octets(&self) -> [u8; 4] {
        self.0.addr.to_le_bytes()
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.octets();
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv4Addr({})", self)
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(octets: [u8; 4]) -> Self {
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
    }
}

/// IPv6 address wrapper
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct Ipv6Addr(pub(crate) ffi::ip6_addr_t);

impl Ipv6Addr {
    pub fn new(segments: [u16; 8]) -> Self {
        let mut addr = ffi::ip6_addr_t::default();
        addr.addr[0] = ((segments[1] as u32) << 16) | (segments[0] as u32);
        addr.addr[1] = ((segments[3] as u32) << 16) | (segments[2] as u32);
        addr.addr[2] = ((segments[5] as u32) << 16) | (segments[4] as u32);
        addr.addr[3] = ((segments[7] as u32) << 16) | (segments[6] as u32);
        Ipv6Addr(addr)
    }

    pub fn any() -> Self {
        Ipv6Addr(ffi::ip6_addr_t::default())
    }

    pub fn is_link_local(&self) -> bool {
        // Link-local: fe80::/10
        (self.0.addr[0] & 0xc0ff) == 0x80fe
    }

    pub fn as_ptr(&self) -> *const ffi::ip6_addr_t {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::ip6_addr_t {
        &mut self.0
    }

    pub fn segments(&self) -> [u16; 8] {
        let mut segments = [0u16; 8];
        for i in 0..4 {
            segments[i * 2] = (self.0.addr[i] & 0xffff) as u16;
            segments[i * 2 + 1] = ((self.0.addr[i] >> 16) & 0xffff) as u16;
        }
        segments
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.segments();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]
        )
    }
}

impl fmt::Debug for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv6Addr({})", self)
    }
}
