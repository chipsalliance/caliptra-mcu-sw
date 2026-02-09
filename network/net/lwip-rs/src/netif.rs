// Licensed under the Apache-2.0 license

//! Network interface wrapper

use core::mem::MaybeUninit;
use core::ptr;

use alloc::boxed::Box;

use crate::error::{LwipError, Result};
use crate::ffi;
use crate::ip::{Ipv4Addr, Ipv6Addr};

/// Callback type for netif status changes
pub type StatusCallback = Box<dyn Fn(&NetIf)>;

/// Network interface
pub struct NetIf {
    inner: Box<ffi::netif>,
    // Keep callbacks alive
    _status_callback: Option<StatusCallback>,
    _link_callback: Option<StatusCallback>,
}

// Global callbacks storage (needed for C callback)
static mut NETIF_STATUS_CB: Option<Box<dyn Fn(*mut ffi::netif)>> = None;
static mut NETIF_LINK_CB: Option<Box<dyn Fn(*mut ffi::netif)>> = None;

extern "C" fn netif_status_callback_wrapper(netif: *mut ffi::netif) {
    unsafe {
        if let Some(ref cb) = NETIF_STATUS_CB {
            cb(netif);
        }
    }
}

extern "C" fn netif_link_callback_wrapper(netif: *mut ffi::netif) {
    unsafe {
        if let Some(ref cb) = NETIF_LINK_CB {
            cb(netif);
        }
    }
}

impl NetIf {
    /// Create a new TAP network interface
    pub fn new_tap(ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> Result<Self> {
        let mut inner = Box::new(unsafe { MaybeUninit::<ffi::netif>::zeroed().assume_init() });

        let result = unsafe {
            ffi::netif_add(
                inner.as_mut(),
                ip.as_ptr(),
                netmask.as_ptr(),
                gateway.as_ptr(),
                ptr::null_mut(),
                Some(ffi::tapif_init),
                Some(ffi::netif_input),
            )
        };

        if result.is_null() {
            return Err(LwipError::Interface);
        }

        Ok(NetIf {
            inner,
            _status_callback: None,
            _link_callback: None,
        })
    }

    /// Set this interface as the default
    pub fn set_default(&mut self) {
        unsafe {
            ffi::netif_set_default(self.inner.as_mut());
        }
    }

    /// Bring the interface up
    pub fn set_up(&mut self) {
        unsafe {
            ffi::netif_set_up(self.inner.as_mut());
        }
    }

    /// Bring the interface down
    pub fn set_down(&mut self) {
        unsafe {
            ffi::netif_set_down(self.inner.as_mut());
        }
    }

    /// Set link up
    pub fn set_link_up(&mut self) {
        unsafe {
            ffi::netif_set_link_up(self.inner.as_mut());
        }
    }

    /// Set link down
    pub fn set_link_down(&mut self) {
        unsafe {
            ffi::netif_set_link_down(self.inner.as_mut());
        }
    }

    /// Check if interface is up
    pub fn is_up(&self) -> bool {
        (self.inner.flags & ffi::NETIF_FLAG_UP as u8) != 0
    }

    /// Check if link is up
    pub fn is_link_up(&self) -> bool {
        (self.inner.flags & ffi::NETIF_FLAG_LINK_UP as u8) != 0
    }

    /// Get IPv4 address
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.ip_addr.u_addr.ip4) }
    }

    /// Get IPv4 netmask
    pub fn ipv4_netmask(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.netmask.u_addr.ip4) }
    }

    /// Get IPv4 gateway
    pub fn ipv4_gateway(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.gw.u_addr.ip4) }
    }

    /// Get IPv6 address at index
    pub fn ipv6_addr(&self, index: usize) -> Option<Ipv6Addr> {
        if index >= ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            return None;
        }
        Some(unsafe { Ipv6Addr(self.inner.ip6_addr[index].u_addr.ip6) })
    }

    /// Get IPv6 address state
    pub fn ipv6_addr_state(&self, index: usize) -> u8 {
        if index >= ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            return 0;
        }
        self.inner.ip6_addr_state[index]
    }

    /// Check if IPv6 address at index is valid
    pub fn ipv6_addr_valid(&self, index: usize) -> bool {
        let state = self.ipv6_addr_state(index);
        state >= ffi::IP6_ADDR_PREFERRED as u8
    }

    /// Create IPv6 link-local address
    pub fn create_ipv6_linklocal(&mut self) {
        unsafe {
            ffi::netif_create_ip6_linklocal_address(self.inner.as_mut(), 1);
            ffi::netif_ip6_addr_set_state(self.inner.as_mut(), 0, ffi::IP6_ADDR_PREFERRED as u8);
        }
    }

    /// Set status callback
    pub fn set_status_callback<F>(&mut self, callback: F)
    where
        F: Fn(*mut ffi::netif) + 'static,
    {
        unsafe {
            NETIF_STATUS_CB = Some(Box::new(callback));
            ffi::netif_set_status_callback(
                self.inner.as_mut(),
                Some(netif_status_callback_wrapper),
            );
        }
    }

    /// Set link callback
    pub fn set_link_callback<F>(&mut self, callback: F)
    where
        F: Fn(*mut ffi::netif) + 'static,
    {
        unsafe {
            NETIF_LINK_CB = Some(Box::new(callback));
            ffi::netif_set_link_callback(self.inner.as_mut(), Some(netif_link_callback_wrapper));
        }
    }

    /// Poll for incoming packets (using select for non-blocking)
    pub fn poll(&mut self) -> i32 {
        unsafe { ffi::tapif_select(self.inner.as_mut()) }
    }

    /// Get raw pointer to netif (for C API interop)
    pub fn as_ptr(&self) -> *const ffi::netif {
        self.inner.as_ref()
    }

    /// Get mutable raw pointer to netif (for C API interop)
    pub fn as_mut_ptr(&mut self) -> *mut ffi::netif {
        self.inner.as_mut()
    }

    /// Get MAC address
    pub fn mac_addr(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.inner.hwaddr[..6]);
        mac
    }
}

impl Drop for NetIf {
    fn drop(&mut self) {
        unsafe {
            ffi::netif_set_down(self.inner.as_mut());
            ffi::netif_remove(self.inner.as_mut());
        }
    }
}

// Safety: NetIf owns its inner netif and callbacks
unsafe impl Send for NetIf {}
