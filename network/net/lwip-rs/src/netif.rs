// Licensed under the Apache-2.0 license

//! Network interface wrapper

use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;

use crate::error::{LwipError, Result};
use crate::ffi;
use crate::ip::{Ipv4Addr, Ipv6Addr};

pub type RawStatusCallback = Box<dyn Fn(*mut ffi::netif)>;

/// Per-netif context for storing callbacks.
/// Stored in a global registry since some drivers use netif->state.
struct NetIfContext {
    netif_ptr: *mut ffi::netif,
    status_callback: Option<RawStatusCallback>,
    link_callback: Option<RawStatusCallback>,
}

impl NetIfContext {
    fn new(netif_ptr: *mut ffi::netif) -> Self {
        Self {
            netif_ptr,
            status_callback: None,
            link_callback: None,
        }
    }
}

static NETIF_CONTEXT: AtomicPtr<NetIfContext> = AtomicPtr::new(ptr::null_mut());

unsafe fn get_context(netif: *mut ffi::netif) -> Option<&'static mut NetIfContext> {
    if netif.is_null() {
        return None;
    }
    let ctx_ptr = NETIF_CONTEXT.load(Ordering::Acquire);
    if ctx_ptr.is_null() {
        return None;
    }
    let ctx = &mut *ctx_ptr;
    if ctx.netif_ptr == netif {
        Some(ctx)
    } else {
        None
    }
}

unsafe fn register_context(ctx: *mut NetIfContext) {
    NETIF_CONTEXT.store(ctx, Ordering::Release);
}

unsafe fn unregister_context(netif: *mut ffi::netif) -> Option<*mut NetIfContext> {
    let ctx_ptr = NETIF_CONTEXT.load(Ordering::Acquire);
    if !ctx_ptr.is_null() && (*ctx_ptr).netif_ptr == netif {
        NETIF_CONTEXT.store(ptr::null_mut(), Ordering::Release);
        Some(ctx_ptr)
    } else {
        None
    }
}

extern "C" fn netif_status_callback_wrapper(netif: *mut ffi::netif) {
    unsafe {
        if let Some(ctx) = get_context(netif) {
            if let Some(ref cb) = ctx.status_callback {
                cb(netif);
            }
        }
    }
}

extern "C" fn netif_link_callback_wrapper(netif: *mut ffi::netif) {
    unsafe {
        if let Some(ctx) = get_context(netif) {
            if let Some(ref cb) = ctx.link_callback {
                cb(netif);
            }
        }
    }
}

/// Network interface
pub struct NetIf {
    inner: Box<ffi::netif>,
    context: *mut NetIfContext,
}

impl NetIf {
    /// Create a new TAP network interface.
    /// Note: Only one NetIf instance is supported at a time for callbacks.
    pub fn new_tap(ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr) -> Result<Self> {
        let mut inner = Box::new(unsafe { MaybeUninit::<ffi::netif>::zeroed().assume_init() });

        let result = unsafe {
            ffi::netif_add(
                inner.as_mut(),
                ip.as_ptr(),
                netmask.as_ptr(),
                gateway.as_ptr(),
                ptr::null_mut(), // Let the driver use state for its own purposes
                Some(ffi::tapif_init),
                Some(ffi::netif_input),
            )
        };

        if result.is_null() {
            return Err(LwipError::Interface);
        }

        // Allocate context and register it globally (after netif_add succeeds)
        let context = Box::into_raw(Box::new(NetIfContext::new(inner.as_mut())));
        unsafe {
            register_context(context);
        }

        Ok(NetIf { inner, context })
    }

    pub fn set_default(&mut self) {
        unsafe {
            ffi::netif_set_default(self.inner.as_mut());
        }
    }

    pub fn set_up(&mut self) {
        unsafe {
            ffi::netif_set_up(self.inner.as_mut());
        }
    }

    pub fn set_down(&mut self) {
        unsafe {
            ffi::netif_set_down(self.inner.as_mut());
        }
    }

    pub fn set_link_up(&mut self) {
        unsafe {
            ffi::netif_set_link_up(self.inner.as_mut());
        }
    }

    pub fn set_link_down(&mut self) {
        unsafe {
            ffi::netif_set_link_down(self.inner.as_mut());
        }
    }

    pub fn is_up(&self) -> bool {
        (self.inner.flags & ffi::NETIF_FLAG_UP as u8) != 0
    }

    pub fn is_link_up(&self) -> bool {
        (self.inner.flags & ffi::NETIF_FLAG_LINK_UP as u8) != 0
    }

    pub fn ipv4_addr(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.ip_addr.u_addr.ip4) }
    }

    pub fn ipv4_netmask(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.netmask.u_addr.ip4) }
    }

    pub fn ipv4_gateway(&self) -> Ipv4Addr {
        unsafe { Ipv4Addr(self.inner.gw.u_addr.ip4) }
    }

    pub fn ipv6_addr(&self, index: usize) -> Option<Ipv6Addr> {
        if index >= ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            return None;
        }
        Some(unsafe { Ipv6Addr(self.inner.ip6_addr[index].u_addr.ip6) })
    }

    pub fn ipv6_addr_state(&self, index: usize) -> u8 {
        if index >= ffi::LWIP_IPV6_NUM_ADDRESSES as usize {
            return 0;
        }
        self.inner.ip6_addr_state[index]
    }

    pub fn ipv6_addr_valid(&self, index: usize) -> bool {
        let state = self.ipv6_addr_state(index);
        state >= ffi::IP6_ADDR_PREFERRED as u8
    }

    pub fn create_ipv6_linklocal(&mut self) {
        unsafe {
            ffi::netif_create_ip6_linklocal_address(self.inner.as_mut(), 1);
            ffi::netif_ip6_addr_set_state(self.inner.as_mut(), 0, ffi::IP6_ADDR_PREFERRED as u8);
        }
    }

    pub fn set_status_callback<F>(&mut self, callback: F)
    where
        F: Fn(*mut ffi::netif) + 'static,
    {
        unsafe {
            (*self.context).status_callback = Some(Box::new(callback));
            ffi::netif_set_status_callback(
                self.inner.as_mut(),
                Some(netif_status_callback_wrapper),
            );
        }
    }

    pub fn set_link_callback<F>(&mut self, callback: F)
    where
        F: Fn(*mut ffi::netif) + 'static,
    {
        unsafe {
            (*self.context).link_callback = Some(Box::new(callback));
            ffi::netif_set_link_callback(self.inner.as_mut(), Some(netif_link_callback_wrapper));
        }
    }

    pub fn poll(&mut self) -> i32 {
        unsafe { ffi::tapif_select(self.inner.as_mut()) }
    }

    pub fn as_ptr(&self) -> *const ffi::netif {
        self.inner.as_ref()
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::netif {
        self.inner.as_mut()
    }

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
            if let Some(ctx_ptr) = unregister_context(self.inner.as_mut()) {
                drop(Box::from_raw(ctx_ptr));
            } else if !self.context.is_null() {
                drop(Box::from_raw(self.context));
            }
        }
    }
}

// Safety: NetIf owns its inner netif and callbacks
unsafe impl Send for NetIf {}
