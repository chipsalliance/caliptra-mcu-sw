// Licensed under the Apache-2.0 license

//! Bare-metal network interface for lwIP
//!
//! Provides a static network interface backed by user-supplied function pointers
//! for transmit, receive, and MAC address operations. Designed for firmware
//! running on bare-metal RISC-V without an allocator.
//!
//! # Usage
//!
//! ```ignore
//! // Initialize lwIP with system callbacks
//! lwip_rs::register_sys_callbacks(lwip_rs::BaremetalSysCallbacks {
//!     sys_now: my_time_ms,
//!     sys_init: || {},
//!     sys_arch_protect: || 0,
//!     sys_arch_unprotect: |_| {},
//!     rand: my_rand,
//! });
//! lwip_rs::init();
//!
//! // Caller owns the static storage
//! static mut NETIF: BaremetalNetIf = BaremetalNetIf::new();
//!
//! // Initialize with driver callbacks
//! let netif = unsafe { &mut NETIF };
//! netif.init(BaremetalCallbacks {
//!     transmit: my_transmit,
//!     receive: my_receive,
//!     mac_addr: my_mac_addr,
//!     rx_available: my_rx_available,
//! }).unwrap();
//!
//! // Start DHCP
//! netif.dhcp_start().unwrap();
//!
//! // Poll loop
//! loop {
//!     netif.poll();
//!     if netif.dhcp_has_address() {
//!         break;
//!     }
//! }
//! ```

use core::mem::MaybeUninit;
use core::ptr;

use crate::error::{check_err, LwipError, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;
#[cfg(feature = "baremetal-ipv6")]
use crate::ip::Ipv6Addr;

/// Maximum Ethernet frame size
const ETH_FRAME_MAX: usize = 1514;

/// Callbacks for the bare-metal network interface.
/// These function pointers bridge lwIP to the hardware Ethernet driver.
pub struct BaremetalCallbacks {
    /// Send a raw Ethernet frame. Returns true on success.
    pub transmit: fn(&[u8]) -> bool,
    /// Receive a raw Ethernet frame into the buffer. Returns number of bytes received (0 if none).
    pub receive: fn(&mut [u8]) -> usize,
    /// Get the MAC address of the interface.
    pub mac_addr: fn() -> [u8; 6],
    /// Check if there's a received frame available.
    pub rx_available: fn() -> bool,
}

/// Bare-metal network interface wrapper.
///
/// Contains all state for the lwIP netif, including the C structs, driver
/// callbacks, and protocol state. The caller must place this in a `static mut`
/// (or equivalent pinned storage) because lwIP holds raw C pointers into the
/// `netif` and `dhcp` fields.
///
/// # Example
/// ```ignore
/// static mut NETIF: BaremetalNetIf = BaremetalNetIf::new();
/// unsafe { NETIF.init(callbacks).unwrap(); }
/// ```
pub struct BaremetalNetIf {
    /// lwIP netif struct — lwIP holds raw pointers to this
    netif: MaybeUninit<ffi::netif>,
    /// lwIP DHCP state — lwIP holds raw pointers to this
    dhcp: MaybeUninit<ffi::dhcp>,
    /// Hardware driver callbacks (None until `init()` is called)
    callbacks: Option<BaremetalCallbacks>,
    /// Whether DHCP has been started
    dhcp_started: bool,
    /// Whether init() has been called successfully
    initialized: bool,
}

impl BaremetalNetIf {
    /// Create an uninitialized `BaremetalNetIf`.
    ///
    /// The caller must place this in a `static mut` (or equivalent pinned
    /// storage) and then call [`init()`](Self::init) before use.
    pub const fn new() -> Self {
        Self {
            netif: MaybeUninit::uninit(),
            dhcp: MaybeUninit::uninit(),
            callbacks: None,
            dhcp_started: false,
            initialized: false,
        }
    }

    /// Initialize the bare-metal network interface.
    ///
    /// Sets up the lwIP netif with the provided callbacks for hardware interaction.
    /// Must only be called once per instance.
    ///
    /// # Arguments
    /// * `callbacks` - Function pointers for transmit, receive, MAC address, and RX availability
    ///
    /// # Safety
    /// `self` must reside in storage that will not move (e.g. a `static mut`),
    /// because lwIP retains raw pointers into the `netif` and `dhcp` fields.
    pub fn init(&mut self, callbacks: BaremetalCallbacks) -> Result<()> {
        unsafe {
            if self.initialized {
                return Err(LwipError::AlreadyConnected);
            }

            // Store callbacks before netif_add (the init callback needs them)
            self.callbacks = Some(callbacks);

            // Zero-initialize the netif
            let netif_ptr = self.netif.as_mut_ptr();
            ptr::write_bytes(netif_ptr, 0, 1);

            // Set up IP addresses (all zeros for DHCP)
            let ip = ffi::ip4_addr_t { addr: 0 };
            let netmask = ffi::ip4_addr_t { addr: 0 };
            let gateway = ffi::ip4_addr_t { addr: 0 };

            // Pass `self` as the lwIP state pointer so C callbacks can recover it
            let state = (self as *mut Self).cast::<core::ffi::c_void>();

            let result = ffi::netif_add(
                netif_ptr,
                &ip,
                &netmask,
                &gateway,
                state,
                Some(baremetal_netif_init),
                Some(ffi::netif_input),
            );

            if result.is_null() {
                self.callbacks = None;
                return Err(LwipError::Interface);
            }

            ffi::netif_set_default(netif_ptr);
            ffi::netif_set_up(netif_ptr);
            ffi::netif_set_link_up(netif_ptr);

            // IPv6: create link-local address from MAC and mark it PREFERRED
            #[cfg(feature = "baremetal-ipv6")]
            {
                ffi::netif_create_ip6_linklocal_address(netif_ptr, 1);
                // Skip DAD (Duplicate Address Detection) — set directly to PREFERRED
                // IP6_ADDR_PREFERRED = 0x30
                ffi::netif_ip6_addr_set_state(netif_ptr, 0, 0x30);
            }

            self.initialized = true;
            Ok(())
        }
    }

    /// Start the DHCP client on this interface.
    pub fn dhcp_start(&mut self) -> Result<()> {
        unsafe {
            if self.dhcp_started {
                return Ok(());
            }

            let netif_ptr = self.netif.as_mut_ptr();
            let dhcp_ptr = self.dhcp.as_mut_ptr();
            ptr::write_bytes(dhcp_ptr, 0, 1);

            ffi::dhcp_set_struct(netif_ptr, dhcp_ptr);
            let err = ffi::dhcp_start(netif_ptr);
            check_err(err)?;
            self.dhcp_started = true;
            Ok(())
        }
    }

    /// Check if DHCP has assigned an IP address.
    pub fn dhcp_has_address(&self) -> bool {
        unsafe {
            if !self.dhcp_started {
                return false;
            }
            ffi::dhcp_supplied_address(self.netif.as_ptr() as *mut _) != 0
        }
    }

    /// Get the IP address assigned by DHCP.
    pub fn dhcp_offered_ip(&self) -> Ipv4Addr {
        unsafe {
            let dhcp_ptr = self.dhcp.as_ptr();
            // dhcp struct always stores offered addresses as ip4_addr_t
            Ipv4Addr((*dhcp_ptr).offered_ip_addr)
        }
    }

    /// Get the netmask assigned by DHCP.
    pub fn dhcp_offered_netmask(&self) -> Ipv4Addr {
        unsafe {
            let dhcp_ptr = self.dhcp.as_ptr();
            Ipv4Addr((*dhcp_ptr).offered_sn_mask)
        }
    }

    /// Get the gateway assigned by DHCP.
    pub fn dhcp_offered_gateway(&self) -> Ipv4Addr {
        unsafe {
            let dhcp_ptr = self.dhcp.as_ptr();
            Ipv4Addr((*dhcp_ptr).offered_gw_addr)
        }
    }

    /// Get the DHCP server IP address.
    pub fn dhcp_server_ip(&self) -> Ipv4Addr {
        unsafe {
            let dhcp_ptr = self.dhcp.as_ptr();
            Ipv4Addr((*dhcp_ptr).offered_si_addr)
        }
    }

    /// Get the current IPv4 address of the interface.
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        unsafe {
            let netif_ptr = self.netif.as_ptr();
            // In IPv4-only mode (LWIP_IPV6=0), ip_addr is ip4_addr_t directly
            // In dual-stack mode (LWIP_IPV6=1), ip_addr is ip_addr_t (union)
            #[cfg(not(feature = "baremetal-ipv6"))]
            {
                Ipv4Addr((*netif_ptr).ip_addr)
            }
            #[cfg(feature = "baremetal-ipv6")]
            {
                Ipv4Addr((*netif_ptr).ip_addr.u_addr.ip4)
            }
        }
    }

    /// Poll the network interface: process received packets and lwIP timeouts.
    ///
    /// This should be called regularly in the main loop. It:
    /// 1. Checks for received Ethernet frames and feeds them into lwIP
    /// 2. Processes lwIP timeouts (DHCP retransmissions, ARP, etc.)
    pub fn poll(&mut self) {
        unsafe {
            let netif_ptr = self.netif.as_mut_ptr();
            let callbacks = self.callbacks.as_ref().unwrap();

            // Process received packets
            while (callbacks.rx_available)() {
                let mut buf = [0u8; ETH_FRAME_MAX];
                let len = (callbacks.receive)(&mut buf);
                if len == 0 {
                    break;
                }

                // Allocate a pbuf and copy the received frame into it
                let p = ffi::pbuf_alloc(
                    ffi::pbuf_layer_PBUF_RAW,
                    len as u16,
                    ffi::pbuf_type_PBUF_POOL,
                );
                if p.is_null() {
                    // Out of pbufs, drop the frame
                    continue;
                }

                // Copy data into the pbuf chain
                let mut offset = 0usize;
                let mut q = p;
                while !q.is_null() && offset < len {
                    let chunk_len = core::cmp::min((*q).len as usize, len - offset);
                    core::ptr::copy_nonoverlapping(
                        buf.as_ptr().add(offset),
                        (*q).payload as *mut u8,
                        chunk_len,
                    );
                    offset += chunk_len;
                    q = (*q).next;
                }

                // Feed the packet into lwIP's input processing
                let err = ((*netif_ptr).input.unwrap())(p, netif_ptr);
                if err != 0 {
                    ffi::pbuf_free(p);
                }
            }

            // Process lwIP timers (DHCP retransmissions, ARP aging, etc.)
            ffi::sys_check_timeouts();
        }
    }

    /// Stop DHCP and clean up.
    pub fn shutdown(&mut self) {
        unsafe {
            #[cfg(feature = "baremetal-ipv6")]
            {
                ffi::dhcp6_disable(self.netif.as_mut_ptr());
            }
            if self.dhcp_started {
                ffi::dhcp_stop(self.netif.as_mut_ptr());
                self.dhcp_started = false;
            }
            ffi::netif_set_down(self.netif.as_mut_ptr());
            ffi::netif_remove(self.netif.as_mut_ptr());
            self.callbacks = None;
            self.initialized = false;
        }
    }

    // ========================================================================
    // IPv6 / SLAAC + stateless DHCPv6 methods
    // ========================================================================

    /// Enable stateless DHCPv6 on this interface.
    ///
    /// Stateless DHCPv6 obtains configuration information (e.g., DNS servers)
    /// from a DHCPv6 server, but does NOT assign addresses. Addresses are
    /// obtained via SLAAC (Stateless Address Autoconfiguration) from Router
    /// Advertisements.
    ///
    /// The link-local address must be configured first (done automatically in init).
    #[cfg(feature = "baremetal-ipv6")]
    pub fn dhcp6_enable_stateless(&mut self) -> Result<()> {
        unsafe {
            let netif_ptr = self.netif.as_mut_ptr();
            let err = ffi::dhcp6_enable_stateless(netif_ptr);
            check_err(err)?;
            Ok(())
        }
    }

    /// Check if the interface has a valid global IPv6 address (assigned via SLAAC).
    ///
    /// Returns true if any IPv6 address at index >= 1 (global scope) has PREFERRED state.
    #[cfg(feature = "baremetal-ipv6")]
    pub fn has_global_ipv6_address(&self) -> bool {
        unsafe {
            let netif_ptr = self.netif.as_ptr();
            // LWIP_IPV6_NUM_ADDRESSES = 3: index 0 = link-local, 1-2 = global
            for i in 1..3u8 {
                let state = (*netif_ptr).ip6_addr_state[i as usize];
                // IP6_ADDR_PREFERRED = 0x30
                if state >= 0x30 {
                    return true;
                }
            }
            false
        }
    }

    /// Get the link-local IPv6 address (index 0).
    #[cfg(feature = "baremetal-ipv6")]
    pub fn link_local_ipv6_addr(&self) -> Ipv6Addr {
        unsafe {
            let netif_ptr = self.netif.as_ptr();
            Ipv6Addr((*netif_ptr).ip6_addr[0].u_addr.ip6)
        }
    }

    /// Get a global IPv6 address.
    ///
    /// Returns the first valid global IPv6 address, or the address at index 1 if none
    /// have reached PREFERRED state yet.
    #[cfg(feature = "baremetal-ipv6")]
    pub fn global_ipv6_addr(&self) -> Ipv6Addr {
        unsafe {
            let netif_ptr = self.netif.as_ptr();
            for i in 1..3usize {
                let state = (*netif_ptr).ip6_addr_state[i];
                if state >= 0x30 {
                    return Ipv6Addr((*netif_ptr).ip6_addr[i].u_addr.ip6);
                }
            }
            // Fallback: return index 1 even if not yet valid
            Ipv6Addr((*netif_ptr).ip6_addr[1].u_addr.ip6)
        }
    }
}

// ============================================================================
// lwIP C callbacks (extern "C" functions called by lwIP)
// ============================================================================

/// lwIP netif initialization callback.
/// Sets up the netif hardware parameters (MAC, MTU, flags, output functions).
unsafe extern "C" fn baremetal_netif_init(netif: *mut ffi::netif) -> ffi::err_t {
    let instance = &*((*netif).state as *const BaremetalNetIf);
    let callbacks = instance.callbacks.as_ref().unwrap();
    let mac = (callbacks.mac_addr)();

    // Set interface name
    (*netif).name[0] = b'e';
    (*netif).name[1] = b'n';

    // Set output function for IP packets (handles ARP resolution)
    (*netif).output = Some(ffi::etharp_output);

    // Set IPv6 output function for Ethernet (handles ND resolution)
    #[cfg(feature = "baremetal-ipv6")]
    {
        (*netif).output_ip6 = Some(ffi::ethip6_output);
    }

    // Set linkoutput function for raw Ethernet frames
    (*netif).linkoutput = Some(baremetal_linkoutput);

    // Set MTU
    (*netif).mtu = 1500;

    // Set hardware address
    (*netif).hwaddr_len = 6;
    (*netif).hwaddr[0] = mac[0];
    (*netif).hwaddr[1] = mac[1];
    (*netif).hwaddr[2] = mac[2];
    (*netif).hwaddr[3] = mac[3];
    (*netif).hwaddr[4] = mac[4];
    (*netif).hwaddr[5] = mac[5];

    // Set flags: broadcast + etharp + ethernet + link_up
    (*netif).flags = (ffi::NETIF_FLAG_BROADCAST
        | ffi::NETIF_FLAG_ETHARP
        | ffi::NETIF_FLAG_ETHERNET
        | ffi::NETIF_FLAG_LINK_UP) as u8;

    ffi::err_enum_t_ERR_OK as ffi::err_t
}

/// lwIP linkoutput callback - sends a raw Ethernet frame.
/// Called by lwIP when it needs to send a frame (ARP, DHCP, etc.).
unsafe extern "C" fn baremetal_linkoutput(
    netif: *mut ffi::netif,
    p: *mut ffi::pbuf,
) -> ffi::err_t {
    if p.is_null() {
        return ffi::err_enum_t_ERR_ARG as ffi::err_t;
    }

    let instance = &*((*netif).state as *const BaremetalNetIf);
    let callbacks = instance.callbacks.as_ref().unwrap();

    // Calculate total frame length
    let total_len = (*p).tot_len as usize;
    if total_len > ETH_FRAME_MAX {
        return ffi::err_enum_t_ERR_BUF as ffi::err_t;
    }

    // Copy pbuf chain into a contiguous buffer
    let mut buf = [0u8; ETH_FRAME_MAX];
    let mut offset = 0usize;
    let mut q = p;
    while !q.is_null() {
        let chunk_len = (*q).len as usize;
        if offset + chunk_len > ETH_FRAME_MAX {
            break;
        }
        core::ptr::copy_nonoverlapping(
            (*q).payload as *const u8,
            buf.as_mut_ptr().add(offset),
            chunk_len,
        );
        offset += chunk_len;
        q = (*q).next;
    }

    // Send via the hardware driver
    if (callbacks.transmit)(&buf[..total_len]) {
        ffi::err_enum_t_ERR_OK as ffi::err_t
    } else {
        ffi::err_enum_t_ERR_IF as ffi::err_t
    }
}
