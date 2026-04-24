// Licensed under the Apache-2.0 license

//! Bare-metal network interface for lwIP.
//!
//! Provides a static network interface backed by user-supplied function pointers
//! for transmit, receive, and MAC address operations. Designed for `no_std`
//! firmware on bare-metal RISC-V.

use core::mem::MaybeUninit;
use core::ptr;

use crate::error::{check_err, LwipError, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;
#[cfg(feature = "baremetal-ipv6")]
use crate::ip::Ipv6Addr;

/// Maximum Ethernet frame size
const ETH_FRAME_MAX: usize = 1514;

/// Callbacks bridging lwIP to the hardware Ethernet driver.
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
/// Must be placed in a `static mut` (or equivalent pinned storage) because
/// lwIP holds raw C pointers into the `netif` and `dhcp` fields.
pub struct BaremetalNetIf {
    /// lwIP netif struct — lwIP holds raw pointers to this
    netif: MaybeUninit<ffi::netif>,
    /// lwIP DHCP state — lwIP holds raw pointers to this
    dhcp: MaybeUninit<ffi::dhcp>,
    /// lwIP DHCPv6 state — lwIP holds raw pointers to this
    #[cfg(feature = "baremetal-dhcp6-stateful")]
    dhcp6: MaybeUninit<ffi::dhcp6>,
    /// Hardware driver callbacks (None until `init()` is called)
    callbacks: Option<BaremetalCallbacks>,
    /// Whether DHCP has been started
    dhcp_started: bool,
    /// Whether init() has been called successfully
    initialized: bool,
}

impl Default for BaremetalNetIf {
    fn default() -> Self {
        Self::new()
    }
}

impl BaremetalNetIf {
    /// Create an uninitialized `BaremetalNetIf`.
    pub const fn new() -> Self {
        Self {
            netif: MaybeUninit::uninit(),
            dhcp: MaybeUninit::uninit(),
            #[cfg(feature = "baremetal-dhcp6-stateful")]
            dhcp6: MaybeUninit::uninit(),
            callbacks: None,
            dhcp_started: false,
            initialized: false,
        }
    }

    /// Initialize the network interface with the provided hardware callbacks.
    ///
    /// Must only be called once. `self` must reside in pinned storage
    /// (e.g. `static mut`) because lwIP retains raw pointers into it.
    pub fn init(&mut self, callbacks: BaremetalCallbacks) -> Result<()> {
        unsafe {
            if self.initialized {
                return Err(LwipError::AlreadyConnected);
            }

            // Store callbacks before netif_add (the init callback needs them)
            self.callbacks = Some(callbacks);

            let netif_ptr = self.netif.as_mut_ptr();
            ptr::write_bytes(netif_ptr, 0, 1);

            let ip = ffi::ip4_addr_t { addr: 0 };
            let netmask = ffi::ip4_addr_t { addr: 0 };
            let gateway = ffi::ip4_addr_t { addr: 0 };

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

            // IPv6: create link-local address and skip DAD
            #[cfg(feature = "baremetal-ipv6")]
            {
                ffi::netif_create_ip6_linklocal_address(netif_ptr, 1);
                ffi::netif_ip6_addr_set_state(netif_ptr, 0, 0x30); // IP6_ADDR_PREFERRED
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

    /// Get the boot file name from the DHCP response (requires `LWIP_DHCP_BOOTP_FILE = 1`).
    pub fn dhcp_boot_file_name(&self) -> &[u8] {
        unsafe {
            let dhcp_ptr = self.dhcp.as_ptr();
            let name = &(*dhcp_ptr).boot_file_name;
            if name[0] == 0 {
                return &[];
            }
            let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            core::slice::from_raw_parts(name.as_ptr() as *const u8, len)
        }
    }

    /// Get the current IPv4 address of the interface.
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        unsafe {
            let netif_ptr = self.netif.as_ptr();
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
    pub fn poll(&mut self) {
        self.poll_limited(usize::MAX);
    }

    /// Poll the network interface, processing at most `max_packets` received
    /// frames. This prevents a burst of queued RX packets from consuming
    /// unbounded buffer resources in callbacks (e.g. TFTP write).
    pub fn poll_limited(&mut self, max_packets: usize) {
        unsafe {
            let netif_ptr = self.netif.as_mut_ptr();
            let callbacks = self.callbacks.as_ref().unwrap();

            let mut count = 0usize;
            while count < max_packets && (callbacks.rx_available)() {
                let mut buf = [0u8; ETH_FRAME_MAX];
                let len = (callbacks.receive)(&mut buf);
                if len == 0 {
                    break;
                }

                let p = ffi::pbuf_alloc(
                    ffi::pbuf_layer_PBUF_RAW,
                    len as u16,
                    ffi::pbuf_type_PBUF_POOL,
                );
                if p.is_null() {
                    continue;
                }

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

                let err = ((*netif_ptr).input.unwrap())(p, netif_ptr);
                if err != 0 {
                    ffi::pbuf_free(p);
                }
                count += 1;
            }

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

    /// Enable stateless DHCPv6 (obtains DNS config; addresses come via SLAAC).
    #[cfg(feature = "baremetal-ipv6")]
    pub fn dhcp6_enable_stateless(&mut self) -> Result<()> {
        unsafe {
            let netif_ptr = self.netif.as_mut_ptr();
            let err = ffi::dhcp6_enable_stateless(netif_ptr);
            check_err(err)?;
            Ok(())
        }
    }

    /// Enable stateful DHCPv6 (RFC 8415).
    ///
    /// The client waits for a Router Advertisement with the Managed Address
    /// Configuration (M) flag set, then performs a Solicit→Advertise→Request→Reply
    /// exchange to acquire an IPv6 address and boot file URL (Option 59).
    #[cfg(feature = "baremetal-dhcp6-stateful")]
    pub fn dhcp6_enable_stateful(&mut self) -> Result<()> {
        unsafe {
            let netif_ptr = self.netif.as_mut_ptr();
            let dhcp6_ptr = self.dhcp6.as_mut_ptr();
            ptr::write_bytes(dhcp6_ptr, 0, 1);
            ffi::dhcp6_set_struct(netif_ptr, dhcp6_ptr);
            let err = ffi::dhcp6_enable_stateful(netif_ptr);
            check_err(err)?;
            Ok(())
        }
    }

    /// Get the Boot File URL from DHCPv6 Option 59 (RFC 5970).
    ///
    /// Returns the raw URL bytes (e.g. `b"tftp://[fd00::1]/boot.bin"`) if the
    /// server provided it, or `None` if the option was not received.
    #[cfg(feature = "baremetal-dhcp6-stateful")]
    pub fn dhcp6_boot_file_url(&self) -> Option<&[u8]> {
        unsafe {
            let dhcp6_ptr = self.dhcp6.as_ptr();
            let len = (*dhcp6_ptr).boot_file_url_len as usize;
            if len == 0 {
                return None;
            }
            let bytes = &(*dhcp6_ptr).boot_file_url[..len];
            Some(core::slice::from_raw_parts(
                bytes.as_ptr() as *const u8,
                len,
            ))
        }
    }

    /// Parse the Boot File URL (Option 59) into a server IPv6 address and file path.
    ///
    /// Expects format: `tftp://[<ipv6-addr>]/<path>`
    /// Returns `(Ipv6Addr, &[u8])` where the slice is the null-terminated file path.
    #[cfg(feature = "baremetal-dhcp6-stateful")]
    pub fn dhcp6_parse_boot_file_url(&self) -> Option<(Ipv6Addr, &[u8])> {
        let url = self.dhcp6_boot_file_url()?;

        // Strip "tftp://[" prefix
        let prefix = b"tftp://[";
        if url.len() < prefix.len() || &url[..prefix.len()] != prefix {
            return None;
        }
        let rest = &url[prefix.len()..];

        // Find the closing ']'
        let bracket_end = rest.iter().position(|&b| b == b']')?;
        let addr_bytes = &rest[..bracket_end];
        let after_bracket = &rest[bracket_end + 1..];

        // Parse the IPv6 address
        let server_addr = parse_ipv6_addr_bytes(addr_bytes)?;

        // The path follows: "/path"
        let path = if !after_bracket.is_empty() && after_bracket[0] == b'/' {
            &after_bracket[1..]
        } else {
            after_bracket
        };

        Some((server_addr, path))
    }

    /// Check if the interface has a valid global IPv6 address (SLAAC PREFERRED state).
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

    /// Get the first valid global IPv6 address (falls back to index 1).
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

/// Parse an IPv6 address from a byte slice (e.g. `b"fd00:1234:5678::1"`).
/// Supports `::` shorthand. No-alloc implementation for bare-metal.
#[cfg(feature = "baremetal-dhcp6-stateful")]
fn parse_ipv6_addr_bytes(s: &[u8]) -> Option<Ipv6Addr> {
    let mut segments = [0u16; 8];

    // Find "::" position
    let double_colon = s.windows(2).position(|w| w == b"::");

    if let Some(dc_pos) = double_colon {
        let left = &s[..dc_pos];
        let right_start = dc_pos + 2;
        let right = if right_start < s.len() {
            &s[right_start..]
        } else {
            &[]
        };

        let left_count = if left.is_empty() {
            0
        } else {
            parse_hex_segments(left, &mut segments, 0)?
        };

        if !right.is_empty() {
            let mut right_segs = [0u16; 8];
            let right_count = parse_hex_segments(right, &mut right_segs, 0)?;
            if left_count + right_count > 8 {
                return None;
            }
            let right_start_idx = 8 - right_count;
            segments[right_start_idx..8].copy_from_slice(&right_segs[..right_count]);
        }
    } else {
        let count = parse_hex_segments(s, &mut segments, 0)?;
        if count != 8 {
            return None;
        }
    }

    Some(Ipv6Addr::new(segments))
}

/// Parse colon-separated hex segments from a byte slice into `out` starting at `start`.
/// Returns the number of segments parsed.
#[cfg(feature = "baremetal-dhcp6-stateful")]
fn parse_hex_segments(s: &[u8], out: &mut [u16; 8], start: usize) -> Option<usize> {
    let mut idx = start;
    let mut val: u16 = 0;
    let mut has_digit = false;

    for &b in s {
        if b == b':' {
            if !has_digit {
                return None;
            }
            if idx >= 8 {
                return None;
            }
            out[idx] = val;
            idx += 1;
            val = 0;
            has_digit = false;
        } else {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return None,
            };
            val = val.checked_shl(4)?.checked_add(digit as u16)?;
            has_digit = true;
        }
    }

    if has_digit {
        if idx >= 8 {
            return None;
        }
        out[idx] = val;
        idx += 1;
    }

    Some(idx - start)
}

/// lwIP netif initialization callback.
unsafe extern "C" fn baremetal_netif_init(netif: *mut ffi::netif) -> ffi::err_t {
    let instance = &*((*netif).state as *const BaremetalNetIf);
    let callbacks = instance.callbacks.as_ref().unwrap();
    let mac = (callbacks.mac_addr)();

    #[cfg(target_arch = "riscv32")]
    {
        (*netif).name[0] = b'e';
        (*netif).name[1] = b'n';
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        (*netif).name[0] = b'e' as i8;
        (*netif).name[1] = b'n' as i8;
    }
    (*netif).output = Some(ffi::etharp_output);
    #[cfg(feature = "baremetal-ipv6")]
    {
        (*netif).output_ip6 = Some(ffi::ethip6_output);
    }
    (*netif).linkoutput = Some(baremetal_linkoutput);
    (*netif).mtu = 1500;
    (*netif).hwaddr_len = 6;
    (*netif).hwaddr[0] = mac[0];
    (*netif).hwaddr[1] = mac[1];
    (*netif).hwaddr[2] = mac[2];
    (*netif).hwaddr[3] = mac[3];
    (*netif).hwaddr[4] = mac[4];
    (*netif).hwaddr[5] = mac[5];
    (*netif).flags = (ffi::NETIF_FLAG_BROADCAST
        | ffi::NETIF_FLAG_ETHARP
        | ffi::NETIF_FLAG_ETHERNET
        | ffi::NETIF_FLAG_LINK_UP) as u8;

    ffi::err_enum_t_ERR_OK as ffi::err_t
}

/// lwIP linkoutput callback — sends a raw Ethernet frame.
unsafe extern "C" fn baremetal_linkoutput(netif: *mut ffi::netif, p: *mut ffi::pbuf) -> ffi::err_t {
    if p.is_null() {
        return ffi::err_enum_t_ERR_ARG as ffi::err_t;
    }

    let instance = &*((*netif).state as *const BaremetalNetIf);
    let callbacks = instance.callbacks.as_ref().unwrap();

    let total_len = (*p).tot_len as usize;
    if total_len > ETH_FRAME_MAX {
        return ffi::err_enum_t_ERR_BUF as ffi::err_t;
    }

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

    // Pad to minimum Ethernet frame size (60 bytes excluding FCS).
    let send_len = if total_len < 60 { 60 } else { total_len };

    if (callbacks.transmit)(&buf[..send_len]) {
        ffi::err_enum_t_ERR_OK as ffi::err_t
    } else {
        ffi::err_enum_t_ERR_IF as ffi::err_t
    }
}
