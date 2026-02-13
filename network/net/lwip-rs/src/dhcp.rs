// Licensed under the Apache-2.0 license

//! DHCP client wrapper

use core::mem::MaybeUninit;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{check_err, Result};
use crate::ffi;
use crate::ip::Ipv4Addr;
use crate::netif::NetIf;

pub const DHCP_BOOT_FILE_LEN: usize = 128;

/// DHCP client
pub struct DhcpClient {
    inner: Box<ffi::dhcp>,
    netif: *mut ffi::netif,
    started: bool,
}

impl DhcpClient {
    pub fn new(netif: &mut NetIf) -> Self {
        let inner = Box::new(unsafe { MaybeUninit::<ffi::dhcp>::zeroed().assume_init() });
        DhcpClient {
            inner,
            netif: netif.as_mut_ptr(),
            started: false,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        unsafe {
            ffi::dhcp_set_struct(self.netif, self.inner.as_mut());
            let err = ffi::dhcp_start(self.netif);
            check_err(err)?;
            self.started = true;
            Ok(())
        }
    }

    pub fn stop(&mut self) {
        if self.started {
            unsafe {
                ffi::dhcp_stop(self.netif);
            }
            self.started = false;
        }
    }

    pub fn has_address(&self) -> bool {
        if !self.started {
            return false;
        }
        unsafe { ffi::dhcp_supplied_address(self.netif) != 0 }
    }

    pub fn state(&self) -> u8 {
        self.inner.state
    }

    pub fn offered_ip(&self) -> Ipv4Addr {
        Ipv4Addr(self.inner.offered_ip_addr)
    }

    pub fn offered_netmask(&self) -> Ipv4Addr {
        Ipv4Addr(self.inner.offered_sn_mask)
    }

    pub fn offered_gateway(&self) -> Ipv4Addr {
        Ipv4Addr(self.inner.offered_gw_addr)
    }

    pub fn tftp_server(&self) -> Ipv4Addr {
        Ipv4Addr(self.inner.offered_si_addr)
    }

    pub fn boot_file(&self) -> Option<String> {
        let name = &self.inner.boot_file_name;
        if name[0] == 0 {
            return None;
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let bytes: Vec<u8> = name[..len].iter().map(|&c| c as u8).collect();
        String::from_utf8(bytes).ok()
    }
}

impl Drop for DhcpClient {
    fn drop(&mut self) {
        self.stop();
    }
}
