/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Test applications for Network Coprocessor ROM.

--*/

#![no_std]

pub mod dhcp_test;

#[cfg(feature = "lwip-dhcp")]
pub mod lwip_dhcp_test;

#[cfg(feature = "lwip-dhcp6")]
pub mod lwip_dhcpv6_test;
