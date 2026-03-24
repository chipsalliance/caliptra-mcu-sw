// Licensed under the Apache-2.0 license

//! Boot source provider application for the Network Coprocessor.
//!
//! Listens for boot source protocol messages from the MCU over the network
//! mailbox and handles DHCP configuration, TOC fetching, and TFTP image
//! downloads.

#![no_std]

#[cfg(target_arch = "riscv32")]
pub mod app;
#[cfg(target_arch = "riscv32")]
pub mod handler;
#[cfg(target_arch = "riscv32")]
pub mod network;
pub mod toc;
