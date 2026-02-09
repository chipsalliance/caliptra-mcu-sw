// Licensed under the Apache-2.0 license

//! Network xtask library
//!
//! Provides utilities for:
//! - Building network applications
//! - Managing TAP interfaces
//! - Managing DHCP/TFTP servers (dnsmasq)

pub mod build;
pub mod server;
pub mod tap;

// Re-export commonly used types
pub use server::ServerOptions;
