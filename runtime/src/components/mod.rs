// Licensed under the Apache-2.0 license

//! Components for the Caliptra MCU runtime.

pub mod flash_partition;
pub mod mailbox;
pub mod mctp_driver;
#[cfg(feature = "test-mctp-capsule-loopback")]
pub mod mock_mctp;
pub mod mux_mctp;
