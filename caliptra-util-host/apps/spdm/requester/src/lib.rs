// Licensed under the Apache-2.0 license

//! SPDM requester library for Caliptra host-side utilities.
//!
//! Provides a thin wrapper around `spdm-utils` (which wraps DMTF libspdm)
//! to support SPDM requester operations and Caliptra VDM commands over SPDM
//! vendor-defined messages.
//!
//! # Transport
//! The library is transport-pluggable via the [`SpdmDeviceIo`] trait.
//! Included implementations:
//! - [`TcpSpdmDeviceIo`] — raw TCP (for direct connections)
//! - [`SpdmSocketDeviceIo`] — socket-framed protocol (for bridge-based testing)
//!
//! For production use (e.g., OpenBMC), implement `SpdmDeviceIo` over AF_MCTP
//! or your platform's MCTP transport.

pub mod requester;
pub mod transport;
pub mod vdm;

pub use requester::SpdmRequester;
pub use transport::{SpdmDeviceIo, SpdmSocketDeviceIo, TcpSpdmDeviceIo};
pub use vdm::SpdmVdmDriverImpl;

/// SPDM requester configuration.
#[derive(Debug, Clone)]
pub struct SpdmConfig {
    /// Certificate slot ID to use (0-7).
    pub slot_id: u8,
    /// Maximum SPDM message size.
    pub max_spdm_msg_size: u32,
}

impl Default for SpdmConfig {
    fn default() -> Self {
        Self {
            slot_id: 0,
            max_spdm_msg_size: libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE,
        }
    }
}
