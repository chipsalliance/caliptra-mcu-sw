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

mod libspdm_hal_stubs;
pub mod requester;
pub mod transport;
pub mod vdm;

pub use requester::{KeyPairInfo, SpdmRequester};
pub use transport::{SpdmDeviceIo, SpdmSocketDeviceIo, TcpSpdmDeviceIo};
pub use vdm::SpdmVdmDriverImpl;

/// Peer trust anchor for libspdm certificate-chain validation.
#[derive(Debug, Clone)]
pub struct PeerRootCert {
    /// SPDM certificate slot this root is allowed to authenticate.
    pub slot_id: u8,
    /// DER-encoded root certificate.
    pub cert_der: Vec<u8>,
}

/// SPDM requester configuration.
#[derive(Debug, Clone)]
pub struct SpdmConfig {
    /// Certificate slot ID to use (0-7).
    pub slot_id: u8,
    /// Maximum SPDM message size.
    pub max_spdm_msg_size: u32,
    /// Accept peer certificate chains returned by GET_CERTIFICATE without
    /// libspdm's built-in X.509 responder-identity validation.
    pub accept_unverified_peer_cert_chain: bool,
    /// Slot-scoped DER trust anchors used when validating peer certificate
    /// chains. libspdm stores raw pointers to these buffers, so the requester
    /// keeps this config alive for the lifetime of the SPDM context.
    pub peer_root_certs: Vec<PeerRootCert>,
}

impl Default for SpdmConfig {
    fn default() -> Self {
        Self {
            slot_id: 0,
            max_spdm_msg_size: libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE,
            accept_unverified_peer_cert_chain: false,
            peer_root_certs: Vec::new(),
        }
    }
}
