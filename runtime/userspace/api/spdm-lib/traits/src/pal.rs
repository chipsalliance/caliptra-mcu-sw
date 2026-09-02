// Licensed under the Apache-2.0 license

//! Platform Abstraction Layer (PAL) for the SPDM-Lite stack.
//!
//! This module defines the [`SpdmPal`] trait, which acts as the top-level
//! abstraction that platform-specific implementations must satisfy. It
//! composes the required transport capabilities (via [`SpdmIoTransport`])
//! into a single trait bound, making it the primary integration point for
//! platform or transport implementations.

use super::*;

/// Top-level Platform Abstraction Layer trait for SPDM-Lite.
///
/// Implementors of this trait provide a complete platform binding for the
/// SPDM-Lite stack: per-I/O allocation, transport I/O, hashing, certificate
/// access, measurement retrieval, persistent large-message storage for
/// chunking, and secure-session cryptographic operations.
pub trait SpdmPal:
    SpdmPalAlloc
    + SpdmPalIoTransport
    + SpdmPalHash
    + SpdmPalCertStore
    + SpdmPalMeasurements
    + SpdmPalSessionCrypto
{
    /// Endpoint-wide maximum logical SPDM request this responder accepts.
    ///
    /// Advertised as `MaxSPDMmsgSize`. This is the maximum across buffered and
    /// streamed request paths, and must be at least [`Self::mtu`].
    fn max_inbound_spdm_request_size(&self) -> usize {
        self.large_buffered_msg_capacity().max(self.mtu())
    }
}
