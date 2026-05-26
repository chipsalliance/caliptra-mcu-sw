// Licensed under the Apache-2.0 license

//! Platform Abstraction Layer (PAL) for the SPDM-Lite stack.
//!
//! This module defines the [`SpdmPal`] trait, which acts as the top-level
//! abstraction that platform-specific implementations must satisfy. It
//! composes the required transport capabilities (via [`SpdmIoTransport`])
//! into a single trait bound, making it the primary integration point for
//! porting the SPDM-Lite stack to a new platform or transport.

use super::*;

/// Top-level Platform Abstraction Layer trait for SPDM-Lite.
///
/// Implementors of this trait provide a complete platform binding for the
/// SPDM-Lite stack: per-I/O allocation, transport I/O, hashing, certificate
/// access, measurement retrieval, and persistent large-message storage for
/// chunking.
pub trait SpdmPal:
    SpdmPalAlloc
    + SpdmPalIoTransport
    + SpdmPalHash
    + SpdmPalCertStore
    + SpdmPalMeasurements
    + SpdmPalLargeMessage
{
}
