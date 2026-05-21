// Licensed under the Apache-2.0 license

//! Top-level SPDM-Lite Platform Abstraction Layer trait.

use super::*;

/// Top-level Platform Abstraction Layer trait for SPDM-Lite.
///
/// Implementors of this trait provide a complete platform binding for the
/// SPDM-Lite stack: per-I/O allocation, transport I/O, hashing, certificate
/// access, and persistent large-message storage for chunking.
pub trait SpdmPal:
    SpdmPalAlloc + SpdmPalIoTransport + SpdmPalHash + SpdmPalCertStore + SpdmPalLargeMessage
{
}
