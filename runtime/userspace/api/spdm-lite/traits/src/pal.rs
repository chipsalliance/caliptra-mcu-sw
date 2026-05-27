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
/// SPDM-Lite stack. The trait currently requires [`SpdmIoTransport`],
/// ensuring that the platform can send and receive SPDM messages.
///
/// As the stack evolves, additional super-traits (e.g., for cryptographic
/// operations or certificate provisioning) may be added here, keeping
/// downstream consumers bound to a single `SpdmPal` constraint.
pub trait SpdmPal: SpdmPalAlloc + SpdmPalIoTransport + SpdmPalHash + SpdmPalCertStore {}
