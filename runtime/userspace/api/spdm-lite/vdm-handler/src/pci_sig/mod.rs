// Licensed under the Apache-2.0 license

//! PCI-SIG VENDOR_DEFINED protocols (Standards Body ID `PciSig`, 0x03).
//!
//! PCI-SIG VDMs are delivered inside a secure SPDM session. This module
//! currently implements IDE-KM and keeps the protocol selected by the PCI-SIG
//! protocol-id byte that prefixes the vendor-defined payload.

pub mod ide_km;

#[cfg(feature = "emulated-ide-km")]
pub use ide_km::EmulatedIdeDriver;
pub use ide_km::{IdeDriver, IdeDriverError, IdeDriverResult, IdeKmResponder, PciSigIdeKmVdm};
