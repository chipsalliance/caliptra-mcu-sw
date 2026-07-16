// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED message (VDM) protocol handling for the SPDM responder.
//!
//! This crate owns the *protocol* side of VDM handling — the wire formats,
//! command codes, and request/response framing for each supported standards
//! body — and implements the VDM backend used to route
//! `VENDOR_DEFINED_REQUEST`s. The actual device operations are delegated to
//! platform-supplied PAL hooks (for example,
//! [`iana::ocp::caliptra_vdm::CaliptraVdmStreamOps`]).
//!
//! Handling is organized by SPDM Standards Body ID:
//!
//! * [`iana`] — IANA-registered vendors (OCP / Caliptra VDM).
//! * [`pci_sig`] — PCI-SIG protocols (IDE-KM and TDISP).
#![no_std]
#![allow(async_fn_in_trait)]

pub mod iana;
pub mod pci_sig;

/// Integrator-facing platform hook traits for supported VDM protocols.
pub mod drivers {
    pub use crate::iana::ocp::caliptra_vdm::{CaliptraVdmAuthorization, CaliptraVdmStreamOps};
    pub use crate::pci_sig::ide_km::{IdeDriver, IdeDriverError, IdeDriverResult};
    pub use crate::pci_sig::tdisp::{TdispDriver, TdispDriverError, TdispDriverResult};
}
