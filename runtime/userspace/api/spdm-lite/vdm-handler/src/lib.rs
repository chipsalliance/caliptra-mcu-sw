// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED message (VDM) protocol handling for the SPDM-Lite stack.
//!
//! This crate owns the *protocol* side of VDM handling — the wire formats,
//! command codes, and request/response framing for each supported standards
//! body — and implements [`mcu_spdm_lite_traits::SpdmVdmBackend`] so the stack
//! can route `VENDOR_DEFINED_REQUEST`s to it. The actual device operations are
//! delegated to platform-supplied PAL hooks (e.g.
//! [`iana::ocp::caliptra_vdm::CaliptraVdmCommands`]).
//!
//! Handling is organized by SPDM Standards Body ID, mirroring the module layout
//! used by the full `spdm-lib` stack:
//!
//! * [`iana`] — IANA-registered vendors (OCP / Caliptra VDM).
//! * [`pci_sig`] — PCI-SIG protocols (IDE-KM today; TDISP can be added alongside it).
#![no_std]
#![allow(async_fn_in_trait)]

pub mod iana;
pub mod pci_sig;
