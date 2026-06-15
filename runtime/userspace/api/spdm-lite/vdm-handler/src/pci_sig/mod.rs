// Licensed under the Apache-2.0 license

//! PCI-SIG VENDOR_DEFINED protocols (Standards Body ID `PciSig`, 0x03).
//!
//! Reserved for the PCI-SIG VDM handlers — IDE_KM and TDISP — which are always
//! delivered inside a secure session on the DOE transport. Not yet implemented.
//!
//! TODO: add `ide_km` and `tdisp` submodules implementing
//! [`mcu_spdm_lite_traits::SpdmVdmBackend`].
