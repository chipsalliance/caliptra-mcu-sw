// Licensed under the Apache-2.0 license

//! SPDM-facing slot mapping for the protocol-neutral certificate store.

#[cfg(feature = "set-certificate")]
pub use caliptra_mcu_cert_store::ManagedEndorsement;
pub use caliptra_mcu_cert_store::{
    CertSlot, CertificateAlgorithm, CertificateAttributes, ReadOnlyEndorsement, SlotEndorsement,
    NUM_CERT_SLOTS,
};

/// SPDM slot_id to internal certificate-store index mapping.
/// Default: Vendor=0, Owner=2, Tenant=3.
// TODO: make configurable per integrator at build time.
pub const DEFAULT_SLOT_MAP: [u8; NUM_CERT_SLOTS] = [0, 2, 3];

/// Supported SPDM slot bitmask derived from [`DEFAULT_SLOT_MAP`].
pub const SUPPORTED_SLOT_MASK: u8 = {
    let mut mask = 0u8;
    let mut i = 0;
    while i < NUM_CERT_SLOTS {
        mask |= 1 << DEFAULT_SLOT_MAP[i];
        i += 1;
    }
    mask
};

/// Map an SPDM slot id to a certificate-store index.
pub const fn slot_index(slot_id: u8) -> Option<usize> {
    let mut i = 0;
    while i < NUM_CERT_SLOTS {
        if DEFAULT_SLOT_MAP[i] == slot_id {
            return Some(i);
        }
        i += 1;
    }
    None
}
