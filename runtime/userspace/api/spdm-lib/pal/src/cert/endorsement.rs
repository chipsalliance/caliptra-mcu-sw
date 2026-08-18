// Licensed under the Apache-2.0 license

//! SPDM-facing slot mapping for the protocol-neutral certificate store.

#[cfg(feature = "set-certificate")]
pub use caliptra_mcu_cert_store::ManagedEndorsement;
pub use caliptra_mcu_cert_store::{
    CertSlot, CertificateAlgorithm, CertificateAttributes, CertificateRole, ReadOnlyEndorsement,
    SlotEndorsement, NUM_CERT_SLOTS,
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
    match slot_role(slot_id) {
        Some(role) => Some(role.index()),
        None => None,
    }
}

/// Map an SPDM slot id to its protocol-neutral certificate role.
pub const fn slot_role(slot_id: u8) -> Option<CertificateRole> {
    if slot_id == DEFAULT_SLOT_MAP[0] {
        Some(CertificateRole::Vendor)
    } else if slot_id == DEFAULT_SLOT_MAP[1] {
        Some(CertificateRole::Owner)
    } else if slot_id == DEFAULT_SLOT_MAP[2] {
        Some(CertificateRole::Tenant)
    } else {
        None
    }
}
