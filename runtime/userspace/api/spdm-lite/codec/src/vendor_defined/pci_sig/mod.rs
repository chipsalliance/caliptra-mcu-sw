// Licensed under the Apache-2.0 license

//! PCI-SIG VDM protocol wire types.

pub mod ide_km;
pub mod tdisp;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// PCI-SIG protocol selector byte that prefixes PCI-SIG VDM payloads.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug)]
#[repr(C)]
pub struct PciSigProtocolHdr {
    /// PCI-SIG protocol ID (0 = IDE-KM).
    pub protocol_id: u8,
}

impl PciSigProtocolHdr {
    /// Size of the PCI-SIG protocol header on the wire.
    pub const SIZE: usize = 1;
}

const _: () = assert!(core::mem::size_of::<PciSigProtocolHdr>() == PciSigProtocolHdr::SIZE);
