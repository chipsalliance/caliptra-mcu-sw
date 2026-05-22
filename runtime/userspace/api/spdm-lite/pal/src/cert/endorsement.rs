// Licensed under the Apache-2.0 license

//! Cert slot and endorsement chain types.
//!
//! Each SPDM slot is represented by a [`CertSlot`] which holds the
//! endorsement chain and per-slot metadata. The endorsement is an
//! enum ([`SlotEndorsement`]) dispatching to `ReadOnly` (slot 0)
//! or `Managed` (slots 1-2) without dynamic dispatch.

use mcu_error::McuResult;
use mcu_spdm_lite_traits::SpdmPalAsymAlgo;

/// Number of cert slots managed by the PAL.
pub const NUM_CERT_SLOTS: usize = 3;

/// SPDM slot_id → internal index mapping.
/// Default: Vendor=0, Owner=2, Tenant=3.
// TODO: make configurable per integrator at build time.
pub const DEFAULT_SLOT_MAP: [u8; NUM_CERT_SLOTS] = [0, 2, 3];

/// Supported slot bitmask, computed from DEFAULT_SLOT_MAP at compile time.
pub const SUPPORTED_SLOT_MASK: u8 = {
    let mut mask = 0u8;
    let mut i = 0;
    while i < NUM_CERT_SLOTS {
        mask |= 1 << DEFAULT_SLOT_MAP[i];
        i += 1;
    }
    mask
};

/// Map SPDM slot_id to internal cert slot index.
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

/// DPE key indices for device cert chain anchor points.
/// IDevID (0) is the default.
#[allow(dead_code)]
pub const DEVICE_KEY_LDEVID: u8 = 1;
#[allow(dead_code)]
pub const DEVICE_KEY_FMC_ALIAS: u8 = 2;
#[allow(dead_code)]
pub const DEVICE_KEY_RT_ALIAS: u8 = 3;

/// A single SPDM certificate slot.
///
/// Composes the full cert chain: endorsement + DPE device chain + leaf.
/// The device chain and leaf are common across all slots (fetched from
/// Caliptra DPE at runtime). Only the endorsement differs per slot.
pub struct CertSlot {
    /// Endorsement cert chain for this slot.
    pub endorsement: SlotEndorsement,
    /// KeyPairID associated with this slot's signing key.
    /// `None` for unprovisioned slots.
    pub key_pair_id: Option<u8>,
}

impl CertSlot {
    pub const fn empty() -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id: None,
        }
    }

    pub fn is_provisioned(&self) -> bool {
        self.endorsement.is_provisioned()
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
#[allow(dead_code)]
pub enum SlotEndorsement {
    /// Not provisioned.
    Empty,
    /// Read-only endorsement backed by static root CA certs (slot 0).
    ReadOnly(ReadOnlyEndorsement),
    /// Managed endorsement backed by flash (slots 1-2, SET_CERTIFICATE).
    Managed(ManagedEndorsement),
}

impl SlotEndorsement {
    pub fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
        match self {
            Self::ReadOnly(e) => e.root_cert_hash(algo, out),
            Self::Managed(e) => e.root_cert_hash(algo, out),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn size(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            Self::Managed(e) => e.size(algo),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn read(&self, algo: SpdmPalAsymAlgo, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.read(algo, offset, buf),
            Self::Managed(e) => e.read(algo, offset, buf),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn is_provisioned(&self) -> bool {
        match self {
            Self::ReadOnly(_) => true,
            Self::Managed(e) => e.is_initialized(),
            Self::Empty => false,
        }
    }

    pub fn write(&mut self, algo: SpdmPalAsymAlgo, data: &[u8]) -> McuResult<()> {
        match self {
            Self::Managed(e) => e.write(algo, data),
            Self::ReadOnly(_) => Err(mcu_error::codes::NOT_IMPLEMENTED),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn erase(&mut self, algo: SpdmPalAsymAlgo) -> McuResult<()> {
        match self {
            Self::Managed(e) => e.erase(algo),
            Self::ReadOnly(_) => Err(mcu_error::codes::NOT_IMPLEMENTED),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }
}

/// Read-only endorsement — static root CA cert chain.
pub struct ReadOnlyEndorsement {
    root_cert_hash: [u8; 48],
    chain: &'static [&'static [u8]],
    chain_len: usize,
}

impl ReadOnlyEndorsement {
    pub fn new(chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        let chain_len = chain.iter().map(|c| c.len()).sum();
        Self {
            root_cert_hash,
            chain,
            chain_len,
        }
    }

    fn root_cert_hash(&self, _algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
        let n = out.len().min(self.root_cert_hash.len());
        out[..n].copy_from_slice(&self.root_cert_hash[..n]);
        Ok(())
    }

    fn size(&self, _algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        Ok(self.chain_len)
    }

    fn read(&self, _algo: SpdmPalAsymAlgo, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        let mut cert_offset = offset;
        let mut pos = 0;
        for cert in self.chain.iter() {
            if cert_offset < cert.len() {
                let len = (cert.len() - cert_offset).min(buf.len() - pos);
                buf[pos..pos + len].copy_from_slice(&cert[cert_offset..cert_offset + len]);
                pos += len;
                cert_offset = 0;
                if pos == buf.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        Ok(pos)
    }
}

/// Managed endorsement — flash-backed cert chain.
/// TODO: implement when flash storage is wired up.
#[allow(dead_code)]
pub struct ManagedEndorsement {
    _slot: u8,
    initialized: bool,
}

#[allow(dead_code)]
impl ManagedEndorsement {
    pub fn new(slot: u8) -> Self {
        Self {
            _slot: slot,
            initialized: false,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn root_cert_hash(&self, _algo: SpdmPalAsymAlgo, _out: &mut [u8]) -> McuResult<()> {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    fn size(&self, _algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    fn read(&self, _algo: SpdmPalAsymAlgo, _offset: usize, _buf: &mut [u8]) -> McuResult<usize> {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    fn write(&mut self, _algo: SpdmPalAsymAlgo, _data: &[u8]) -> McuResult<()> {
        // TODO: write endorsement to flash
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }

    fn erase(&mut self, _algo: SpdmPalAsymAlgo) -> McuResult<()> {
        // TODO: erase endorsement from flash
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }
}
