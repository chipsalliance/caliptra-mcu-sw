// Licensed under the Apache-2.0 license

//! SPDM cert-store abstraction (DSP0274 §10.5 / §10.6).
//!
//! All cert-chain methods take an [`SpdmPalAsymAlgo`] parameter
//! so each slot can hold chains for multiple algorithms (e.g.
//! ECC-384 and MLDSA-87). Only ECC-384 is implemented today;
//! MLDSA-87 will be added later using the same interfaces.

use crate::SpdmPalHashAlgo;
use mcu_error::McuResult;

/// Maximum number of cert-chain slots the responder advertises.
/// DSP0274 §10.5 caps this at 8 (`SlotMask` is one byte).
pub const MAX_SLOTS: u8 = 8;

/// Opaque snapshot of a cert slot's provisioning state.
///
/// Stack code carries this token across signed-object construction, but only
/// the PAL interprets the version value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CertSlotSnapshot {
    slot: u8,
    provisioning_state_version: u32,
}

impl CertSlotSnapshot {
    pub const fn new(slot: u8, provisioning_state_version: u32) -> Self {
        Self {
            slot,
            provisioning_state_version,
        }
    }

    pub const fn slot(self) -> u8 {
        self.slot
    }

    pub const fn provisioning_state_version(self) -> u32 {
        self.provisioning_state_version
    }
}

/// Asymmetric algorithm selector.
///
/// Passed to cert-store and endorsement methods so the
/// implementation can select the right cert chain and signing
/// key for the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpdmPalAsymAlgo {
    /// ECDSA P-384 / SHA-384 (96-byte signature: r || s).
    EccP384,
    /// ML-DSA-87 (post-quantum). Reserved for future use.
    MlDsa87,
}

/// Endorsement certificate chain provider for a single slot.
///
/// Integrators implement this for each endorsement type:
/// - `ReadOnlyEndorsement` — static root CA certs (slot 0)
/// - `MutableEndorsement` — flash-backed certs (slots 1-2, SET_CERTIFICATE)
///
/// The PAL uses this to compose the full SPDM cert chain:
/// `endorsement (this) + DPE device chain + leaf (CertifyKey)`
#[allow(async_fn_in_trait)]
pub trait EndorsementCertChain {
    /// Hash of the root certificate under the given algorithm.
    async fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()>;

    /// Total byte length of the endorsement cert chain for the
    /// given algorithm.
    async fn size(&mut self, algo: SpdmPalAsymAlgo) -> McuResult<usize>;

    /// Read endorsement chain bytes at `offset` into `buf`.
    /// Returns bytes written.
    async fn read(
        &mut self,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize>;

    /// Write endorsement cert chain data for the given algorithm.
    /// `ReadOnlyEndorsement` rejects this; `MutableEndorsement`
    /// persists to flash.
    async fn write(&mut self, algo: SpdmPalAsymAlgo, data: &[u8]) -> McuResult<()>;

    /// Erase the endorsement cert chain for the given algorithm.
    async fn erase(&mut self, algo: SpdmPalAsymAlgo) -> McuResult<()>;
}

/// Slot-indexed cert-store backend.
#[allow(async_fn_in_trait)]
pub trait SpdmPalCertStore: crate::SpdmPalIoTransport {
    /// Bitmask of supported slots, bits 0..=7.
    fn supported_slots(&self) -> u8;

    /// Bitmask of provisioned slots, bits 0..=7. Drives DIGESTS's
    /// `SupportedSlotMask` / `ProvisionedSlotMask` (DSP0274 §10.5
    /// Table 25).
    fn provisioned_slots(&self) -> u8;

    /// Raw DER capacity/size for a slot-size query.
    async fn cert_chain_slot_size(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize>;

    /// Check whether a specific SET_CERTIFICATE request is authorized.
    #[cfg(feature = "set-certificate")]
    fn set_certificate_authorized(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        erase: bool,
    ) -> bool;

    /// Validate an incoming SET_CERTIFICATE chain before it is committed.
    ///
    /// The PAL implementation **must** verify that `SHA-384(first DER
    /// certificate in `cert_chain`) == *root_hash`. The stack no longer
    /// performs this check, since the PAL already has access to hashing
    /// machinery and avoids a duplicate async hash pass at the SPDM
    /// responder layer.
    #[cfg(feature = "set-certificate")]
    async fn validate_set_certificate_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; 48],
        cert_chain: &[u8],
    ) -> McuResult<()>;

    /// Length in bytes of slot's raw DER cert chain for the given
    /// algorithm (excludes the 52-byte SPDM cert-chain header).
    async fn cert_chain_len(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize>;

    /// Write the digest of slot's **root certificate** into `out`.
    async fn root_cert_hash(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()>;

    /// Read at most `dst.len()` bytes from slot's raw cert chain
    /// for the given algorithm at `offset` into `dst`.
    async fn read_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize>;

    /// Sign `digest` using the key in `slot` for the given algorithm.
    async fn sign_hash(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        digest: &[u8],
        signature: &mut [u8],
    ) -> McuResult<usize>;

    /// Write a cert chain into `slot` for the given algorithm.
    /// Used by SET_CERTIFICATE.
    #[cfg(feature = "set-certificate")]
    #[allow(clippy::too_many_arguments)]
    async fn write_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<()>;

    /// Erase the cert chain in `slot` for the given algorithm.
    #[cfg(feature = "set-certificate")]
    async fn erase_cert_chain(
        &self,
        io: &Self::Io<'_>,
        slot: u8,
        algo: SpdmPalAsymAlgo,
    ) -> McuResult<()>;

    /// KeyPairID associated with the slot.
    /// Returns `None` for unprovisioned slots.
    fn key_pair_id(&self, slot: u8) -> Option<u8>;

    /// CertificateInfo for the slot.
    /// Returns `None` for unprovisioned slots.
    fn cert_info(&self, slot: u8) -> Option<u8>;

    /// KeyUsageMask for the slot.
    /// Returns `None` for unprovisioned slots.
    fn key_usage_mask(&self, slot: u8) -> Option<u16>;

    /// Snapshot endorsement/provisioning state of a provisioned slot.
    fn cert_slot_snapshot(&self, _slot: u8) -> Option<CertSlotSnapshot> {
        None
    }

    /// Return true if the slot still matches a previously captured snapshot.
    fn cert_slot_matches_snapshot(&self, _snapshot: CertSlotSnapshot) -> bool {
        false
    }

    /// Optional cache hook: return a previously stored full
    /// SPDM-cert-chain digest for `(snapshot, algo)`, or `None` to
    /// force recomputation. Default impl never caches.
    #[inline]
    fn cached_chain_digest(
        &self,
        _snapshot: CertSlotSnapshot,
        _algo: SpdmPalHashAlgo,
    ) -> Option<[u8; 48]> {
        None
    }

    /// Optional cache hook: store the freshly computed SPDM
    /// cert-chain digest for future
    /// [`cached_chain_digest`](Self::cached_chain_digest) lookups.
    /// Default impl is a no-op.
    #[inline]
    fn cache_chain_digest(
        &self,
        _snapshot: CertSlotSnapshot,
        _algo: SpdmPalHashAlgo,
        _digest: &[u8],
    ) {
    }

    /// Fill `out` with random bytes from the platform RNG.
    async fn generate_nonce(&self, io: &Self::Io<'_>, out: &mut [u8]) -> McuResult<()>;
}
