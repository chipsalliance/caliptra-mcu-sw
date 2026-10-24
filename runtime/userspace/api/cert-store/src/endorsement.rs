// Licensed under the Apache-2.0 license

//! Cert slot and endorsement chain types.
//!
//! Each SPDM slot is represented by a [`CertSlot`] which holds slot
//! certificate bytes and per-slot metadata. The backing storage is an
//! enum ([`SlotEndorsement`]) dispatching to `ReadOnly` (slot 0)
//! or `Managed` (slots 1-2) without dynamic dispatch.

#[cfg(feature = "set-certificate")]
use crate::{errors as cert_errors, DeviceKey};
use crate::{CertificateAlgorithm, EndorsementRole};
#[cfg(feature = "set-certificate")]
use caliptra_mcu_libsyscall_caliptra::{flash::SpiFlash, DefaultSyscalls};
#[cfg(feature = "set-certificate")]
use caliptra_mcu_libtock_platform::ErrorCode;
use mcu_error::McuResult;

#[cfg(feature = "set-certificate")]
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Number of cert slots managed by the store.
pub const NUM_CERT_SLOTS: usize = 3;

/// Default KeyUsageMask for Caliptra certificate slots.
pub const DEFAULT_KEY_USAGE_MASK: u16 = 0x0003;

/// Map internal cert slot index to [`EndorsementRole`].
pub const fn endorsement_role(index: usize) -> Option<EndorsementRole> {
    EndorsementRole::from_index(index)
}

/// Number of asymmetric algorithms a slot can hold a chain for.
pub const NUM_ASYM_ALGOS: usize = 2;

/// Supported certificate model in Caliptra (AliasCert).
pub const CERT_MODEL_ALIAS_CERT: u8 = 2;

/// Index into per-algorithm arrays.
pub const fn algo_index(algo: CertificateAlgorithm) -> usize {
    algo.index()
}

/// A single SPDM certificate slot.
///
/// Slots store the endorsement/root portion. The PAL composes the full
/// SPDM cert chain by appending the DPE device chain and DPE leaf cert.
///
/// Identity and certificate model are shared by the slot. Certificate
/// availability and the in-progress write lock remain per algorithm.
pub const MANAGED_BANK_COUNT: usize = 2;

pub struct CertSlot {
    /// Slot certificate-chain backing storage.
    pub endorsement: SlotEndorsement,
    /// Immutable logical device-key binding shared by both algorithms.
    key_pair_id: Option<u8>,
    /// State lock held high while an async write (flash erase/write) is
    /// in progress for the corresponding algorithm.
    write_in_progress: [AtomicBool; NUM_ASYM_ALGOS],
    /// Monotonic generation counter per algorithm, incremented whenever an
    /// endorsement is configured, published, or removed.
    generation_counter: [AtomicU32; NUM_ASYM_ALGOS],
    /// Count of in-flight async readers per `(algorithm, bank)` so an active
    /// bank cannot be reclaimed/erased while a reader is suspended at `.await`.
    bank_readers: [[AtomicU32; MANAGED_BANK_COUNT]; NUM_ASYM_ALGOS],
}

impl CertSlot {
    pub const fn empty(key_pair_id: Option<u8>) -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id,
            write_in_progress: [const { AtomicBool::new(false) }; NUM_ASYM_ALGOS],
            generation_counter: [const { AtomicU32::new(0) }; NUM_ASYM_ALGOS],
            bank_readers: [const { [const { AtomicU32::new(0) }; MANAGED_BANK_COUNT] };
                NUM_ASYM_ALGOS],
        }
    }

    pub fn is_supported(&self) -> bool {
        self.endorsement.is_supported()
    }

    pub fn is_writable(&self) -> bool {
        self.endorsement.is_writable()
    }

    /// Whether this slot can serve a cert chain for `algo` right now.
    pub fn is_provisioned(&self, algo: CertificateAlgorithm) -> bool {
        self.endorsement.is_provisioned(algo)
    }

    pub fn write_in_progress(&self, algo: CertificateAlgorithm) -> bool {
        self.write_in_progress[algo_index(algo)].load(Ordering::Relaxed)
    }

    pub fn set_write_in_progress(&self, algo: CertificateAlgorithm, value: bool) {
        self.write_in_progress[algo_index(algo)].store(value, Ordering::Relaxed);
    }

    pub fn generation_counter(&self, algo: CertificateAlgorithm) -> u32 {
        self.generation_counter[algo_index(algo)].load(Ordering::Relaxed)
    }

    pub(crate) fn bump_generation_counter(&self, algo: CertificateAlgorithm) {
        let idx = algo_index(algo);
        let next = self.generation_counter[idx]
            .load(Ordering::Relaxed)
            .wrapping_add(1);
        self.generation_counter[idx].store(next, Ordering::Relaxed);
    }

    pub(crate) fn acquire_bank_reader(&self, algo: CertificateAlgorithm, bank: u8) {
        let idx = algo_index(algo);
        let b = (bank as usize) % MANAGED_BANK_COUNT;
        let next = self.bank_readers[idx][b]
            .load(Ordering::Relaxed)
            .saturating_add(1);
        self.bank_readers[idx][b].store(next, Ordering::Relaxed);
    }

    pub(crate) fn release_bank_reader(&self, algo: CertificateAlgorithm, bank: u8) {
        let idx = algo_index(algo);
        let b = (bank as usize) % MANAGED_BANK_COUNT;
        let next = self.bank_readers[idx][b]
            .load(Ordering::Relaxed)
            .saturating_sub(1);
        self.bank_readers[idx][b].store(next, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "set-certificate"))]
    pub(crate) fn bank_has_readers(&self, algo: CertificateAlgorithm, bank: u8) -> bool {
        let idx = algo_index(algo);
        let b = (bank as usize) % MANAGED_BANK_COUNT;
        self.bank_readers[idx][b].load(Ordering::Relaxed) > 0
    }

    #[cfg(any(test, feature = "set-certificate"))]
    pub(crate) fn any_bank_has_readers(&self, algo: CertificateAlgorithm) -> bool {
        let idx = algo_index(algo);
        self.bank_readers[idx]
            .iter()
            .any(|count| count.load(Ordering::Relaxed) > 0)
    }

    pub fn key_pair_id(&self, algo: CertificateAlgorithm) -> Option<u8> {
        if !self.is_provisioned(algo) {
            return None;
        }
        match &self.endorsement {
            SlotEndorsement::ReadOnly(_) => self.key_pair_id,
            #[cfg(feature = "set-certificate")]
            SlotEndorsement::Managed(m) => m.get_endorsement(algo)?.key_pair_id(),
            SlotEndorsement::Empty => None,
        }
    }

    pub(crate) fn configured_key_pair_id(&self) -> Option<u8> {
        self.key_pair_id
    }

    pub fn cert_info(&self, algo: CertificateAlgorithm) -> Option<u8> {
        if !self.is_provisioned(algo) {
            return None;
        }
        Some(CERT_MODEL_ALIAS_CERT)
    }

    pub fn key_usage_mask(&self, algo: CertificateAlgorithm) -> Option<u16> {
        if !self.is_provisioned(algo) {
            return None;
        }
        #[cfg(feature = "set-certificate")]
        {
            match &self.endorsement {
                SlotEndorsement::Managed(m) => m.get_endorsement(algo)?.key_usage_mask(),
                _ => Some(DEFAULT_KEY_USAGE_MASK),
            }
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            Some(DEFAULT_KEY_USAGE_MASK)
        }
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
pub enum SlotEndorsement {
    /// Not provisioned and not exposed as a supported slot.
    Empty,
    /// Read-only endorsement backed by static root CA certs (slot 0).
    ReadOnly(ReadOnlyEndorsementSlot),
    /// Managed endorsement/root chains backed by flash (slots 1-2),
    /// one independent region per algorithm.
    #[cfg(feature = "set-certificate")]
    Managed(ManagedEndorsementSlot),
}

impl SlotEndorsement {
    pub fn root_cert_hash(&self, algo: CertificateAlgorithm, out: &mut [u8]) -> McuResult<()> {
        match self {
            Self::ReadOnly(e) => e.root_cert_hash(algo, out),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .root_cert_hash(out),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn size(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .size(),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn capacity(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => Ok(m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .der_capacity()),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub(crate) fn snapshot(&self, algo: CertificateAlgorithm) -> McuResult<EndorsementSnapshot> {
        match self {
            Self::ReadOnly(e) => e
                .get_endorsement(algo)
                .copied()
                .map(EndorsementSnapshot::ReadOnly)
                .ok_or(mcu_error::codes::INVARIANT),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m
                .get_endorsement(algo)
                .copied()
                .map(EndorsementSnapshot::Managed)
                .ok_or(mcu_error::codes::INVARIANT),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub async fn read(
        &self,
        algo: CertificateAlgorithm,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        let snapshot = self.snapshot(algo)?;
        snapshot.read(offset, buf).await
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Empty)
    }

    pub fn is_writable(&self) -> bool {
        #[cfg(feature = "set-certificate")]
        {
            matches!(self, Self::Managed(_))
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            false
        }
    }

    pub fn is_provisioned(&self, algo: CertificateAlgorithm) -> bool {
        match self {
            Self::ReadOnly(e) => e.get_endorsement(algo).is_some(),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m.get_endorsement(algo).is_some_and(|r| r.is_initialized()),
            Self::Empty => false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SingleEndorsementChain {
    pub root_cert_hash: [u8; 48],
    pub chain: &'static [&'static [u8]],
    pub chain_len: usize,
}

impl SingleEndorsementChain {
    pub fn new(chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        let chain_len = chain.iter().map(|c| c.len()).sum();
        Self {
            root_cert_hash,
            chain,
            chain_len,
        }
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let mut cert_offset = offset;
        let mut pos = 0;
        for cert in self.chain.iter() {
            if cert_offset < cert.len() {
                let len = cert
                    .len()
                    .saturating_sub(cert_offset)
                    .min(buf.len().saturating_sub(pos));
                if let (Some(dst), Some(src)) = (
                    buf.get_mut(pos..pos + len),
                    cert.get(cert_offset..cert_offset + len),
                ) {
                    for (d, s) in dst.iter_mut().zip(src) {
                        *d = *s;
                    }
                }
                pos += len;
                cert_offset = 0;
                if pos == buf.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        pos
    }
}

/// Immutable value-type snapshot of a single `(role, algo)` endorsement
/// that can be held across `.await` points without borrowing [`CertSlot`].
#[derive(Clone, Copy)]
pub(crate) enum EndorsementSnapshot {
    ReadOnly(SingleEndorsementChain),
    #[cfg(feature = "set-certificate")]
    Managed(SingleManagedEndorsement),
}

impl EndorsementSnapshot {
    pub(crate) fn size(&self) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => Ok(e.chain_len),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m.size(),
        }
    }

    pub(crate) fn active_bank(&self) -> Option<u8> {
        match self {
            Self::ReadOnly(_) => None,
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m.active_bank(),
        }
    }

    pub(crate) async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => Ok(e.read(offset, buf)),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => m.read(offset, buf).await,
        }
    }
}

/// Read-only endorsement — static root CA cert chain for ECC and optional ML-DSA.
pub struct ReadOnlyEndorsementSlot {
    ecc: SingleEndorsementChain,
    mldsa: Option<SingleEndorsementChain>,
}

impl ReadOnlyEndorsementSlot {
    pub fn new(chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        Self {
            ecc: SingleEndorsementChain::new(chain, root_cert_hash),
            mldsa: None,
        }
    }

    pub fn with_mldsa(mut self, chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        self.mldsa = Some(SingleEndorsementChain::new(chain, root_cert_hash));
        self
    }

    pub fn get_endorsement(&self, algo: CertificateAlgorithm) -> Option<&SingleEndorsementChain> {
        match algo {
            CertificateAlgorithm::EccP384 => Some(&self.ecc),
            CertificateAlgorithm::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    fn root_cert_hash(&self, algo: CertificateAlgorithm, out: &mut [u8]) -> McuResult<()> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        for (d, s) in out.iter_mut().zip(&chain.root_cert_hash) {
            *d = *s;
        }
        Ok(())
    }

    fn size(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        Ok(chain.chain_len)
    }
}

#[cfg(feature = "set-certificate")]
const MANAGED_MAGIC: [u8; 4] = *b"SPCE";
#[cfg(feature = "set-certificate")]
const MANAGED_FORMAT_VERSION: u16 = 2;
#[cfg(feature = "set-certificate")]
const MANAGED_HEADER_SIZE: usize = 76;
#[cfg(feature = "set-certificate")]
const MANAGED_ALGO_ECC_P384: u8 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_ALGO_MLDSA_87: u8 = 2;

#[cfg(feature = "set-certificate")]
const fn managed_algo_code(algo: CertificateAlgorithm) -> u8 {
    match algo {
        CertificateAlgorithm::EccP384 => MANAGED_ALGO_ECC_P384,
        CertificateAlgorithm::MlDsa87 => MANAGED_ALGO_MLDSA_87,
    }
}
#[cfg(feature = "set-certificate")]
const MANAGED_ERASED_BYTE: u8 = 0xFF;
#[cfg(feature = "set-certificate")]
const MANAGED_KEY_USAGE_MASK: u16 = 0x0003;
#[cfg(feature = "set-certificate")]
const SPDM_CERT_CHAIN_HEADER_SIZE: usize = 4 + 48;
/// Largest DER payload the SPDM cert-chain format can describe.
///
/// SPDM allows for large certificate chain indexing up to 32 bits, so in
/// practice, this limit is the size of one bank in the managed flash region.
#[cfg(feature = "set-certificate")]
const MANAGED_MAX_DER_LEN: usize = (u32::MAX as usize) - SPDM_CERT_CHAIN_HEADER_SIZE;

/// Usable DER bytes in one bank of a two-bank managed endorsement region.
#[cfg(feature = "set-certificate")]
pub const fn managed_endorsement_der_capacity(region_size: usize) -> usize {
    let bank_size = region_size / MANAGED_BANK_COUNT;
    let available = bank_size.saturating_sub(MANAGED_HEADER_SIZE);
    if available < MANAGED_MAX_DER_LEN {
        available
    } else {
        MANAGED_MAX_DER_LEN
    }
}

/// Whether two half-open byte ranges intersect.
///
/// The single definition of "these managed flash regions collide".
/// Updating a chain erases a bank within its region, so any intersection at
/// all — partial, exact or containing — is destructive; only abutting
/// ranges are safe. Empty ranges never overlap anything.
#[cfg(feature = "set-certificate")]
fn ranges_overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    !a.is_empty() && !b.is_empty() && a.start < b.end && b.start < a.end
}

#[cfg(feature = "set-certificate")]
type CertStoreFlash = SpiFlash<DefaultSyscalls>;

/// One managed flash-backed endorsement/root chain installed by
/// SET_CERTIFICATE.
///
/// A region is dedicated to a single asymmetric algorithm for its
/// lifetime, fixed when the platform wires it up, and subdivided into two
/// equal A/B ping-pong banks so replacement writes stage in the inactive
/// bank while the active bank remains readable.
#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy)]
pub struct SingleManagedEndorsement {
    slot: u8,
    driver_num: u32,
    base: usize,
    capacity: usize,
    initialized: bool,
    active_bank: u8,
    active_sequence: u32,
    staging_bank: Option<u8>,
    algo: CertificateAlgorithm,
    len: usize,
    root_hash: [u8; 48],
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
    device_key: Option<DeviceKey>,
}

#[cfg(feature = "set-certificate")]
impl SingleManagedEndorsement {
    pub const fn new(
        slot: u8,
        algo: CertificateAlgorithm,
        driver_num: u32,
        base: usize,
        capacity: usize,
        device_key: Option<DeviceKey>,
    ) -> Self {
        Self {
            slot,
            driver_num,
            base,
            capacity,
            initialized: false,
            active_bank: 0,
            active_sequence: 0,
            staging_bank: None,
            algo,
            len: 0,
            root_hash: [0; 48],
            key_pair_id: 0,
            cert_info: 0,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            device_key,
        }
    }

    pub async fn load(&mut self) -> McuResult<()> {
        self.discard();
        if self.capacity % MANAGED_BANK_COUNT != 0 || self.der_capacity() == 0 {
            return Err(mcu_error::codes::INVARIANT);
        }
        let flash = self.flash();
        match flash.exists() {
            Ok(()) => {}
            Err(ErrorCode::NoDevice | ErrorCode::NoSupport | ErrorCode::Uninstalled) => {
                return Ok(())
            }
            Err(err) => return Err(map_flash_error(err)),
        }
        let mut selected: Option<(u8, ManagedRecord)> = None;
        for bank in 0..(MANAGED_BANK_COUNT as u8) {
            let Some(record) = self.load_bank(&flash, bank).await? else {
                continue;
            };
            let replace = match &selected {
                None => true,
                Some((_, current)) => record.sequence > current.sequence,
            };
            if replace {
                selected = Some((bank, record));
            }
        }
        if let Some((bank, record)) = selected {
            self.initialized = true;
            self.active_bank = bank;
            self.active_sequence = record.sequence;
            self.len = record.cert_len;
            self.root_hash = record.root_hash;
            self.key_pair_id = record.key_pair_id;
            self.cert_info = record.cert_info;
            self.key_usage_mask = record.key_usage_mask;
        }
        Ok(())
    }

    async fn load_bank(
        &self,
        flash: &CertStoreFlash,
        bank: u8,
    ) -> McuResult<Option<ManagedRecord>> {
        let mut header = [0u8; MANAGED_HEADER_SIZE];
        flash
            .read(self.bank_base(bank), MANAGED_HEADER_SIZE, &mut header)
            .await
            .map_err(map_flash_error)?;
        if header.iter().all(|&b| b == MANAGED_ERASED_BYTE) {
            return Ok(None);
        }
        let Some(record) = ManagedRecord::decode(&header) else {
            return Ok(None);
        };
        if self.validate_record(&record).is_err() {
            return Ok(None);
        }
        if self.stored_checksum(bank, record.cert_len).await? != record.data_checksum {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn validate_record(&self, record: &ManagedRecord) -> McuResult<()> {
        if self.capacity % MANAGED_BANK_COUNT != 0
            || record.version != MANAGED_FORMAT_VERSION
            || record.header_size as usize != MANAGED_HEADER_SIZE
            || record.slot != self.slot
            || record.algo != managed_algo_code(self.algo)
            || record.cert_len > self.der_capacity()
            || record.cert_len == 0
            || record.key_usage_mask != MANAGED_KEY_USAGE_MASK
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        self.validate_metadata(record.key_pair_id, record.cert_info)
    }

    fn validate_metadata(&self, key_pair_id: u8, cert_info: u8) -> McuResult<()> {
        let key = DeviceKey::from_key_pair_id(key_pair_id).ok_or(cert_errors::KEY_MISMATCH)?;
        if let Some(expected) = self.device_key {
            if key != expected {
                return Err(cert_errors::KEY_MISMATCH);
            }
        }
        key.validate_anchor_point()?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        Ok(())
    }

    pub(crate) fn validate_erase(&self) -> McuResult<()> {
        if let Some(key) = self.device_key {
            key.validate_anchor_point()?;
        }
        Ok(())
    }

    pub(crate) fn discard(&mut self) {
        self.initialized = false;
        self.active_bank = 0;
        self.active_sequence = 0;
        self.staging_bank = None;
        self.len = 0;
        self.root_hash = [0; 48];
        self.key_pair_id = 0;
        self.cert_info = 0;
    }

    pub(crate) fn abort_stream_update(&mut self) {
        self.staging_bank = None;
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub(crate) const fn active_bank(&self) -> Option<u8> {
        if self.initialized {
            Some(self.active_bank)
        } else {
            None
        }
    }

    pub(crate) const fn inactive_bank(&self) -> u8 {
        if self.initialized {
            1 - (self.active_bank & 1)
        } else {
            0
        }
    }

    const fn next_sequence(&self) -> u32 {
        self.active_sequence.wrapping_add(1)
    }

    /// The algorithm this region is dedicated to.
    pub const fn algo(&self) -> CertificateAlgorithm {
        self.algo
    }

    pub fn key_pair_id(&self) -> Option<u8> {
        self.initialized.then_some(self.key_pair_id)
    }

    pub fn cert_info(&self) -> Option<u8> {
        self.initialized.then_some(self.cert_info)
    }

    pub fn key_usage_mask(&self) -> Option<u16> {
        self.initialized.then_some(self.key_usage_mask)
    }

    fn root_cert_hash(&self, out: &mut [u8]) -> McuResult<()> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        let n = out.len().min(self.root_hash.len());
        out[..n].copy_from_slice(&self.root_hash[..n]);
        Ok(())
    }

    fn size(&self) -> McuResult<usize> {
        if self.initialized {
            Ok(self.len)
        } else {
            Err(mcu_error::codes::INVARIANT)
        }
    }

    async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.len - offset).min(buf.len());
        self.flash()
            .read(
                self.bank_data_base(self.active_bank) + offset,
                n,
                &mut buf[..n],
            )
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    pub async fn begin_stream_update(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        data_len: usize,
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if self.capacity % MANAGED_BANK_COUNT != 0
            || data_len == 0
            || data_len > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let target_bank = self.inactive_bank();
        self.flash()
            .erase(self.bank_base(target_bank), self.bank_capacity())
            .await
            .map_err(map_flash_error)?;
        self.staging_bank = Some(target_bank);
        Ok(self)
    }

    pub async fn write_stream_chunk(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        let end = offset
            .checked_add(data.len())
            .ok_or(mcu_error::codes::INVARIANT)?;
        if end > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if !data.is_empty() {
            self.flash()
                .write(self.bank_data_base(bank) + offset, data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        Ok(())
    }

    pub async fn read_stream_chunk(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        let bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        if offset >= self.der_capacity() || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.der_capacity() - offset).min(buf.len());
        self.flash()
            .read(self.bank_data_base(bank) + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    pub async fn finish_stream_update(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if self.capacity % MANAGED_BANK_COUNT != 0
            || data_len == 0
            || data_len > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        let data_checksum = self.stored_checksum(bank, data_len).await?;
        let sequence = self.next_sequence();
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: managed_algo_code(self.algo),
            key_pair_id,
            cert_info,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            cert_len: data_len,
            data_checksum,
            root_hash: *root_hash,
            sequence,
        };
        self.commit_record_to_bank(bank, &record).await?;
        self.initialized = true;
        self.active_bank = bank;
        self.active_sequence = sequence;
        self.staging_bank = None;
        self.len = data_len;
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    pub async fn write_updated(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if self.capacity % MANAGED_BANK_COUNT != 0
            || data.is_empty()
            || data.len() > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }

        let bank = self.inactive_bank();
        let expected_checksum = checksum(data);
        let sequence = self.next_sequence();
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: managed_algo_code(self.algo),
            key_pair_id,
            cert_info,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            cert_len: data.len(),
            data_checksum: expected_checksum,
            root_hash: *root_hash,
            sequence,
        };

        let flash = self.flash();
        flash
            .erase(self.bank_base(bank), self.bank_capacity())
            .await
            .map_err(map_flash_error)?;
        flash
            .write(self.bank_data_base(bank), data.len(), data)
            .await
            .map_err(map_flash_error)?;
        if self.stored_checksum(bank, data.len()).await? != expected_checksum {
            return Err(cert_errors::STORAGE_ERROR);
        }
        self.commit_record_to_bank(bank, &record).await?;

        self.initialized = true;
        self.active_bank = bank;
        self.active_sequence = sequence;
        self.staging_bank = None;
        self.len = data.len();
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    pub async fn erase_updated(mut self) -> McuResult<Self> {
        self.validate_erase()?;
        if self.capacity % MANAGED_BANK_COUNT != 0 {
            return Err(mcu_error::codes::INVARIANT);
        }
        let active_bank = self.active_bank & 1;
        let inactive_bank = 1 - active_bank;
        let bank_cap = self.bank_capacity();
        let flash = self.flash();
        // Erase the inactive (superseded) bank first, then the active bank, so
        // an interrupted erase can never resurrect an older bank after reset.
        flash
            .erase(self.bank_base(inactive_bank), bank_cap)
            .await
            .map_err(map_flash_error)?;
        flash
            .erase(self.bank_base(active_bank), bank_cap)
            .await
            .map_err(map_flash_error)?;
        self.discard();
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    async fn commit_record_to_bank(&self, bank: u8, record: &ManagedRecord) -> McuResult<()> {
        let mut header = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut header);
        self.flash()
            .write(self.bank_base(bank), MANAGED_HEADER_SIZE, &header)
            .await
            .map_err(map_flash_error)?;
        Ok(())
    }

    fn flash(&self) -> CertStoreFlash {
        CertStoreFlash::new(self.driver_num)
    }

    async fn stored_checksum(&self, bank: u8, len: usize) -> McuResult<u32> {
        let mut remaining = len;
        let mut offset = 0usize;
        let mut sum = 0u32;
        let mut chunk = [0u8; 256];
        let flash = self.flash();
        let data_base = self.bank_data_base(bank);
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            flash
                .read(data_base + offset, n, &mut chunk[..n])
                .await
                .map_err(map_flash_error)?;
            sum = sum.wrapping_add(checksum(&chunk[..n]));
            remaining -= n;
            offset += n;
        }
        Ok(sum)
    }

    pub(crate) const fn bank_capacity(&self) -> usize {
        self.capacity / MANAGED_BANK_COUNT
    }

    pub(crate) const fn bank_base(&self, bank: u8) -> usize {
        self.base + ((bank as usize) % MANAGED_BANK_COUNT) * self.bank_capacity()
    }

    const fn bank_data_base(&self, bank: u8) -> usize {
        self.bank_base(bank) + MANAGED_HEADER_SIZE
    }

    pub(crate) fn der_capacity(&self) -> usize {
        managed_endorsement_der_capacity(self.capacity)
    }

    /// The flash region this chain occupies, as a half-open range.
    pub fn region_range(&self) -> Range<usize> {
        self.base..self.base.saturating_add(self.capacity)
    }

    /// Whether this chain's flash region intersects `range` on the
    /// flash device `driver_num`.
    ///
    /// Regions on different devices never collide.
    pub fn region_overlaps(&self, driver_num: u32, range: &Range<usize>) -> bool {
        self.driver_num == driver_num && ranges_overlap(&self.region_range(), range)
    }
}

/// The managed flash regions backing one SPDM slot.
///
/// ECC is mandatory — a managed slot always has somewhere to put the
/// classical chain — while ML-DSA is optional so that a platform which
/// has not allocated a PQC region still builds and runs. A slot with
/// no ML-DSA region simply reports itself unprovisioned on an ML-DSA
/// connection.
#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy)]
pub struct ManagedEndorsementSlot {
    ecc: SingleManagedEndorsement,
    mldsa: Option<SingleManagedEndorsement>,
}

#[cfg(feature = "set-certificate")]
impl ManagedEndorsementSlot {
    pub const fn new(ecc: SingleManagedEndorsement) -> Self {
        debug_assert!(matches!(ecc.algo(), CertificateAlgorithm::EccP384));
        Self { ecc, mldsa: None }
    }

    pub const fn with_mldsa(mut self, mldsa: SingleManagedEndorsement) -> Self {
        debug_assert!(matches!(mldsa.algo(), CertificateAlgorithm::MlDsa87));
        self.mldsa = Some(mldsa);
        self
    }

    /// The endorsement region serving `algo`, or `None` if this slot has none.
    pub fn get_endorsement(&self, algo: CertificateAlgorithm) -> Option<&SingleManagedEndorsement> {
        match algo {
            CertificateAlgorithm::EccP384 => Some(&self.ecc),
            CertificateAlgorithm::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    /// Install an updated endorsement region, which must belong to this slot's
    /// algorithm for that position.
    pub fn set_endorsement(&mut self, endorsement: SingleManagedEndorsement) {
        match endorsement.algo() {
            CertificateAlgorithm::EccP384 => self.ecc = endorsement,
            CertificateAlgorithm::MlDsa87 => self.mldsa = Some(endorsement),
        }
    }

    /// Whether any of this slot's regions intersects `range` on the
    /// flash device `driver_num`.
    pub fn any_region_overlaps(&self, driver_num: u32, range: &Range<usize>) -> bool {
        self.ecc.region_overlaps(driver_num, range)
            || self
                .mldsa
                .as_ref()
                .is_some_and(|m| m.region_overlaps(driver_num, range))
    }
}

#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagedRecord {
    version: u16,
    header_size: u16,
    slot: u8,
    algo: u8,
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
    cert_len: usize,
    data_checksum: u32,
    root_hash: [u8; 48],
    sequence: u32,
}

#[cfg(feature = "set-certificate")]
impl ManagedRecord {
    fn encode(&self, out: &mut [u8; MANAGED_HEADER_SIZE]) {
        // Layout (matches decode below):
        //   [0..4]   magic ("SPCE")
        //   [4..6]   version (LE)
        //   [6..8]   header_size (LE)
        //   [8]      slot
        //   [9]      algo
        //   [10]     key_pair_id
        //   [11]     cert_info
        //   [12..14] key_usage_mask (LE)
        //   [14..16] reserved
        //   [16..20] cert_len (LE u32)
        //   [20..24] data_checksum (LE)
        //   [24..72] root_hash
        //   [72..76] sequence (LE u32)
        out[0..4].copy_from_slice(&MANAGED_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.header_size.to_le_bytes());
        out[8] = self.slot;
        out[9] = self.algo;
        out[10] = self.key_pair_id;
        out[11] = self.cert_info;
        out[12..14].copy_from_slice(&self.key_usage_mask.to_le_bytes());
        out[14..16].copy_from_slice(&[0, 0]);
        out[16..20].copy_from_slice(&(self.cert_len as u32).to_le_bytes());
        out[20..24].copy_from_slice(&self.data_checksum.to_le_bytes());
        out[24..72].copy_from_slice(&self.root_hash);
        out[72..76].copy_from_slice(&self.sequence.to_le_bytes());
    }

    fn decode(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let (magic, rest) = input.split_first_chunk::<4>()?;
        if magic != &MANAGED_MAGIC {
            return None;
        }
        let (version, rest) = rest.split_first_chunk::<2>()?;
        let (header_size, rest) = rest.split_first_chunk::<2>()?;
        let (slot, rest) = rest.split_first()?;
        let (algo, rest) = rest.split_first()?;
        let (key_pair_id, rest) = rest.split_first()?;
        let (cert_info, rest) = rest.split_first()?;
        let (kum, rest) = rest.split_first_chunk::<2>()?;
        let (_reserved, rest) = rest.split_first_chunk::<2>()?;
        let (cert_len, rest) = rest.split_first_chunk::<4>()?;
        let (data_checksum, rest) = rest.split_first_chunk::<4>()?;
        let (root_hash, rest) = rest.split_first_chunk::<48>()?;
        let (sequence, _) = rest.split_first_chunk::<4>()?;
        Some(Self {
            version: u16::from_le_bytes(*version),
            header_size: u16::from_le_bytes(*header_size),
            slot: *slot,
            algo: *algo,
            key_pair_id: *key_pair_id,
            cert_info: *cert_info,
            key_usage_mask: u16::from_le_bytes(*kum),
            cert_len: u32::from_le_bytes(*cert_len) as usize,
            data_checksum: u32::from_le_bytes(*data_checksum),
            root_hash: *root_hash,
            sequence: u32::from_le_bytes(*sequence),
        })
    }
}

#[cfg(feature = "set-certificate")]
fn checksum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32))
}

#[cfg(feature = "set-certificate")]
fn map_flash_error(err: ErrorCode) -> mcu_error::McuErrorCode {
    match err {
        ErrorCode::Busy => cert_errors::STORAGE_BUSY,
        _ => cert_errors::STORAGE_ERROR,
    }
}

#[cfg(all(test, feature = "set-certificate"))]
mod tests {
    extern crate std;

    use super::*;
    use CertificateAlgorithm as SpdmPalAsymAlgo;

    // Image partition exposed by FakeFlashDriver.
    const TEST_DRIVER: u32 = 0x8000_0006;
    const TEST_REGION: usize = 4096;

    fn chain(algo: SpdmPalAsymAlgo, base: usize) -> SingleManagedEndorsement {
        SingleManagedEndorsement::new(
            2,
            algo,
            TEST_DRIVER,
            base,
            TEST_REGION,
            Some(DeviceKey::LDevId),
        )
    }

    fn span(base: usize) -> Range<usize> {
        base..base + TEST_REGION
    }

    /// The shared predicate behind both the intra-slot check in
    /// `store.rs` and the cross-slot check here. A region update erases
    /// the whole region, so partial overlap is as destructive as exact
    /// aliasing; only abutting ranges are safe.
    #[test]
    fn ranges_overlap_detects_any_intersection() {
        let region = span(TEST_REGION);

        // Exact aliasing.
        assert!(ranges_overlap(&region, &span(TEST_REGION)));

        // Partial overlap from either side.
        assert!(ranges_overlap(&region, &span(TEST_REGION / 2)));
        assert!(ranges_overlap(
            &region,
            &span(TEST_REGION + TEST_REGION / 2)
        ));

        // Strict containment, both directions.
        assert!(ranges_overlap(&region, &(0..TEST_REGION * 4)));
        assert!(ranges_overlap(&(0..TEST_REGION * 4), &span(TEST_REGION)));

        // Abutting on either side is disjoint — the boundary case that
        // decides whether a back-to-back layout is legal.
        assert!(!ranges_overlap(&region, &span(0)));
        assert!(!ranges_overlap(&region, &span(TEST_REGION * 2)));

        // Empty ranges never overlap anything, including themselves or
        // when interior to a non-empty range.
        assert!(!ranges_overlap(&region, &(TEST_REGION..TEST_REGION)));
        assert!(!ranges_overlap(
            &(TEST_REGION..TEST_REGION),
            &(TEST_REGION..TEST_REGION)
        ));
        assert!(!ranges_overlap(
            &(TEST_REGION + 5..TEST_REGION + 5),
            &region
        ));
        assert!(!ranges_overlap(
            &region,
            &(TEST_REGION + 5..TEST_REGION + 5)
        ));
    }

    /// `region_overlaps` adds flash-device scoping on top of the range
    /// predicate: identical addresses on another device must not
    /// collide.
    #[test]
    fn region_overlap_is_scoped_to_one_flash_device() {
        let ecc = chain(SpdmPalAsymAlgo::EccP384, TEST_REGION);

        assert_eq!(ecc.region_range(), span(TEST_REGION));
        assert!(ecc.region_overlaps(TEST_DRIVER, &span(TEST_REGION)));
        assert!(!ecc.region_overlaps(TEST_DRIVER + 1, &span(TEST_REGION)));
    }

    /// Cross-slot collisions must be caught against either of a slot's
    /// regions, including the optional ML-DSA one.
    #[test]
    fn any_region_overlap_covers_both_algorithms() {
        let slot = ManagedEndorsementSlot::new(chain(SpdmPalAsymAlgo::EccP384, 0))
            .with_mldsa(chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION));

        assert!(slot.any_region_overlaps(TEST_DRIVER, &span(0)));
        assert!(slot.any_region_overlaps(TEST_DRIVER, &span(TEST_REGION)));
        assert!(!slot.any_region_overlaps(TEST_DRIVER, &span(TEST_REGION * 2)));

        // Without an ML-DSA region that address range is free.
        let ecc_only = ManagedEndorsementSlot::new(chain(SpdmPalAsymAlgo::EccP384, 0));
        assert!(!ecc_only.any_region_overlaps(TEST_DRIVER, &span(TEST_REGION)));
    }

    /// Each algorithm's region is provisioned independently: writing
    /// one must not make the slot appear provisioned for the other.
    /// Otherwise DIGESTS would advertise the slot and GET_CERTIFICATE
    /// would serve bytes signed under the wrong algorithm.
    #[test]
    fn managed_regions_are_provisioned_independently() {
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);

        // Nothing written yet: provisioned for neither.
        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        // Simulate a committed ECC endorsement without touching flash.
        ecc.initialized = true;
        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        let endorsement = SlotEndorsement::Managed(slot);
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        // And now the ML-DSA side as well.
        let mut mldsa = mldsa;
        mldsa.initialized = true;
        let endorsement =
            SlotEndorsement::Managed(ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa));
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));
    }

    /// A slot with no ML-DSA region must fail closed rather than fall
    /// back to serving its ECC chain.
    #[test]
    fn managed_slot_without_mldsa_region_fails_closed() {
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        ecc.initialized = true;
        ecc.len = 64;
        let endorsement = SlotEndorsement::Managed(ManagedEndorsementSlot::new(ecc));

        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        assert!(endorsement.size(SpdmPalAsymAlgo::EccP384).is_ok());
        assert!(endorsement.size(SpdmPalAsymAlgo::MlDsa87).is_err());

        let mut out = [0u8; 48];
        assert!(endorsement
            .root_cert_hash(SpdmPalAsymAlgo::EccP384, &mut out)
            .is_ok());
        assert!(endorsement
            .root_cert_hash(SpdmPalAsymAlgo::MlDsa87, &mut out)
            .is_err());
    }

    /// `set_endorsement` routes by the region's own algorithm, so committing
    /// an ML-DSA write cannot overwrite the ECC region.
    #[test]
    fn set_endorsement_routes_by_algorithm() {
        let ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);
        let mut slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);

        let mut updated = mldsa;
        updated.initialized = true;
        updated.len = 128;
        slot.set_endorsement(updated);

        assert!(!slot
            .get_endorsement(SpdmPalAsymAlgo::EccP384)
            .unwrap()
            .is_initialized());
        assert_eq!(
            slot.get_endorsement(SpdmPalAsymAlgo::MlDsa87)
                .unwrap()
                .size(),
            Ok(128)
        );
    }

    /// The ML-DSA code must be distinct so an ML-DSA region never
    /// accepts a record written by the ECC region, and vice versa.
    #[test]
    fn managed_algo_codes_are_distinct() {
        assert_eq!(
            managed_algo_code(SpdmPalAsymAlgo::EccP384),
            MANAGED_ALGO_ECC_P384
        );
        assert_eq!(
            managed_algo_code(SpdmPalAsymAlgo::MlDsa87),
            MANAGED_ALGO_MLDSA_87
        );
        assert_ne!(MANAGED_ALGO_ECC_P384, MANAGED_ALGO_MLDSA_87);
    }

    #[test]
    fn managed_record_round_trips() {
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: 2,
            algo: MANAGED_ALGO_ECC_P384,
            key_pair_id: 7,
            cert_info: 3,
            key_usage_mask: 0x0003,
            cert_len: 1234,
            data_checksum: 0xfeed_beef,
            root_hash: [0x5a; 48],
            sequence: 42,
        };
        let mut buf = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut buf);
        assert_eq!(&buf[0..4], &MANAGED_MAGIC);
        assert_eq!(ManagedRecord::decode(&buf), Some(record));
    }

    #[test]
    fn managed_capacity_excludes_header() {
        let endorsement = chain(SpdmPalAsymAlgo::EccP384, 0);
        assert_eq!(
            endorsement.der_capacity(),
            TEST_REGION / MANAGED_BANK_COUNT - MANAGED_HEADER_SIZE
        );
    }

    #[test]
    fn managed_der_capacity_obeys_cert_chain_format_limit() {
        assert_eq!(
            managed_endorsement_der_capacity(usize::MAX),
            u32::MAX as usize - SPDM_CERT_CHAIN_HEADER_SIZE
        );
    }

    #[test]
    fn managed_der_capacity_is_region_bound_past_64kib() {
        // ML-DSA chains routinely exceed the pre-1.4 64 KiB ceiling;
        // only the per-bank flash capacity should limit them now.
        let region = 256 * 1024;
        assert_eq!(
            managed_endorsement_der_capacity(region),
            region / MANAGED_BANK_COUNT - MANAGED_HEADER_SIZE
        );
        assert!(managed_endorsement_der_capacity(region) > u16::MAX as usize);
    }

    #[test]
    fn managed_endorsements_share_the_configured_key_pair_id() {
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mut mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);

        ecc.initialized = true;
        ecc.key_pair_id = 1;
        ecc.cert_info = CERT_MODEL_ALIAS_CERT;

        mldsa.initialized = true;
        mldsa.key_pair_id = 1;
        mldsa.cert_info = CERT_MODEL_ALIAS_CERT;

        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        assert_eq!(
            slot.get_endorsement(SpdmPalAsymAlgo::EccP384)
                .unwrap()
                .key_pair_id(),
            Some(1)
        );
        assert_eq!(
            slot.get_endorsement(SpdmPalAsymAlgo::MlDsa87)
                .unwrap()
                .key_pair_id(),
            Some(1)
        );
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let endorsement = slot.get_endorsement(algo).unwrap();
            assert_eq!(
                endorsement.validate_metadata(1, CERT_MODEL_ALIAS_CERT),
                Ok(())
            );
            assert_eq!(
                endorsement.validate_metadata(2, CERT_MODEL_ALIAS_CERT),
                Err(cert_errors::KEY_MISMATCH)
            );
        }
    }

    #[test]
    fn wrong_key_is_rejected_before_ordinary_or_streamed_flash_writes() {
        use futures::executor::block_on;

        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            for provisioned in [false, true] {
                let mut region = chain(algo, 0);
                region.initialized = provisioned;
                for id in [0, 2, 3, 255] {
                    assert_eq!(
                        block_on(region.write_updated(id, CERT_MODEL_ALIAS_CERT, &[0; 48], &[1]))
                            .err(),
                        Some(cert_errors::KEY_MISMATCH),
                    );
                    assert_eq!(
                        block_on(region.begin_stream_update(id, CERT_MODEL_ALIAS_CERT, 1)).err(),
                        Some(cert_errors::KEY_MISMATCH),
                    );
                }
            }
        }
    }

    #[test]
    fn none_policy_allows_explicit_supported_key_and_rejects_invalid_ids() {
        use futures::executor::block_on;

        let mut region = chain(SpdmPalAsymAlgo::EccP384, 0);
        region.device_key = None;
        assert_eq!(region.validate_metadata(1, CERT_MODEL_ALIAS_CERT), Ok(()));
        assert_eq!(
            region.validate_metadata(0, CERT_MODEL_ALIAS_CERT),
            Err(cert_errors::KEY_MISMATCH)
        );
        for id in [2, 3] {
            assert_eq!(
                region.validate_metadata(id, CERT_MODEL_ALIAS_CERT),
                Err(cert_errors::UNSUPPORTED_KEY)
            );
            assert_eq!(
                block_on(region.begin_stream_update(id, CERT_MODEL_ALIAS_CERT, 1)).err(),
                Some(cert_errors::UNSUPPORTED_KEY),
            );
        }
    }

    #[test]
    fn recovery_rejects_old_ids_and_unsupported_models() {
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let region = chain(algo, 0);
            let record = ManagedRecord {
                version: MANAGED_FORMAT_VERSION,
                header_size: MANAGED_HEADER_SIZE as u16,
                slot: 2,
                algo: managed_algo_code(algo),
                key_pair_id: 1,
                cert_info: CERT_MODEL_ALIAS_CERT,
                key_usage_mask: MANAGED_KEY_USAGE_MASK,
                cert_len: 123,
                data_checksum: 0,
                root_hash: [0; 48],
                sequence: 1,
            };
            assert_eq!(region.validate_record(&record), Ok(()));
            assert_eq!(
                region.validate_record(&ManagedRecord {
                    version: 1,
                    ..record
                }),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            for id in [0, 2, 3] {
                assert_eq!(
                    region.validate_record(&ManagedRecord {
                        key_pair_id: id,
                        ..record
                    }),
                    Err(cert_errors::KEY_MISMATCH),
                );
            }
            assert_eq!(
                region.validate_record(&ManagedRecord {
                    cert_info: 1,
                    ..record
                }),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            let mut unrestricted = region;
            unrestricted.device_key = None;
            assert_eq!(unrestricted.validate_record(&record), Ok(()));
            assert_eq!(
                unrestricted.validate_record(&ManagedRecord {
                    key_pair_id: 0,
                    ..record
                }),
                Err(cert_errors::KEY_MISMATCH),
            );
            assert_eq!(
                unrestricted.validate_record(&ManagedRecord {
                    key_pair_id: 2,
                    ..record
                }),
                Err(cert_errors::UNSUPPORTED_KEY),
            );
        }
    }

    #[test]
    fn stream_commit_rejects_key_and_model_before_flash_access() {
        use futures::executor::block_on;

        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let region = chain(algo, 0);
            for (id, model, error) in [
                (0, CERT_MODEL_ALIAS_CERT, cert_errors::KEY_MISMATCH),
                (2, CERT_MODEL_ALIAS_CERT, cert_errors::KEY_MISMATCH),
                (1, 1, cert_errors::INVALID_ENDORSEMENT),
            ] {
                assert_eq!(
                    block_on(region.finish_stream_update(id, model, &[3; 48], 100)).err(),
                    Some(error),
                );
            }
        }
    }

    #[test]
    fn discarding_data_does_not_change_the_binding() {
        let mut region = chain(SpdmPalAsymAlgo::EccP384, 0);
        region.initialized = true;
        region.key_pair_id = 1;
        region.cert_info = CERT_MODEL_ALIAS_CERT;
        region.discard();
        assert_eq!(region.key_pair_id(), None);
        assert_eq!(region.validate_metadata(1, CERT_MODEL_ALIAS_CERT), Ok(()));
        assert_eq!(
            region.validate_metadata(2, CERT_MODEL_ALIAS_CERT),
            Err(cert_errors::KEY_MISMATCH)
        );
    }

    #[test]
    fn flash_replacement_removal_and_recovery_preserve_the_configured_identity() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; 2 * TEST_REGION]);
        kernel.add_driver(&flash);
        // Provision ML-DSA first, with no ECC endorsement present.
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);
        let mldsa = fake::wait_for_future_ready(Box::pin(mldsa.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[2; 48],
            &[2; 16],
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(ecc.load())).unwrap();
        assert!(!ecc.is_initialized());
        assert_eq!(mldsa.key_pair_id(), Some(1));

        for (algo, base) in [
            (SpdmPalAsymAlgo::EccP384, 0),
            (SpdmPalAsymAlgo::MlDsa87, TEST_REGION),
        ] {
            let mut region = chain(algo, base);
            for byte in [3, 4] {
                region = fake::wait_for_future_ready(Box::pin(region.write_updated(
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[byte; 48],
                    &[byte; 16],
                )))
                .unwrap();
                let mut recovered = chain(algo, base);
                fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
                assert_eq!(recovered.key_pair_id(), Some(1));
                let mut data = [0; 16];
                assert_eq!(
                    fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut data))),
                    Ok(16)
                );
                assert_eq!(data, [byte; 16]);
            }
            let mut unrestricted = region;
            unrestricted.device_key = None;
            fake::wait_for_future_ready(Box::pin(unrestricted.load())).unwrap();
            assert_eq!(unrestricted.key_pair_id(), Some(1));
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert_eq!(region.key_pair_id(), Some(1));

            region = fake::wait_for_future_ready(Box::pin(region.erase_updated())).unwrap();
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert!(!region.is_initialized());
            region = fake::wait_for_future_ready(Box::pin(region.write_updated(
                1,
                CERT_MODEL_ALIAS_CERT,
                &[5; 48],
                &[5; 16],
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert_eq!(region.key_pair_id(), Some(1));
        }
    }

    #[test]
    fn streamed_flash_record_is_not_published_with_changed_metadata() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; TEST_REGION]);
        kernel.add_driver(&flash);
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let mut region = chain(algo, 0);
            region = fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
                1,
                CERT_MODEL_ALIAS_CERT,
                16,
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(region.write_stream_chunk(0, &[4; 8]))).unwrap();
            fake::wait_for_future_ready(Box::pin(region.write_stream_chunk(8, &[5; 8]))).unwrap();
            assert_eq!(
                fake::wait_for_future_ready(Box::pin(region.finish_stream_update(
                    2,
                    CERT_MODEL_ALIAS_CERT,
                    &[3; 48],
                    16,
                )))
                .err(),
                Some(cert_errors::KEY_MISMATCH),
            );
            let mut recovered = region;
            fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
            assert!(!recovered.is_initialized());
            region = fake::wait_for_future_ready(Box::pin(region.finish_stream_update(
                1,
                CERT_MODEL_ALIAS_CERT,
                &[3; 48],
                16,
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
            assert_eq!(recovered.key_pair_id(), Some(1));
            assert_eq!(region.key_pair_id(), Some(1));
        }
    }

    #[test]
    fn two_bank_ping_pong_preserves_active_bank_during_stream_and_abort() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; TEST_REGION]);
        kernel.add_driver(&flash);

        // 1. Initial write lands in Bank 0 with sequence 1.
        let region = chain(SpdmPalAsymAlgo::EccP384, 0);
        let region = fake::wait_for_future_ready(Box::pin(region.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x11; 48],
            &[0xAA; 16],
        )))
        .unwrap();
        assert_eq!(region.active_bank(), Some(0));
        assert_eq!(region.inactive_bank(), 1);

        // 2. Begin streaming replacement into Bank 1 while Bank 0 stays active and readable.
        let mut staging = fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            16,
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(staging.write_stream_chunk(0, &[0xBB; 16]))).unwrap();

        let mut active_bytes = [0u8; 16];
        assert_eq!(
            fake::wait_for_future_ready(Box::pin(staging.read(0, &mut active_bytes))),
            Ok(16)
        );
        assert_eq!(active_bytes, [0xAA; 16]);

        // Simulated power loss mid-stream: load() recovers Bank 0 because Bank 1 has no CMTD marker.
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_bank(), Some(0));
        let mut rec_bytes = [0u8; 16];
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xAA; 16]);

        // Aborting stream leaves Bank 0 intact.
        staging.abort_stream_update();
        assert!(staging.is_initialized());
        assert_eq!(staging.active_bank(), Some(0));

        // 3. Re-stream and commit to Bank 1 (sequence 2).
        let staging = fake::wait_for_future_ready(Box::pin(staging.begin_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            16,
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(staging.write_stream_chunk(0, &[0xBB; 16]))).unwrap();
        let region = fake::wait_for_future_ready(Box::pin(staging.finish_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x22; 48],
            16,
        )))
        .unwrap();
        assert_eq!(region.active_bank(), Some(1));
        fake::wait_for_future_ready(Box::pin(region.read(0, &mut active_bytes))).unwrap();
        assert_eq!(active_bytes, [0xBB; 16]);

        // Reboot recovery picks Bank 1 (sequence 2 > Bank 0 sequence 1).
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_bank(), Some(1));
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xBB; 16]);

        // 4. Third write ping-pongs back to Bank 0 (sequence 3).
        let region = fake::wait_for_future_ready(Box::pin(region.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x33; 48],
            &[0xCC; 16],
        )))
        .unwrap();
        assert_eq!(region.active_bank(), Some(0));
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_bank(), Some(0));
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xCC; 16]);
    }
}

#[cfg(test)]
mod algo_tests {
    use super::*;

    const ECC_CHAIN: &[&[u8]] = &[&[0x30, 0x01, 0x00]];
    const MLDSA_CHAIN: &[&[u8]] = &[&[0x30, 0x02, 0x00, 0x00]];

    #[test]
    fn read_only_slot_is_unprovisioned_for_missing_algorithm() {
        let ecc_only =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]));
        assert!(ecc_only.is_provisioned(CertificateAlgorithm::EccP384));
        // Without an ML-DSA chain the slot must not be advertised in an
        // ML-DSA connection: otherwise GET_CERTIFICATE would serve the
        // ECC chain against an ML-DSA negotiation.
        assert!(!ecc_only.is_provisioned(CertificateAlgorithm::MlDsa87));

        let both = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]).with_mldsa(MLDSA_CHAIN, [1u8; 48]),
        );
        assert!(both.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(both.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn empty_slot_is_never_provisioned() {
        let empty = SlotEndorsement::Empty;
        assert!(!empty.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!empty.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn cert_slot_metadata_consistency_and_write_lock() {
        let mut slot = CertSlot::empty(Some(1));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), None);
        assert_eq!(slot.cert_info(CertificateAlgorithm::EccP384), None);

        // Provision a read-only slot for both algorithms.
        slot.endorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]).with_mldsa(MLDSA_CHAIN, [1u8; 48]),
        );

        // Both algorithms expose the configured identity when provisioned.
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::EccP384),
            Some(CERT_MODEL_ALIAS_CERT)
        );
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::MlDsa87),
            Some(CERT_MODEL_ALIAS_CERT)
        );

        // When a write is in progress for ECC, the writer lock is active for ECC only,
        // while active-bank metadata remains readable for both algorithms.
        slot.set_write_in_progress(CertificateAlgorithm::EccP384, true);
        assert!(slot.write_in_progress(CertificateAlgorithm::EccP384));
        assert!(!slot.write_in_progress(CertificateAlgorithm::MlDsa87));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::EccP384),
            Some(CERT_MODEL_ALIAS_CERT)
        );
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::MlDsa87),
            Some(CERT_MODEL_ALIAS_CERT)
        );

        slot.set_write_in_progress(CertificateAlgorithm::EccP384, false);
        assert!(!slot.write_in_progress(CertificateAlgorithm::EccP384));
    }

    #[test]
    fn configured_identity_is_hidden_for_an_absent_algorithm() {
        let mut slot = CertSlot::empty(Some(1));
        slot.endorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0; 48]));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), None);
        assert_eq!(slot.cert_info(CertificateAlgorithm::MlDsa87), None);
    }
}
