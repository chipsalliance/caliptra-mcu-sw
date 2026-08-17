// Licensed under the Apache-2.0 license

//! Cert slot and endorsement chain types.
//!
//! Each SPDM slot is represented by a [`CertSlot`] which holds slot
//! certificate bytes and per-slot metadata. The backing storage is an
//! enum ([`SlotEndorsement`]) dispatching to `ReadOnly` (slot 0)
//! or `Managed` (slots 1-2) without dynamic dispatch.

#[cfg(feature = "set-certificate")]
use caliptra_mcu_libsyscall_caliptra::{flash::SpiFlash, DefaultSyscalls};
#[cfg(feature = "set-certificate")]
use caliptra_mcu_libtock_platform::ErrorCode;
#[cfg(feature = "set-certificate")]
use caliptra_mcu_spdm_traits::CertWriteSession;
use caliptra_mcu_spdm_traits::SpdmPalAsymAlgo;
use mcu_error::McuResult;

#[cfg(feature = "set-certificate")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU32, Ordering};

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

/// A single SPDM certificate slot.
///
/// Slots store the endorsement/root portion. The PAL composes the full
/// SPDM cert chain by appending the DPE device chain and DPE leaf cert.
pub struct CertSlot {
    /// Slot certificate-chain backing storage.
    pub endorsement: SlotEndorsement,
    /// KeyPairID associated with this slot's signing key.
    /// `None` for unprovisioned slots.
    pub key_pair_id: Option<u8>,
    /// CertificateInfo/CertModel associated with this slot.
    /// `None` for unprovisioned slots.
    pub cert_info: Option<u8>,
    /// True while the current write session owns inactive-bank staging.
    #[cfg(feature = "set-certificate")]
    write_in_progress: AtomicBool,
    /// Volatile identity for the currently authorized streaming write.
    #[cfg(feature = "set-certificate")]
    write_session_epoch: AtomicU32,
    /// Bumped when this slot's endorsement/provisioning state changes.
    pub provisioning_state_version: AtomicU32,
}

impl CertSlot {
    pub const fn empty() -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id: None,
            cert_info: None,
            #[cfg(feature = "set-certificate")]
            write_in_progress: AtomicBool::new(false),
            #[cfg(feature = "set-certificate")]
            write_session_epoch: AtomicU32::new(0),
            provisioning_state_version: AtomicU32::new(0),
        }
    }

    pub fn is_supported(&self) -> bool {
        self.endorsement.is_supported()
    }

    pub fn is_writable(&self) -> bool {
        self.endorsement.is_writable()
    }

    pub fn is_provisioned(&self) -> bool {
        self.endorsement.is_provisioned()
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn begin_write_session(&self, slot: u8) -> CertWriteSession {
        critical_section::with(|_| {
            let epoch = self
                .write_session_epoch
                .load(Ordering::Acquire)
                .wrapping_add(1);
            self.write_session_epoch.store(epoch, Ordering::Release);
            self.write_in_progress.store(true, Ordering::Release);
            CertWriteSession::new(slot, epoch)
        })
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn write_session_matches(&self, slot: u8, session: CertWriteSession) -> bool {
        session.matches_slot(slot)
            && self.write_in_progress.load(Ordering::Acquire)
            && self.write_session_epoch.load(Ordering::Acquire) == session.epoch()
    }

    #[cfg(feature = "set-certificate")]
    pub(crate) fn end_write_session(&self, slot: u8, session: CertWriteSession) -> bool {
        critical_section::with(|_| {
            if self.write_session_matches(slot, session) {
                self.write_in_progress.store(false, Ordering::Release);
                true
            } else {
                false
            }
        })
    }

    pub fn provisioning_state_version(&self) -> u32 {
        self.provisioning_state_version.load(Ordering::Acquire)
    }

    pub fn bump_provisioning_state_version(&self) {
        critical_section::with(|_| {
            let version = self.provisioning_state_version.load(Ordering::Acquire);
            self.provisioning_state_version
                .store(version.wrapping_add(1), Ordering::Release);
        });
    }

    pub fn clear_metadata(&mut self) {
        self.key_pair_id = None;
        self.cert_info = None;
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
#[derive(Clone, Copy)]
pub enum SlotEndorsement {
    /// Not provisioned and not exposed as a supported SPDM slot.
    Empty,
    /// Read-only endorsement backed by static root CA certs (slot 0).
    ReadOnly(ReadOnlyEndorsement),
    /// Managed endorsement/root chain backed by flash (slots 1-2, SET_CERTIFICATE).
    #[cfg(feature = "set-certificate")]
    Managed(ManagedEndorsement),
}

impl SlotEndorsement {
    pub fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
        match self {
            Self::ReadOnly(e) => e.root_cert_hash(algo, out),
            #[cfg(feature = "set-certificate")]
            Self::Managed(e) => e.root_cert_hash(algo, out),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn size(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            #[cfg(feature = "set-certificate")]
            Self::Managed(e) => e.size(algo),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn capacity(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            #[cfg(feature = "set-certificate")]
            Self::Managed(e) => e.capacity(algo),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub async fn read(
        &self,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.read(algo, offset, buf),
            #[cfg(feature = "set-certificate")]
            Self::Managed(e) => e.read(algo, offset, buf).await,
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
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

    pub fn is_provisioned(&self) -> bool {
        match self {
            Self::ReadOnly(_) => true,
            #[cfg(feature = "set-certificate")]
            Self::Managed(e) => e.is_initialized(),
            Self::Empty => false,
        }
    }
}

/// Read-only endorsement — static root CA cert chain.
#[derive(Clone, Copy)]
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
        // Copies `min(out.len(), root_cert_hash.len())` bytes with no
        // length-equality check, so no `copy_from_slice` panic path.
        for (d, s) in out.iter_mut().zip(&self.root_cert_hash) {
            *d = *s;
        }
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
        Ok(pos)
    }
}

#[cfg(feature = "set-certificate")]
const MANAGED_MAGIC: [u8; 4] = *b"SPCE";
#[cfg(feature = "set-certificate")]
const MANAGED_LEGACY_FORMAT_VERSION: u16 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_FORMAT_VERSION: u16 = 2;
#[cfg(feature = "set-certificate")]
const MANAGED_HEADER_SIZE: usize = 80;
#[cfg(feature = "set-certificate")]
const MANAGED_ALGO_ECC_P384: u8 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_ERASED_BYTE: u8 = 0xFF;
#[cfg(feature = "set-certificate")]
const MANAGED_KEY_USAGE_MASK: u16 = 0x0003;
#[cfg(feature = "set-certificate")]
const MANAGED_MAX_DER_LEN: usize = (u16::MAX as usize) - 52;
#[cfg(feature = "set-certificate")]
const MANAGED_RECORD_DATA: u8 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_RECORD_TOMBSTONE: u8 = 2;
#[cfg(feature = "set-certificate")]
const MANAGED_COMMIT_OFFSET: usize = MANAGED_HEADER_SIZE - size_of::<u32>();
#[cfg(feature = "set-certificate")]
const MANAGED_COMMIT_TAG: u32 = 0x4345_5254;

#[cfg(feature = "set-certificate")]
type CertStoreFlash = SpiFlash<DefaultSyscalls>;

/// Managed flash-backed endorsement/root chain installed by SET_CERTIFICATE.
#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy)]
pub struct ManagedEndorsement {
    slot: u8,
    driver_nums: [u32; 2],
    base: usize,
    capacity: usize,
    active_bank: Option<usize>,
    staging_bank: Option<usize>,
    staging_data_len: Option<usize>,
    staging_next_offset: usize,
    generation: u32,
    initialized: bool,
    algo: SpdmPalAsymAlgo,
    len: usize,
    root_hash: [u8; 48],
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
}

#[cfg(feature = "set-certificate")]
impl ManagedEndorsement {
    pub const fn new(
        slot: u8,
        driver_num: u32,
        backup_driver_num: u32,
        base: usize,
        capacity: usize,
    ) -> Self {
        Self {
            slot,
            driver_nums: [driver_num, backup_driver_num],
            base,
            capacity,
            active_bank: None,
            staging_bank: None,
            staging_data_len: None,
            staging_next_offset: 0,
            generation: 0,
            initialized: false,
            algo: SpdmPalAsymAlgo::EccP384,
            len: 0,
            root_hash: [0; 48],
            key_pair_id: 0,
            cert_info: 0,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
        }
    }

    pub async fn load(&mut self) -> McuResult<()> {
        self.clear_active_state();
        self.active_bank = None;
        self.staging_bank = None;
        self.staging_data_len = None;
        self.staging_next_offset = 0;
        self.generation = 0;

        let primary = self.load_bank(0).await?;
        let backup = self.load_bank(1).await?;
        let Some((bank, record)) = self.select_active_record(primary, backup) else {
            return Ok(());
        };

        self.active_bank = Some(bank);
        self.generation = record.generation;
        if record.kind == ManagedRecordKind::Tombstone {
            return Ok(());
        }

        self.initialized = true;
        self.algo = SpdmPalAsymAlgo::EccP384;
        self.len = record.cert_len;
        self.root_hash = record.root_hash;
        self.key_pair_id = record.key_pair_id;
        self.cert_info = record.cert_info;
        self.key_usage_mask = record.key_usage_mask;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
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

    fn root_cert_hash(&self, _algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        let n = out.len().min(self.root_hash.len());
        out[..n].copy_from_slice(&self.root_hash[..n]);
        Ok(())
    }

    fn size(&self, _algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        if self.initialized {
            Ok(self.len)
        } else {
            Err(mcu_error::codes::INVARIANT)
        }
    }

    fn capacity(&self, _algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        Ok(self.der_capacity())
    }

    async fn read(
        &self,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.len - offset).min(buf.len());
        let active_bank = self.active_bank.ok_or(mcu_error::codes::INVARIANT)?;
        self.flash(active_bank)
            .read(self.data_base(active_bank) + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    pub async fn begin_stream_update(
        mut self,
        algo: SpdmPalAsymAlgo,
        data_len: usize,
    ) -> McuResult<Self> {
        if algo != SpdmPalAsymAlgo::EccP384 || data_len == 0 || data_len > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let staging_bank = self.inactive_bank();
        self.flash(staging_bank)
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        self.staging_bank = Some(staging_bank);
        self.staging_data_len = Some(data_len);
        self.staging_next_offset = 0;
        Ok(self)
    }

    pub async fn write_stream_chunk(mut self, offset: usize, data: &[u8]) -> McuResult<Self> {
        let staging_bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        let end = self.stream_chunk_end(offset, data.len())?;
        if !data.is_empty() {
            self.flash(staging_bank)
                .write(self.data_base(staging_bank) + offset, data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        self.staging_next_offset = end;
        Ok(self)
    }

    pub async fn read_stream_chunk(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        let staging_data_len = self.staging_data_len.ok_or(mcu_error::codes::INVARIANT)?;
        if offset >= staging_data_len || buf.is_empty() {
            return Ok(0);
        }
        let n = (staging_data_len - offset).min(buf.len());
        let staging_bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        self.flash(staging_bank)
            .read(self.data_base(staging_bank) + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    pub async fn finish_stream_update(
        mut self,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<Self> {
        if algo != SpdmPalAsymAlgo::EccP384 || data_len > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let staging_bank = self.staging_bank.ok_or(mcu_error::codes::INVARIANT)?;
        if !self.stream_is_complete(data_len) {
            return Err(mcu_error::codes::INVARIANT);
        }
        let data_checksum = self.stored_crc32(staging_bank, data_len).await?;
        let record = self.data_record(key_pair_id, cert_info, root_hash, data_len, data_checksum);
        self.write_record(staging_bank, &record).await?;
        self.publish_data(staging_bank, algo, &record);
        Ok(self)
    }

    pub async fn write_updated(
        mut self,
        algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<Self> {
        if algo != SpdmPalAsymAlgo::EccP384 || data.len() > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }

        let staging_bank = self.inactive_bank();
        let flash = self.flash(staging_bank);
        flash
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        if !data.is_empty() {
            flash
                .write(self.data_base(staging_bank), data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        let record = self.data_record(key_pair_id, cert_info, root_hash, data.len(), crc32(data));
        self.write_record(staging_bank, &record).await?;
        self.publish_data(staging_bank, algo, &record);
        Ok(self)
    }

    pub async fn erase_updated(mut self, _algo: SpdmPalAsymAlgo) -> McuResult<Self> {
        let staging_bank = self.inactive_bank();
        self.flash(staging_bank)
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        let record = ManagedRecord::tombstone(self.slot, self.next_generation());
        self.write_record(staging_bank, &record).await?;
        self.publish_tombstone(staging_bank, &record);
        Ok(self)
    }

    pub fn abort_stream_update(mut self) -> Self {
        self.staging_bank = None;
        self.staging_data_len = None;
        self.staging_next_offset = 0;
        self
    }

    fn flash(&self, bank: usize) -> CertStoreFlash {
        CertStoreFlash::new(self.driver_nums[bank])
    }

    async fn load_bank(&self, bank: usize) -> McuResult<Option<ManagedRecord>> {
        let flash = self.flash(bank);
        match flash.exists() {
            Ok(()) => {}
            Err(ErrorCode::NoDevice | ErrorCode::NoSupport | ErrorCode::Uninstalled) => {
                return Ok(None)
            }
            Err(err) => return Err(map_flash_error(err)),
        }

        let mut header = [0u8; MANAGED_HEADER_SIZE];
        flash
            .read(self.base, MANAGED_HEADER_SIZE, &mut header)
            .await
            .map_err(map_flash_error)?;
        if header.iter().all(|&b| b == MANAGED_ERASED_BYTE) || header[0..4] != MANAGED_MAGIC {
            return Ok(None);
        }

        let Some(record) = ManagedRecord::decode(&header) else {
            return Ok(None);
        };
        if !record.is_valid_for(self.slot, self.der_capacity()) {
            return Ok(None);
        }
        if record.kind == ManagedRecordKind::Data {
            let data_checksum = if record.version == MANAGED_LEGACY_FORMAT_VERSION {
                self.stored_legacy_checksum(bank, record.cert_len).await?
            } else {
                self.stored_crc32(bank, record.cert_len).await?
            };
            if data_checksum != record.data_checksum {
                return Ok(None);
            }
        }
        Ok(Some(record))
    }

    fn select_active_record(
        &self,
        primary: Option<ManagedRecord>,
        backup: Option<ManagedRecord>,
    ) -> Option<(usize, ManagedRecord)> {
        match (primary, backup) {
            (Some(primary), Some(backup)) => {
                if generation_is_newer(backup.generation, primary.generation) {
                    Some((1, backup))
                } else {
                    // Equal generations are not expected for a completed
                    // transaction. Prefer the original bank deterministically.
                    Some((0, primary))
                }
            }
            (Some(record), None) => Some((0, record)),
            (None, Some(record)) => Some((1, record)),
            (None, None) => None,
        }
    }

    fn inactive_bank(&self) -> usize {
        self.active_bank.map(|bank| 1 - bank).unwrap_or(0)
    }

    fn next_generation(&self) -> u32 {
        self.generation.wrapping_add(1)
    }

    fn data_record(
        &self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        cert_len: usize,
        data_checksum: u32,
    ) -> ManagedRecord {
        ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: MANAGED_ALGO_ECC_P384,
            key_pair_id,
            cert_info,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            kind: ManagedRecordKind::Data,
            generation: self.next_generation(),
            cert_len,
            data_checksum,
            root_hash: *root_hash,
        }
    }

    async fn write_record(&self, bank: usize, record: &ManagedRecord) -> McuResult<()> {
        let mut header = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut header);
        let flash = self.flash(bank);
        flash
            .write(self.base, MANAGED_HEADER_SIZE, &header)
            .await
            .map_err(map_flash_error)?;

        // The computed marker covers the header and is written separately,
        // after every staged byte and the uncommitted header are durable.
        let commit = ManagedRecord::commit_word(&header).to_le_bytes();
        flash
            .write(self.base + MANAGED_COMMIT_OFFSET, commit.len(), &commit)
            .await
            .map_err(map_flash_error)
    }

    fn publish_data(&mut self, bank: usize, algo: SpdmPalAsymAlgo, record: &ManagedRecord) {
        self.active_bank = Some(bank);
        self.clear_staging_state();
        self.generation = record.generation;
        self.initialized = true;
        self.algo = algo;
        self.len = record.cert_len;
        self.root_hash = record.root_hash;
        self.key_pair_id = record.key_pair_id;
        self.cert_info = record.cert_info;
        self.key_usage_mask = record.key_usage_mask;
    }

    fn publish_tombstone(&mut self, bank: usize, record: &ManagedRecord) {
        self.active_bank = Some(bank);
        self.clear_staging_state();
        self.generation = record.generation;
        self.clear_active_state();
    }

    fn clear_active_state(&mut self) {
        self.initialized = false;
        self.algo = SpdmPalAsymAlgo::EccP384;
        self.len = 0;
        self.root_hash = [0; 48];
        self.key_pair_id = 0;
        self.cert_info = 0;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
    }

    fn clear_staging_state(&mut self) {
        self.staging_bank = None;
        self.staging_data_len = None;
        self.staging_next_offset = 0;
    }

    fn stream_is_complete(&self, data_len: usize) -> bool {
        self.staging_data_len == Some(data_len) && self.staging_next_offset == data_len
    }

    fn stream_chunk_end(&self, offset: usize, len: usize) -> McuResult<usize> {
        let staging_data_len = self.staging_data_len.ok_or(mcu_error::codes::INVARIANT)?;
        if offset != self.staging_next_offset {
            return Err(mcu_error::codes::INVARIANT);
        }
        let end = offset.checked_add(len).ok_or(mcu_error::codes::INVARIANT)?;
        if end > staging_data_len {
            return Err(mcu_error::codes::INVARIANT);
        }
        Ok(end)
    }

    async fn stored_crc32(&self, bank: usize, len: usize) -> McuResult<u32> {
        let mut remaining = len;
        let mut offset = 0usize;
        let mut crc = !0u32;
        let mut chunk = [0u8; 256];
        let flash = self.flash(bank);
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            flash
                .read(self.data_base(bank) + offset, n, &mut chunk[..n])
                .await
                .map_err(map_flash_error)?;
            crc = crc32_update(crc, &chunk[..n]);
            remaining -= n;
            offset += n;
        }
        Ok(!crc)
    }

    async fn stored_legacy_checksum(&self, bank: usize, len: usize) -> McuResult<u32> {
        let mut remaining = len;
        let mut offset = 0usize;
        let mut sum = 0u32;
        let mut chunk = [0u8; 256];
        let flash = self.flash(bank);
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            flash
                .read(self.data_base(bank) + offset, n, &mut chunk[..n])
                .await
                .map_err(map_flash_error)?;
            sum = sum.wrapping_add(legacy_checksum(&chunk[..n]));
            remaining -= n;
            offset += n;
        }
        Ok(sum)
    }

    fn data_base(&self, _bank: usize) -> usize {
        self.base + MANAGED_HEADER_SIZE
    }

    fn der_capacity(&self) -> usize {
        self.capacity
            .saturating_sub(MANAGED_HEADER_SIZE)
            .min(MANAGED_MAX_DER_LEN)
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
    kind: ManagedRecordKind,
    generation: u32,
    cert_len: usize,
    data_checksum: u32,
    root_hash: [u8; 48],
}

#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedRecordKind {
    Data,
    Tombstone,
}

#[cfg(feature = "set-certificate")]
impl ManagedRecord {
    fn encode(&self, out: &mut [u8; MANAGED_HEADER_SIZE]) {
        // Layout (matches decode below):
        //   [0..4]   magic
        //   [4..6]   version (LE)
        //   [6..8]   header_size (LE)
        //   [8]      slot
        //   [9]      algo
        //   [10]     key_pair_id
        //   [11]     cert_info
        //   [12..14] key_usage_mask (LE)
        //   [14]     record kind
        //   [15]     reserved (zero)
        //   [16..20] record generation (LE)
        //   [20..24] cert_len (LE u32)
        //   [24..28] payload CRC-32 (LE)
        //   [28..76] root_hash
        //   [76..80] commit marker, written separately
        out.fill(MANAGED_ERASED_BYTE);
        let (magic, rest) = out.split_first_chunk_mut::<4>().unwrap();
        *magic = MANAGED_MAGIC;
        let (version, rest) = rest.split_first_chunk_mut::<2>().unwrap();
        *version = self.version.to_le_bytes();
        let (hdr_size, rest) = rest.split_first_chunk_mut::<2>().unwrap();
        *hdr_size = self.header_size.to_le_bytes();
        rest[0] = self.slot;
        rest[1] = self.algo;
        rest[2] = self.key_pair_id;
        rest[3] = self.cert_info;
        let rest = &mut rest[4..];
        let (kum, rest) = rest.split_first_chunk_mut::<2>().unwrap();
        *kum = self.key_usage_mask.to_le_bytes();
        rest[0] = match self.kind {
            ManagedRecordKind::Data => MANAGED_RECORD_DATA,
            ManagedRecordKind::Tombstone => MANAGED_RECORD_TOMBSTONE,
        };
        rest[1] = 0;
        let rest = &mut rest[2..];
        let (generation, rest) = rest.split_first_chunk_mut::<4>().unwrap();
        *generation = self.generation.to_le_bytes();
        let (len, rest) = rest.split_first_chunk_mut::<4>().unwrap();
        *len = (self.cert_len as u32).to_le_bytes();
        let (chk, rest) = rest.split_first_chunk_mut::<4>().unwrap();
        *chk = self.data_checksum.to_le_bytes();
        let (rh, _) = rest.split_first_chunk_mut::<48>().unwrap();
        *rh = self.root_hash;
    }

    fn decode(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let version = u16::from_le_bytes(*input.get(4..6)?.first_chunk::<2>()?);
        match version {
            MANAGED_LEGACY_FORMAT_VERSION => Self::decode_legacy(input),
            MANAGED_FORMAT_VERSION => Self::decode_current(input),
            _ => None,
        }
    }

    fn decode_legacy(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let header_size = u16::from_le_bytes(*input.get(6..8)?.first_chunk::<2>()?);
        let key_usage_mask = u16::from_le_bytes(*input.get(12..14)?.first_chunk::<2>()?);
        let cert_len = u32::from_le_bytes(*input.get(16..20)?.first_chunk::<4>()?) as usize;
        let data_checksum = u32::from_le_bytes(*input.get(20..24)?.first_chunk::<4>()?);
        Some(Self {
            version: MANAGED_LEGACY_FORMAT_VERSION,
            header_size,
            slot: *input.get(8)?,
            algo: *input.get(9)?,
            key_pair_id: *input.get(10)?,
            cert_info: *input.get(11)?,
            key_usage_mask,
            kind: ManagedRecordKind::Data,
            generation: 0,
            cert_len,
            data_checksum,
            root_hash: *input.get(24..72)?.first_chunk::<48>()?,
        })
    }

    fn decode_current(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let stored_commit =
            u32::from_le_bytes(*input.get(MANAGED_COMMIT_OFFSET..)?.first_chunk::<4>()?);
        if stored_commit != Self::commit_word(input) {
            return None;
        }
        let header_size = u16::from_le_bytes(*input.get(6..8)?.first_chunk::<2>()?);
        let key_usage_mask = u16::from_le_bytes(*input.get(12..14)?.first_chunk::<2>()?);
        let kind = match *input.get(14)? {
            MANAGED_RECORD_DATA => ManagedRecordKind::Data,
            MANAGED_RECORD_TOMBSTONE => ManagedRecordKind::Tombstone,
            _ => return None,
        };
        let generation = u32::from_le_bytes(*input.get(16..20)?.first_chunk::<4>()?);
        let cert_len = u32::from_le_bytes(*input.get(20..24)?.first_chunk::<4>()?) as usize;
        let data_checksum = u32::from_le_bytes(*input.get(24..28)?.first_chunk::<4>()?);
        Some(Self {
            version: MANAGED_FORMAT_VERSION,
            header_size,
            slot: *input.get(8)?,
            algo: *input.get(9)?,
            key_pair_id: *input.get(10)?,
            cert_info: *input.get(11)?,
            key_usage_mask,
            kind,
            generation,
            cert_len,
            data_checksum,
            root_hash: *input.get(28..76)?.first_chunk::<48>()?,
        })
    }

    fn tombstone(slot: u8, generation: u32) -> Self {
        Self {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot,
            algo: MANAGED_ALGO_ECC_P384,
            key_pair_id: 0,
            cert_info: 0,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            kind: ManagedRecordKind::Tombstone,
            generation,
            cert_len: 0,
            data_checksum: 0,
            root_hash: [0; 48],
        }
    }

    fn is_valid_for(&self, slot: u8, capacity: usize) -> bool {
        matches!(
            self.version,
            MANAGED_LEGACY_FORMAT_VERSION | MANAGED_FORMAT_VERSION
        ) && self.header_size as usize == MANAGED_HEADER_SIZE
            && self.slot == slot
            && self.algo == MANAGED_ALGO_ECC_P384
            && match self.kind {
                ManagedRecordKind::Data => self.cert_len <= capacity,
                ManagedRecordKind::Tombstone => {
                    self.cert_len == 0
                        && self.data_checksum == 0
                        && self.root_hash == [0; 48]
                        && self.key_pair_id == 0
                        && self.cert_info == 0
                }
            }
    }

    fn commit_word(header: &[u8; MANAGED_HEADER_SIZE]) -> u32 {
        let commit = crc32(&header[..MANAGED_COMMIT_OFFSET]) ^ MANAGED_COMMIT_TAG;
        if commit == u32::MAX {
            0
        } else {
            commit
        }
    }
}

#[cfg(feature = "set-certificate")]
fn generation_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
}

#[cfg(feature = "set-certificate")]
fn legacy_checksum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32))
}

#[cfg(feature = "set-certificate")]
fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0u32, data)
}

#[cfg(feature = "set-certificate")]
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    crc
}

#[cfg(feature = "set-certificate")]
fn map_flash_error(err: ErrorCode) -> mcu_error::McuErrorCode {
    use caliptra_mcu_spdm_codec::errors::*;

    match err {
        ErrorCode::Busy => SPDM_BUSY,
        _ => SPDM_OPERATION_FAILED,
    }
}

#[cfg(all(test, feature = "set-certificate"))]
mod tests {
    use super::*;

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
            kind: ManagedRecordKind::Data,
            generation: 42,
            cert_len: 1234,
            data_checksum: 0xfeed_beef,
            root_hash: [0x5a; 48],
        };
        let mut buf = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut buf);
        assert_eq!(&buf[0..4], &MANAGED_MAGIC);
        assert_eq!(ManagedRecord::decode(&buf), None);
        let commit = ManagedRecord::commit_word(&buf).to_le_bytes();
        buf[MANAGED_COMMIT_OFFSET..].copy_from_slice(&commit);
        assert_eq!(ManagedRecord::decode(&buf), Some(record));

        buf[28] ^= 1;
        assert_eq!(ManagedRecord::decode(&buf), None);
    }

    #[test]
    fn managed_capacity_excludes_header() {
        let endorsement = ManagedEndorsement::new(2, 0x7000_000A, 0x7000_000C, 0, 4096);
        assert_eq!(endorsement.der_capacity(), 4096 - MANAGED_HEADER_SIZE);
    }

    #[test]
    fn newer_generation_selects_backup_record() {
        let endorsement = ManagedEndorsement::new(2, 0x7000_000A, 0x7000_000C, 0, 4096);
        let primary = ManagedRecord::tombstone(2, 4);
        let backup = ManagedRecord::tombstone(2, 5);
        assert_eq!(
            endorsement.select_active_record(Some(primary), Some(backup)),
            Some((1, backup))
        );
    }

    #[test]
    fn legacy_record_remains_loadable() {
        let mut buf = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        buf[..4].copy_from_slice(&MANAGED_MAGIC);
        buf[4..6].copy_from_slice(&MANAGED_LEGACY_FORMAT_VERSION.to_le_bytes());
        buf[6..8].copy_from_slice(&(MANAGED_HEADER_SIZE as u16).to_le_bytes());
        buf[8] = 2;
        buf[9] = MANAGED_ALGO_ECC_P384;
        buf[10] = 7;
        buf[11] = 3;
        buf[12..14].copy_from_slice(&MANAGED_KEY_USAGE_MASK.to_le_bytes());
        buf[16..20].copy_from_slice(&1234u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0xfeed_beefu32.to_le_bytes());
        buf[24..72].fill(0x5a);

        assert_eq!(
            ManagedRecord::decode(&buf),
            Some(ManagedRecord {
                version: MANAGED_LEGACY_FORMAT_VERSION,
                header_size: MANAGED_HEADER_SIZE as u16,
                slot: 2,
                algo: MANAGED_ALGO_ECC_P384,
                key_pair_id: 7,
                cert_info: 3,
                key_usage_mask: MANAGED_KEY_USAGE_MASK,
                kind: ManagedRecordKind::Data,
                generation: 0,
                cert_len: 1234,
                data_checksum: 0xfeed_beef,
                root_hash: [0x5a; 48],
            })
        );
    }

    #[test]
    fn crc32_matches_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn generation_advances() {
        let slot = CertSlot::empty();
        assert_eq!(slot.provisioning_state_version(), 0);
        slot.bump_provisioning_state_version();
        assert_eq!(slot.provisioning_state_version(), 1);
    }

    #[test]
    fn newer_write_session_supersedes_older_callbacks() {
        let slot = CertSlot::empty();
        let first = slot.begin_write_session(2);
        assert!(slot.write_session_matches(2, first));

        let second = slot.begin_write_session(2);
        assert!(!slot.write_session_matches(2, first));
        assert!(!slot.end_write_session(2, first));
        assert!(slot.write_session_matches(2, second));
        assert!(slot.end_write_session(2, second));
        assert!(!slot.write_session_matches(2, second));
        assert!(!slot.write_session_matches(3, second));
    }

    #[test]
    fn stream_completion_requires_full_coverage() {
        let mut endorsement = ManagedEndorsement::new(2, 0x7000_000A, 0x7000_000C, 0, 4096);
        endorsement.staging_bank = Some(0);
        endorsement.staging_data_len = Some(16);
        endorsement.staging_next_offset = 8;
        assert!(!endorsement.stream_is_complete(16));

        endorsement.staging_next_offset = 16;
        assert!(endorsement.stream_is_complete(16));
        assert!(!endorsement.stream_is_complete(15));

        assert_eq!(endorsement.stream_chunk_end(16, 0), Ok(16));
        assert!(endorsement.stream_chunk_end(15, 1).is_err());
        assert!(endorsement.stream_chunk_end(16, 1).is_err());
    }
}
