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
use caliptra_mcu_spdm_traits::SpdmPalAsymAlgo;
use mcu_error::McuResult;

#[cfg(feature = "set-certificate")]
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// Number of asymmetric algorithms a slot can hold a chain for.
pub const NUM_ASYM_ALGOS: usize = 2;

/// Index into per-algorithm arrays.
///
/// Exactly one asymmetric algorithm is negotiated per SPDM connection,
/// so every read and write path is already scoped to one of these.
pub const fn algo_index(algo: SpdmPalAsymAlgo) -> usize {
    match algo {
        SpdmPalAsymAlgo::EccP384 => 0,
        SpdmPalAsymAlgo::MlDsa87 => 1,
    }
}

/// A single SPDM certificate slot.
///
/// Slots store the endorsement/root portion. The PAL composes the full
/// SPDM cert chain by appending the DPE device chain and DPE leaf cert.
///
/// A slot may hold an independent chain per asymmetric algorithm, so
/// the metadata and the in-progress write lock are tracked per
/// algorithm rather than per slot.
pub struct CertSlot {
    /// Slot certificate-chain backing storage.
    pub endorsement: SlotEndorsement,
    /// KeyPairID associated with this slot's signing key, per algorithm.
    /// `None` where that algorithm is unprovisioned.
    key_pair_id: [Option<u8>; NUM_ASYM_ALGOS],
    /// CertificateInfo/CertModel for this slot, per algorithm.
    /// `None` where that algorithm is unprovisioned.
    cert_info: [Option<u8>; NUM_ASYM_ALGOS],
    /// State lock held high while an async write (flash erase/write) is
    /// in progress for the corresponding algorithm.
    write_in_progress: [AtomicBool; NUM_ASYM_ALGOS],
}

impl CertSlot {
    pub const fn empty() -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id: [None; NUM_ASYM_ALGOS],
            cert_info: [None; NUM_ASYM_ALGOS],
            write_in_progress: [const { AtomicBool::new(false) }; NUM_ASYM_ALGOS],
        }
    }

    pub fn is_supported(&self) -> bool {
        self.endorsement.is_supported()
    }

    pub fn is_writable(&self) -> bool {
        self.endorsement.is_writable()
    }

    /// Whether this slot can serve a cert chain for `algo` right now.
    pub fn is_provisioned(&self, algo: SpdmPalAsymAlgo) -> bool {
        !self.write_in_progress(algo) && self.endorsement.is_provisioned(algo)
    }

    pub fn write_in_progress(&self, algo: SpdmPalAsymAlgo) -> bool {
        self.write_in_progress[algo_index(algo)].load(Ordering::Relaxed)
    }

    pub fn set_write_in_progress(&self, algo: SpdmPalAsymAlgo, value: bool) {
        self.write_in_progress[algo_index(algo)].store(value, Ordering::Relaxed);
    }

    pub fn key_pair_id(&self, algo: SpdmPalAsymAlgo) -> Option<u8> {
        self.key_pair_id[algo_index(algo)]
    }

    pub fn cert_info(&self, algo: SpdmPalAsymAlgo) -> Option<u8> {
        self.cert_info[algo_index(algo)]
    }

    pub fn set_metadata(
        &mut self,
        algo: SpdmPalAsymAlgo,
        key_pair_id: Option<u8>,
        info: Option<u8>,
    ) {
        let i = algo_index(algo);
        self.key_pair_id[i] = key_pair_id;
        self.cert_info[i] = info;
    }

    /// Apply the same metadata to every algorithm.
    ///
    /// Read-only slots derive both chains from one provisioning event,
    /// so they share a KeyPairID and CertificateInfo.
    pub fn set_metadata_all(&mut self, key_pair_id: Option<u8>, info: Option<u8>) {
        self.key_pair_id = [key_pair_id; NUM_ASYM_ALGOS];
        self.cert_info = [info; NUM_ASYM_ALGOS];
    }

    pub fn clear_metadata(&mut self, algo: SpdmPalAsymAlgo) {
        self.set_metadata(algo, None, None);
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
pub enum SlotEndorsement {
    /// Not provisioned and not exposed as a supported SPDM slot.
    Empty,
    /// Read-only endorsement backed by static root CA certs (slot 0).
    ReadOnly(ReadOnlyEndorsementSlot),
    /// Managed endorsement/root chains backed by flash (slots 1-2,
    /// SET_CERTIFICATE), one independent region per algorithm.
    #[cfg(feature = "set-certificate")]
    Managed(ManagedEndorsementSlot),
}

impl SlotEndorsement {
    pub fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
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

    pub fn size(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
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

    pub fn capacity(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
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

    pub async fn read(
        &self,
        algo: SpdmPalAsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.read(algo, offset, buf),
            #[cfg(feature = "set-certificate")]
            Self::Managed(m) => {
                m.get_endorsement(algo)
                    .ok_or(mcu_error::codes::INVARIANT)?
                    .read(offset, buf)
                    .await
            }
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

    pub fn is_provisioned(&self, algo: SpdmPalAsymAlgo) -> bool {
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

    pub fn get_endorsement(&self, algo: SpdmPalAsymAlgo) -> Option<&SingleEndorsementChain> {
        match algo {
            SpdmPalAsymAlgo::EccP384 => Some(&self.ecc),
            SpdmPalAsymAlgo::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    fn root_cert_hash(&self, algo: SpdmPalAsymAlgo, out: &mut [u8]) -> McuResult<()> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        for (d, s) in out.iter_mut().zip(&chain.root_cert_hash) {
            *d = *s;
        }
        Ok(())
    }

    fn size(&self, algo: SpdmPalAsymAlgo) -> McuResult<usize> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        Ok(chain.chain_len)
    }

    fn read(&self, algo: SpdmPalAsymAlgo, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        let mut cert_offset = offset;
        let mut pos = 0;
        for cert in chain.chain.iter() {
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
const MANAGED_FORMAT_VERSION: u16 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_HEADER_SIZE: usize = 80;
#[cfg(feature = "set-certificate")]
const MANAGED_ALGO_ECC_P384: u8 = 1;
#[cfg(feature = "set-certificate")]
const MANAGED_ALGO_MLDSA_87: u8 = 2;

#[cfg(feature = "set-certificate")]
const fn managed_algo_code(algo: SpdmPalAsymAlgo) -> u8 {
    match algo {
        SpdmPalAsymAlgo::EccP384 => MANAGED_ALGO_ECC_P384,
        SpdmPalAsymAlgo::MlDsa87 => MANAGED_ALGO_MLDSA_87,
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
/// practice, this limit is the size of the managed flash region
#[cfg(feature = "set-certificate")]
const MANAGED_MAX_DER_LEN: usize = (u32::MAX as usize) - SPDM_CERT_CHAIN_HEADER_SIZE;

/// Usable DER bytes in one managed endorsement region.
#[cfg(feature = "set-certificate")]
pub const fn managed_endorsement_der_capacity(region_size: usize) -> usize {
    let available = region_size.saturating_sub(MANAGED_HEADER_SIZE);
    if available < MANAGED_MAX_DER_LEN {
        available
    } else {
        MANAGED_MAX_DER_LEN
    }
}

/// Whether two half-open byte ranges intersect.
///
/// The single definition of "these managed flash regions collide".
/// Updating a chain erases its whole region, so any intersection at
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
/// lifetime, fixed when the platform wires it up. A slot that serves
/// both ECC and ML-DSA therefore owns two disjoint regions — see
/// [`ManagedEndorsement`]. Sharing one region would make installing one
/// algorithm's chain silently destroy the other's.
#[cfg(feature = "set-certificate")]
#[derive(Clone, Copy)]
pub struct SingleManagedEndorsement {
    slot: u8,
    driver_num: u32,
    base: usize,
    capacity: usize,
    initialized: bool,
    algo: SpdmPalAsymAlgo,
    len: usize,
    root_hash: [u8; 48],
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
}

#[cfg(feature = "set-certificate")]
impl SingleManagedEndorsement {
    pub const fn new(
        slot: u8,
        algo: SpdmPalAsymAlgo,
        driver_num: u32,
        base: usize,
        capacity: usize,
    ) -> Self {
        Self {
            slot,
            driver_num,
            base,
            capacity,
            initialized: false,
            algo,
            len: 0,
            root_hash: [0; 48],
            key_pair_id: 0,
            cert_info: 0,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
        }
    }

    pub async fn load(&mut self) -> McuResult<()> {
        self.initialized = false;
        self.len = 0;
        let mut header = [0u8; MANAGED_HEADER_SIZE];
        let flash = self.flash();
        match flash.exists() {
            Ok(()) => {}
            Err(ErrorCode::NoDevice | ErrorCode::NoSupport | ErrorCode::Uninstalled) => {
                return Ok(())
            }
            Err(err) => return Err(map_flash_error(err)),
        }
        flash
            .read(self.base, MANAGED_HEADER_SIZE, &mut header)
            .await
            .map_err(map_flash_error)?;
        if header.iter().all(|&b| b == MANAGED_ERASED_BYTE) || header[0..4] != MANAGED_MAGIC {
            return Ok(());
        }
        let Some(record) = ManagedRecord::decode(&header) else {
            return Ok(());
        };
        if record.version != MANAGED_FORMAT_VERSION
            || record.header_size as usize != MANAGED_HEADER_SIZE
            || record.slot != self.slot
            || record.algo != managed_algo_code(self.algo)
            || record.cert_len > self.der_capacity()
        {
            return Ok(());
        }
        if self.stored_checksum(record.cert_len).await? != record.data_checksum {
            return Ok(());
        }
        self.initialized = true;
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

    /// The algorithm this region is dedicated to.
    pub const fn algo(&self) -> SpdmPalAsymAlgo {
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
            .read(self.data_base() + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    pub async fn begin_stream_update(mut self, data_len: usize) -> McuResult<Self> {
        if data_len > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        self.flash()
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        self.initialized = false;
        self.len = 0;
        self.root_hash = [0; 48];
        self.key_pair_id = 0;
        self.cert_info = 0;
        Ok(self)
    }

    pub async fn write_stream_chunk(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let end = offset
            .checked_add(data.len())
            .ok_or(mcu_error::codes::INVARIANT)?;
        if end > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if !data.is_empty() {
            self.flash()
                .write(self.data_base() + offset, data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        Ok(())
    }

    pub async fn read_stream_chunk(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        if offset >= self.der_capacity() || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.der_capacity() - offset).min(buf.len());
        self.flash()
            .read(self.data_base() + offset, n, &mut buf[..n])
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
        if data_len > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        let data_checksum = self.stored_checksum(data_len).await?;
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
        };
        let mut header = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut header);
        self.flash()
            .write(self.base, MANAGED_HEADER_SIZE, &header)
            .await
            .map_err(map_flash_error)?;
        self.initialized = true;
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
        if data.len() > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }

        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: managed_algo_code(self.algo),
            key_pair_id,
            cert_info,
            key_usage_mask: MANAGED_KEY_USAGE_MASK,
            cert_len: data.len(),
            data_checksum: checksum(data),
            root_hash: *root_hash,
        };
        let mut header = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut header);

        let flash = self.flash();
        flash
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        if !data.is_empty() {
            flash
                .write(self.data_base(), data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        // Commit the record last so an interrupted write is seen as empty/invalid.
        flash
            .write(self.base, MANAGED_HEADER_SIZE, &header)
            .await
            .map_err(map_flash_error)?;

        self.initialized = true;
        self.len = data.len();
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    pub async fn erase_updated(mut self) -> McuResult<Self> {
        self.flash()
            .erase(self.base, self.capacity)
            .await
            .map_err(map_flash_error)?;
        self.initialized = false;
        self.len = 0;
        self.root_hash = [0; 48];
        self.key_pair_id = 0;
        self.cert_info = 0;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    fn flash(&self) -> CertStoreFlash {
        CertStoreFlash::new(self.driver_num)
    }

    async fn stored_checksum(&self, len: usize) -> McuResult<u32> {
        let mut remaining = len;
        let mut offset = 0usize;
        let mut sum = 0u32;
        let mut chunk = [0u8; 256];
        let flash = self.flash();
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            flash
                .read(self.data_base() + offset, n, &mut chunk[..n])
                .await
                .map_err(map_flash_error)?;
            sum = sum.wrapping_add(checksum(&chunk[..n]));
            remaining -= n;
            offset += n;
        }
        Ok(sum)
    }

    fn data_base(&self) -> usize {
        self.base + MANAGED_HEADER_SIZE
    }

    fn der_capacity(&self) -> usize {
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
        debug_assert!(matches!(ecc.algo(), SpdmPalAsymAlgo::EccP384));
        Self { ecc, mldsa: None }
    }

    pub const fn with_mldsa(mut self, mldsa: SingleManagedEndorsement) -> Self {
        debug_assert!(matches!(mldsa.algo(), SpdmPalAsymAlgo::MlDsa87));
        self.mldsa = Some(mldsa);
        self
    }

    /// The endorsement region serving `algo`, or `None` if this slot has none.
    pub fn get_endorsement(&self, algo: SpdmPalAsymAlgo) -> Option<&SingleManagedEndorsement> {
        match algo {
            SpdmPalAsymAlgo::EccP384 => Some(&self.ecc),
            SpdmPalAsymAlgo::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    /// Install an updated endorsement region, which must belong to this slot's
    /// algorithm for that position.
    pub fn set_endorsement(&mut self, endorsement: SingleManagedEndorsement) {
        match endorsement.algo() {
            SpdmPalAsymAlgo::EccP384 => self.ecc = endorsement,
            SpdmPalAsymAlgo::MlDsa87 => self.mldsa = Some(endorsement),
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
        //   [14..16] reserved (zero)
        //   [16..20] cert_len (LE u32)
        //   [20..24] data_checksum (LE)
        //   [24..72] root_hash
        //   [72..80] reserved (zero)
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
        // skip [14..16] reserved (already MANAGED_ERASED_BYTE-filled)
        let rest = &mut rest[2..];
        let (len, rest) = rest.split_first_chunk_mut::<4>().unwrap();
        *len = (self.cert_len as u32).to_le_bytes();
        let (chk, rest) = rest.split_first_chunk_mut::<4>().unwrap();
        *chk = self.data_checksum.to_le_bytes();
        let (rh, _) = rest.split_first_chunk_mut::<48>().unwrap();
        *rh = self.root_hash;
    }

    fn decode(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let (magic, rest) = input.split_first_chunk::<4>()?;
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
        let (root_hash, _) = rest.split_first_chunk::<48>()?;
        // magic is not parsed here; caller checks it before invoking decode.
        let _ = magic;
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
    use caliptra_mcu_spdm_codec::errors::*;

    match err {
        ErrorCode::Busy => SPDM_BUSY,
        _ => SPDM_OPERATION_FAILED,
    }
}

#[cfg(all(test, feature = "set-certificate"))]
mod tests {
    use super::*;

    const TEST_DRIVER: u32 = 0x7000_000A;
    const TEST_REGION: usize = 4096;

    fn chain(algo: SpdmPalAsymAlgo, base: usize) -> SingleManagedEndorsement {
        SingleManagedEndorsement::new(2, algo, TEST_DRIVER, base, TEST_REGION)
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
        };
        let mut buf = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut buf);
        assert_eq!(&buf[0..4], &MANAGED_MAGIC);
        assert_eq!(ManagedRecord::decode(&buf), Some(record));
    }

    #[test]
    fn managed_capacity_excludes_header() {
        let endorsement = chain(SpdmPalAsymAlgo::EccP384, 0);
        assert_eq!(endorsement.der_capacity(), 4096 - MANAGED_HEADER_SIZE);
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
        // only the flash region should limit them now.
        let region = 128 * 1024;
        assert_eq!(
            managed_endorsement_der_capacity(region),
            region - MANAGED_HEADER_SIZE
        );
        assert!(managed_endorsement_der_capacity(region) > u16::MAX as usize);
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
        assert!(ecc_only.is_provisioned(SpdmPalAsymAlgo::EccP384));
        // Without an ML-DSA chain the slot must not be advertised in an
        // ML-DSA connection: otherwise GET_CERTIFICATE would serve the
        // ECC chain against an ML-DSA negotiation.
        assert!(!ecc_only.is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        let both = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]).with_mldsa(MLDSA_CHAIN, [1u8; 48]),
        );
        assert!(both.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(both.is_provisioned(SpdmPalAsymAlgo::MlDsa87));
    }

    #[test]
    fn empty_slot_is_never_provisioned() {
        let empty = SlotEndorsement::Empty;
        assert!(!empty.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!empty.is_provisioned(SpdmPalAsymAlgo::MlDsa87));
    }
}
