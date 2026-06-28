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
    /// State lock high when an active async write (flash erase/write) is in progress on this slot.
    pub write_in_progress: AtomicBool,
}

impl CertSlot {
    pub const fn empty() -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id: None,
            cert_info: None,
            write_in_progress: AtomicBool::new(false),
        }
    }

    pub fn is_supported(&self) -> bool {
        self.endorsement.is_supported()
    }

    pub fn is_writable(&self) -> bool {
        self.endorsement.is_writable()
    }

    pub fn is_provisioned(&self) -> bool {
        !self.write_in_progress.load(Ordering::Relaxed) && self.endorsement.is_provisioned()
    }

    pub fn clear_metadata(&mut self) {
        self.key_pair_id = None;
        self.cert_info = None;
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
#[allow(dead_code)]
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
const MANAGED_FORMAT_VERSION: u16 = 1;
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
type CertStoreFlash = SpiFlash<DefaultSyscalls>;

/// Managed flash-backed endorsement/root chain installed by SET_CERTIFICATE.
#[cfg(feature = "set-certificate")]
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct ManagedEndorsement {
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
#[allow(dead_code)]
impl ManagedEndorsement {
    pub const fn new(slot: u8, driver_num: u32, base: usize, capacity: usize) -> Self {
        Self {
            slot,
            driver_num,
            base,
            capacity,
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
            || record.algo != MANAGED_ALGO_ECC_P384
            || record.cert_len > self.der_capacity()
        {
            return Ok(());
        }
        if self.stored_checksum(record.cert_len).await? != record.data_checksum {
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
        self.flash()
            .read(self.data_base() + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
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

        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: MANAGED_ALGO_ECC_P384,
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
        self.algo = algo;
        self.len = data.len();
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = MANAGED_KEY_USAGE_MASK;
        Ok(self)
    }

    pub async fn erase_updated(mut self, _algo: SpdmPalAsymAlgo) -> McuResult<Self> {
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
        let endorsement = ManagedEndorsement::new(2, 0x7000_000A, 0, 4096);
        assert_eq!(endorsement.der_capacity(), 4096 - MANAGED_HEADER_SIZE);
    }
}
