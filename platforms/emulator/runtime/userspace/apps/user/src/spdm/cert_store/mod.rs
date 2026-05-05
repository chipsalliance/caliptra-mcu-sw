// Licensed under the Apache-2.0 license

extern crate alloc;

pub(crate) mod cert_chain;

use crate::spdm::cert_store::cert_chain::CertChain;
use alloc::vec::Vec;
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libapi_caliptra::crypto::asym::{AsymAlgo, ECC_P384_SIGNATURE_SIZE};
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_spdm_lib::cert_store::{
    CertStoreError, CertStoreResult, MAX_CERT_SLOTS_SUPPORTED,
};
use caliptra_mcu_spdm_lib::protocol::{CertificateInfo, KeyUsageMask};

const VENDOR_SLOT_ID: u8 = 0;
const FLASH_MAGIC: [u8; 4] = *b"SPCT";
const FLASH_FORMAT_VERSION: u16 = 1;
const FLASH_HEADER_SIZE: usize = 68;
const FLASH_SLOT_COUNT: usize = MAX_CERT_SLOTS_SUPPORTED as usize;
const FLASH_SLOT_SIZE: usize = CERT_STORE_PARTITION.size / FLASH_SLOT_COUNT;
const FLASH_CERT_CHAIN_OFFSET: usize = FLASH_HEADER_SIZE;
const MAX_INSTALLED_CERT_CHAIN_SIZE: usize = 2048;
const FLASH_CERT_CHAIN_CAPACITY: usize =
    if FLASH_SLOT_SIZE - FLASH_CERT_CHAIN_OFFSET < MAX_INSTALLED_CERT_CHAIN_SIZE {
        FLASH_SLOT_SIZE - FLASH_CERT_CHAIN_OFFSET
    } else {
        MAX_INSTALLED_CERT_CHAIN_SIZE
    };

const HEADER_MAGIC_OFFSET: usize = 0;
const HEADER_VERSION_OFFSET: usize = 4;
const HEADER_SLOT_ID_OFFSET: usize = 6;
const HEADER_KEY_PAIR_ID_OFFSET: usize = 7;
const HEADER_CERT_MODEL_OFFSET: usize = 8;
const HEADER_CERT_LEN_OFFSET: usize = 12;
const HEADER_ROOT_HASH_OFFSET: usize = 16;
const HEADER_CHECKSUM_OFFSET: usize = HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE;

fn slot_flash_offset(slot_id: u8) -> usize {
    usize::from(slot_id) * FLASH_SLOT_SIZE
}

fn checksum_update(mut checksum: u32, data: &[u8]) -> u32 {
    for byte in data {
        checksum = checksum.wrapping_add(u32::from(*byte));
    }
    checksum
}

fn flash_checksum(header_without_checksum: &[u8], cert_chain: &[u8]) -> u32 {
    checksum_update(checksum_update(0, header_without_checksum), cert_chain)
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

struct InstalledCertChain {
    asym_algo: AsymAlgo,
    key_pair_id: u8,
    cert_info: CertificateInfo,
    key_usage_mask: KeyUsageMask,
    root_cert_hash: [u8; SHA384_HASH_SIZE],
    cert_chain: Vec<u8>,
}

impl InstalledCertChain {
    fn new(
        asym_algo: AsymAlgo,
        key_pair_id: u8,
        cert_info: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
    ) -> CertStoreResult<Self> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if cert_chain.is_empty() {
            return Err(CertStoreError::CertWriteError);
        }
        if cert_chain.len() > FLASH_CERT_CHAIN_CAPACITY {
            return Err(CertStoreError::BufferTooSmall);
        }

        // Do not advertise signing usages until the platform can verify the leaf public key and
        // sign with the SPDM KeyPairID associated with this installed certificate.
        let key_usage_mask = KeyUsageMask::default();

        Ok(Self {
            asym_algo,
            key_pair_id,
            cert_info,
            key_usage_mask,
            root_cert_hash: *root_cert_hash,
            cert_chain: cert_chain.to_vec(),
        })
    }

    fn ensure_asym_algo(&self, asym_algo: AsymAlgo) -> CertStoreResult<()> {
        if self.asym_algo != asym_algo {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        Ok(())
    }

    fn size(&self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        self.ensure_asym_algo(asym_algo)?;
        Ok(self.cert_chain.len())
    }

    fn read(&self, asym_algo: AsymAlgo, offset: usize, buf: &mut [u8]) -> CertStoreResult<usize> {
        self.ensure_asym_algo(asym_algo)?;
        if offset > self.cert_chain.len() {
            return Err(CertStoreError::InvalidOffset);
        }
        if offset == self.cert_chain.len() {
            return Ok(0);
        }

        let read_len = buf.len().min(self.cert_chain.len() - offset);
        buf[..read_len].copy_from_slice(&self.cert_chain[offset..offset + read_len]);
        Ok(read_len)
    }

    fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        self.ensure_asym_algo(asym_algo)?;
        cert_hash.copy_from_slice(&self.root_cert_hash);
        Ok(())
    }
}

fn encode_flash_header(slot_id: u8, cert_chain: &InstalledCertChain) -> [u8; FLASH_HEADER_SIZE] {
    let mut header = [0u8; FLASH_HEADER_SIZE];
    header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + FLASH_MAGIC.len()]
        .copy_from_slice(&FLASH_MAGIC);
    header[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + size_of::<u16>()]
        .copy_from_slice(&FLASH_FORMAT_VERSION.to_le_bytes());
    header[HEADER_SLOT_ID_OFFSET] = slot_id;
    header[HEADER_KEY_PAIR_ID_OFFSET] = cert_chain.key_pair_id;
    header[HEADER_CERT_MODEL_OFFSET] = cert_chain.cert_info.cert_model();
    header[HEADER_CERT_LEN_OFFSET..HEADER_CERT_LEN_OFFSET + size_of::<u32>()]
        .copy_from_slice(&(cert_chain.cert_chain.len() as u32).to_le_bytes());
    header[HEADER_ROOT_HASH_OFFSET..HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE]
        .copy_from_slice(&cert_chain.root_cert_hash);

    let checksum = flash_checksum(&header[..HEADER_CHECKSUM_OFFSET], &cert_chain.cert_chain);
    header[HEADER_CHECKSUM_OFFSET..HEADER_CHECKSUM_OFFSET + size_of::<u32>()]
        .copy_from_slice(&checksum.to_le_bytes());
    header
}

async fn read_installed_cert_chain_from_flash(
    flash: &SpiFlash,
    slot_id: u8,
) -> CertStoreResult<Option<InstalledCertChain>> {
    let offset = slot_flash_offset(slot_id);
    let mut header = [0u8; FLASH_HEADER_SIZE];
    flash
        .read(offset, header.len(), &mut header)
        .await
        .map_err(|_| CertStoreError::CertReadError)?;

    if header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + FLASH_MAGIC.len()] != FLASH_MAGIC {
        return Ok(None);
    }
    if read_u16(&header, HEADER_VERSION_OFFSET) != FLASH_FORMAT_VERSION {
        return Ok(None);
    }
    if header[HEADER_SLOT_ID_OFFSET] != slot_id {
        return Ok(None);
    }

    let cert_chain_len = read_u32(&header, HEADER_CERT_LEN_OFFSET) as usize;
    if cert_chain_len == 0 || cert_chain_len > FLASH_CERT_CHAIN_CAPACITY {
        return Ok(None);
    }

    let mut cert_chain = Vec::new();
    cert_chain.resize(cert_chain_len, 0);
    flash
        .read(
            offset + FLASH_CERT_CHAIN_OFFSET,
            cert_chain_len,
            &mut cert_chain,
        )
        .await
        .map_err(|_| CertStoreError::CertReadError)?;

    let expected_checksum = read_u32(&header, HEADER_CHECKSUM_OFFSET);
    let actual_checksum = flash_checksum(&header[..HEADER_CHECKSUM_OFFSET], &cert_chain);
    if expected_checksum != actual_checksum {
        return Ok(None);
    }

    let cert_model = header[HEADER_CERT_MODEL_OFFSET];
    if cert_model > 3 {
        return Ok(None);
    }

    let mut root_cert_hash = [0u8; SHA384_HASH_SIZE];
    root_cert_hash.copy_from_slice(
        &header[HEADER_ROOT_HASH_OFFSET..HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE],
    );
    let mut cert_info = CertificateInfo::default();
    cert_info.set_cert_model(cert_model);

    InstalledCertChain::new(
        AsymAlgo::EccP384,
        header[HEADER_KEY_PAIR_ID_OFFSET],
        cert_info,
        &root_cert_hash,
        &cert_chain,
    )
    .map(Some)
}

async fn write_installed_cert_chain_to_flash(
    slot_id: u8,
    cert_chain: &InstalledCertChain,
) -> CertStoreResult<()> {
    let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
    flash.exists().map_err(|_| CertStoreError::CertWriteError)?;

    let offset = slot_flash_offset(slot_id);
    let header = encode_flash_header(slot_id, cert_chain);
    flash
        .erase(offset, FLASH_SLOT_SIZE)
        .await
        .map_err(|_| CertStoreError::CertWriteError)?;
    flash
        .write(
            offset + FLASH_CERT_CHAIN_OFFSET,
            cert_chain.cert_chain.len(),
            &cert_chain.cert_chain,
        )
        .await
        .map_err(|_| CertStoreError::CertWriteError)?;
    // Commit the record only after the certificate bytes are written. If power is lost before this
    // header write completes, the next boot treats the slot as empty/corrupt instead of failing
    // certificate-store initialization.
    flash
        .write(offset, header.len(), &header)
        .await
        .map_err(|_| CertStoreError::CertWriteError)
}

async fn erase_installed_cert_chain_from_flash(slot_id: u8) -> CertStoreResult<()> {
    let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
    flash.exists().map_err(|_| CertStoreError::CertWriteError)?;
    flash
        .erase(slot_flash_offset(slot_id), FLASH_SLOT_SIZE)
        .await
        .map_err(|_| CertStoreError::CertWriteError)
}

enum CertSlot {
    BuiltIn(CertChain),
    Installed(InstalledCertChain),
}

impl CertSlot {
    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.size(asym_algo).await,
            CertSlot::Installed(cert_chain) => cert_chain.size(asym_algo),
        }
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.read(asym_algo, offset, buf).await,
            CertSlot::Installed(cert_chain) => cert_chain.read(asym_algo, offset, buf),
        }
    }

    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.root_cert_hash(asym_algo, cert_hash).await,
            CertSlot::Installed(cert_chain) => cert_chain.root_cert_hash(asym_algo, cert_hash),
        }
    }

    async fn sign(
        &self,
        asym_algo: AsymAlgo,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        match self {
            CertSlot::BuiltIn(cert_chain) => cert_chain.sign(asym_algo, hash, signature).await,
            // The installed cert chain is persisted with its KeyPairID metadata, but the emulator
            // does not yet have a Caliptra API for signing by SPDM KeyPairID. Keep this explicit
            // instead of silently signing with the wrong key.
            CertSlot::Installed(_) => Err(CertStoreError::OperationFailed),
        }
    }

    fn key_pair_id(&self) -> Option<u8> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.key_pair_id),
        }
    }

    fn cert_info(&self) -> Option<CertificateInfo> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.cert_info),
        }
    }

    fn key_usage_mask(&self) -> Option<KeyUsageMask> {
        match self {
            CertSlot::BuiltIn(_) => None,
            CertSlot::Installed(cert_chain) => Some(cert_chain.key_usage_mask),
        }
    }
}

pub struct DeviceCertStore {
    cert_chains: [Option<CertSlot>; MAX_CERT_SLOTS_SUPPORTED as usize],
}

impl DeviceCertStore {
    pub fn new() -> Self {
        Self {
            cert_chains: Default::default(),
        }
    }

    pub fn set_cert_chain(&mut self, slot: u8, cert_chain: CertChain) -> CertStoreResult<()> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains[slot as usize] = Some(CertSlot::BuiltIn(cert_chain));
        Ok(())
    }

    fn cert_chain(&self, slot: u8) -> CertStoreResult<&CertSlot> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains
            .get(slot as usize)
            .and_then(|chain| chain.as_ref())
            .ok_or(CertStoreError::UnprovisionedSlot)
    }

    fn cert_chain_mut(&mut self, slot: u8) -> CertStoreResult<&mut CertSlot> {
        if slot >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }

        self.cert_chains
            .get_mut(slot as usize)
            .and_then(|chain| chain.as_mut())
            .ok_or(CertStoreError::UnprovisionedSlot)
    }

    pub fn slot_count(&self) -> u8 {
        MAX_CERT_SLOTS_SUPPORTED
    }

    pub fn is_provisioned(&self, slot: u8) -> bool {
        self.cert_chain(slot).is_ok()
    }

    pub async fn cert_chain_len(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.size(asym_algo).await
    }

    pub async fn get_cert_chain(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        let cert_chain = self.cert_chain_mut(slot_id)?;
        cert_chain.read(asym_algo, offset, cert_portion).await
    }

    pub async fn root_cert_hash(
        &self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.root_cert_hash(asym_algo, cert_hash).await
    }

    pub async fn sign_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        let cert_chain = self.cert_chain(slot_id)?;
        cert_chain.sign(asym_algo, hash, signature).await
    }

    pub fn key_pair_id(&self, slot_id: u8) -> Option<u8> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(CertSlot::key_pair_id)
    }

    pub fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo> {
        self.cert_chain(slot_id).ok().and_then(CertSlot::cert_info)
    }

    pub fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask> {
        self.cert_chain(slot_id)
            .ok()
            .and_then(CertSlot::key_usage_mask)
    }

    pub async fn load_cert_chains_from_flash(&mut self) -> CertStoreResult<()> {
        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        if flash.exists().is_err() {
            return Ok(());
        }

        for slot_id in 1..MAX_CERT_SLOTS_SUPPORTED {
            if let Some(cert_chain) = read_installed_cert_chain_from_flash(&flash, slot_id).await? {
                self.cert_chains[slot_id as usize] = Some(CertSlot::Installed(cert_chain));
            }
        }

        Ok(())
    }

    pub async fn write_cert_chain(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        key_pair_id: u8,
        cert_model: CertificateInfo,
        root_cert_hash: &[u8; SHA384_HASH_SIZE],
        cert_chain: &[u8],
    ) -> CertStoreResult<()> {
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }
        if cert_chain.len() > FLASH_CERT_CHAIN_CAPACITY {
            return Err(CertStoreError::BufferTooSmall);
        }

        let installed_cert_chain = InstalledCertChain::new(
            asym_algo,
            key_pair_id,
            cert_model,
            root_cert_hash,
            cert_chain,
        )?;
        write_installed_cert_chain_to_flash(slot_id, &installed_cert_chain).await?;
        self.cert_chains[slot_id as usize] = Some(CertSlot::Installed(installed_cert_chain));
        Ok(())
    }

    pub async fn erase_cert_chain(
        &mut self,
        asym_algo: AsymAlgo,
        slot_id: u8,
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if slot_id >= MAX_CERT_SLOTS_SUPPORTED {
            return Err(CertStoreError::InvalidSlotId);
        }
        if slot_id == VENDOR_SLOT_ID {
            return Err(CertStoreError::OperationFailed);
        }

        erase_installed_cert_chain_from_flash(slot_id).await?;
        self.cert_chains[slot_id as usize] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed_cert_chain(cert_chain: &[u8]) -> InstalledCertChain {
        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(1);
        InstalledCertChain::new(
            AsymAlgo::EccP384,
            1,
            cert_info,
            &[0x5a; SHA384_HASH_SIZE],
            cert_chain,
        )
        .unwrap()
    }

    #[test]
    fn test_installed_cert_chain_read_allows_exact_eof() {
        let cert_chain = installed_cert_chain(&[1, 2, 3, 4]);
        let mut buf = [0u8; 4];

        assert_eq!(cert_chain.read(AsymAlgo::EccP384, 4, &mut buf), Ok(0));
        assert_eq!(
            cert_chain.read(AsymAlgo::EccP384, 5, &mut buf),
            Err(CertStoreError::InvalidOffset)
        );
    }

    #[test]
    fn test_installed_cert_chain_does_not_advertise_signing_usage() {
        let cert_chain = installed_cert_chain(&[1, 2, 3, 4]);

        assert_eq!(cert_chain.key_usage_mask.key_exch_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.challenge_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.measurement_usage(), 0);
        assert_eq!(cert_chain.key_usage_mask.standards_key_usage(), 0);
    }

    #[test]
    fn test_flash_header_encodes_commit_metadata_and_checksum() {
        let cert_chain = installed_cert_chain(&[1, 2, 3, 4]);
        let header = encode_flash_header(2, &cert_chain);

        assert_eq!(
            &header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + 4],
            &FLASH_MAGIC
        );
        assert_eq!(
            read_u16(&header, HEADER_VERSION_OFFSET),
            FLASH_FORMAT_VERSION
        );
        assert_eq!(header[HEADER_SLOT_ID_OFFSET], 2);
        assert_eq!(header[HEADER_KEY_PAIR_ID_OFFSET], 1);
        assert_eq!(header[HEADER_CERT_MODEL_OFFSET], 1);
        assert_eq!(read_u32(&header, HEADER_CERT_LEN_OFFSET), 4);
        assert_eq!(
            read_u32(&header, HEADER_CHECKSUM_OFFSET),
            flash_checksum(&header[..HEADER_CHECKSUM_OFFSET], &cert_chain.cert_chain)
        );
    }

    #[test]
    fn test_installed_cert_chain_rejects_flash_oversized_chain() {
        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(1);
        let cert_chain = alloc::vec![0xa5; FLASH_CERT_CHAIN_CAPACITY + 1];

        assert!(matches!(
            InstalledCertChain::new(
                AsymAlgo::EccP384,
                1,
                cert_info,
                &[0x5a; SHA384_HASH_SIZE],
                &cert_chain,
            ),
            Err(CertStoreError::BufferTooSmall)
        ));
    }
}
