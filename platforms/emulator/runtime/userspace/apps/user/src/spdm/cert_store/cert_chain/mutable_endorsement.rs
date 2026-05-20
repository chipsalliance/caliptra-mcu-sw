// Licensed under the Apache-2.0 license

//! Flash-backed endorsement chain for mutable (Owner / Tenant) SPDM slots.
//! Stateless: holds only slot_id, reads from flash on demand.

extern crate alloc;

use super::EndorsementCertChainTrait;
use crate::spdm::device_cert_store::flash_layout::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_spdm_lib::cert_store::{CertStoreError, CertStoreResult};

pub struct MutableEndorsement {
    slot_id: u8,
}

impl MutableEndorsement {
    pub const fn new(slot_id: u8) -> Self {
        Self { slot_id }
    }

    async fn read_header(&self) -> CertStoreResult<[u8; FLASH_HEADER_SIZE]> {
        let mut header = [0u8; FLASH_HEADER_SIZE];
        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        flash
            .read(
                slot_flash_offset(self.slot_id),
                FLASH_HEADER_SIZE,
                &mut header,
            )
            .await
            .map_err(|_| CertStoreError::CertReadError)?;
        Ok(header)
    }

    fn header_valid(header: &[u8; FLASH_HEADER_SIZE], slot_id: u8) -> bool {
        header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + FLASH_MAGIC.len()] == FLASH_MAGIC
            && header[HEADER_SLOT_ID_OFFSET] == slot_id
    }
}

#[async_trait]
impl EndorsementCertChainTrait for MutableEndorsement {
    async fn root_cert_hash(
        &self,
        asym_algo: AsymAlgo,
        root_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        let header = self.read_header().await?;
        if !Self::header_valid(&header, self.slot_id) {
            return Err(CertStoreError::UnprovisionedSlot);
        }
        root_hash.copy_from_slice(
            &header[HEADER_ROOT_HASH_OFFSET..HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE],
        );
        Ok(())
    }

    async fn refresh(&mut self) {
        // Stateless, no-op.
    }

    async fn size(&mut self, asym_algo: AsymAlgo) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        let header = self.read_header().await?;
        if !Self::header_valid(&header, self.slot_id) {
            return Err(CertStoreError::UnprovisionedSlot);
        }
        let chain_len = read_u32(&header, HEADER_CHAIN_LEN_OFFSET) as usize;
        if chain_len == 0 || chain_len > FLASH_BODY_CAPACITY {
            return Err(CertStoreError::CertReadError);
        }
        Ok(chain_len)
    }

    async fn read(
        &mut self,
        asym_algo: AsymAlgo,
        offset: usize,
        buf: &mut [u8],
    ) -> CertStoreResult<usize> {
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        flash
            .read(
                slot_flash_offset(self.slot_id) + FLASH_BODY_OFFSET + offset,
                buf.len(),
                buf,
            )
            .await
            .map_err(|_| CertStoreError::CertReadError)?;
        Ok(buf.len())
    }
}
