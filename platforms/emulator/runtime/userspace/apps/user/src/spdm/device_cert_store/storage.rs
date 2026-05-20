// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::spdm::cert_store::{CertSlotStorage, LoadedSlot, WriteParams};
use crate::spdm::device_cert_store::flash_layout::*;
use alloc::boxed::Box;
use async_trait::async_trait;
use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_libapi_caliptra::crypto::asym::AsymAlgo;
use caliptra_mcu_libapi_caliptra::crypto::hash::SHA384_HASH_SIZE;
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_spdm_lib::cert_store::{CertStoreError, CertStoreResult};
use caliptra_mcu_spdm_lib::protocol::CertificateInfo;

pub struct EmulatedCertSlotStorage;

impl EmulatedCertSlotStorage {
    fn header_valid(header: &[u8; FLASH_HEADER_SIZE], slot_id: u8) -> bool {
        header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + FLASH_MAGIC.len()] == FLASH_MAGIC
            && header[HEADER_SLOT_ID_OFFSET] == slot_id
    }

    fn chain_len(header: &[u8; FLASH_HEADER_SIZE]) -> Option<usize> {
        let chain_len = read_u32(header, HEADER_CHAIN_LEN_OFFSET) as usize;
        if chain_len == 0 || chain_len > FLASH_BODY_CAPACITY {
            None
        } else {
            Some(chain_len)
        }
    }

    fn cert_info(header: &[u8; FLASH_HEADER_SIZE]) -> Option<CertificateInfo> {
        let cert_model = header[HEADER_CERT_MODEL_OFFSET];
        if !(1..=3).contains(&cert_model) {
            return None;
        }

        let mut cert_info = CertificateInfo::default();
        cert_info.set_cert_model(cert_model);
        Some(cert_info)
    }
}

#[async_trait]
impl CertSlotStorage for EmulatedCertSlotStorage {
    async fn load(&self, slot_id: u8) -> CertStoreResult<Option<LoadedSlot>> {
        let mut header = [0u8; FLASH_HEADER_SIZE];
        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        if flash.exists().is_err() {
            return Ok(None);
        }
        flash
            .read(slot_flash_offset(slot_id), FLASH_HEADER_SIZE, &mut header)
            .await
            .map_err(|_| CertStoreError::CertReadError)?;

        if !Self::header_valid(&header, slot_id) {
            return Ok(None);
        }
        let Some(cert_info) = Self::cert_info(&header) else {
            return Ok(None);
        };
        if Self::chain_len(&header).is_none() {
            return Ok(None);
        }

        let mut root_cert_hash = [0u8; SHA384_HASH_SIZE];
        root_cert_hash.copy_from_slice(
            &header[HEADER_ROOT_HASH_OFFSET..HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE],
        );

        Ok(Some(LoadedSlot {
            key_pair_id: header[HEADER_KEY_PAIR_ID_OFFSET],
            cert_info,
            root_cert_hash,
        }))
    }

    async fn write(&self, slot_id: u8, params: WriteParams<'_>) -> CertStoreResult<()> {
        if params.asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedAsymAlgo);
        }
        if params.cert_chain.is_empty() || params.cert_chain.len() > FLASH_BODY_CAPACITY {
            return Err(CertStoreError::BufferTooSmall);
        }
        let cert_model = params.cert_info.cert_model();
        if !(1..=3).contains(&cert_model) {
            return Err(CertStoreError::CertWriteError);
        }

        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        flash.exists().map_err(|_| CertStoreError::CertWriteError)?;

        let slot_offset = slot_flash_offset(slot_id);
        let mut header = [0u8; FLASH_HEADER_SIZE];
        header[HEADER_MAGIC_OFFSET..HEADER_MAGIC_OFFSET + FLASH_MAGIC.len()]
            .copy_from_slice(&FLASH_MAGIC);
        header[HEADER_SLOT_ID_OFFSET] = slot_id;
        header[HEADER_KEY_PAIR_ID_OFFSET] = params.key_pair_id;
        header[HEADER_CERT_MODEL_OFFSET] = cert_model;
        header[HEADER_CHAIN_LEN_OFFSET..HEADER_CHAIN_LEN_OFFSET + size_of::<u32>()]
            .copy_from_slice(&(params.cert_chain.len() as u32).to_le_bytes());
        header[HEADER_ROOT_HASH_OFFSET..HEADER_ROOT_HASH_OFFSET + SHA384_HASH_SIZE]
            .copy_from_slice(params.root_cert_hash);

        flash
            .erase(slot_offset, FLASH_SLOT_SIZE)
            .await
            .map_err(|_| CertStoreError::CertWriteError)?;
        flash
            .write(
                slot_offset + FLASH_BODY_OFFSET,
                params.cert_chain.len(),
                params.cert_chain,
            )
            .await
            .map_err(|_| CertStoreError::CertWriteError)?;
        flash
            .write(slot_offset, FLASH_HEADER_SIZE, &header)
            .await
            .map_err(|_| CertStoreError::CertWriteError)
    }

    async fn erase(&self, slot_id: u8) -> CertStoreResult<()> {
        let flash: SpiFlash = SpiFlash::new(CERT_STORE_PARTITION.driver_num);
        flash.exists().map_err(|_| CertStoreError::CertWriteError)?;
        flash
            .erase(slot_flash_offset(slot_id), FLASH_SLOT_SIZE)
            .await
            .map_err(|_| CertStoreError::CertWriteError)
    }
}
