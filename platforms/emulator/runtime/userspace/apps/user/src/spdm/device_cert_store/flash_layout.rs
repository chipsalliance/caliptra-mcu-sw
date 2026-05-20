// Licensed under the Apache-2.0 license

use caliptra_mcu_config_emulator::flash::CERT_STORE_PARTITION;
use caliptra_mcu_spdm_lib::cert_store::MAX_CERT_SLOTS_SUPPORTED;

pub const FLASH_MAGIC: [u8; 4] = *b"SPCT";
pub const FLASH_HEADER_SIZE: usize = 128;
pub const FLASH_BODY_OFFSET: usize = FLASH_HEADER_SIZE;
pub const FLASH_SLOT_SIZE: usize = CERT_STORE_PARTITION.size / MAX_CERT_SLOTS_SUPPORTED as usize;
pub const FLASH_BODY_CAPACITY: usize = FLASH_SLOT_SIZE - FLASH_BODY_OFFSET;

pub const HEADER_MAGIC_OFFSET: usize = 0;
pub const HEADER_SLOT_ID_OFFSET: usize = 4;
pub const HEADER_KEY_PAIR_ID_OFFSET: usize = 5;
pub const HEADER_CERT_MODEL_OFFSET: usize = 6;
pub const HEADER_CHAIN_LEN_OFFSET: usize = 8;
pub const HEADER_ROOT_HASH_OFFSET: usize = 12;

pub const fn slot_flash_offset(slot_id: u8) -> usize {
    slot_id as usize * FLASH_SLOT_SIZE
}

pub fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}
