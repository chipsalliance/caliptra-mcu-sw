// Licensed under the Apache-2.0 license

use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_romtime::ocp_lock::{Error, KernelConfig};
use caliptra_mcu_romtime::Otp;

pub struct RuntimeOcpLockPlatform;

impl KernelConfig for RuntimeOcpLockPlatform {
    fn get_hek_slot_offset(&self, slot: usize) -> Result<usize, Error> {
        if slot >= caliptra_mcu_romtime::HEK_OFFSETS.len() {
            return Err(Error::ROM_INVALID_HEK_SLOT);
        }
        Ok(caliptra_mcu_romtime::HEK_OFFSETS[slot])
    }

    fn sanitize_hek_slot(&self, otp: &Otp, slot: usize) -> Result<(), Error> {
        let offset = self.get_hek_slot_offset(slot)?;
        let active_word_addr = (offset / 4) as u32;

        // Sanitize words 0..7 (Seed, 32-bit granules)
        for i in 0..8 {
            caliptra_mcu_romtime::fuse_write_dai(
                otp,
                active_word_addr + i as u32,
                0xFFFFFFFF,
                0xFFFFFFFF,
            )
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;
        }
        // Sanitize words 8..9 (Digest, 64-bit granule)
        let digest_dword_addr = ((active_word_addr + 8) / 2) as usize;
        otp.write_dword(digest_dword_addr, 0xFFFFFFFF_FFFFFFFF)
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;

        // Sanitize words 10..11 (ZER, 64-bit granule)
        let zer_dword_addr = ((active_word_addr + 10) / 2) as usize;
        otp.write_dword(zer_dword_addr, 0xFFFFFFFF_FFFFFFFF)
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;
        Ok(())
    }

    fn program_hek_slot(
        &self,
        otp: &Otp,
        slot: usize,
        seed: &[u8; 32],
        digest: u64,
    ) -> Result<(), Error> {
        let offset = self.get_hek_slot_offset(slot)?;
        let next_word_addr = (offset / 4) as u32;

        let mut payload = [0u32; 12];
        for i in 0..8 {
            let mut word_bytes = [0u8; 4];
            word_bytes.copy_from_slice(&seed[i * 4..(i + 1) * 4]);
            payload[i] = u32::from_le_bytes(word_bytes);
        }
        let digest_bytes = digest.to_le_bytes();
        payload[8] = u32::from_le_bytes(digest_bytes[0..4].try_into().unwrap());
        payload[9] = u32::from_le_bytes(digest_bytes[4..8].try_into().unwrap());

        // Write words 0..7 (Seed, 32-bit granules)
        for (i, &val) in payload.iter().take(8).enumerate() {
            caliptra_mcu_romtime::fuse_write_dai(otp, next_word_addr + i as u32, val, 0xFFFFFFFF)
                .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;
        }
        // Write words 8..9 (Digest, 64-bit granule)
        let digest_dword_addr = ((next_word_addr + 8) / 2) as usize;
        let digest_dword_val = ((payload[9] as u64) << 32) | payload[8] as u64;
        otp.write_dword(digest_dword_addr, digest_dword_val)
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;

        // Write words 10..11 (ZER, 64-bit granule)
        let zer_dword_addr = ((next_word_addr + 10) / 2) as usize;
        let zer_dword_val = ((payload[11] as u64) << 32) | payload[10] as u64;
        otp.write_dword(zer_dword_addr, zer_dword_val)
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;
        Ok(())
    }

    fn validate_hek_transition(
        &self,
        active_slot: usize,
        target_slot: usize,
        total_slots: usize,
    ) -> Result<(), Error> {
        if target_slot != active_slot + 1 {
            return Err(Error::RUNTIME_INVALID_HEK_SLOT);
        }
        if target_slot > total_slots {
            return Err(Error::RUNTIME_INVALID_HEK_SLOT);
        }
        Ok(())
    }

    fn is_perma_bit_set(&self, otp: &Otp) -> Result<bool, Error> {
        match otp.read_entry(fuses::PERMA_HEK_EN) {
            Ok(val) => Ok(val != 0),
            Err(_) => Err(Error::ROM_INVALID_HEK_SLOT),
        }
    }

    fn is_hek_slot_zeroized(&self, otp: &Otp, slot: usize) -> Result<bool, Error> {
        let mut seed = [0u8; caliptra_mcu_romtime::HEK_PARTITION_SIZE];
        otp.read_hek_seed(slot, &mut seed)
            .map_err(|_| Error::ROM_INVALID_HEK_SLOT)?;
        Ok(seed.iter().all(|&b| b == 0xFF))
    }
}

pub static RUNTIME_OCP_LOCK_PLATFORM: RuntimeOcpLockPlatform = RuntimeOcpLockPlatform;
