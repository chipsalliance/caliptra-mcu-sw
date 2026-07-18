// Licensed under the Apache-2.0 license
//
// OTP Fuse Provisioning via DAI (Direct Access Interface)
//
// Implements three fuse provisioning commands per the MC_FUSE specification:
//   MC_FUSE_READ           (0x4946_5052 / "IFPR")
//   MC_FUSE_WRITE          (0x4946_5057 / "IFPW")
//   MC_FUSE_LOCK_PARTITION (0x4946_504B / "IFPK")
//
// All OTP access goes through the DAI helpers in romtime::Otp
// (read_word, write_word, finalize_digest).

use crate::{HexWord, Otp};
use caliptra_mcu_error::McuError;
pub use caliptra_mcu_otp_fuse::{fuse_read_dai_params, FuseReadParams, PartitionId, PartitionInfo};

// ===========================================================================
// MC_FUSE_READ  (0x4946_5052 / "IFPR")
// ===========================================================================

/// Convenience wrapper: validates and reads fuse data into a caller-provided
/// buffer.  Kept for callers that already have a `&mut [u32]` destination.
pub fn fuse_read_dai(
    otp: &Otp,
    partition: u32,
    entry: u32,
    out_data: &mut [u32],
) -> Result<u32, McuError> {
    let params = fuse_read_dai_params(partition, entry, out_data.len())?;

    for (i, slot) in out_data.iter_mut().enumerate().take(params.words_to_read) {
        match otp.read_word(params.base_word_addr + i) {
            Ok(word) => *slot = word,
            Err(_) => {
                crate::println!(
                    "[otp-provision] DAI read error at word addr {}",
                    params.base_word_addr + i
                );
                return Err(McuError::ROM_OTP_FUSE_DAI_READ_ERROR);
            }
        }
    }

    Ok(params.valid_bits)
}

// ===========================================================================
// MC_FUSE_WRITE  (0x4946_5057 / "IFPW")
// ===========================================================================
/// Writes a word to an OTP word address.
///
/// Only bits specified with `mask` are written.
/// Bits outside of `mask` are ignored.
///
/// # Errors
/// - When `word_addr` is not a valid address
/// - When any of the existing data is `1` but is set to `0` in the input data
pub fn fuse_write_dai(otp: &Otp, word_addr: u32, data: u32, mask: u32) -> Result<(), McuError> {
    // Mask the input value with the provided mask (in case the user didn't do so).
    let masked_value = data & mask;

    let current_word = otp.read_word(word_addr as usize)?;

    // Mask the current word to our interest range.
    let masked_current_word = current_word & mask;

    // No-op if the fuse already holds identical data.
    if masked_current_word == masked_value {
        crate::println!("[otp-provision] Superflous fuse write, input matches existing data");
        return Ok(());
    }
    // Check if the user wants to set a bit from `1` to `0`.
    if !fuse_write_possible(masked_current_word, masked_value) {
        crate::println!("[otp-provision] Write error, attempted to set bit(s) from 1 to 0");
        return Err(McuError::ROM_OTP_FUSE_DAI_WRITE_ERROR);
    }

    // Finally calculate the new fuse value and write it.
    let new_otp_value = current_word | masked_value;
    otp.write_word(word_addr as usize, new_otp_value)?;
    Ok(())
}

/// Return `false` if the new word would set a bit from `1` to `0`.
fn fuse_write_possible(current_word: u32, new_word: u32) -> bool {
    // We can do this by inverting `value` to compare every `0` bit in value to the stored one.
    (current_word & !new_word) == 0
}

// ===========================================================================
// MC_FUSE_LOCK_PARTITION  (0x4946_504B / "IFPK")
// ===========================================================================
//
/// Locks a partition by computing and writing its integrity digest via DAI.
/// Idempotent: locking an already-locked partition is a no-op.
/// Locking does not fully take effect until the next reset.
pub fn fuse_lock_partition_dai(otp: &Otp, partition: u32) -> Result<(), McuError> {
    let info = PartitionId::try_from(partition)?.info();

    crate::println!(
        "[otp-provision] DAI lock: partition={}, base_addr={}",
        HexWord(partition),
        HexWord(info.byte_offset as u32)
    );

    match otp.finalize_digest(info.byte_offset) {
        Ok(()) => {
            crate::println!(
                "[otp-provision] Partition {} locked successfully",
                partition
            );
            Ok(())
        }
        Err(_) => {
            crate::println!("[otp-provision] Failed to lock partition {}", partition);
            Err(McuError::ROM_OTP_FUSE_LOCK_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_fuse_write_possible() {
        use crate::otp_provision::fuse_write_possible;

        let current = 0b0011_1100;

        assert!(fuse_write_possible(current, 0b0111_1100));
        assert!(fuse_write_possible(current, 0b1111_1111));

        assert!(!fuse_write_possible(current, 0b010_1100));
        assert!(!fuse_write_possible(current, 0b010_1101));
        assert!(!fuse_write_possible(current, 0b000_0000));
    }
}
