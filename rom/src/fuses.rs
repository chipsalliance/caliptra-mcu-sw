// Licensed under the Apache-2.0 license

// TODO: remove after we use these
#![allow(dead_code)]
#![allow(unused)]

use core::num::NonZero;
use mcu_error::{McuError, McuResult};

pub struct OwnerPkHash([u32; 12]);
pub struct VendorPkHash([u32; 12]);

/// Trait for accessing raw fuse values.
/// Implementors should provide access to the individual fuse values as u32 slices,
/// which will be interpreted by the McuFuses struct to provide the values.
pub trait RawFuses {
    fn anti_rollback_disable(&self) -> u32;
    fn idevid_cert_idevid_attr(&self) -> &[u32];
    fn soc_specific_idevid_certificate(&self) -> Option<&[u32]>;
    fn idevid_manuf_hsm_identifier(&self) -> &[u32];
    fn soc_stepping_id(&self) -> u32;
    fn fmc_key_manifest_svn(&self) -> &[u8];
    fn runtime_svn(&self) -> &[u8];
    fn soc_manifest_svn(&self) -> &[u8];
    fn soc_manifest_max_svn(&self) -> &[u8];
    fn owner_pk_hash(&self) -> Option<OwnerPkHash>;
    fn owner_pqc_key_type(&self) -> &[u8];
    fn owner_pk_hash_valid(&self) -> u32;
    fn vendor_pk_hashes(&self) -> &[VendorPkHash];
    fn pqc_key_types(&self) -> &[u32];
    fn vendor_pk_hash_valid(&self) -> &[u32];
    fn owner_ecc_revocation(&self) -> &[u32];
    fn owner_lms_revocation(&self) -> &[u32];
    fn owner_mldsa_revocation(&self) -> &[u32];
    fn ecc_revocations(&self) -> &[u32];
    fn lms_revocations(&self) -> Option<&[u32]>;
    fn mldsa_revocations(&self) -> Option<&[u32]>;
}

pub struct McuFuseLayoutPolicy {
    anti_rollback_disable: FuseLayout,
    idevid_cert_idevid_attr: FuseLayout,
    soc_specific_idevid_certificate: Option<FuseLayout>,
    idevid_manuf_hsm_identifier: FuseLayout,
    soc_stepping_id: FuseLayout,
    fmc_key_manifest_svn: FuseLayout,
    runtime_svn: FuseLayout,
    soc_manifest_svn: FuseLayout,
    soc_manifest_max_svn: FuseLayout,
    owner_pqc_key_type: FuseLayout,
    owner_pk_hash_valid: FuseLayout,
    pqc_key_types: FuseLayout,
    vendor_pk_hash_valid: FuseLayout,
    owner_ecc_revocation: FuseLayout,
    owner_lms_revocation: FuseLayout,
    owner_mldsa_revocation: FuseLayout,
    ecc_revocations: FuseLayout,
    lms_revocations: FuseLayout,
    mldsa_revocations: FuseLayout,
}

impl Default for McuFuseLayoutPolicy {
    fn default() -> Self {
        Self {
            anti_rollback_disable: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            idevid_cert_idevid_attr: FuseLayout::Single(Bits(NonZero::new(768 * 8).unwrap())),
            soc_specific_idevid_certificate: None,
            idevid_manuf_hsm_identifier: FuseLayout::Single(Bits(NonZero::new(32).unwrap())),
            soc_stepping_id: FuseLayout::Single(Bits(NonZero::new(32).unwrap())),
            fmc_key_manifest_svn: FuseLayout::OneHotLinearMajorityVote(
                Bits(NonZero::new(32).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            runtime_svn: FuseLayout::OneHotLinearMajorityVote(
                Bits(NonZero::new(128).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            soc_manifest_svn: FuseLayout::OneHotLinearMajorityVote(
                Bits(NonZero::new(128).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            soc_manifest_max_svn: FuseLayout::Single(Bits(NonZero::new(128).unwrap())),
            owner_pqc_key_type: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            owner_pk_hash_valid: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            pqc_key_types: FuseLayout::Single(Bits(NonZero::new(16).unwrap())),
            vendor_pk_hash_valid: FuseLayout::Single(Bits(NonZero::new(16).unwrap())),
            owner_ecc_revocation: FuseLayout::LinearMajorityVote(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            owner_lms_revocation: FuseLayout::LinearMajorityVote(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            owner_mldsa_revocation: FuseLayout::LinearMajorityVote(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            ecc_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            lms_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            mldsa_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Bits(pub NonZero<usize>);

#[derive(Copy, Clone)]
pub struct Duplication(pub NonZero<usize>);

#[derive(Copy, Clone)]
pub enum FuseLayout {
    /// Values are stored literally
    Single(Bits),
    /// Value is the number of bits set,
    /// e.g., 0b110111 -> 5
    OneHot(Bits),
    /// Each bit is duplicated within a single u32 (or across adjacent u32s) and the majority vote
    /// is used to compute the final value,
    /// e.g., 0b110111 -> 0b11
    LinearMajorityVote(Bits, Duplication),
    /// Same as LinearMajorityVote, but the end result is simply the count of the bits,
    /// e.g., 0b110111 -> 2
    OneHotLinearMajorityVote(Bits, Duplication),
    /// u32s are duplicated, with bits are duplicated across multiple u32s. The result takes
    /// the majority vote of each bit,
    /// e.g., [0b100, 0b110, 0b111] -> [0b110]
    WordMajorityVote(Bits, Duplication),
}

pub struct McuFuses {
    raw_fuses: &'static dyn RawFuses,
    fuse_layout_policy: McuFuseLayoutPolicy,
}

impl McuFuses {
    pub fn new(
        raw_fuses: &'static dyn RawFuses,
        fuse_layout_policy_override: Option<McuFuseLayoutPolicy>,
    ) -> Self {
        Self {
            raw_fuses,
            fuse_layout_policy: fuse_layout_policy_override.unwrap_or_default(),
        }
    }
}

fn extract_majority_vote_u32(bits: NonZero<usize>, dupe: NonZero<usize>, raw_value: u32) -> u32 {
    let mut mask = (1 << dupe.get()) - 1;
    let mut result = 0;
    let half = (dupe.get() as u32).div_ceil(2);
    for i in 0..bits.get() {
        let votes = (raw_value & mask).count_ones();
        if votes >= half {
            result |= 1 << i;
        }
        mask <<= dupe.get();
    }
    result
}

/// Collapses a slice of words into a single word via majority vote.
fn extract_majority_vote_words(words: &[u32]) -> u32 {
    if words.is_empty() {
        return 0;
    }
    let half = words.len().div_ceil(2) as u32;
    let mut counts = [0u32; 32];
    for &word in words {
        for (i, count) in counts.iter_mut().enumerate() {
            *count += (word >> i) & 1;
        }
    }
    let mut result = 0;
    for (i, &count) in counts.iter().enumerate() {
        if count >= half {
            result |= 1 << i;
        }
    }
    result
}

pub fn extract_single_fuse_value(layout: FuseLayout, raw_value: u32) -> McuResult<u32> {
    match layout {
        FuseLayout::Single(Bits(bits)) if bits.get() > 32 => {
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        }
        FuseLayout::Single(Bits(bits)) if bits.get() == 32 => Ok(raw_value),
        FuseLayout::Single(Bits(bits)) => Ok(raw_value & ((1 << bits.get()) - 1)),
        FuseLayout::OneHot(Bits(bits)) if bits.get() > 32 => {
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        }
        FuseLayout::OneHot(Bits(bits)) if bits.get() == 32 => Ok(raw_value.count_ones()),
        FuseLayout::OneHot(Bits(bits)) => Ok((raw_value & ((1 << bits.get()) - 1)).count_ones()),
        FuseLayout::LinearMajorityVote(Bits(bits), Duplication(dupe)) if dupe.get() <= 32 => {
            // check that the duplicated bits fit in a single u32
            if bits.get() * dupe.get() > 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            Ok(extract_majority_vote_u32(bits, dupe, raw_value))
        }
        FuseLayout::OneHotLinearMajorityVote(Bits(bits), Duplication(dupe)) if dupe.get() <= 32 => {
            // check that the duplicated bits fit in a single u32
            if bits.get() * dupe.get() > 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            let value = extract_majority_vote_u32(bits, dupe, raw_value);
            Ok(value.count_ones())
        }
        _ => Err(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT),
    }
}

/// Extract bits from raw_value starting at offset for bits length.
#[inline(always)]
fn extract_bits(raw_value: &[u32], offset: usize, bits: usize) -> McuResult<u32> {
    if offset + bits > raw_value.len() * 32 || bits > 32 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }
    if bits == 0 {
        return Ok(0);
    }
    if bits > 32 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }
    // skip to the offset
    if offset >= 32 {
        return extract_bits(&raw_value[offset / 32..], offset % 32, bits);
    }
    if bits + offset > 64 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }

    if offset + bits <= 32 {
        // single u32
        if bits == 32 {
            Ok(raw_value[0] >> offset)
        } else {
            Ok((raw_value[0] >> offset) & ((1 << bits) - 1))
        }
    } else {
        // split across two adjacent u32s
        let bits_from_first = 32 - offset;
        let bits_from_second = bits - bits_from_first;

        let lower = (raw_value[0] >> offset) & ((1 << bits_from_first) - 1);
        let upper = raw_value[1] & ((1 << bits_from_second) - 1);

        Ok(lower | (upper << bits_from_first))
    }
}

pub fn extract_fuse_value<const N: usize>(
    layout: FuseLayout,
    raw_value: &[u32],
) -> McuResult<[u32; N]> {
    let mut result = [0u32; N];
    match layout {
        FuseLayout::Single(Bits(bits)) => {
            if bits.get() > result.len() * 32 {
                Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
            } else {
                let len = raw_value.len().min(result.len());
                result[..len].copy_from_slice(&raw_value[..len]);
                Ok(result)
            }
        }
        FuseLayout::OneHot(Bits(_)) => {
            if N != 1 {
                Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
            } else {
                let result = raw_value.iter().map(|&v| v.count_ones()).sum();
                Ok([result; N])
            }
        }
        FuseLayout::LinearMajorityVote(Bits(bits), Duplication(dupe)) if dupe.get() <= 32 => {
            // Total bits needed in raw_value
            let total_bits = bits.get() * dupe.get();
            if total_bits > raw_value.len() * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            let half = (dupe.get() as u32).div_ceil(2);
            for i in 0..bits.get() {
                // compute a single bit via majority vote
                let offset = i * dupe.get();
                let raw = extract_bits(raw_value, offset, dupe.get())?;
                let bit = if raw.count_ones() >= half { 1 } else { 0 };
                result[i / 32] |= bit << (i % 32);
            }
            Ok(result)
        }
        FuseLayout::OneHotLinearMajorityVote(Bits(bits), Duplication(dupe)) if dupe.get() <= 32 => {
            if N != 1 {
                Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
            } else {
                let half = (dupe.get() as u32).div_ceil(2);
                let mut result = 0;
                for i in 0..bits.get() {
                    // compute a single bit via majority vote
                    let offset = i * dupe.get();
                    let raw = extract_bits(raw_value, offset, dupe.get())?;
                    if raw.count_ones() >= half {
                        result += 1;
                    }
                }
                Ok([result; N])
            }
        }
        FuseLayout::WordMajorityVote(Bits(bits), Duplication(dupe)) if dupe.get() <= 32 => {
            // Total bits needed in raw_value
            let total_bits = bits.get() * dupe.get();
            if total_bits > raw_value.len() * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            // ensure that we have the right number of words
            if N != bits.get() / 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            // ensure that we have the right number of words
            if raw_value.len() % dupe.get() != 0 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            for (i, chunk) in raw_value.chunks_exact(dupe.get()).enumerate() {
                result[i] = extract_majority_vote_words(chunk);
            }
            Ok(result)
        }
        _ => Err(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_layout_extracts_bits() {
        // Extract 1 bit
        let layout = FuseLayout::Single(Bits(NonZero::new(1).unwrap()));
        assert_eq!(extract_single_fuse_value(layout, 0b1).unwrap(), 0b1);
        assert_eq!(
            extract_single_fuse_value(FuseLayout::Single(Bits(NonZero::new(1).unwrap())), 0b0)
                .unwrap(),
            0b0
        );

        // Extract 8 bits
        let layout = FuseLayout::Single(Bits(NonZero::new(8).unwrap()));
        assert_eq!(
            extract_single_fuse_value(layout, 0b11111111).unwrap(),
            0b11111111
        );

        // Extract 16 bits with masking
        let layout = FuseLayout::Single(Bits(NonZero::new(16).unwrap()));
        assert_eq!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF).unwrap(),
            0xFFFF
        );

        // Extract 32 bits
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        assert_eq!(
            extract_single_fuse_value(layout, 0xDEAD_BEEF).unwrap(),
            0xDEAD_BEEF
        );
    }

    #[test]
    fn test_linear_majority_vote_3x_duplication() {
        // 1 bit with 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0b111).unwrap(), 0b1);
        assert_eq!(extract_single_fuse_value(layout, 0b011).unwrap(), 0b1); // 2 votes out of 3
        assert_eq!(extract_single_fuse_value(layout, 0b001).unwrap(), 0b0); // only 1 vote out of 3

        // 2 bits with 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0b110111).unwrap(), 0b11);
        assert_eq!(extract_single_fuse_value(layout, 0b100011).unwrap(), 0b01);
    }

    #[test]
    fn test_linear_majority_vote_5x_duplication() {
        // 1 bit with 5x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0b11111).unwrap(), 0b1);
        assert_eq!(extract_single_fuse_value(layout, 0b00111).unwrap(), 0b1); // 3 votes out of 5
        assert_eq!(extract_single_fuse_value(layout, 0b00011).unwrap(), 0b0); // only 2 votes out of 5
    }

    #[test]
    fn test_linear_majority_vote_error_on_overflow() {
        // 11 bits * 3 duplication = 33 bits, exceeds u32
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        // 32 bits * 2 duplication = 64 bits, exceeds u32
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_linear_majority_vote_edge_case_max_bits() {
        // Maximum valid: 10 bits * 3 duplication = 30 bits (fits in u32)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        // All bits set to 0b111 pattern (all ones vote for 1)
        let value = 0b111111111111111111111111111111u32; // 30 bits of 1s
        assert_eq!(
            extract_single_fuse_value(layout, value).unwrap(),
            0b1111111111
        );

        // Edge case: exactly 32 bits with 1x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );
        assert_eq!(
            extract_single_fuse_value(layout, 0xAAAA_AAAA).unwrap(),
            0xAAAA_AAAA
        );
    }

    #[test]
    fn test_linear_majority_vote_multi_bit_patterns() {
        // 4 bits with 3x duplication = 12 bits total
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Pattern: bit0=111, bit1=110, bit2=001, bit3=011 -> 0b1011
        assert_eq!(
            extract_single_fuse_value(layout, 0b011_001_110_111u32).unwrap(),
            0b1011
        );

        // All zeros
        assert_eq!(extract_single_fuse_value(layout, 0b0).unwrap(), 0b0);

        // All ones (12 bits)
        assert_eq!(
            extract_single_fuse_value(layout, 0b111111111111u32).unwrap(),
            0b1111
        );
    }

    #[test]
    fn test_onehot_layout() {
        let layout = FuseLayout::OneHot(Bits(NonZero::new(8).unwrap()));
        assert_eq!(extract_single_fuse_value(layout, 0b00000000).unwrap(), 0);
        assert_eq!(extract_single_fuse_value(layout, 0b00000001).unwrap(), 1);
        assert_eq!(extract_single_fuse_value(layout, 0b00010101).unwrap(), 3);
        assert_eq!(extract_single_fuse_value(layout, 0b11111111).unwrap(), 8);

        // 16 bits with masking (upper bits ignored)
        let layout = FuseLayout::OneHot(Bits(NonZero::new(16).unwrap()));
        assert_eq!(extract_single_fuse_value(layout, 0xFFFF_FFFF).unwrap(), 16);

        // 32 bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        assert_eq!(extract_single_fuse_value(layout, 0xFFFF_FFFF).unwrap(), 32);
        assert_eq!(extract_single_fuse_value(layout, 0xAAAA_AAAA).unwrap(), 16);
    }

    #[test]
    fn test_onehot_error_on_overflow() {
        // 33 bits exceeds u32
        let layout = FuseLayout::OneHot(Bits(NonZero::new(33).unwrap()));
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        // 64 bits exceeds u32
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_onehot_linear_majority_vote_3x_duplication() {
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0b111).unwrap(), 1);
        assert_eq!(extract_single_fuse_value(layout, 0b011).unwrap(), 1); // bit set by majority
        assert_eq!(extract_single_fuse_value(layout, 0b001).unwrap(), 0); // bit not set by majority

        // 2 bits with 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0b110111).unwrap(), 2); // both bits set
        assert_eq!(extract_single_fuse_value(layout, 0b100011).unwrap(), 1); // only bit0 set
        assert_eq!(extract_single_fuse_value(layout, 0b000000).unwrap(), 0); // no bits set
    }

    #[test]
    fn test_onehot_linear_majority_vote_5x_duplication() {
        // 4 bits with 5x duplication = 20 bits total
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        // All bits vote 5/5 for 1
        assert_eq!(
            extract_single_fuse_value(layout, 0b11111_11111_11111_11111u32).unwrap(),
            4
        );

        // Mixed voting: bit0=11111(1), bit1=00111(1), bit2=00011(0), bit3=11100(1) -> 3
        assert_eq!(
            extract_single_fuse_value(layout, 0b11100_00011_00111_11111u32).unwrap(),
            3
        );

        // No bits set by majority
        assert_eq!(extract_single_fuse_value(layout, 0).unwrap(), 0);
    }

    #[test]
    fn test_onehot_linear_majority_vote_error_on_overflow() {
        // 11 bits * 3 duplication = 33 bits, exceeds u32
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        // 17 bits * 2 duplication = 34 bits, exceeds u32
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(17).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        assert!(matches!(
            extract_single_fuse_value(layout, 0xFFFF_FFFF),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_onehot_linear_majority_vote_edge_cases() {
        // Maximum valid: 10 bits * 3 duplication = 30 bits (fits in u32)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        // All bits set to 0b111 pattern -> all 10 bits counted
        assert_eq!(
            extract_single_fuse_value(layout, 0b111111111111111111111111111111u32).unwrap(),
            10
        );

        // Edge case: 32 bits with 1x duplication, 0xAAAA_AAAA has 16 bits set
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0xAAAA_AAAA).unwrap(), 16);

        // Edge case: 16 bits with 2x duplication = 32 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(16).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        assert_eq!(extract_single_fuse_value(layout, 0xFFFF_FFFF).unwrap(), 16);
    }

    #[test]
    fn test_onehot_linear_majority_vote_partial_patterns() {
        // 8 bits with 3x duplication = 24 bits total
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Pattern where only some bits pass majority vote
        // bit0=111(1), bit1=110(1), bit2=100(0), bit3=011(1),
        // bit4=001(0), bit5=000(0), bit6=111(1), bit7=101(1) -> 5 bits set
        assert_eq!(
            extract_single_fuse_value(layout, 0b101_111_000_001_011_100_110_111u32).unwrap(),
            5
        );

        // Alternating pattern: even bits pass, odd bits fail -> 4 bits set out of 8
        assert_eq!(
            extract_single_fuse_value(layout, 0b100_111_100_111_100_111_100_111u32).unwrap(),
            4
        );
    }

    #[test]
    fn test_extract_fuse_value_single_layout() {
        // Extract single u32
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        let raw = [0xDEADBEEF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xDEADBEEF]);

        // Extract multiple u32s
        let layout = FuseLayout::Single(Bits(NonZero::new(96).unwrap()));
        let raw = [0x11111111, 0x22222222, 0x33333333];
        let result: [u32; 3] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x11111111, 0x22222222, 0x33333333]);

        // Extract with exact size match
        let layout = FuseLayout::Single(Bits(NonZero::new(128).unwrap()));
        let raw = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
        let result: [u32; 4] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD]);
    }

    #[test]
    fn test_extract_fuse_value_single_layout_truncation() {
        // Result array smaller than raw data - should error
        let layout = FuseLayout::Single(Bits(NonZero::new(128).unwrap()));
        let raw = [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555];
        let result = extract_fuse_value::<3>(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Result array larger than raw data - should zero-pad
        let layout = FuseLayout::Single(Bits(NonZero::new(64).unwrap()));
        let raw = [0xAAAAAAAA, 0xBBBBBBBB];
        let result: [u32; 4] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xAAAAAAAA, 0xBBBBBBBB, 0, 0]);
    }

    #[test]
    fn test_extract_fuse_value_single_layout_empty() {
        // Empty input
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        let raw: [u32; 0] = [];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0, 0]);

        // Empty output (zero-sized array)
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        let raw = [0xDEADBEEF];
        let result = extract_fuse_value::<0>(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_single_layout_error_on_overflow() {
        // Layout specifies more bits than result array can hold
        let layout = FuseLayout::Single(Bits(NonZero::new(128).unwrap()));
        let raw = [0x11111111, 0x22222222, 0x33333333];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Extremely large bit count
        let layout = FuseLayout::Single(Bits(NonZero::new(1024).unwrap()));
        let raw = [0xFFFFFFFF; 10];
        let result: Result<[u32; 8], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_single_layout_large_arrays() {
        // Large certificate-like data (768 bits = 24 u32s)
        let layout = FuseLayout::Single(Bits(NonZero::new(768).unwrap()));
        let mut raw = [0u32; 24];
        for (i, val) in raw.iter_mut().enumerate() {
            *val = i as u32;
        }
        let result: [u32; 24] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, raw);

        // Extract subset of large data
        let layout = FuseLayout::Single(Bits(NonZero::new(384).unwrap()));
        let result: [u32; 12] = extract_fuse_value(layout, &raw).unwrap();
        let mut expected = [0u32; 12];
        for (i, val) in expected.iter_mut().enumerate() {
            *val = i as u32;
        }
        assert_eq!(result, expected);
    }

    #[test]
    fn test_extract_fuse_value_onehot_layout() {
        // Single u32 with various bit counts
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw = [0b00000000_00000000_00000000_00000001]; // 1 bit set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0b00000000_00000000_00000000_00001111]; // 4 bits set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [4]);

        let raw = [0xFFFFFFFF]; // 32 bits set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [32]);

        let raw = [0xAAAAAAAA]; // 16 bits set (alternating pattern)
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [16]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_multiple_words() {
        // Multiple u32s - sum of all bits set
        let layout = FuseLayout::OneHot(Bits(NonZero::new(96).unwrap()));
        let raw = [0x00000001, 0x00000003, 0x00000007]; // 1 + 2 + 3 = 6 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [6]);

        let raw = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]; // 32 + 32 + 32 = 96 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [96]);

        let raw = [0xAAAAAAAA, 0x55555555, 0xF0F0F0F0]; // 16 + 16 + 16 = 48 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [48]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_zero_bits() {
        // No bits set
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw = [0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);

        // Multiple words with no bits set
        let raw = [0x00000000, 0x00000000, 0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_empty_input() {
        // Empty input array
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw: [u32; 0] = [];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_large_arrays() {
        // Large array like certificate data (192 u32s = 6144 bits)
        let layout = FuseLayout::OneHot(Bits(NonZero::new(6144).unwrap()));
        let mut raw = [0u32; 192];
        // Set specific bits in various positions
        raw[0] = 0xFFFFFFFF; // 32 bits
        raw[50] = 0x0F0F0F0F; // 16 bits
        raw[100] = 0x00FF00FF; // 16 bits
        raw[191] = 0x000000FF; // 8 bits
                               // Total: 32 + 16 + 16 + 8 = 72 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [72]);

        // All bits set in a moderately large array
        let raw = [0xFFFFFFFF; 16]; // 16 * 32 = 512 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [512]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_error_on_non_single_result() {
        // OneHot with N != 1 should error
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw = [0xFFFFFFFF];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        let result: Result<[u32; 4], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Even with zero-sized result
        let result: Result<[u32; 0], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_onehot_various_patterns() {
        let layout = FuseLayout::OneHot(Bits(NonZero::new(128).unwrap()));

        // Sparse pattern
        let raw = [0x00000001, 0x00000001, 0x00000001, 0x00000001]; // 4 bits total
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [4]);

        // Dense pattern
        let raw = [0xFFFF0000, 0x0000FFFF, 0xF0F0F0F0, 0x0F0F0F0F]; // 16+16+16+16 = 64 bits
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [64]);

        // Mixed pattern
        let raw = [0x12345678u32, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210];
        let expected_count = raw.iter().map(|&v| v.count_ones()).sum::<u32>();
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [expected_count]);
    }

    #[test]
    fn test_extract_bits_single_word() {
        // Extract from beginning
        let raw = [0xDEADBEEF];
        assert_eq!(extract_bits(&raw, 0, 8).unwrap(), 0xEF);
        assert_eq!(extract_bits(&raw, 0, 16).unwrap(), 0xBEEF);
        assert_eq!(extract_bits(&raw, 0, 32).unwrap(), 0xDEADBEEF);

        // Extract from middle
        assert_eq!(extract_bits(&raw, 8, 8).unwrap(), 0xBE);
        assert_eq!(extract_bits(&raw, 8, 16).unwrap(), 0xADBE);
        assert_eq!(extract_bits(&raw, 16, 8).unwrap(), 0xAD);

        // Extract from end
        assert_eq!(extract_bits(&raw, 24, 8).unwrap(), 0xDE);
        assert_eq!(extract_bits(&raw, 28, 4).unwrap(), 0x0D);
    }

    #[test]
    fn test_extract_bits_split_across_words() {
        let raw = [0x12345678, 0x9ABCDEF0];

        // Split: 4 bits from first word, 4 bits from second
        // First[28:31] = 0x1, Second[0:3] = 0x0
        assert_eq!(extract_bits(&raw, 28, 8).unwrap(), 0x01);

        // Split: 8 bits from first word, 8 bits from second
        // First[24:31] = 0x12, Second[0:7] = 0xF0
        assert_eq!(extract_bits(&raw, 24, 16).unwrap(), 0xF012);

        // Split: 16 bits from first word, 16 bits from second
        // First[16:31] = 0x1234, Second[0:15] = 0xDEF0
        assert_eq!(extract_bits(&raw, 16, 32).unwrap(), 0xDEF01234);

        // Split: 20 bits from first word, 12 bits from second
        // First[12:31] = 0x12345, Second[0:11] = 0xEF0
        assert_eq!(extract_bits(&raw, 12, 32).unwrap(), 0xEF012345);
    }

    #[test]
    fn test_extract_bits_offset_beyond_first_word() {
        let raw = [0x11111111, 0x22222222, 0x33333333];

        // Extract from second word (offset 32)
        assert_eq!(extract_bits(&raw, 32, 8).unwrap(), 0x22);
        assert_eq!(extract_bits(&raw, 32, 32).unwrap(), 0x22222222);

        // Extract from third word (offset 64)
        assert_eq!(extract_bits(&raw, 64, 8).unwrap(), 0x33);
        assert_eq!(extract_bits(&raw, 64, 32).unwrap(), 0x33333333);

        // Extract split between second and third word
        assert_eq!(extract_bits(&raw, 56, 16).unwrap(), 0x3322);
    }

    #[test]
    fn test_extract_bits_edge_cases() {
        let raw = [0xFFFFFFFF, 0x00000000, 0xAAAAAAAA];

        // Extract 1 bit
        assert_eq!(extract_bits(&raw, 0, 1).unwrap(), 1);
        assert_eq!(extract_bits(&raw, 31, 1).unwrap(), 1);
        assert_eq!(extract_bits(&raw, 32, 1).unwrap(), 0);

        // Extract split with all 1s and all 0s
        assert_eq!(extract_bits(&raw, 28, 8).unwrap(), 0x0F);

        // Extract from alternating pattern
        assert_eq!(extract_bits(&raw, 64, 16).unwrap(), 0xAAAA);
    }

    #[test]
    fn test_extract_bits_error_on_overflow() {
        let raw = [0xDEADBEEF, 0x12345678];

        // Bits extend beyond array
        assert!(matches!(
            extract_bits(&raw, 60, 8),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        // More than 32 bits requested
        assert!(matches!(
            extract_bits(&raw, 0, 33),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        // Offset way beyond array
        assert!(matches!(
            extract_bits(&raw, 100, 8),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_extract_bits_all_positions() {
        // Test that we can extract from every possible position
        let raw = [0x01234567, 0x89ABCDEF];

        // Test various offsets and lengths
        for offset in 0..48 {
            for bits in 1..=(32.min(64 - offset)) {
                if (offset + bits + 31) / 32 <= raw.len() {
                    // Should not panic or error
                    let _ = extract_bits(&raw, offset, bits);
                }
            }
        }
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_basic() {
        // Single u32 result with 1 bit, 3x duplication (3 bits total)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0b111]; // Unanimous vote for 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b1]);

        let raw = [0b011]; // 2 out of 3 vote for 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b1]);

        let raw = [0b001]; // Only 1 out of 3 votes for 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b0]);

        let raw = [0b000]; // No votes for 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b0]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_multi_bit() {
        // 2 bits with 3x duplication (6 bits total)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0b110111]; // bit0=111(1), bit1=110(1) -> 0b11
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b11]);

        let raw = [0b100011]; // bit0=011(1), bit1=100(0) -> 0b01
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b01]);

        let raw = [0b001110]; // bit0=110(1), bit1=001(0) -> 0b01
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b01]);

        let raw = [0b000000]; // All zeros
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b00]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_spanning_words() {
        // 8 bits with 3x duplication = 24 bits (spans single u32 comfortably)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Pattern: all bits vote for 1
        let raw = [0b111111111111111111111111u32]; // 24 bits all set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b11111111]);

        // Pattern: alternating bits pass/fail
        // bit0=111(1), bit1=000(0), bit2=111(1), bit3=000(0), etc.
        let raw = [0b000111000111000111000111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b01010101]);

        // Mixed pattern
        let raw = [0b101_111_000_001_011_100_110_111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        // bit0=111(1), bit1=110(1), bit2=100(0), bit3=011(1),
        // bit4=001(0), bit5=000(0), bit6=111(1), bit7=101(1)
        assert_eq!(result, [0b11001011]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_across_u32_boundary() {
        // 12 bits with 3x duplication = 36 bits (spans 2 u32s)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(12).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // First 32 bits: bits 0-9 (30 bits), next u32: bits 10-11 (6 bits)
        // All bits vote for 1
        let raw = [0xFFFFFFFF, 0x0000003F]; // First 32 bits all set, next 6 bits set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b111111111111]); // All 12 bits set

        // Pattern where some bits span the boundary
        let raw = [0b111, 0b111];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b10_0000000001]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_multiple_u32_results() {
        // 64 bits with 3x duplication = 192 bits (spans 6 u32s input, 2 u32s output)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All bits vote for 1
        let raw = [0xFFFFFFFF; 6];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF, 0xFFFFFFFF]);

        // All bits vote for 0
        let raw = [0x00000000; 6];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x00000000, 0x00000000]);

        // First 32 bits vote for 1, last 32 bits vote for 0
        let raw = [
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
        ];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF, 0x00000000]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_5x_duplication() {
        // 4 bits with 5x duplication = 20 bits
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        // All bits vote 5/5 for 1
        let raw = [0b11111_11111_11111_11111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b1111]);

        // Mixed voting: bit0=11111(1), bit1=00111(1), bit2=00011(0), bit3=11100(1)
        let raw = [0b11100_00011_00111_11111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b1011]);

        // All bits need at least 3/5 votes
        let raw = [0b00011_00011_00011_00011u32]; // All fail (only 2/5)
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b0000]);

        // Exactly 3/5 on each (passes)
        let raw = [0b00111_00111_00111_00111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b1111]);
    }

    #[test]
    fn test_extract_fuse_value_linear_majority_vote_error_cases() {
        // Total bits exceed raw_value size
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(12).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = [0xFFFFFFFF]; // Only 32 bits, need 36
        let result: Result<[u32; 1], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Very large configuration
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1000).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = [0xFFFFFFFF; 10]; // Not enough data
        let result: Result<[u32; 32], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_basic() {
        // Single bit result with 1 bit, 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0b111]; // Unanimous vote for 1 -> count = 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0b011]; // Majority vote for 1 -> count = 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0b001]; // No majority -> count = 0
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);

        let raw = [0b000]; // No votes -> count = 0
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_multi_bit() {
        // 2 bits with 3x duplication -> count how many pass majority
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0b110111]; // bit0=111(1), bit1=110(1) -> count = 2
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [2]);

        let raw = [0b100011]; // bit0=011(1), bit1=100(0) -> count = 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0b000000]; // No bits pass majority -> count = 0
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_many_bits() {
        // 8 bits with 3x duplication = 24 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All 8 bits vote for 1
        let raw = [0b111111111111111111111111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [8]);

        // Alternating: bit0=111(1), bit1=000(0), bit2=111(1), bit3=000(0), etc.
        let raw = [0b000111000111000111000111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [4]); // 4 bits pass majority

        // Mixed pattern: bit0=111(1), bit1=110(1), bit2=100(0), bit3=011(1),
        //                bit4=001(0), bit5=000(0), bit6=111(1), bit7=101(1)
        let raw = [0b101_111_000_001_011_100_110_111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [5]); // 5 bits pass majority

        // No bits pass majority
        let raw = [0b000000000000000000000000u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_5x_duplication() {
        // 4 bits with 5x duplication = 20 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        // All bits vote 5/5 for 1
        let raw = [0b11111_11111_11111_11111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [4]);

        // Mixed: bit0=11111(1), bit1=00111(1), bit2=00011(0), bit3=11100(1)
        let raw = [0b11100_00011_00111_11111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [3]); // 3 bits pass majority

        // All need at least 3/5 votes
        let raw = [0b00011_00011_00011_00011u32]; // All fail (only 2/5)
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);

        // Exactly 3/5 on each (passes)
        let raw = [0b00111_00111_00111_00111u32];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [4]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_across_words() {
        // 12 bits with 3x duplication = 36 bits (spans 2 u32s)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(12).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All bits vote for 1
        let raw = [0xFFFFFFFF, 0x0000003F]; // First 32 bits + 6 more bits = 36 bits all set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [12]); // All 12 bits pass

        // 1 fails
        let raw = [0xFFFFFFFF, 0x00000000]; // First 11 bits pass (32 bits set), last 1 fails
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [11]);

        // None pass
        let raw = [0x00000000, 0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_large_bit_count() {
        // 32 bits with 3x duplication = 96 bits (3 u32s)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All bits vote for 1
        let raw = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [32]);

        let raw = [0xFFFFFFFF, 0x00000000, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        // First 11 bits + last 11 bits pass, middle 10 fail = 22 bits pass
        assert_eq!(result, [22]);

        // None pass
        let raw = [0x00000000; 3];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_error_cases() {
        // Result array size must be 1
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = [0xFFFFFFFF];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Not enough raw data
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(12).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = [0xFFFFFFFF]; // Only 32 bits, need 36
        let result: Result<[u32; 1], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_onehot_linear_majority_vote_edge_cases() {
        // Maximum bits that fit in u32 with 1x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );
        let raw = [0xAAAAAAAA]; // 16 bits set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [16]);

        let raw = [0xFFFFFFFF]; // All 32 bits set
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [32]);

        // 1 bit with maximum duplication that fits in 32 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(32).unwrap()),
        );
        let raw = [0xFFFFFFFF]; // All 32 votes for 1
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0x0000FFFF]; // 16 votes for 1 (passes)
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [1]);

        let raw = [0x000000FF]; // 8 votes for 1 (fails, needs 17)
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn test_extract_majority_vote_words_single_word() {
        // Single word should return itself
        assert_eq!(extract_majority_vote_words(&[0xDEADBEEF]), 0xDEADBEEF);
        assert_eq!(extract_majority_vote_words(&[0x00000000]), 0x00000000);
        assert_eq!(extract_majority_vote_words(&[0xFFFFFFFF]), 0xFFFFFFFF);
        assert_eq!(extract_majority_vote_words(&[0xAAAAAAAA]), 0xAAAAAAAA);
    }

    #[test]
    fn test_extract_majority_vote_words_two_words_unanimous() {
        // Both words agree - should return the same value
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0xFFFFFFFF]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0x00000000]),
            0x00000000
        );
        assert_eq!(
            extract_majority_vote_words(&[0xAAAAAAAA, 0xAAAAAAAA]),
            0xAAAAAAAA
        );
        assert_eq!(
            extract_majority_vote_words(&[0x12345678, 0x12345678]),
            0x12345678
        );
    }

    #[test]
    fn test_extract_majority_vote_words_two_words_split() {
        // Two words with different values - tie goes to 1 (need ceiling for majority)
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0x00000000]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0xFFFFFFFF]),
            0xFFFFFFFF
        );

        // Specific bit patterns
        assert_eq!(
            extract_majority_vote_words(&[0xF0F0F0F0, 0x0F0F0F0F]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0xFF00FF00, 0x00FF00FF]),
            0xFFFFFFFF
        );
    }

    #[test]
    fn test_extract_majority_vote_words_three_words_unanimous() {
        // All three agree
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0x00000000, 0x00000000]),
            0x00000000
        );
        assert_eq!(
            extract_majority_vote_words(&[0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA]),
            0xAAAAAAAA
        );
    }

    #[test]
    fn test_extract_majority_vote_words_three_words_majority() {
        // 2 out of 3 vote for each bit
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0xFFFFFFFF, 0x00000000]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0xFFFFFFFF, 0xFFFFFFFF]),
            0xFFFFFFFF
        );
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0x00000000, 0xFFFFFFFF]),
            0xFFFFFFFF
        );

        // 2 out of 3 vote for 0
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0x00000000, 0xFFFFFFFF]),
            0x00000000
        );
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0x00000000, 0x00000000]),
            0x00000000
        );
        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0xFFFFFFFF, 0x00000000]),
            0x00000000
        );
    }

    #[test]
    fn test_extract_majority_vote_words_three_words_mixed_bits() {
        // Mixed patterns where different bits have different majorities
        // bit0: [1,0,1]=1, bit1: [0,1,0]=0, etc.
        assert_eq!(extract_majority_vote_words(&[0b101, 0b010, 0b101]), 0b101);
        assert_eq!(extract_majority_vote_words(&[0b111, 0b010, 0b100]), 0b110);

        // More complex pattern
        let words = [0xF0F0F0F0, 0x0F0F0F0F, 0xF0F0F0F0];
        // For each bit position, 2 out of 3 vote for the pattern 0xF0F0F0F0
        assert_eq!(extract_majority_vote_words(&words), 0xF0F0F0F0);
    }

    #[test]
    fn test_extract_majority_vote_words_five_words_majority() {
        // 5 words - need at least 3 to pass
        assert_eq!(
            extract_majority_vote_words(&[
                0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000
            ]),
            0xFFFFFFFF
        );

        assert_eq!(
            extract_majority_vote_words(&[
                0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF
            ]),
            0x00000000
        );

        // Exactly 3 out of 5
        assert_eq!(
            extract_majority_vote_words(&[
                0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF
            ]),
            0xFFFFFFFF
        );
    }

    #[test]
    fn test_extract_majority_vote_words_five_words_per_bit() {
        // Test where different bits have different vote outcomes
        let words = [
            0b11111, // All bits 0-4 set
            0b01110, // Bits 1-3 set
            0b00100, // Only bit 2 set
            0b01110, // Bits 1-3 set
            0b11111, // All bits 0-4 set
        ];
        // bit0: 2/5 vote for 1 -> 0
        // bit1: 4/5 vote for 1 -> 1
        // bit2: 5/5 vote for 1 -> 1
        // bit3: 4/5 vote for 1 -> 1
        // bit4: 2/5 vote for 1 -> 0
        assert_eq!(extract_majority_vote_words(&words), 0b01110);
    }

    #[test]
    fn test_extract_majority_vote_words_empty_slice() {
        // Empty slice - should return 0 (no bits set)
        assert_eq!(extract_majority_vote_words(&[]), 0x00000000);
    }

    #[test]
    fn test_extract_majority_vote_words_edge_case_all_patterns() {
        // Test specific patterns across multiple words
        let words = [0xAAAAAAAA, 0x55555555, 0xAAAAAAAA];
        // bit0: [0,1,0]=0, bit1: [1,0,1]=1, alternating
        assert_eq!(extract_majority_vote_words(&words), 0xAAAAAAAA);

        let words = [0x55555555, 0xAAAAAAAA, 0x55555555];
        assert_eq!(extract_majority_vote_words(&words), 0x55555555);
    }

    #[test]
    fn test_extract_majority_vote_words_four_words_tie() {
        // With 4 words, tie (2-2) should favor 1 (div_ceil(4/2) = 2)
        assert_eq!(
            extract_majority_vote_words(&[0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000]),
            0xFFFFFFFF
        );

        assert_eq!(
            extract_majority_vote_words(&[0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF]),
            0xFFFFFFFF
        );

        // Mixed bit patterns with ties
        let words = [0xF0F0F0F0, 0xF0F0F0F0, 0x0F0F0F0F, 0x0F0F0F0F];
        // Each bit position has a 2-2 tie, which should favor 1
        assert_eq!(extract_majority_vote_words(&words), 0xFFFFFFFF);
    }

    #[test]
    fn test_extract_majority_vote_words_real_world_svn_pattern() {
        // Simulate a real SVN fuse scenario with 3x duplication
        // SVN value of 0x00000005 duplicated 3 times
        assert_eq!(
            extract_majority_vote_words(&[0x00000005, 0x00000005, 0x00000005]),
            0x00000005
        );

        // One corrupted
        assert_eq!(
            extract_majority_vote_words(&[0x00000005, 0x00000005, 0xFFFFFFFF]),
            0x00000005
        );

        // Two corrupted differently
        assert_eq!(
            extract_majority_vote_words(&[0x00000005, 0x00000007, 0x00000001]),
            0x00000005
        );
    }

    #[test]
    fn test_extract_majority_vote_words_large_array() {
        // Test with many words (7 words, need 4 to pass)
        let words = [
            0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0x12345678, 0x12345678, 0x12345678,
        ];
        assert_eq!(extract_majority_vote_words(&words), 0xDEADBEEF);

        // Test with 9 words (need 5 to pass)
        let words = [
            0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0x55555555, 0x55555555,
            0x55555555, 0x55555555,
        ];
        assert_eq!(extract_majority_vote_words(&words), 0xAAAAAAAA);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_single_word_3x_duplication() {
        // 1 word with 3x duplication = 3 input u32s
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All three words unanimous
        let raw = [0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xDEADBEEF]);

        // Two words agree, one differs (majority wins)
        let raw = [0xFFFFFFFF, 0xFFFFFFFF, 0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF]);

        let raw = [0x00000000, 0xFFFFFFFF, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF]);

        // Per-bit majority vote
        // bit pattern: [0b101, 0b110, 0b111]
        // bit 0: 2 ones, 1 zero -> 1
        // bit 1: 2 ones, 1 zero -> 1
        // bit 2: 3 ones -> 1
        let raw = [0b101, 0b110, 0b111];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0b111]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_single_word_5x_duplication() {
        // 1 word with 5x duplication = 5 input u32s
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        // All five words unanimous
        let raw = [0x12345678, 0x12345678, 0x12345678, 0x12345678, 0x12345678];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x12345678]);

        // 3 out of 5 agree
        let raw = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF]);

        let raw = [0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF]);

        // Per-bit majority with complex pattern
        // For each bit position, count which value wins
        let raw = [0xAAAAAAAA, 0xAAAAAAAA, 0xAAAAAAAA, 0x55555555, 0x55555555];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xAAAAAAAA]); // 3 votes for 0xAAAAAAAA pattern wins
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_multiple_words() {
        // 2 words with 3x duplication = 6 input u32s
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All words unanimous
        let raw = [
            0x11111111, 0x11111111, 0x11111111, 0x22222222, 0x22222222, 0x22222222,
        ];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x11111111, 0x22222222]);

        // First word has majority, second word has majority
        let raw = [
            0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0xAAAAAAAA, 0xAAAAAAAA,
        ];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF, 0xAAAAAAAA]);

        // Mixed patterns requiring per-bit voting
        let raw = [0b1010, 0b1100, 0b1110, 0b0001, 0b0011, 0b0111];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        // First word: bit0=[0,0,0]->0, bit1=[1,0,1]->1, bit2=[0,1,1]->1, bit3=[1,1,1]->1
        // Second word: bit0=[1,1,1]->1, bit1=[0,1,1]->1, bit2=[0,0,1]->0, bit3=[0,0,0]->0
        assert_eq!(result, [0b1110, 0b0011]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_large_array() {
        // 4 words with 3x duplication = 12 input u32s
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [
            0xAAAAAAAA, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE,
            0xEEEEEEEE, 0xFFFFFFFF, 0x12345678, 0x12345678, 0x87654321,
        ];
        let result: [u32; 4] = extract_fuse_value(layout, &raw).unwrap();
        // Each chunk of 3: majority vote per bit
        assert_eq!(result[0], extract_majority_vote_words(&raw[0..3]));
        assert_eq!(result[1], extract_majority_vote_words(&raw[3..6]));
        assert_eq!(result[2], extract_majority_vote_words(&raw[6..9]));
        assert_eq!(result[3], extract_majority_vote_words(&raw[9..12]));
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_certificate_size() {
        // Simulate certificate data: 24 words with 3x duplication = 72 input u32s
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(768).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let mut raw = [0u32; 72];
        // Fill with pattern where every group of 3 has majority
        for i in 0..24 {
            let value = (i as u32).wrapping_mul(0x11111111);
            raw[i * 3] = value;
            raw[i * 3 + 1] = value;
            raw[i * 3 + 2] = !value; // One dissenting vote
        }

        let result: [u32; 24] = extract_fuse_value(layout, &raw).unwrap();
        for (i, &item) in result.iter().enumerate() {
            let expected = (i as u32).wrapping_mul(0x11111111);
            assert_eq!(item, expected);
        }
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_all_zeros() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0x00000000; 6];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x00000000, 0x00000000]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_all_ones() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(96).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        let raw = [0xFFFFFFFF; 15]; // 3 words * 5 duplication
        let result: [u32; 3] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_alternating_pattern() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Alternating 0xAAAAAAAA and 0x55555555 patterns
        let raw = [
            0xAAAAAAAA, 0xAAAAAAAA, 0x55555555, 0x55555555, 0x55555555, 0xAAAAAAAA,
        ];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result[0], 0xAAAAAAAA); // 2 vs 1
        assert_eq!(result[1], 0x55555555); // 2 vs 1
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_complex_bit_patterns() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Complex pattern where each bit position needs individual majority vote
        // Word 0: 0b11110000111100001111000011110000
        // Word 1: 0b10101010101010101010101010101010
        // Word 2: 0b11001100110011001100110011001100
        let raw = [
            0b11110000111100001111000011110000u32,
            0b10101010101010101010101010101010u32,
            0b11001100110011001100110011001100u32,
        ];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();

        // Manually compute expected result by majority vote per bit
        let expected = extract_majority_vote_words(&raw);
        assert_eq!(result, [expected]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_error_on_misaligned_input() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Need 6 u32s (2 words * 3 duplication), but provide 7
        let raw = [0x11111111; 7];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Need 6 u32s, but provide 5
        let raw = [0x11111111; 5];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Need 6 u32s, but provide 4
        let raw = [0x11111111; 4];
        let result: Result<[u32; 2], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_error_on_insufficient_raw_data() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Need 12 u32s (4 words * 3 duplication), but provide empty
        let raw: [u32; 0] = [];
        let result: Result<[u32; 4], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // Provide some but not enough
        let raw = [0x11111111; 9];
        let result: Result<[u32; 4], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_error_on_result_mismatch() {
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let raw = [0x11111111; 6]; // Correct input size

        // Request wrong output size
        let result: Result<[u32; 3], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        let result: Result<[u32; 1], _> = extract_fuse_value(layout, &raw);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_single_duplication() {
        // Edge case: 1x duplication (no actual redundancy)
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );

        let raw = [0xDEADBEEF, 0x12345678];
        let result: [u32; 2] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xDEADBEEF, 0x12345678]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_even_duplication_ties() {
        // With 2x duplication, ties are possible (need 1 out of 2 for majority due to div_ceil)
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // When both words agree
        let raw = [0xAAAAAAAA, 0xAAAAAAAA];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0xAAAAAAAA]);

        // When words disagree - with div_ceil, need at least 1 vote for majority
        let raw = [0xFFFFFFFF, 0x00000000];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        // Each bit needs at least 1 vote (50% rounded up)
        let expected = extract_majority_vote_words(&raw);
        assert_eq!(result, [expected]);

        // Complex disagreement
        let raw = [0xAAAAAAAA, 0x55555555];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        let expected = extract_majority_vote_words(&raw);
        assert_eq!(result, [expected]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_real_world_svn_pattern() {
        // Simulate SVN storage: small values with 5x duplication
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        // SVN value of 7 with one corrupted copy
        let raw = [0x00000007, 0x00000007, 0x00000007, 0x00000007, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x00000007]);

        // SVN value of 15 with two corrupted copies
        let raw = [0x0000000F, 0x0000000F, 0x0000000F, 0x00000000, 0xFFFFFFFF];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0x0000000F]);
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_hash_pattern() {
        // Simulate hash storage: 12 words (384 bits) with 3x duplication
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(384).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let mut raw = [0u32; 36]; // 12 words * 3 duplication
                                  // Fill with a hash-like pattern
        for i in 0..12 {
            let value = 0x01234567u32.wrapping_add(i as u32 * 0x11111111);
            raw[i * 3] = value;
            raw[i * 3 + 1] = value;
            raw[i * 3 + 2] = value; // All unanimous for simplicity
        }

        let result: [u32; 12] = extract_fuse_value(layout, &raw).unwrap();
        for (i, &item) in result.iter().enumerate() {
            let expected = 0x01234567u32.wrapping_add(i as u32 * 0x11111111);
            assert_eq!(item, expected);
        }
    }

    #[test]
    fn test_extract_fuse_value_word_majority_vote_maximum_practical_size() {
        // Large but practical: 32 words with 3x duplication
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(1024).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let mut raw = [0u32; 96]; // 32 words * 3 duplication
        for i in 0..32 {
            let value = i as u32;
            raw[i * 3] = value;
            raw[i * 3 + 1] = value;
            raw[i * 3 + 2] = value;
        }

        let result: [u32; 32] = extract_fuse_value(layout, &raw).unwrap();
        for (i, &item) in result.iter().enumerate() {
            assert_eq!(item, i as u32);
        }
    }
}
