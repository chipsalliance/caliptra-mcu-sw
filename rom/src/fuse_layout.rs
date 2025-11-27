// Licensed under the Apache-2.0 license

// TODO: remove after we use these
#![allow(dead_code)]
#![allow(unused)]

use core::num::NonZero;
use mcu_error::{McuError, McuResult};

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
    /// Same as LinearMajorityVote, but the end result is to simply the count of the bits,
    /// e.g., 0b110111 -> 2
    OneHotLinearMajorityVote(Bits, Duplication),
    /// u32s are duplicated, with bits are duplicated across multiple u32s. The result takes
    /// the majority vote of each bit,
    /// e.g., [0b100, 0b110, 0b111] -> [0b110]
    WordMajorityVote(Bits, Duplication),
}

/// Writes a value into a u32 with majority vote duplication, returning the raw value that
/// should be written to fuses.
fn write_majority_vote_u32(bits: NonZero<usize>, dupe: NonZero<usize>, value: u32) -> u32 {
    let one = (1 << dupe.get()) - 1;
    let mut raw = 0;
    for i in 0..bits.get() {
        let bit = (value >> i) & 1;
        let raw_bit = if bit == 1 { one } else { 0 };
        raw |= raw_bit << (i * dupe.get());
    }
    raw
}

/// Reads a raw fuse value with majority vote duplication, returning the collapsed value.
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

/// For a value that fits into a single u32, duplicates it according to the layout
/// and returns the raw fuse value.
pub fn write_single_fuse_value(layout: FuseLayout, value: u32) -> McuResult<u32> {
    match layout {
        FuseLayout::Single(_) => Ok(value),
        FuseLayout::OneHot(_) if value > 32 => Err(McuError::ROM_FUSE_VALUE_TOO_LARGE),
        FuseLayout::OneHot(_) if value == 32 => Ok(0xffff_ffff),
        FuseLayout::OneHot(_) => Ok((1 << value) - 1),
        FuseLayout::LinearMajorityVote(Bits(bits), Duplication(dupe)) => {
            // check that the duplicated bits fit in a single u32
            if bits.get() * dupe.get() > 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            Ok(write_majority_vote_u32(bits, dupe, value))
        }
        FuseLayout::OneHotLinearMajorityVote(_, _) if value > 32 => {
            Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)
        }
        FuseLayout::OneHotLinearMajorityVote(Bits(bits), Duplication(dupe)) => {
            // check that the duplicated bits fit in a single u32
            if bits.get() * dupe.get() > 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            let value = if value == 32 {
                0xffff_ffff
            } else {
                (1 << value) - 1
            };
            Ok(write_majority_vote_u32(bits, dupe, value))
        }
        _ => Err(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT),
    }
}

/// For a raw fuse value that fits into a single u32, collapses it according to the layout
/// and returns the final value.
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
        FuseLayout::LinearMajorityVote(Bits(bits), Duplication(dupe)) => {
            // check that the duplicated bits fit in a single u32
            if bits.get() * dupe.get() > 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            Ok(extract_majority_vote_u32(bits, dupe, raw_value))
        }
        FuseLayout::OneHotLinearMajorityVote(Bits(bits), Duplication(dupe)) => {
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

#[inline(always)]
fn inject_bits(output: &mut [u32], offset: usize, bits: usize, value: u32) -> McuResult<()> {
    if offset + bits > output.len() * 32 || bits > 32 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }
    if bits == 0 {
        return Ok(());
    }
    if bits > 32 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }
    // skip to the offset
    if offset >= 32 {
        return inject_bits(&mut output[offset / 32..], offset % 32, bits, value);
    }
    if bits + offset > 64 {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }

    if offset + bits <= 32 {
        // single u32
        if bits == 32 {
            output[0] = value;
        } else {
            let mask = (1 << bits) - 1;
            output[0] &= !(mask << offset);
            output[0] |= (value & mask) << offset;
        }
    } else {
        // split across two adjacent u32s
        let bits_from_first = 32 - offset;
        let bits_from_second = bits - bits_from_first;

        let first_value = value & ((1 << bits_from_first) - 1);
        output[0] &= (1 << offset) - 1;
        output[0] |= first_value << offset;

        let second_value = (value >> bits_from_first) & ((1 << bits_from_second) - 1);
        output[1] &= !((1 << bits_from_second) - 1);
        output[1] |= second_value;
    }
    Ok(())
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

/// Writes values into raw fuse format according to the specified layout.
/// This is the inverse of extract_fuse_value - it takes a logical value and produces
/// the raw fuse representation that extract_fuse_value expects.
///
/// Returns the raw fuse data.
pub fn write_fuse_value<const N: usize, const M: usize>(
    layout: FuseLayout,
    value: &[u32; N],
) -> McuResult<[u32; M]> {
    if N > M {
        return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
    }
    let mut result = [0u32; M];

    match layout {
        FuseLayout::Single(Bits(bits)) => {
            if bits.get() > N * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            result[..N].copy_from_slice(&value[..]);
        }
        FuseLayout::OneHot(Bits(bits)) => {
            if N != 1 || bits.get() > M * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            let value = value[0];
            if value > bits.get() as u32 {
                return Err(McuError::ROM_FUSE_VALUE_TOO_LARGE);
            }
            // Burn exactly 'value' bits, starting from LSB
            let mut bits_left = value as usize;
            for r in result.iter_mut() {
                let burn = bits_left.min(32);
                if burn == 32 {
                    *r = 0xffff_ffff;
                } else if burn > 0 {
                    *r = (1 << burn) - 1;
                }
                bits_left -= burn;
            }
        }

        FuseLayout::LinearMajorityVote(Bits(bits), Duplication(dupe)) => {
            // Duplicate each bit a certain number of times
            if bits.get() * dupe.get() > M * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            for i in 0..bits.get() {
                let bit = (value[i / 32] >> (i % 32)) & 1;
                let raw_bit = (bit << dupe.get()).saturating_sub(1);
                inject_bits(&mut result, i * dupe.get(), dupe.get(), raw_bit)?;
            }
        }

        FuseLayout::OneHotLinearMajorityVote(Bits(bits), Duplication(dupe)) => {
            if N != 1 || bits.get() * dupe.get() > M * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            let value = value[0];
            if value > bits.get() as u32 {
                return Err(McuError::ROM_FUSE_VALUE_TOO_LARGE);
            }
            // Burn exactly 'value' * 'dupe' bits, starting from LSB
            let mut bits_left = value as usize * dupe.get();
            for r in result.iter_mut() {
                let burn = bits_left.min(32);
                if burn == 32 {
                    *r = 0xffff_ffff;
                } else if burn > 0 {
                    *r = (1 << burn) - 1;
                }
                bits_left -= burn;
            }
        }

        FuseLayout::WordMajorityVote(Bits(bits), Duplication(dupe)) => {
            // Total bits needed in raw_value
            let total_bits = bits.get() * dupe.get();
            if total_bits > M * 32 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            // ensure that we have the right number of words
            if M % dupe.get() != 0 {
                return Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE);
            }
            for (i, &x) in value.iter().enumerate() {
                for j in 0..dupe.get() {
                    result[i * dupe.get() + j] = x;
                }
            }
        }
    }
    Ok(result)
}

/// Reads a fuse value from a raw fuse value, applying the given layout to the
/// raw fuses.
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
    fn test_extract_fuse_value_onehot_empty_input() {
        // Empty input array
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw: [u32; 0] = [];
        let result: [u32; 1] = extract_fuse_value(layout, &raw).unwrap();
        assert_eq!(result, [0]);
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
    fn test_majority_vote_u32_round_trip_single_bit() {
        // Test 1 bit with various duplication factors
        let bits = NonZero::new(1).unwrap();

        // 3x duplication
        let dupe = NonZero::new(3).unwrap();
        for value in [0u32, 1u32] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value {} with 3x duplication",
                value
            );
        }

        // 5x duplication
        let dupe = NonZero::new(5).unwrap();
        for value in [0u32, 1u32] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value {} with 5x duplication",
                value
            );
        }

        // 7x duplication
        let dupe = NonZero::new(7).unwrap();
        for value in [0u32, 1u32] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value {} with 7x duplication",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_two_bits() {
        // Test 2 bits with 3x duplication
        let bits = NonZero::new(2).unwrap();
        let dupe = NonZero::new(3).unwrap();

        for value in [0b00u32, 0b01, 0b10, 0b11] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0b{:02b}",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_four_bits() {
        // Test 4 bits with 3x duplication
        let bits = NonZero::new(4).unwrap();
        let dupe = NonZero::new(3).unwrap();

        for value in [0x0u32, 0x1, 0x5, 0x7, 0x9, 0xA, 0xF] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:X}",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_eight_bits() {
        // Test 8 bits with 3x duplication
        let bits = NonZero::new(8).unwrap();
        let dupe = NonZero::new(3).unwrap();

        for value in [0x00u32, 0x01, 0x55, 0xAA, 0xFF, 0x12, 0x34, 0x78] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:02X}",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_ten_bits() {
        // Test 10 bits with 3x duplication (maximum that fits in u32)
        let bits = NonZero::new(10).unwrap();
        let dupe = NonZero::new(3).unwrap();

        for value in [0x000u32, 0x001, 0x3FF, 0x155, 0x2AA, 0x123, 0x200] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:03X}",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_edge_cases() {
        // Test with 1x duplication (no actual duplication)
        let bits = NonZero::new(8).unwrap();
        let dupe = NonZero::new(1).unwrap();
        for value in [0x00u32, 0xFF, 0xAA, 0x55] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:02X} with 1x duplication",
                value
            );
        }

        // Test with 2x duplication
        let dupe = NonZero::new(2).unwrap();
        for value in [0x00u32, 0xFF, 0xAA, 0x55] {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:02X} with 2x duplication",
                value
            );
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_all_zeros() {
        // Test all zeros with various configurations
        for bits_count in [1, 2, 4, 8, 10] {
            for dupe_count in [1, 3, 5] {
                let bits = NonZero::new(bits_count).unwrap();
                let dupe = NonZero::new(dupe_count).unwrap();

                // Skip configurations that don't fit in u32
                if bits_count * dupe_count > 32 {
                    continue;
                }

                let value = 0u32;
                let raw = write_majority_vote_u32(bits, dupe, value);
                let extracted = extract_majority_vote_u32(bits, dupe, raw);
                assert_eq!(
                    extracted, value,
                    "Failed round-trip for all zeros with {} bits and {}x duplication",
                    bits_count, dupe_count
                );
                assert_eq!(raw, 0, "Raw value should be 0 for all zeros");
            }
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_all_ones() {
        // Test all ones with various configurations
        for bits_count in [1, 2, 4, 8, 10] {
            for dupe_count in [1, 3, 5] {
                let bits = NonZero::new(bits_count).unwrap();
                let dupe = NonZero::new(dupe_count).unwrap();

                // Skip configurations that don't fit in u32
                if bits_count * dupe_count > 32 {
                    continue;
                }

                let value = (1u32 << bits_count) - 1; // All bits set
                let raw = write_majority_vote_u32(bits, dupe, value);
                let extracted = extract_majority_vote_u32(bits, dupe, raw);
                assert_eq!(
                    extracted, value,
                    "Failed round-trip for all ones with {} bits and {}x duplication",
                    bits_count, dupe_count
                );
            }
        }
    }

    #[test]
    fn test_majority_vote_u32_round_trip_alternating_patterns() {
        let bits = NonZero::new(8).unwrap();
        let dupe = NonZero::new(3).unwrap();

        // Alternating 0101...
        let value = 0b01010101u32;
        let raw = write_majority_vote_u32(bits, dupe, value);
        let extracted = extract_majority_vote_u32(bits, dupe, raw);
        assert_eq!(extracted, value);

        // Alternating 1010...
        let value = 0b10101010u32;
        let raw = write_majority_vote_u32(bits, dupe, value);
        let extracted = extract_majority_vote_u32(bits, dupe, raw);
        assert_eq!(extracted, value);
    }

    #[test]
    fn test_majority_vote_u32_round_trip_comprehensive() {
        // Comprehensive test: try all possible values for small bit sizes
        let bits = NonZero::new(4).unwrap();
        let dupe = NonZero::new(3).unwrap();

        for value in 0u32..16 {
            let raw = write_majority_vote_u32(bits, dupe, value);
            let extracted = extract_majority_vote_u32(bits, dupe, raw);
            assert_eq!(extracted, value, "Failed round-trip for value {}", value);
        }
    }

    #[test]
    fn test_majority_vote_u32_write_format() {
        // Verify the format of written values
        let bits = NonZero::new(2).unwrap();
        let dupe = NonZero::new(3).unwrap();

        // Value 0b00 -> raw should be 0b000_000
        let raw = write_majority_vote_u32(bits, dupe, 0b00);
        assert_eq!(raw, 0b000_000);

        // Value 0b01 -> raw should be 0b000_111
        let raw = write_majority_vote_u32(bits, dupe, 0b01);
        assert_eq!(raw, 0b000_111);

        // Value 0b10 -> raw should be 0b111_000
        let raw = write_majority_vote_u32(bits, dupe, 0b10);
        assert_eq!(raw, 0b111_000);

        // Value 0b11 -> raw should be 0b111_111
        let raw = write_majority_vote_u32(bits, dupe, 0b11);
        assert_eq!(raw, 0b111_111);
    }

    // Round-trip tests for write_single_fuse_value with all layouts

    #[test]
    fn test_write_single_fuse_value_single_layout() {
        // Test Single layout with various bit sizes
        let layout = FuseLayout::Single(Bits(NonZero::new(1).unwrap()));
        for value in [0u32, 1] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value {} with 1-bit Single layout",
                value
            );
        }

        // 8 bits
        let layout = FuseLayout::Single(Bits(NonZero::new(8).unwrap()));
        for value in [0x00u32, 0x01, 0x55, 0xAA, 0xFF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:02X} with 8-bit Single layout",
                value
            );
        }

        // 16 bits
        let layout = FuseLayout::Single(Bits(NonZero::new(16).unwrap()));
        for value in [0x0000u32, 0x1234, 0x5555, 0xAAAA, 0xFFFF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:04X} with 16-bit Single layout",
                value
            );
        }

        // 32 bits
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        for value in [0x00000000u32, 0x12345678, 0xDEADBEEF, 0xFFFFFFFF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:08X} with 32-bit Single layout",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_onehot_layout() {
        // Test OneHot layout with various bit sizes
        let layout = FuseLayout::OneHot(Bits(NonZero::new(8).unwrap()));

        // Test count values from 0 to 8
        for value in 0u32..=8 {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 8-bit OneHot layout",
                value
            );

            // Verify raw format: should have exactly 'value' bits set
            assert_eq!(
                raw.count_ones(),
                value,
                "Raw value should have {} bits set for count {}",
                value,
                value
            );
        }

        // Test with 16 bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(16).unwrap()));
        for value in [0u32, 1, 5, 10, 15, 16] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 16-bit OneHot layout",
                value
            );
            assert_eq!(raw.count_ones(), value);
        }

        // Test with 32 bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        for value in [0u32, 1, 8, 16, 24, 31, 32] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 32-bit OneHot layout",
                value
            );
            assert_eq!(raw.count_ones(), value);
        }
    }

    #[test]
    fn test_write_single_fuse_value_onehot_layout_edge_cases() {
        // Test boundary conditions
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));

        // Value of 0 should produce 0x00000000
        let raw = write_single_fuse_value(layout, 0).unwrap();
        assert_eq!(raw, 0x00000000);
        assert_eq!(extract_single_fuse_value(layout, raw).unwrap(), 0);

        // Value of 1 should produce 0x00000001
        let raw = write_single_fuse_value(layout, 1).unwrap();
        assert_eq!(raw, 0x00000001);
        assert_eq!(extract_single_fuse_value(layout, raw).unwrap(), 1);

        // Value of 32 should produce 0xFFFFFFFF
        let raw = write_single_fuse_value(layout, 32).unwrap();
        assert_eq!(raw, 0xFFFFFFFF);
        assert_eq!(extract_single_fuse_value(layout, raw).unwrap(), 32);
    }

    #[test]
    fn test_write_single_fuse_value_onehot_layout_errors() {
        // Test that values > 32 return an error
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        assert!(matches!(
            write_single_fuse_value(layout, 33),
            Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)
        ));
        assert!(matches!(
            write_single_fuse_value(layout, 100),
            Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)
        ));
    }

    #[test]
    fn test_write_single_fuse_value_linear_majority_vote_layout() {
        // Test LinearMajorityVote with 1 bit, 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value {} with 1-bit 3x LinearMajorityVote",
                value
            );
        }

        // Test with 2 bits, 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0b00u32, 0b01, 0b10, 0b11] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0b{:02b} with 2-bit 3x LinearMajorityVote",
                value
            );
        }

        // Test with 4 bits, 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0x0u32, 0x5, 0x9, 0xA, 0xF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:X} with 4-bit 3x LinearMajorityVote",
                value
            );
        }

        // Test with 8 bits, 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0x00u32, 0x12, 0x55, 0xAA, 0xFF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:02X} with 8-bit 3x LinearMajorityVote",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_linear_majority_vote_various_duplications() {
        // Test with different duplication factors
        let bits = Bits(NonZero::new(4).unwrap());

        // 1x duplication
        let layout = FuseLayout::LinearMajorityVote(bits, Duplication(NonZero::new(1).unwrap()));
        for value in [0x0u32, 0x5, 0xA, 0xF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value, "Failed round-trip with 1x duplication");
        }

        // 2x duplication
        let layout = FuseLayout::LinearMajorityVote(bits, Duplication(NonZero::new(2).unwrap()));
        for value in [0x0u32, 0x5, 0xA, 0xF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value, "Failed round-trip with 2x duplication");
        }

        // 5x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );
        for value in [0x0u32, 0x5, 0xA, 0xF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value, "Failed round-trip with 5x duplication");
        }
    }

    #[test]
    fn test_write_single_fuse_value_linear_majority_vote_max_size() {
        // Test maximum size that fits in u32: 10 bits * 3 duplication = 30 bits
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0x000u32, 0x001, 0x155, 0x2AA, 0x3FF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:03X} with 10-bit 3x LinearMajorityVote",
                value
            );
        }

        // Test exactly 32 bits with 1x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );
        for value in [0x00000000u32, 0xAAAAAAAA, 0xFFFFFFFF] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value 0x{:08X} with 32-bit 1x LinearMajorityVote",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_linear_majority_vote_errors() {
        // Test that layouts exceeding u32 size return error
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 0),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 0),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_write_single_fuse_value_onehot_linear_majority_vote_layout() {
        // Test OneHotLinearMajorityVote with 1 bit, 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 1-bit 3x OneHotLinearMajorityVote",
                value
            );
        }

        // Test with 2 bits, 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1, 2] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 2-bit 3x OneHotLinearMajorityVote",
                value
            );
        }

        // Test with 4 bits, 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1, 2, 3, 4] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 4-bit 3x OneHotLinearMajorityVote",
                value
            );
        }

        // Test with 8 bits, 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1, 4, 7, 8] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 8-bit 3x OneHotLinearMajorityVote",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_onehot_linear_majority_vote_various_duplications() {
        let bits = Bits(NonZero::new(4).unwrap());

        // 1x duplication
        let layout =
            FuseLayout::OneHotLinearMajorityVote(bits, Duplication(NonZero::new(1).unwrap()));
        for value in [0u32, 1, 2, 3, 4] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 1x duplication",
                value
            );
        }

        // 2x duplication
        let layout =
            FuseLayout::OneHotLinearMajorityVote(bits, Duplication(NonZero::new(2).unwrap()));
        for value in [0u32, 1, 2, 3, 4] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 2x duplication",
                value
            );
        }

        // 5x duplication
        let layout =
            FuseLayout::OneHotLinearMajorityVote(bits, Duplication(NonZero::new(5).unwrap()));
        for value in [0u32, 1, 2, 3, 4] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 5x duplication",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_onehot_linear_majority_vote_max_size() {
        // Test maximum size that fits in u32: 10 bits * 3 duplication = 30 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in [0u32, 1, 5, 9, 10] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 10-bit 3x OneHotLinearMajorityVote",
                value
            );
        }

        // Test exactly 32 bits with 1x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );
        for value in [0u32, 1, 16, 31, 32] {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for count {} with 32-bit 1x OneHotLinearMajorityVote",
                value
            );
        }
    }

    #[test]
    fn test_write_single_fuse_value_onehot_linear_majority_vote_errors() {
        // Test that values > 32 return an error
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 33),
            Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)
        ));

        // Test that layouts exceeding u32 size return error
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 0),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));

        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(17).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 0),
            Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)
        ));
    }

    #[test]
    fn test_write_single_fuse_value_comprehensive_all_layouts() {
        // Comprehensive test across all layout types with compatible parameters

        // Single layout - comprehensive value testing
        let layout = FuseLayout::Single(Bits(NonZero::new(8).unwrap()));
        for value in 0u32..=255 {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value);
        }

        // OneHot layout - test all valid counts
        let layout = FuseLayout::OneHot(Bits(NonZero::new(16).unwrap()));
        for value in 0u32..=16 {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value);
        }

        // LinearMajorityVote - test all values for 4 bits
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in 0u32..16 {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value);
        }

        // OneHotLinearMajorityVote - test all valid counts
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        for value in 0u32..=8 {
            let raw = write_single_fuse_value(layout, value).unwrap();
            let extracted = extract_single_fuse_value(layout, raw).unwrap();
            assert_eq!(extracted, value);
        }
    }

    #[test]
    fn test_write_single_fuse_value_word_majority_vote_unsupported() {
        // WordMajorityVote should not be supported for single u32 operations
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        assert!(matches!(
            write_single_fuse_value(layout, 0),
            Err(McuError::ROM_UNSUPPORTED_FUSE_LAYOUT)
        ));
    }

    #[test]
    fn test_write_fuse_value_single_layout_1_word() {
        // Test Single layout with 1 word (N=1, M=1)
        let layout = FuseLayout::Single(Bits(NonZero::new(8).unwrap()));

        for value in [0x00u32, 0x01, 0x55, 0xAA, 0xFF] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for value 0x{:02X} with 8-bit Single layout (1 word)",
                value
            );
        }

        // Test with full 32-bit values
        let layout = FuseLayout::Single(Bits(NonZero::new(32).unwrap()));
        for value in [0x00000000u32, 0x12345678, 0xDEADBEEF, 0xFFFFFFFF] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for value 0x{:08X} with 32-bit Single layout (1 word)",
                value
            );
        }
    }

    #[test]
    fn test_write_fuse_value_single_layout_2_words() {
        // Test Single layout with 2 words (N=2, M=2)
        let layout = FuseLayout::Single(Bits(NonZero::new(64).unwrap()));

        let test_cases = [
            [0x00000000u32, 0x00000000],
            [0x12345678, 0x9ABCDEF0],
            [0xDEADBEEF, 0xCAFEBABE],
            [0xFFFFFFFF, 0xFFFFFFFF],
            [0xAAAAAAAA, 0x55555555],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<2, 2>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value [0x{:08X}, 0x{:08X}] with 64-bit Single layout (2 words)",
                value[0], value[1]
            );
        }
    }

    #[test]
    fn test_write_fuse_value_single_layout_4_words() {
        // Test Single layout with 4 words (N=4, M=4)
        let layout = FuseLayout::Single(Bits(NonZero::new(128).unwrap()));

        let test_cases = [
            [0x00000000u32, 0x00000000, 0x00000000, 0x00000000],
            [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222],
            [0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBADF00D0],
            [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<4, 4>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<4>(layout, &raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}] with 128-bit Single layout (4 words)",
                value[0], value[1], value[2], value[3]
            );
        }
    }

    #[test]
    fn test_write_fuse_value_single_layout_partial_bits() {
        // Test Single layout where bits don't fill all words

        // 16 bits in 1 word
        let layout = FuseLayout::Single(Bits(NonZero::new(16).unwrap()));
        for value in [0x0000u32, 0x1234, 0xFFFF] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }

        // 48 bits (1.5 words) in 2 words
        let layout = FuseLayout::Single(Bits(NonZero::new(48).unwrap()));
        let test_cases = [
            [0x12345678u32, 0x0000ABCD],
            [0xFFFFFFFF, 0x0000FFFF],
            [0xAAAAAAAA, 0x00005555],
        ];
        for value in test_cases {
            let raw = write_fuse_value::<2, 2>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(extracted, value);
        }
    }

    #[test]
    fn test_write_fuse_value_single_layout_n_less_than_m() {
        // Test Single layout where N < M (input smaller than output buffer)
        let layout = FuseLayout::Single(Bits(NonZero::new(64).unwrap()));

        // N=2, M=4: input is 2 words, output buffer is 4 words
        let value = [0x12345678u32, 0x9ABCDEF0];
        let raw = write_fuse_value::<2, 4>(layout, &value).unwrap();

        // The first 2 words should contain our data, rest should be zero
        assert_eq!(raw[0], 0x12345678);
        assert_eq!(raw[1], 0x9ABCDEF0);
        assert_eq!(raw[2], 0x00000000);
        assert_eq!(raw[3], 0x00000000);

        // Extract and verify
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
    }

    #[test]
    fn test_write_fuse_value_single_layout_error_n_greater_than_m() {
        // Test error when N > M (input larger than output buffer)
        let layout = FuseLayout::Single(Bits(NonZero::new(128).unwrap()));

        // N=4, M=2: input is 4 words but output buffer is only 2 words
        let value = [0x12345678u32, 0x9ABCDEF0, 0xDEADBEEF, 0xCAFEBABE];
        let result = write_fuse_value::<4, 2>(layout, &value);

        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_single_layout_error_bits_too_large() {
        // Test error when bits exceed N * 32
        let layout = FuseLayout::Single(Bits(NonZero::new(96).unwrap()));

        // N=2 means we can only handle 64 bits, but layout specifies 96 bits
        let value = [0x12345678u32, 0x9ABCDEF0];
        let result = write_fuse_value::<2, 4>(layout, &value);

        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_single_layout_8_words() {
        // Test with a larger array (256 bits / 8 words)
        let layout = FuseLayout::Single(Bits(NonZero::new(256).unwrap()));

        let value = [
            0x00112233u32,
            0x44556677,
            0x8899AABB,
            0xCCDDEEFF,
            0xFEDCBA98,
            0x76543210,
            0x13579BDF,
            0x2468ACE0,
        ];

        let raw = write_fuse_value::<8, 8>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<8>(layout, &raw).unwrap();

        assert_eq!(extracted, value);
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_1_word() {
        // Test OneHot layout with values that fit in 1 word
        let layout = FuseLayout::OneHot(Bits(NonZero::new(8).unwrap()));

        // Test count values from 0 to 8
        for value in 0u32..=8 {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for count {} with 8-bit OneHot layout (1 word)",
                value
            );

            // Verify raw format: should have exactly 'value' bits set
            assert_eq!(
                raw[0].count_ones(),
                value,
                "Raw value should have {} bits set for count {}",
                value,
                value
            );
        }

        // Test with 16 bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(16).unwrap()));
        for value in [0u32, 1, 5, 10, 15, 16] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            assert_eq!(raw[0].count_ones(), value);
        }

        // Test with 32 bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        for value in [0u32, 1, 8, 16, 24, 31, 32] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            if value == 32 {
                assert_eq!(raw[0], 0xFFFFFFFF);
            } else {
                assert_eq!(raw[0].count_ones(), value);
            }
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_multi_word() {
        // Test OneHot layout spanning multiple words

        // 64-bit layout with various count values
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));

        for value in [0u32, 1, 16, 31, 32, 33, 48, 63, 64] {
            let raw = write_fuse_value::<1, 2>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for count {} with 64-bit OneHot layout (2 words)",
                value
            );

            // Verify total bit count
            let total_bits = raw[0].count_ones() + raw[1].count_ones();
            assert_eq!(
                total_bits, value,
                "Total bits set should be {} for count {}",
                value, value
            );
        }

        // 128-bit layout
        let layout = FuseLayout::OneHot(Bits(NonZero::new(128).unwrap()));

        for value in [0u32, 1, 32, 64, 96, 127, 128] {
            let raw = write_fuse_value::<1, 4>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for count {} with 128-bit OneHot layout (4 words)",
                value
            );

            // Verify total bit count
            let total_bits: u32 = raw.iter().map(|&v| v.count_ones()).sum();
            assert_eq!(total_bits, value);
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_word_boundaries() {
        // Test values at word boundaries (32, 64, 96, etc.)
        let layout = FuseLayout::OneHot(Bits(NonZero::new(128).unwrap()));

        // Exactly 32 bits: first word should be all 1s
        let raw = write_fuse_value::<1, 4>(layout, &[32]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x00000000);
        assert_eq!(raw[2], 0x00000000);
        assert_eq!(raw[3], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [32]);

        // Exactly 64 bits: first two words should be all 1s
        let raw = write_fuse_value::<1, 4>(layout, &[64]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0xFFFFFFFF);
        assert_eq!(raw[2], 0x00000000);
        assert_eq!(raw[3], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [64]);

        // Exactly 96 bits: first three words should be all 1s
        let raw = write_fuse_value::<1, 4>(layout, &[96]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0xFFFFFFFF);
        assert_eq!(raw[2], 0xFFFFFFFF);
        assert_eq!(raw[3], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [96]);

        // Exactly 128 bits: all four words should be all 1s
        let raw = write_fuse_value::<1, 4>(layout, &[128]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0xFFFFFFFF);
        assert_eq!(raw[2], 0xFFFFFFFF);
        assert_eq!(raw[3], 0xFFFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [128]);
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_partial_word() {
        // Test values that don't fill complete words
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));

        // 33 bits: first word full, second word has 1 bit
        let raw = write_fuse_value::<1, 2>(layout, &[33]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x00000001);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [33]);

        // 48 bits: first word full, second word has 16 bits
        let raw = write_fuse_value::<1, 2>(layout, &[48]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x0000FFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [48]);

        // 63 bits: first word full, second word has 31 bits
        let raw = write_fuse_value::<1, 2>(layout, &[63]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x7FFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [63]);
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_error_n_not_1() {
        // OneHot requires N=1 (single input value for count)
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));

        // Try with N=2 (should fail)
        let value = [5u32, 10];
        let result = write_fuse_value::<2, 2>(layout, &value);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_error_value_too_large() {
        // Value (count) cannot exceed the number of bits in the layout

        // 8-bit layout, try value of 9
        let layout = FuseLayout::OneHot(Bits(NonZero::new(8).unwrap()));
        let result = write_fuse_value::<1, 1>(layout, &[9]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));

        // 32-bit layout, try value of 33
        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let result = write_fuse_value::<1, 1>(layout, &[33]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));

        // 64-bit layout, try value of 65
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));
        let result = write_fuse_value::<1, 2>(layout, &[65]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_error_bits_exceed_output() {
        // Layout bits cannot exceed M * 32 (output buffer size)

        // 128-bit layout but only 2 words (64 bits) output buffer
        let layout = FuseLayout::OneHot(Bits(NonZero::new(128).unwrap()));
        let result = write_fuse_value::<1, 2>(layout, &[64]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // 96-bit layout but only 2 words (64 bits) output buffer
        let layout = FuseLayout::OneHot(Bits(NonZero::new(96).unwrap()));
        let result = write_fuse_value::<1, 2>(layout, &[50]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_zero_value() {
        // Test that count of 0 produces all zeros

        let layout = FuseLayout::OneHot(Bits(NonZero::new(32).unwrap()));
        let raw = write_fuse_value::<1, 1>(layout, &[0]).unwrap();
        assert_eq!(raw[0], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0]);

        let layout = FuseLayout::OneHot(Bits(NonZero::new(128).unwrap()));
        let raw = write_fuse_value::<1, 4>(layout, &[0]).unwrap();
        assert_eq!(raw[0], 0x00000000);
        assert_eq!(raw[1], 0x00000000);
        assert_eq!(raw[2], 0x00000000);
        assert_eq!(raw[3], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0]);
    }

    #[test]
    fn test_write_fuse_value_onehot_layout_m_larger_than_needed() {
        // Test when M is larger than necessary to hold the bits
        let layout = FuseLayout::OneHot(Bits(NonZero::new(64).unwrap()));

        // N=1, M=4 (need only 2 words, but providing 4)
        let raw = write_fuse_value::<1, 4>(layout, &[48]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x0000FFFF);
        assert_eq!(raw[2], 0x00000000); // Extra words should be zero
        assert_eq!(raw[3], 0x00000000); // Extra words should be zero
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [48]);
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_1_word() {
        // Test LinearMajorityVote with values that fit in 1 word

        // 1 bit with 3x duplication = 3 bits total
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(1).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        for value in [0u32, 1] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for value {} with 1-bit 3x duplication",
                value
            );

            // Verify raw format
            if value == 1 {
                assert_eq!(raw[0], 0b111); // All 3 bits set
            } else {
                assert_eq!(raw[0], 0b000); // All 3 bits clear
            }
        }

        // 2 bits with 3x duplication = 6 bits total
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        for value in [0b00u32, 0b01, 0b10, 0b11] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }

        // Verify specific patterns
        let raw = write_fuse_value::<1, 1>(layout, &[0b11]).unwrap();
        assert_eq!(raw[0], 0b111_111); // Both bits fully duplicated

        let raw = write_fuse_value::<1, 1>(layout, &[0b01]).unwrap();
        assert_eq!(raw[0], 0b000_111); // bit0=111, bit1=000

        let raw = write_fuse_value::<1, 1>(layout, &[0b10]).unwrap();
        assert_eq!(raw[0], 0b111_000); // bit0=000, bit1=111
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_various_duplications() {
        // Test with 2x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        for value in [0x0u32, 0x5, 0xA, 0xF] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }

        // Test with 5x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(2).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        for value in [0b00u32, 0b01, 0b10, 0b11] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_multi_word() {
        // Test LinearMajorityVote spanning multiple words

        // 40 bits with 2x duplication = 80 bits = 3 words needed
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(40).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let test_cases = [
            [0x00000000u32, 0x00000000],
            [0xFFFFFFFF, 0x000000FF],
            [0xAAAAAAAA, 0x000000AA],
            [0x12345678, 0x00000012],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<2, 3>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value [0x{:08X}, 0x{:08X}]",
                value[0], value[1]
            );
        }

        // 64 bits with 2x duplication = 128 bits = 4 words
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let test_cases = [
            [0x00000000u32, 0x00000000],
            [0xFFFFFFFF, 0xFFFFFFFF],
            [0xAAAAAAAA, 0x55555555],
            [0x12345678, 0x9ABCDEF0],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<2, 4>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(extracted, value);
        }
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_cross_word_boundary() {
        // Test that bits properly span across word boundaries

        // 10 bits with 3x duplication = 30 bits (fits in 1 word)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let value = [0b1010101010u32];
        let raw = write_fuse_value::<1, 1>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // 11 bits with 3x duplication = 33 bits (spans 2 words)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let value = [0b10101010101u32];
        let raw = write_fuse_value::<1, 2>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // Verify the pattern crosses correctly
        // First 32 bits contain: bits 0-9 (3x each) + 2 bits of bit 10
        // Second word contains: remaining 1 bit of bit 10
        assert_eq!(raw[1] & 0b1, 0b1); // bit 10 is set, so last duplicate should be 1
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_4_words() {
        // Test with 4 words of data

        // 128 bits with 1x duplication = 128 bits = 4 words
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(1).unwrap()),
        );

        let test_cases = [
            [0x00000000u32, 0x00000000, 0x00000000, 0x00000000],
            [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
            [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222],
            [0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBADF00D0],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<4, 4>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<4>(layout, &raw).unwrap();
            assert_eq!(extracted, value);
            // With 1x duplication, raw should equal value
            assert_eq!(raw, value);
        }

        // 64 bits with 2x duplication = 128 bits = 4 words
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let value = [0xAAAAAAAAu32, 0x55555555];
        let raw = write_fuse_value::<2, 4>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_pattern_verification() {
        // Verify specific bit patterns are duplicated correctly

        // 4 bits with 3x duplication
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Value 0b1010
        let raw = write_fuse_value::<1, 1>(layout, &[0b1010]).unwrap();
        assert_eq!(raw[0], 0b111_000_111_000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0b1010]);

        // Value 0b0101
        let raw = write_fuse_value::<1, 1>(layout, &[0b0101]).unwrap();
        assert_eq!(raw[0], 0b000_111_000_111);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0b0101]);

        // Value 0b1111
        let raw = write_fuse_value::<1, 1>(layout, &[0b1111]).unwrap();
        assert_eq!(raw[0], 0b111_111_111_111);

        // Value 0b0000
        let raw = write_fuse_value::<1, 1>(layout, &[0b0000]).unwrap();
        assert_eq!(raw[0], 0b000_000_000_000);
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_error_layout_too_large() {
        // Test error when bits * dupe exceeds M * 32

        // 11 bits * 3 duplication = 33 bits, but only 1 word (32 bits) output
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(11).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let result = write_fuse_value::<1, 1>(layout, &[0xFF]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // 64 bits * 2 duplication = 128 bits, but only 2 words (64 bits) output
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        let result = write_fuse_value::<2, 2>(layout, &[0xFFFFFFFF, 0xFFFFFFFF]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_m_larger_than_needed() {
        // Test when M is larger than necessary

        // 8 bits with 2x duplication = 16 bits, provide 2 words (64 bits)
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let raw = write_fuse_value::<1, 2>(layout, &[0xAA]).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0xAA]);

        // Upper bits of first word and all of second word should be zero
        assert_eq!(raw[0] & 0xFFFF0000, 0);
        assert_eq!(raw[1], 0);
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_8_bits_all_duplications() {
        // Test 8 bits with various duplication factors

        for dupe in [1, 2, 3, 4] {
            let layout = FuseLayout::LinearMajorityVote(
                Bits(NonZero::new(8).unwrap()),
                Duplication(NonZero::new(dupe).unwrap()),
            );

            let total_bits = 8 * dupe;
            let m_words = (total_bits + 31) / 32;

            for value in [0x00u32, 0x55, 0xAA, 0xFF] {
                match m_words {
                    1 => {
                        let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
                        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                        assert_eq!(extracted, [value]);
                    }
                    2 => {
                        let raw = write_fuse_value::<1, 2>(layout, &[value]).unwrap();
                        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                        assert_eq!(extracted, [value]);
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_zero_and_max_values() {
        // Test boundary values

        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // All zeros
        let raw = write_fuse_value::<1, 2>(layout, &[0x00000000]).unwrap();
        assert_eq!(raw[0], 0x00000000);
        assert_eq!(raw[1], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0x00000000]);

        // All ones
        let raw = write_fuse_value::<1, 2>(layout, &[0xFFFFFFFF]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0xFFFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0xFFFFFFFF]);

        // Alternating pattern
        let raw = write_fuse_value::<1, 2>(layout, &[0xAAAAAAAA]).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0xAAAAAAAA]);
    }

    #[test]
    fn test_write_fuse_value_linear_majority_vote_large_duplication() {
        // Test with larger duplication factors

        // 4 bits with 7x duplication = 28 bits
        let layout = FuseLayout::LinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(7).unwrap()),
        );

        for value in [0x0u32, 0x5, 0xA, 0xF] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }

        // Verify pattern for 0xF (all bits set)
        let raw = write_fuse_value::<1, 1>(layout, &[0xF]).unwrap();
        // Each of 4 bits duplicated 7 times = 28 bits all set
        assert_eq!(raw[0] & 0x0FFFFFFF, 0x0FFFFFFF);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_1_word() {
        // Test OneHotLinearMajorityVote with values that fit in 1 word

        // 8 bits with 3x duplication = 24 bits total
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Test count values from 0 to 8
        for value in 0u32..=8 {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for count {} with 8-bit 3x duplication OneHotLinearMajorityVote",
                value
            );

            // Verify raw format: should have exactly 'value * 3' bits set
            assert_eq!(
                raw[0].count_ones(),
                value * 3,
                "Raw value should have {} bits set for count {}",
                value * 3,
                value
            );
        }

        // Test with 10 bits and 3x duplication = 30 bits
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(10).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        for value in [0u32, 1, 5, 9, 10] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            assert_eq!(raw[0].count_ones(), value * 3);
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_pattern_verification() {
        // Verify specific patterns with different duplication factors

        // 4 bits with 3x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(4).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Count 0: no bits set
        let raw = write_fuse_value::<1, 1>(layout, &[0]).unwrap();
        assert_eq!(raw[0], 0b0000_0000_0000);

        // Count 1: first bit position fully duplicated
        let raw = write_fuse_value::<1, 1>(layout, &[1]).unwrap();
        assert_eq!(raw[0], 0b0000_0000_0111);

        // Count 2: first two bit positions fully duplicated
        let raw = write_fuse_value::<1, 1>(layout, &[2]).unwrap();
        assert_eq!(raw[0], 0b111_111);

        // Count 3: first three bit positions fully duplicated
        let raw = write_fuse_value::<1, 1>(layout, &[3]).unwrap();
        assert_eq!(raw[0], 0b111_111_111);

        // Count 4: all four bit positions fully duplicated
        let raw = write_fuse_value::<1, 1>(layout, &[4]).unwrap();
        assert_eq!(raw[0], 0b111_111_111_111);

        // Verify all extractions work
        for value in 0u32..=4 {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_various_duplications() {
        // Test with 2x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        for value in [0u32, 1, 4, 7, 8] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            assert_eq!(raw[0].count_ones(), value * 2);
        }

        // Test with 5x duplication
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(6).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        for value in [0u32, 1, 3, 6] {
            let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            assert_eq!(raw[0].count_ones(), value * 5);
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_multi_word() {
        // Test OneHotLinearMajorityVote spanning multiple words

        // 32 bits with 2x duplication = 64 bits = 2 words
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        for value in [0u32, 1, 16, 31, 32] {
            let raw = write_fuse_value::<1, 2>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for count {} with 32-bit 2x duplication (2 words)",
                value
            );

            // Verify total bit count
            let total_bits = raw[0].count_ones() + raw[1].count_ones();
            assert_eq!(total_bits, value * 2);
        }

        // 64 bits with 2x duplication = 128 bits = 4 words
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        for value in [0u32, 1, 32, 63, 64] {
            let raw = write_fuse_value::<1, 4>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);

            let total_bits: u32 = raw.iter().map(|&v| v.count_ones()).sum();
            assert_eq!(total_bits, value * 2);
        }
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_word_boundaries() {
        // Test values at word boundaries
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // 16 bits set: 32 raw bits (fills first word exactly)
        let raw = write_fuse_value::<1, 2>(layout, &[16]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [16]);

        // 32 bits set: 64 raw bits (fills both words)
        let raw = write_fuse_value::<1, 2>(layout, &[32]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0xFFFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [32]);

        // Test with 3x duplication crossing words
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // 10 bits set: 30 raw bits (fits in first word)
        let raw = write_fuse_value::<1, 3>(layout, &[10]).unwrap();
        assert_eq!(raw[0] & 0x3FFFFFFF, 0x3FFFFFFF);
        assert_eq!(raw[1], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [10]);

        // 11 bits set: 33 raw bits (spans to second word)
        let raw = write_fuse_value::<1, 3>(layout, &[11]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1] & 0x1, 0x1);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [11]);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_partial_word() {
        // Test values that don't fill complete words
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // 17 bits set: 34 raw bits (first word full + 2 bits in second)
        let raw = write_fuse_value::<1, 2>(layout, &[17]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x00000003);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [17]);

        // 24 bits set: 48 raw bits (first word full + 16 bits in second)
        let raw = write_fuse_value::<1, 2>(layout, &[24]).unwrap();
        assert_eq!(raw[0], 0xFFFFFFFF);
        assert_eq!(raw[1], 0x0000FFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [24]);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_error_n_not_1() {
        // OneHotLinearMajorityVote requires N=1 (single input value for count)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // Try with N=2 (should fail)
        let value = [5u32, 10];
        let result = write_fuse_value::<2, 2>(layout, &value);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_error_value_too_large() {
        // Value (count) cannot exceed the number of bits in the layout

        // 8-bit layout, try value of 9
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let result = write_fuse_value::<1, 1>(layout, &[9]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));

        // 16-bit layout, try value of 17
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(16).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        let result = write_fuse_value::<1, 1>(layout, &[17]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));

        // 32-bit layout, try value of 33
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        let result = write_fuse_value::<1, 2>(layout, &[33]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_VALUE_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_error_bits_exceed_output() {
        // Layout bits * dupe cannot exceed M * 32 (output buffer size)

        // 64 bits * 3 duplication = 192 bits, but only 4 words (128 bits) output
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let result = write_fuse_value::<1, 4>(layout, &[32]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // 32 bits * 5 duplication = 160 bits, but only 4 words (128 bits) output
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );
        let result = write_fuse_value::<1, 4>(layout, &[16]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_zero_value() {
        // Test that count of 0 produces all zeros

        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(16).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        let raw = write_fuse_value::<1, 1>(layout, &[0]).unwrap();
        assert_eq!(raw[0], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0]);

        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = write_fuse_value::<1, 3>(layout, &[0]).unwrap();
        assert_eq!(raw[0], 0x00000000);
        assert_eq!(raw[1], 0x00000000);
        assert_eq!(raw[2], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [0]);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_max_value() {
        // Test maximum count values

        // 8 bits max value (8)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(8).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let raw = write_fuse_value::<1, 1>(layout, &[8]).unwrap();
        // 8 bits * 3 duplication = 24 bits set
        assert_eq!(raw[0] & 0xFFFFFF, 0xFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [8]);

        // 16 bits max value (16)
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(16).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );
        let raw = write_fuse_value::<1, 1>(layout, &[16]).unwrap();
        // 16 bits * 2 duplication = 32 bits set (full word)
        assert_eq!(raw[0], 0xFFFFFFFF);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [16]);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_m_larger_than_needed() {
        // Test when M is larger than necessary
        let layout = FuseLayout::OneHotLinearMajorityVote(
            Bits(NonZero::new(16).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        // 16 bits * 2 = 32 bits needed, but provide 4 words
        let raw = write_fuse_value::<1, 4>(layout, &[8]).unwrap();
        // 8 bits * 2 = 16 bits set
        assert_eq!(raw[0] & 0xFFFF, 0xFFFF);
        assert_eq!(raw[0] & 0xFFFF0000, 0);
        assert_eq!(raw[1], 0x00000000);
        assert_eq!(raw[2], 0x00000000);
        assert_eq!(raw[3], 0x00000000);
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, [8]);
    }

    #[test]
    fn test_write_fuse_value_onehot_linear_majority_vote_comprehensive() {
        // Comprehensive test with various combinations
        let test_cases = [
            (4, 2, 1),  // 4 bits, 2x dupe, 1 word
            (8, 2, 1),  // 8 bits, 2x dupe, 1 word
            (10, 3, 1), // 10 bits, 3x dupe, 1 word
            (16, 2, 1), // 16 bits, 2x dupe, 1 word
            (32, 2, 2), // 32 bits, 2x dupe, 2 words
        ];

        for (bits, dupe, m_words) in test_cases {
            let layout = FuseLayout::OneHotLinearMajorityVote(
                Bits(NonZero::new(bits).unwrap()),
                Duplication(NonZero::new(dupe).unwrap()),
            );

            // Test a few values for each configuration
            for value in [0u32, 1, bits as u32 / 2, bits as u32] {
                match m_words {
                    1 => {
                        let raw = write_fuse_value::<1, 1>(layout, &[value]).unwrap();
                        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                        assert_eq!(extracted, [value]);
                        assert_eq!(raw[0].count_ones(), value * dupe as u32);
                    }
                    2 => {
                        let raw = write_fuse_value::<1, 2>(layout, &[value]).unwrap();
                        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                        assert_eq!(extracted, [value]);
                        let total_bits = raw[0].count_ones() + raw[1].count_ones();
                        assert_eq!(total_bits, value * dupe as u32);
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_1_word() {
        // Test WordMajorityVote with 1 word (32 bits)

        // 32 bits with 3x duplication = 3 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let test_values = [
            0x00000000u32,
            0xFFFFFFFF,
            0x12345678,
            0xDEADBEEF,
            0xAAAAAAAA,
            0x55555555,
        ];

        for value in test_values {
            let raw = write_fuse_value::<1, 3>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(
                extracted,
                [value],
                "Failed round-trip for value 0x{:08X} with 32-bit 3x duplication",
                value
            );

            // Verify raw format: all 3 words should be identical
            assert_eq!(raw[0], value);
            assert_eq!(raw[1], value);
            assert_eq!(raw[2], value);
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_2_words() {
        // Test WordMajorityVote with 2 words (64 bits)

        // 64 bits with 3x duplication = 6 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let test_cases = [
            [0x00000000u32, 0x00000000],
            [0xFFFFFFFF, 0xFFFFFFFF],
            [0x12345678, 0x9ABCDEF0],
            [0xDEADBEEF, 0xCAFEBABE],
            [0xAAAAAAAA, 0x55555555],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value [0x{:08X}, 0x{:08X}]",
                value[0], value[1]
            );

            // Verify raw format: word0 duplicated 3 times, then word1 duplicated 3 times
            assert_eq!(raw[0], value[0]);
            assert_eq!(raw[1], value[0]);
            assert_eq!(raw[2], value[0]);
            assert_eq!(raw[3], value[1]);
            assert_eq!(raw[4], value[1]);
            assert_eq!(raw[5], value[1]);
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_4_words() {
        // Test WordMajorityVote with 4 words (128 bits)

        // 128 bits with 2x duplication = 8 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let test_cases = [
            [0x00000000u32, 0x00000000, 0x00000000, 0x00000000],
            [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
            [0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222],
            [0xDEADBEEF, 0xCAFEBABE, 0xFEEDFACE, 0xBADF00D0],
        ];

        for value in test_cases {
            let raw = write_fuse_value::<4, 8>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<4>(layout, &raw).unwrap();
            assert_eq!(
                extracted, value,
                "Failed round-trip for value [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}]",
                value[0], value[1], value[2], value[3]
            );

            // Verify raw format: each word duplicated 2 times
            for i in 0..4 {
                assert_eq!(raw[i * 2], value[i]);
                assert_eq!(raw[i * 2 + 1], value[i]);
            }
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_various_duplications() {
        // Test with 2x duplication
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        for value in [0x00000000u32, 0xFFFFFFFF, 0xAAAAAAAA] {
            let raw = write_fuse_value::<1, 2>(layout, &[value]).unwrap();
            let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
            assert_eq!(extracted, [value]);
            assert_eq!(raw[0], value);
            assert_eq!(raw[1], value);
        }

        // Test with 5x duplication
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );

        let value = [0x12345678u32];
        let raw = write_fuse_value::<1, 5>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // All 5 words should be identical
        for r in raw {
            assert_eq!(r, value[0]);
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_pattern_verification() {
        // Verify specific bit patterns are preserved
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // Test alternating bit pattern
        let value = [0xAAAAAAAAu32, 0x55555555];
        let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // Test specific patterns
        let value = [0xF0F0F0F0u32, 0x0F0F0F0F];
        let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // Test single bit set
        let value = [0x00000001u32, 0x80000000];
        let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_8_words() {
        // Test with larger array (256 bits / 8 words)

        // 256 bits with 2x duplication = 16 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(256).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let value = [
            0x00112233u32,
            0x44556677,
            0x8899AABB,
            0xCCDDEEFF,
            0xFEDCBA98,
            0x76543210,
            0x13579BDF,
            0x2468ACE0,
        ];

        let raw = write_fuse_value::<8, 16>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<8>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // Verify duplication
        for i in 0..8 {
            assert_eq!(raw[i * 2], value[i]);
            assert_eq!(raw[i * 2 + 1], value[i]);
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_zero_and_max() {
        // Test boundary values
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        // All zeros
        let value = [0x00000000u32, 0x00000000];
        let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
        for word in &raw {
            assert_eq!(*word, 0x00000000);
        }

        // All ones
        let value = [0xFFFFFFFFu32, 0xFFFFFFFF];
        let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
        for word in &raw {
            assert_eq!(*word, 0xFFFFFFFF);
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_error_layout_too_large() {
        // Test error when bits * dupe exceeds M * 32

        // 128 bits * 3 duplication = 384 bits = 12 words, but only 8 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let value = [0xFFFFFFFFu32, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF];
        let result = write_fuse_value::<4, 8>(layout, &value);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // 64 bits * 5 duplication = 320 bits = 10 words, but only 6 words output
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );
        let value = [0xFFFFFFFFu32, 0xFFFFFFFF];
        let result = write_fuse_value::<2, 6>(layout, &value);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_error_m_not_multiple_of_dupe() {
        // M must be a multiple of duplication factor

        // 32 bits with 3x duplication needs 3 words, but M=4 is not divisible by 3
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );
        let result = write_fuse_value::<1, 4>(layout, &[0xFFFFFFFF]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));

        // 64 bits with 5x duplication needs 10 words, but M=9 is not divisible by 5
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(5).unwrap()),
        );
        let result = write_fuse_value::<2, 9>(layout, &[0xFFFFFFFF, 0xFFFFFFFF]);
        assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_consistency_with_single() {
        // Compare behavior with write_single_fuse_value for single word
        // Note: write_single_fuse_value returns unsupported for WordMajorityVote
        // This test just ensures our multi-word version works correctly

        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(32).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let value = [0x12345678u32];
        let raw = write_fuse_value::<1, 3>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
        assert_eq!(extracted, value);
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_comprehensive() {
        // Comprehensive test with various combinations
        // Format: (bits, dupe, n_input_words, m_output_words)
        let test_cases = [
            (32, 2, 1, 2),  // 32 bits, 2x dupe, 1 input word, 2 output words - VALID
            (32, 3, 1, 3),  // 32 bits, 3x dupe, 1 input word, 3 output words - VALID
            (64, 2, 2, 4),  // 64 bits, 2x dupe, 2 input words, 4 output words - VALID
            (64, 3, 2, 6),  // 64 bits, 3x dupe, 2 input words, 6 output words - VALID
            (128, 2, 4, 8), // 128 bits, 2x dupe, 4 input words, 8 output words - VALID
            (32, 2, 1, 3),  // 32 bits, 2x dupe, but M=3 not divisible by 2 - INVALID
            (64, 3, 2, 5),  // 64 bits, 3x dupe, but M=5 not divisible by 3 - INVALID
            (128, 3, 4, 6), // 128 bits, 3x dupe, needs 12 words but only 6 - INVALID
        ];

        for (bits, dupe, n, m) in test_cases {
            let layout = FuseLayout::WordMajorityVote(
                Bits(NonZero::new(bits).unwrap()),
                Duplication(NonZero::new(dupe).unwrap()),
            );

            // Calculate if this should be valid
            let total_bits_needed = bits * dupe;
            let is_m_multiple_of_dupe = m % dupe == 0;
            let fits_in_output = total_bits_needed <= m * 32;
            let should_succeed = is_m_multiple_of_dupe && fits_in_output;

            // Create test values based on n
            match (n, m, should_succeed) {
                (1, 2, true) => {
                    let value = [0xABCDEF01u32];
                    let raw = write_fuse_value::<1, 2>(layout, &value).unwrap();
                    let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                    assert_eq!(extracted, value);
                }
                (1, 3, true) => {
                    let value = [0xABCDEF01u32];
                    let raw = write_fuse_value::<1, 3>(layout, &value).unwrap();
                    let extracted = extract_fuse_value::<1>(layout, &raw).unwrap();
                    assert_eq!(extracted, value);
                }
                (1, 3, false) => {
                    // M=3 with dupe=2, not divisible
                    let value = [0xABCDEF01u32];
                    let result = write_fuse_value::<1, 3>(layout, &value);
                    assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
                }
                (2, 4, true) => {
                    let value = [0x12345678u32, 0x9ABCDEF0];
                    let raw = write_fuse_value::<2, 4>(layout, &value).unwrap();
                    let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
                    assert_eq!(extracted, value);
                }
                (2, 6, true) => {
                    let value = [0x12345678u32, 0x9ABCDEF0];
                    let raw = write_fuse_value::<2, 6>(layout, &value).unwrap();
                    let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
                    assert_eq!(extracted, value);
                }
                (2, 5, false) => {
                    // M=5 with dupe=3, not divisible
                    let value = [0x12345678u32, 0x9ABCDEF0];
                    let result = write_fuse_value::<2, 5>(layout, &value);
                    assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
                }
                (4, 8, true) => {
                    let value = [0x11111111u32, 0x22222222, 0x33333333, 0x44444444];
                    let raw = write_fuse_value::<4, 8>(layout, &value).unwrap();
                    let extracted = extract_fuse_value::<4>(layout, &raw).unwrap();
                    assert_eq!(extracted, value);
                }
                (4, 6, false) => {
                    // 128 bits * 3 dupe = 384 bits needs 12 words, but only 6 provided
                    let value = [0x11111111u32, 0x22222222, 0x33333333, 0x44444444];
                    let result = write_fuse_value::<4, 6>(layout, &value);
                    assert!(matches!(result, Err(McuError::ROM_FUSE_LAYOUT_TOO_LARGE)));
                }
                _ => {
                    // Skip other combinations
                }
            }
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_mixed_patterns() {
        // Test with various bit patterns in different words
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(128).unwrap()),
            Duplication(NonZero::new(3).unwrap()),
        );

        let value = [
            0x00000000u32, // All zeros
            0xFFFFFFFF,    // All ones
            0xAAAAAAAA,    // Alternating 1010...
            0x55555555,    // Alternating 0101...
        ];

        let raw = write_fuse_value::<4, 12>(layout, &value).unwrap();
        let extracted = extract_fuse_value::<4>(layout, &raw).unwrap();
        assert_eq!(extracted, value);

        // Verify each word is duplicated correctly
        for i in 0..4 {
            for j in 0..3 {
                assert_eq!(raw[i * 3 + j], value[i]);
            }
        }
    }

    #[test]
    fn test_write_fuse_value_word_majority_vote_single_bit_patterns() {
        // Test patterns with single bits set in different positions
        let layout = FuseLayout::WordMajorityVote(
            Bits(NonZero::new(64).unwrap()),
            Duplication(NonZero::new(2).unwrap()),
        );

        let test_cases = [
            [0x00000001u32, 0x00000000], // LSB of first word
            [0x80000000, 0x00000000],    // MSB of first word
            [0x00000000, 0x00000001],    // LSB of second word
            [0x00000000, 0x80000000],    // MSB of second word
            [0x80000000, 0x00000001],    // MSBs and LSBs
        ];

        for value in test_cases {
            let raw = write_fuse_value::<2, 4>(layout, &value).unwrap();
            let extracted = extract_fuse_value::<2>(layout, &raw).unwrap();
            assert_eq!(extracted, value);
        }
    }
}
