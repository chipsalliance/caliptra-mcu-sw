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

/// Convert from the generated `FuseLayoutType` to the runtime `FuseLayout`.
///
/// Returns `None` if the bits or duplication value is zero (which shouldn't
/// happen for well-formed generated code).
impl FuseLayout {
    pub fn from_generated(layout: &registers_generated::fuses::FuseLayoutType) -> Option<Self> {
        use registers_generated::fuses::FuseLayoutType;
        match *layout {
            FuseLayoutType::Single { bits } => {
                Some(FuseLayout::Single(Bits(NonZero::new(bits as usize)?)))
            }
            FuseLayoutType::OneHot { bits } => {
                Some(FuseLayout::OneHot(Bits(NonZero::new(bits as usize)?)))
            }
            FuseLayoutType::LinearMajorityVote { bits, duplication } => {
                Some(FuseLayout::LinearMajorityVote(
                    Bits(NonZero::new(bits as usize)?),
                    Duplication(NonZero::new(duplication as usize)?),
                ))
            }
            FuseLayoutType::OneHotLinearMajorityVote { bits, duplication } => {
                Some(FuseLayout::OneHotLinearMajorityVote(
                    Bits(NonZero::new(bits as usize)?),
                    Duplication(NonZero::new(duplication as usize)?),
                ))
            }
            FuseLayoutType::WordMajorityVote { bits, duplication } => {
                Some(FuseLayout::WordMajorityVote(
                    Bits(NonZero::new(bits as usize)?),
                    Duplication(NonZero::new(duplication as usize)?),
                ))
            }
        }
    }
}
