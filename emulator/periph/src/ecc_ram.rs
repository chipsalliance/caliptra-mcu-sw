/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc_ram.rs

Abstract:

    ECC-protected RAM using a 16/22 SECDED (Single Error Correction, Double
    Error Detection) Hamming code. Each 16-bit data word is stored with 6
    parity bits for a total of 22 bits. On read the syndrome is checked:
    single-bit errors are corrected in-place and flagged as a correctable
    interrupt; double-bit errors are flagged as uncorrectable.

--*/

use serde::{Deserialize, Serialize};

// Parity masks
const P0_MASK: u32 = 0x0ad5b;
const P1_MASK: u32 = 0x0366d;
const P2_MASK: u32 = 0x0c78e;
const P3_MASK: u32 = 0x007f0;
const P4_MASK: u32 = 0x0f800;
const P5_MASK: u32 = 0x1f_ffff;

/// Syndrome-to-bit-position lookup table. `SYNDROME_MAP[s]` gives the bit
/// index (0-21) that has the error when the 5-bit syndrome equals `s`.
/// Entries for impossible syndrome values are set to 0xFF.
const SYNDROME_MAP: [u8; 23] = build_syndrome_map();

const fn build_syndrome_map() -> [u8; 23] {
    let mut map = [0xFFu8; 23];

    // Parity bit positions (syndrome = single check-bit index)
    map[1] = 16; // P0
    map[2] = 17; // P1
    map[4] = 18; // P2
    map[8] = 19; // P3
    map[16] = 20; // P4

    // Data bit positions – computed from the parity masks.
    let masks: [u32; 5] = [P0_MASK, P1_MASK, P2_MASK, P3_MASK, P4_MASK];
    let mut bit: u8 = 0;
    while bit < 16 {
        let mut syndrome: usize = 0;
        let mut p: usize = 0;
        while p < 5 {
            if masks[p] & (1 << bit) != 0 {
                syndrome |= 1 << p;
            }
            p += 1;
        }
        if syndrome < 23 {
            map[syndrome] = bit;
        }
        bit += 1;
    }

    map
}

/// Encode a 16-bit data word into a 22-bit word with ECC parity bits.
pub fn ecc_encode(data: u16) -> u32 {
    let mut w = data as u32;
    w |= ((w & P0_MASK).count_ones() & 1) << 16;
    w |= ((w & P1_MASK).count_ones() & 1) << 17;
    w |= ((w & P2_MASK).count_ones() & 1) << 18;
    w |= ((w & P3_MASK).count_ones() & 1) << 19;
    w |= ((w & P4_MASK).count_ones() & 1) << 20;
    w |= ((w & P5_MASK).count_ones() & 1) << 21;
    w
}

/// Result of decoding a 22-bit ECC word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EccResult {
    /// No error detected.
    Ok(u16),
    /// Single-bit error corrected; returns the corrected data.
    Corrected(u16),
    /// Uncorrectable (double-bit) error detected; returns data as-is.
    Uncorrectable(u16),
}

/// Decode a 22-bit stored word, checking and (if possible) correcting errors.
fn ecc_decode(stored: u32) -> EccResult {
    // Recompute parity from data bits (0-15) to get expected check bits.
    let data_bits = stored & 0xFFFF;
    let s0 = ((data_bits & P0_MASK).count_ones() ^ ((stored >> 16) & 1)) & 1;
    let s1 = ((data_bits & P1_MASK).count_ones() ^ ((stored >> 17) & 1)) & 1;
    let s2 = ((data_bits & P2_MASK).count_ones() ^ ((stored >> 18) & 1)) & 1;
    let s3 = ((data_bits & P3_MASK).count_ones() ^ ((stored >> 19) & 1)) & 1;
    let s4 = ((data_bits & P4_MASK).count_ones() ^ ((stored >> 20) & 1)) & 1;
    let syndrome = (s4 << 4) | (s3 << 3) | (s2 << 2) | (s1 << 1) | s0;

    // Overall parity of all 22 bits (should be even / 0 when no error).
    let overall = (stored & 0x3F_FFFF).count_ones() & 1;

    if syndrome == 0 && overall == 0 {
        EccResult::Ok(data_bits as u16)
    } else if syndrome == 0 {
        // Error only in P5 – data is fine, still counts as correctable.
        EccResult::Corrected(data_bits as u16)
    } else if overall != 0 {
        // Single-bit error; syndrome tells us which bit to flip.
        let mut corrected = stored;
        if (syndrome as usize) < SYNDROME_MAP.len() {
            let bit_pos = SYNDROME_MAP[syndrome as usize];
            if bit_pos != 0xFF {
                corrected ^= 1 << bit_pos;
            }
        }
        EccResult::Corrected((corrected & 0xFFFF) as u16)
    } else {
        EccResult::Uncorrectable(data_bits as u16)
    }
}

/// ECC-protected RAM block.
#[derive(Clone, Serialize, Deserialize)]
pub struct EccRam {
    /// Backing store – one u32 per 16-bit data word.
    words: Vec<u32>,
    /// Sticky flag: at least one correctable (single-bit) error was seen.
    correctable_error: bool,
    /// Sticky flag: at least one uncorrectable (double-bit) error was seen.
    uncorrectable_error: bool,
}

impl EccRam {
    /// Create a new ECC RAM sized to hold `num_bytes` of data.
    /// `num_bytes` must be a multiple of 2.
    pub fn new(num_bytes: usize) -> Self {
        assert_eq!(num_bytes % 2, 0);
        let num_words = num_bytes / 2;
        Self {
            words: vec![0u32; num_words],
            correctable_error: false,
            uncorrectable_error: false,
        }
    }

    /// Size in bytes.
    pub fn len(&self) -> usize {
        self.words.len() * 2
    }

    /// `true` if the RAM has zero capacity.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Initialize the entire RAM from raw byte data (no ECC).
    pub fn init_from_bytes(&mut self, data: &[u8]) {
        assert!(data.len() <= self.len());
        for (i, word) in self.words.iter_mut().enumerate() {
            let lo = data.get(i * 2).copied().unwrap_or(0);
            let hi = data.get(i * 2 + 1).copied().unwrap_or(0);
            *word = ecc_encode(u16::from_le_bytes([lo, hi]));
        }
    }

    /// Write raw bytes starting at `offset` (byte address relative to the
    /// start of this RAM). ECC is computed for each affected 16-bit word.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        for (i, &byte) in data.iter().enumerate() {
            let byte_addr = offset + i;
            let word_idx = byte_addr / 2;
            if word_idx >= self.words.len() {
                break;
            }
            // Decode current word to get both bytes.
            let cur = (self.words[word_idx] & 0xFFFF) as u16;
            let mut bytes = cur.to_le_bytes();
            bytes[byte_addr & 1] = byte;
            self.words[word_idx] = ecc_encode(u16::from_le_bytes(bytes));
        }
    }

    /// Read decoded bytes. ECC is checked for each accessed word.
    pub fn read_bytes(&mut self, offset: usize, buf: &mut [u8]) {
        for (i, dst) in buf.iter_mut().enumerate() {
            let byte_addr = offset + i;
            let word_idx = byte_addr / 2;
            if word_idx >= self.words.len() {
                *dst = 0;
                continue;
            }
            let result = ecc_decode(self.words[word_idx]);
            let data = match result {
                EccResult::Ok(d) => d,
                EccResult::Corrected(d) => {
                    self.correctable_error = true;
                    // Correct the stored word in-place.
                    self.words[word_idx] = ecc_encode(d);
                    d
                }
                EccResult::Uncorrectable(d) => {
                    self.uncorrectable_error = true;
                    d
                }
            };
            *dst = data.to_le_bytes()[byte_addr & 1];
        }
    }

    /// Returns `true` if a correctable (single-bit) error has been detected
    /// since the last call to [`clear_errors`].
    pub fn has_correctable_error(&self) -> bool {
        self.correctable_error
    }

    /// Returns `true` if an uncorrectable (double-bit) error has been detected
    /// since the last call to [`clear_errors`].
    pub fn has_uncorrectable_error(&self) -> bool {
        self.uncorrectable_error
    }

    /// Clear both error flags.
    pub fn clear_errors(&mut self) {
        self.correctable_error = false;
        self.uncorrectable_error = false;
    }

    /// Flip a single bit in the raw stored word at the given byte offset.
    /// `bit` is a bit index within the 22-bit stored word (0-21).
    /// Useful for injecting errors in tests.
    pub fn flip_bit(&mut self, byte_offset: usize, bit: u8) {
        let word_idx = byte_offset / 2;
        if word_idx < self.words.len() && bit < 22 {
            self.words[word_idx] ^= 1u32 << bit;
        }
    }

    /// OTP-style OR-only write.  Computes the new 22-bit ECC word for each
    /// affected 16-bit granule, then checks that ORing it with the currently
    /// stored word would not require any 1→0 bit transitions (across all 22
    /// bits, including parity).  If the check passes for every affected word
    /// the write is committed; otherwise no words are modified and the method
    /// returns `false`.
    pub fn otp_write_bytes(&mut self, offset: usize, data: &[u8]) -> bool {
        // Build the complete new data for each affected word before computing
        // ECC, so that partial-byte updates don't produce intermediate parity.
        let mut pending: Vec<(usize, u16)> = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            let byte_addr = offset + i;
            let word_idx = byte_addr / 2;
            if word_idx >= self.words.len() {
                break;
            }

            // Start from a previous pending update for this word, or the
            // stored data bits.
            let base = pending
                .iter()
                .rfind(|&&(idx, _)| idx == word_idx)
                .map(|&(_, d)| d)
                .unwrap_or((self.words[word_idx] & 0xFFFF) as u16);

            let mut bytes = base.to_le_bytes();
            bytes[byte_addr & 1] = byte;
            pending.push((word_idx, u16::from_le_bytes(bytes)));
        }

        // De-duplicate: keep only the last entry per word index (it has all
        // byte updates folded in), then encode and blank-check.
        let mut final_updates: Vec<(usize, u32)> = Vec::new();
        for &(idx, data_val) in pending.iter().rev() {
            if final_updates.iter().any(|&(i, _)| i == idx) {
                continue;
            }
            let new_word = ecc_encode(data_val);
            let stored = self.words[idx];
            if (stored & new_word) != stored {
                return false;
            }
            final_updates.push((idx, stored | new_word));
        }

        // All checks passed — commit.
        for (idx, val) in final_updates {
            self.words[idx] = val;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        for val in [0u16, 1, 0x1234, 0xFFFF, 0xA5A5] {
            let encoded = ecc_encode(val);
            assert_eq!(ecc_decode(encoded), EccResult::Ok(val));
        }
    }

    #[test]
    fn single_bit_correction() {
        let data: u16 = 0xBEEF;
        let encoded = ecc_encode(data);
        // Flip each of the 22 bits and verify correction.
        for bit in 0..22u8 {
            let corrupted = encoded ^ (1 << bit);
            match ecc_decode(corrupted) {
                EccResult::Corrected(d) => assert_eq!(d, data, "bit {bit}"),
                other => panic!("bit {bit}: expected Corrected, got {other:?}"),
            }
        }
    }

    #[test]
    fn double_bit_detection() {
        let data: u16 = 0xCAFE;
        let encoded = ecc_encode(data);
        // Flip two distinct bits – should be uncorrectable.
        for b1 in 0..22u8 {
            for b2 in (b1 + 1)..22u8 {
                let corrupted = encoded ^ (1 << b1) ^ (1 << b2);
                match ecc_decode(corrupted) {
                    EccResult::Uncorrectable(_) => {}
                    other => panic!("bits {b1},{b2}: expected Uncorrectable, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn ram_write_read() {
        let mut ram = EccRam::new(8);
        let data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        ram.write_bytes(0, &data);
        let mut buf = [0u8; 8];
        ram.read_bytes(0, &mut buf);
        assert_eq!(buf, data);
        assert!(!ram.has_correctable_error());
        assert!(!ram.has_uncorrectable_error());
    }

    #[test]
    fn ram_init_from_bytes() {
        let mut ram = EccRam::new(4);
        ram.init_from_bytes(&[0x12, 0x34, 0x56, 0x78]);
        let mut buf = [0u8; 4];
        ram.read_bytes(0, &mut buf);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn ram_flip_bit_correctable() {
        let mut ram = EccRam::new(4);
        ram.write_bytes(0, &[0xAA, 0x55, 0x00, 0xFF]);
        // Inject a single-bit error in the first word.
        ram.flip_bit(0, 3);
        let mut buf = [0u8; 4];
        ram.read_bytes(0, &mut buf);
        // Data should be corrected back.
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[1], 0x55);
        assert!(ram.has_correctable_error());
        assert!(!ram.has_uncorrectable_error());
    }

    #[test]
    fn ram_flip_two_bits_uncorrectable() {
        let mut ram = EccRam::new(4);
        ram.write_bytes(0, &[0xAA, 0x55, 0x00, 0xFF]);
        // Inject a double-bit error in the first word.
        ram.flip_bit(0, 0);
        ram.flip_bit(0, 1);
        let mut buf = [0u8; 2];
        ram.read_bytes(0, &mut buf);
        assert!(ram.has_uncorrectable_error());
    }

    #[test]
    fn ram_clear_errors() {
        let mut ram = EccRam::new(2);
        ram.write_bytes(0, &[0xFF, 0x00]);
        ram.flip_bit(0, 5);
        let mut buf = [0u8; 2];
        ram.read_bytes(0, &mut buf);
        assert!(ram.has_correctable_error());
        ram.clear_errors();
        assert!(!ram.has_correctable_error());
        assert!(!ram.has_uncorrectable_error());
    }

    #[test]
    fn exhaustive_roundtrip() {
        for val in 0..=u16::MAX {
            let encoded = ecc_encode(val);
            assert_eq!(
                ecc_decode(encoded),
                EccResult::Ok(val),
                "roundtrip failed for {val:#06x}"
            );
        }
    }

    #[test]
    fn exhaustive_single_bit_correction() {
        for val in 0..=u16::MAX {
            let encoded = ecc_encode(val);
            for bit in 0..22u8 {
                let corrupted = encoded ^ (1u32 << bit);
                match ecc_decode(corrupted) {
                    EccResult::Corrected(d) => {
                        assert_eq!(d, val, "correction failed for {val:#06x} bit {bit}")
                    }
                    other => panic!("{val:#06x} bit {bit}: expected Corrected, got {other:?}"),
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn exhaustive_double_bit_detection() {
        for val in 0..=u16::MAX {
            let encoded = ecc_encode(val);
            for b1 in 0..22u8 {
                for b2 in (b1 + 1)..22u8 {
                    let corrupted = encoded ^ (1u32 << b1) ^ (1u32 << b2);
                    match ecc_decode(corrupted) {
                        EccResult::Uncorrectable(_) => {}
                        other => panic!(
                            "{val:#06x} bits {b1},{b2}: expected Uncorrectable, got {other:?}"
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn otp_write_blank_succeeds() {
        let mut ram = EccRam::new(4);
        assert!(ram.otp_write_bytes(0, &[0xAA, 0x55]));
        let mut buf = [0u8; 2];
        ram.read_bytes(0, &mut buf);
        assert_eq!(buf, [0xAA, 0x55]);
    }

    #[test]
    fn otp_write_superset_succeeds() {
        let mut ram = EccRam::new(4);
        assert!(ram.otp_write_bytes(0, &[0x0F, 0x00]));
        // 0xFF is a data-bit superset of 0x0F, but the ECC parity bits may
        // conflict.  Verify that the write outcome matches the 22-bit check.
        let old_ecc = ecc_encode(0x000F);
        let new_ecc = ecc_encode(0x00FF);
        let expected = (old_ecc & new_ecc) == old_ecc;
        assert_eq!(ram.otp_write_bytes(0, &[0xFF, 0x00]), expected);
    }

    #[test]
    fn otp_write_same_value_succeeds() {
        let mut ram = EccRam::new(4);
        assert!(ram.otp_write_bytes(0, &[0xAB, 0xCD]));
        // Rewriting the same value should succeed (no bit transitions).
        assert!(ram.otp_write_bytes(0, &[0xAB, 0xCD]));
    }

    #[test]
    fn otp_write_clear_data_bit_fails() {
        let mut ram = EccRam::new(4);
        assert!(ram.otp_write_bytes(0, &[0xFF, 0xFF]));
        // Trying to clear data bits should fail.
        assert!(!ram.otp_write_bytes(0, &[0x00, 0x00]));
        // Data should be unchanged.
        let mut buf = [0u8; 2];
        ram.read_bytes(0, &mut buf);
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn otp_write_parity_conflict_fails() {
        // Write a value whose ECC parity bits are set, then write a different
        // value that needs some of those parity bits to be 0.  The blank
        // check on the 22-bit word must catch this even though the new data
        // bits are a superset of the old data bits.
        let mut ram = EccRam::new(2);
        // 0x0001 → parity has certain bits set
        assert!(ram.otp_write_bytes(0, &[0x01, 0x00]));
        // 0x0003 is a data-bit superset of 0x0001, but the ECC parity
        // pattern changes; if any parity bit needs to go 1→0 the write
        // must be rejected.
        let old_ecc = ecc_encode(0x0001);
        let new_ecc = ecc_encode(0x0003);
        if (old_ecc & new_ecc) != old_ecc {
            // There is a parity conflict — write must fail.
            assert!(!ram.otp_write_bytes(0, &[0x03, 0x00]));
        } else {
            // No conflict for this particular pair — write is fine.
            assert!(ram.otp_write_bytes(0, &[0x03, 0x00]));
        }
    }

    /// Exhaustive test: for every pair (old, new) where new is a data-bit
    /// superset of old, verify that otp_write succeeds iff the 22-bit ECC
    /// word is also a superset.
    #[test]
    #[ignore]
    fn exhaustive_otp_write_parity_consistency() {
        for old in 0..=u16::MAX {
            let old_ecc = ecc_encode(old);
            // Only test superset values — skip the non-superset cases
            // (those always fail on data bits alone).
            // Iterate over subsets of the complement bits.
            let complement = !old & 0xFFFF;
            let mut extra = complement;
            loop {
                let new_val = old | extra;
                let new_ecc = ecc_encode(new_val);
                let ecc_superset = (old_ecc & new_ecc) == old_ecc;

                let mut ram = EccRam::new(2);
                assert!(ram.otp_write_bytes(0, &old.to_le_bytes()));
                let ok = ram.otp_write_bytes(0, &new_val.to_le_bytes());
                assert_eq!(
                    ok, ecc_superset,
                    "old={old:#06x} new={new_val:#06x} old_ecc={old_ecc:#08x} new_ecc={new_ecc:#08x}"
                );

                if extra == 0 {
                    break;
                }
                // Enumerate subsets of `complement` using Gosper's hack.
                extra = (extra - 1) & complement;
            }
        }
    }
}
