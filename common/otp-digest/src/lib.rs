// Licensed under the Apache-2.0 license.
// Copyright lowRISC contributors (OpenTitan project).

// This section is converted from the OpenTitan project's Python implementation of OTP digest algorithm.

#![no_std]

const ROUNDS: usize = 32;

/// Scramble a 64bit block with PRESENT cipher.
fn present_64bit_encrypt(plain: u64, key: u128) -> u64 {
    Present::new_128(&key.to_le_bytes()).encrypt_block(plain)
}

pub fn otp_scramble(data: u64, key: u128) -> u64 {
    Present::new_128(&key.to_le_bytes()).encrypt_block(data)
}

pub fn otp_unscramble(data: u64, key: u128) -> u64 {
    Present::new_128(&key.to_le_bytes()).decrypt_block(data)
}

pub fn otp_digest(data: &[u8], iv: u64, cnst: u128) -> u64 {
    assert_eq!(data.len() % 8, 0);

    let blocks = data.chunks_exact(8).map(|chunk| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        u64::from_le_bytes(bytes)
    });

    otp_digest_iter(blocks, iv, cnst)
}

/// Compute an OTP digest over an iterator of little-endian 64-bit data blocks.
///
/// This is equivalent to [`otp_digest`] but avoids requiring all data in memory
/// at once — the caller can stream blocks from OTP word-by-word.
pub fn otp_digest_iter(blocks: impl Iterator<Item = u64>, iv: u64, cnst: u128) -> u64 {
    let mut state = iv;
    let mut prev: Option<u64> = None;

    // Merkle-Damgard construction with Davies-Meyer compression (PRESENT cipher).
    // See also: https://docs.opentitan.org/hw/ip/otp_ctrl/doc/index.html#scrambling-datapath
    for block in blocks {
        match prev {
            None => {
                prev = Some(block);
            }
            Some(b0) => {
                let b128 = b0 as u128 | ((block as u128) << 64);
                state ^= present_64bit_encrypt(state, b128);
                prev = None;
            }
        }
    }

    // Align to 2x64bit: if odd number of blocks, duplicate the last one.
    if let Some(last) = prev {
        let b128 = last as u128 | ((last as u128) << 64);
        state ^= present_64bit_encrypt(state, b128);
    }

    // Digest finalization with 128-bit constant.
    state ^= present_64bit_encrypt(state, cnst);

    state
}

/// PRESENT block cipher.
///
/// Based on version 1.2 of the following Python implementation
/// <https://github.com/doegox/python-cryptoplus>
pub struct Present {
    round_keys: [u64; ROUNDS],
}

impl Present {
    /// Create a new 128-bit PRESENT cipher instance.
    pub fn new_128(key: &[u8; 16]) -> Present {
        Present {
            round_keys: generate_round_keys_128(key),
        }
    }

    /// Create a new 80-bit PRESENT cipher instance.
    pub fn new_80(key: &[u8; 10]) -> Present {
        Present {
            round_keys: generate_round_keys_80(key),
        }
    }

    /// Encrypt a 64-bit block.
    pub fn encrypt_block(&self, block: u64) -> u64 {
        let mut state = block;
        state ^= self.round_keys[0];
        for round_key in &self.round_keys[1..] {
            state = s_box_layer(state);
            state = p_box_layer(state);
            state ^= round_key;
        }
        state
    }

    /// Decrypt a 64-bit block.
    pub fn decrypt_block(&self, block: u64) -> u64 {
        let mut state = block;
        for round_key in self.round_keys[1..].iter().rev() {
            state ^= round_key;
            state = p_box_layer_dec(state);
            state = s_box_layer_dec(state);
        }
        state ^ self.round_keys[0]
    }
}

const S_BOX: [u8; 16] = [
    0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02,
];

const S_BOX_INV: [u8; 16] = [
    0x05, 0x0e, 0x0f, 0x08, 0x0c, 0x01, 0x02, 0x0d, 0x0b, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0a,
];

const P_BOX: [u8; 64] = [
    0x00, 0x10, 0x20, 0x30, 0x01, 0x11, 0x21, 0x31, 0x02, 0x12, 0x22, 0x32, 0x03, 0x13, 0x23, 0x33,
    0x04, 0x14, 0x24, 0x34, 0x05, 0x15, 0x25, 0x35, 0x06, 0x16, 0x26, 0x36, 0x07, 0x17, 0x27, 0x37,
    0x08, 0x18, 0x28, 0x38, 0x09, 0x19, 0x29, 0x39, 0x0a, 0x1a, 0x2a, 0x3a, 0x0b, 0x1b, 0x2b, 0x3b,
    0x0c, 0x1c, 0x2c, 0x3c, 0x0d, 0x1d, 0x2d, 0x3d, 0x0e, 0x1e, 0x2e, 0x3e, 0x0f, 0x1f, 0x2f, 0x3f,
];

const P_BOX_INV: [u8; 64] = [
    0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
    0x01, 0x05, 0x09, 0x0d, 0x11, 0x15, 0x19, 0x1d, 0x21, 0x25, 0x29, 0x2d, 0x31, 0x35, 0x39, 0x3d,
    0x02, 0x06, 0x0a, 0x0e, 0x12, 0x16, 0x1a, 0x1e, 0x22, 0x26, 0x2a, 0x2e, 0x32, 0x36, 0x3a, 0x3e,
    0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b, 0x2f, 0x33, 0x37, 0x3b, 0x3f,
];

/// Generate the round_keys for an 80-bit key.
fn generate_round_keys_80(key: &[u8; 10]) -> [u64; ROUNDS] {
    let mut round_keys = [0u64; ROUNDS];

    // Pad out key so it fits in a u128.
    let mut padded = [0u8; 16];
    padded[6..16].copy_from_slice(key);
    let mut key = u128::from_le_bytes(padded);

    for (i, round_key) in round_keys.iter_mut().enumerate() {
        // rawKey[0:64]
        *round_key = (key >> 16) as u64;

        // 1. Rotate bits
        // rawKey[19:len(rawKey)]+rawKey[0:19]
        key = ((key & 0x7ffff) << 61) | (key >> 19);

        // 2. SBox
        // rawKey[76:80] = S(rawKey[76:80])
        key =
            ((S_BOX[((key >> 76) & 0xF) as usize] as u128) << 76) | (key & (!0u128 >> (128 - 76)));

        // 3. Salt
        // rawKey[15:20] ^ i
        key ^= ((i + 1) as u128) << 15;
    }

    round_keys
}

/// Generate the round_keys for a 128-bit key.
fn generate_round_keys_128(key: &[u8; 16]) -> [u64; ROUNDS] {
    let mut round_keys = [0u64; ROUNDS];

    // Convert key into a u128 for easier bit manipulation.
    let mut key = u128::from_le_bytes(*key);
    for (i, round_key) in round_keys.iter_mut().enumerate() {
        // rawKey[0:64]
        *round_key = (key >> 64) as u64;

        // 1. Rotate bits
        key = key.rotate_left(61);

        // 2. SBox
        key = ((S_BOX[((key >> 124) & 0xF) as usize] as u128) << 124)
            | ((S_BOX[((key >> 120) & 0xF) as usize] as u128) << 120)
            | (key & (!0u128 >> 8));

        // 3. Salt
        // rawKey[62:67] ^ i
        key ^= ((i + 1) as u128) << 62;
    }

    round_keys
}

/// SBox function for encryption.
fn s_box_layer(state: u64) -> u64 {
    let mut output: u64 = 0;
    for i in (0..64).step_by(4) {
        output |= (S_BOX[((state >> i) & 0x0f) as usize] as u64) << i;
    }
    output
}

/// SBox inverse function for decryption.
fn s_box_layer_dec(state: u64) -> u64 {
    let mut output: u64 = 0;
    for i in (0..64).step_by(4) {
        output |= (S_BOX_INV[((state >> i) & 0x0f) as usize] as u64) << i;
    }
    output
}

/// PBox function for encryption.
fn p_box_layer(state: u64) -> u64 {
    let mut output: u64 = 0;
    for (i, v) in P_BOX.iter().enumerate() {
        output |= ((state >> i) & 0x01) << v;
    }
    output
}

/// PBox inverse function for decryption.
fn p_box_layer_dec(state: u64) -> u64 {
    let mut output: u64 = 0;
    for (i, v) in P_BOX_INV.iter().enumerate() {
        output |= ((state >> i) & 0x01) << v;
    }
    output
}

#[cfg(test)]
mod test {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;

    #[rustfmt::skip]
    const ROUND_KEYS_80: [u64; 32] = [
        0x0000000000000000, 0xc000000000000000, 0x5000180000000001, 0x60000a0003000001,
        0xb0000c0001400062, 0x900016000180002a, 0x0001920002c00033, 0xa000a0003240005b,
        0xd000d4001400064c, 0x30017a001a800284, 0xe01926002f400355, 0xf00a1c0324c005ed,
        0x800d5e014380649e, 0x4017b001abc02876, 0x71926802f600357f, 0x10a1ce324d005ec7,
        0x20d5e21439c649a8, 0xc17b041abc428730, 0xc926b82f60835781, 0x6a1cd924d705ec19,
        0xbd5e0d439b249aea, 0x07b077abc1a8736e, 0x426ba0f60ef5783e, 0x41cda84d741ec1d5,
        0xf5e0e839b509ae8f, 0x2b075ebc1d0736ad, 0x86ba2560ebd783ad, 0x8cdab0d744ac1d77,
        0x1e0eb19b561ae89b, 0xd075c3c1d6336acd, 0x8ba27a0eb8783ac9, 0x6dab31744f41d700,
    ];

    #[rustfmt::skip]
    const ROUND_KEYS_128: [u64; 32] = [
        0x0000000000000000, 0xcc00000000000000, 0xc300000000000000, 0x5b30000000000000,
        0x580c000000000001, 0x656cc00000000001, 0x6e60300000000001, 0xb595b30000000001,
        0xbeb980c000000002, 0x96d656cc00000002, 0x9ffae60300000002, 0x065b595b30000002,
        0x0f7feb980c000003, 0xac196d656cc00003, 0xa33dffae60300003, 0xd6b065b595b30003,
        0xdf8cf7feb980c004, 0x3b5ac196d656cc04, 0x387e33dffae60304, 0xeced6b065b595b34,
        0xe3e1f8cf7feb9809, 0x6bb3b5ac196d6569, 0xbb8f87e33dffae65, 0x80aeced6b065b590,
        0xc1ee3e1f8cf7febf, 0x2602bb3b5ac196d0, 0xcb07b8f87e33dffc, 0x34980aeced6b065d,
        0x8b2c1ee3e1f8cf78, 0x54d2602bb3b5ac1e, 0x4a2cb07b8f87e33a, 0x97534980aeced6b7,
    ];

    #[test]
    fn test_generate_80() {
        let key = [0u8; 10];
        let round_keys = generate_round_keys_80(&key);
        assert_eq!(round_keys, ROUND_KEYS_80);
    }

    #[test]
    fn test_generate_128() {
        let key = [0u8; 16];
        let round_keys = generate_round_keys_128(&key);
        assert_eq!(round_keys, ROUND_KEYS_128);
    }

    #[test]
    fn test_enc_80() {
        let cipher = Present::new_80(&[0; 10]);
        assert_eq!(cipher.encrypt_block(0), 0x5579c1387b228445);
    }

    #[test]
    fn test_dec_80() {
        let cipher = Present::new_80(&[0; 10]);
        assert_eq!(cipher.decrypt_block(0x5579c1387b228445), 0);
    }

    #[test]
    fn test_enc_128() {
        let cipher = Present::new_128(&[0; 16]);
        assert_eq!(cipher.encrypt_block(0), 0x96db702a2e6900af);
        assert_eq!(cipher.encrypt_block(!0), 0x3c6019e5e5edd563);
        let cipher = Present::new_128(&[0xff; 16]);
        assert_eq!(cipher.encrypt_block(0), 0x13238c710272a5d8);
        assert_eq!(cipher.encrypt_block(!0), 0x628d9fbd4218e5b4);
    }

    #[test]
    fn test_dec_128() {
        let cipher = Present::new_128(&[0; 16]);
        assert_eq!(cipher.decrypt_block(0x96db702a2e6900af), 0);
        assert_eq!(cipher.decrypt_block(0x3c6019e5e5edd563), !0);
        let cipher = Present::new_128(&[0xff; 16]);
        assert_eq!(cipher.decrypt_block(0x13238c710272a5d8), 0);
        assert_eq!(cipher.decrypt_block(0x628d9fbd4218e5b4), !0);
    }

    #[test]
    fn test_matches_python_128_and_is_little_endian() {
        assert_eq!(
            present_64bit_encrypt(0x0123456789abcdef, 0x0123456789abcdef0123456789abcdefu128),
            0xe9d28685e671dd6
        );
    }

    #[test]
    fn test_digest_iter_matches_digest() {
        // Even number of blocks
        let data: Vec<u8> = (0..32).collect();
        let iv = 0x1234567890abcdef;
        let cnst = 0xfedcba0987654321fedcba0987654321u128;
        let expected = otp_digest(&data, iv, cnst);
        let blocks = data
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()));
        assert_eq!(otp_digest_iter(blocks, iv, cnst), expected);

        // Odd number of blocks
        let data: Vec<u8> = (0..24).collect();
        let expected = otp_digest(&data, iv, cnst);
        let blocks = data
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()));
        assert_eq!(otp_digest_iter(blocks, iv, cnst), expected);

        // Single block
        let data = [0u8; 8];
        let expected = otp_digest(&data, iv, cnst);
        let blocks = data
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()));
        assert_eq!(otp_digest_iter(blocks, iv, cnst), expected);

        // Empty
        let expected = otp_digest(&[], iv, cnst);
        assert_eq!(otp_digest_iter(core::iter::empty(), iv, cnst), expected);
    }
}
