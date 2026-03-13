// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use emulator_periph::{otp_digest, otp_scramble, otp_unscramble};
use mcu_rom_common::LifecycleControllerState;
use sha3::{digest::ExtendableOutput, digest::Update, CShake128, CShake128Core};

// Re-export lifecycle ECC encode/decode from the common crate.
pub use otp_lifecycle::{
    lc_generate_count_mem, LIFECYCLE_COUNT_SIZE, LIFECYCLE_MEM_SIZE, LIFECYCLE_STATE_SIZE,
};

/// Generate the OTP memory contents associated with the lifecycle state.
pub fn lc_generate_state_mem(
    state: LifecycleControllerState,
) -> Result<[u8; LIFECYCLE_STATE_SIZE]> {
    otp_lifecycle::lc_generate_state_mem(u8::from(state))
}

/// Generate the OTP memory contents associated with the lifecycle state and transition count.
pub fn lc_generate_memory(
    state: LifecycleControllerState,
    transition_count: u8,
) -> Result<[u8; LIFECYCLE_MEM_SIZE]> {
    otp_lifecycle::lc_generate_memory(u8::from(state), transition_count)
}

/// Decode the lifecycle state and transition count from OTP memory (as stored, i.e., reversed).
pub fn lc_decode_memory(mem: &[u8; LIFECYCLE_MEM_SIZE]) -> Result<(LifecycleControllerState, u8)> {
    let (state_idx, count) = otp_lifecycle::lc_decode_memory(mem)?;
    Ok((LifecycleControllerState::from(state_idx), count))
}

/// Decode the lifecycle state from OTP memory (pre-reversal format).
pub fn lc_decode_state_mem(mem: &[u8; LIFECYCLE_STATE_SIZE]) -> Result<LifecycleControllerState> {
    let state_idx = otp_lifecycle::lc_decode_state_mem(mem)?;
    Ok(LifecycleControllerState::from(state_idx))
}

/// Decode the lifecycle transition count from OTP memory (pre-reversal format).
pub fn lc_decode_count_mem(mem: &[u8; LIFECYCLE_COUNT_SIZE]) -> Result<u8> {
    otp_lifecycle::lc_decode_count_mem(mem)
}

/// Hash a token using cSHAKE128 for the lifecycle controller.
fn hash_token(raw_token: &[u8; 16]) -> [u8; 16] {
    let mut hasher: CShake128 = CShake128::from_core(CShake128Core::new(b"LC_CTRL"));
    hasher.update(raw_token);
    let mut output = [0u8; 16];
    hasher.finalize_xof_into(&mut output);
    output
}

pub const DIGEST_SIZE: usize = 8;
pub const LIFECYCLE_TOKENS_MEM_SIZE: usize = 184; // 11 tokens of 16 bytes each + 8 bytes for the digest

// Default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const OTP_IV: u64 = 0x90C7F21F6224F027;
const OTP_CNST: u128 = 0xF98C48B1F93772844A22D4B78FE0266F;

// These are in reverse order from the RTL.
pub(crate) const OTP_SCRAMBLE_KEYS: [u128; 7] = [
    0x3BA121C5E097DDEB7768B4C666E9C3DA,
    0xEFFA6D736C5EFF49AE7B70F9C46E5A62,
    0x85A9E830BC059BA9286D6E2856A05CC3,
    0xBEAD91D5FA4E09150E95F517CB98955B,
    0x4D5A89AA9109294AE048B657396B4B83,
    0x277195FC471E4B26B6641214B61D1B43,
    0xB7474D640F8A7F5D60822E1FAEC5C72,
];

const LC_TOKENS_KEY_IDX: usize = 6;

fn otp_scramble_data(data: &mut [u8], key_idx: usize) -> Result<()> {
    if data.len() % 8 != 0 {
        bail!("Data length must be a multiple of 8 bytes for scrambling");
    }
    if key_idx >= OTP_SCRAMBLE_KEYS.len() {
        bail!("Invalid key index for OTP scrambling");
    }
    for chunk in data.chunks_exact_mut(8) {
        let input = u64::from_le_bytes(chunk.try_into().unwrap());
        let output = otp_scramble(input, OTP_SCRAMBLE_KEYS[key_idx]);
        chunk.copy_from_slice(&output.to_le_bytes());
    }
    Ok(())
}

#[allow(unused)]
fn otp_unscramble_data(data: &mut [u8], key_idx: usize) -> Result<()> {
    if data.len() % 8 != 0 {
        bail!("Data length must be a multiple of 8 bytes for scrambling");
    }
    if key_idx >= OTP_SCRAMBLE_KEYS.len() {
        bail!("Invalid key index for OTP scrambling");
    }
    for chunk in data.chunks_exact_mut(8) {
        let input = u64::from_le_bytes(chunk.try_into().unwrap());
        let output = otp_unscramble(input, OTP_SCRAMBLE_KEYS[key_idx]);
        chunk.copy_from_slice(&output.to_le_bytes());
    }
    Ok(())
}

/// Generate the OTP memory contents for lifecycle tokens partition (including the digest).
pub fn otp_generate_lifecycle_tokens_mem(
    tokens: &mcu_rom_common::LifecycleRawTokens,
) -> Result<[u8; LIFECYCLE_TOKENS_MEM_SIZE]> {
    let mut output = [0u8; LIFECYCLE_TOKENS_MEM_SIZE];
    for (i, token) in tokens.test_unlock.iter().enumerate() {
        let hashed_token = hash_token(&token.0);
        output[i * 16..(i + 1) * 16].copy_from_slice(&hashed_token);
    }
    output[7 * 16..8 * 16].copy_from_slice(&hash_token(&tokens.manuf.0));
    output[8 * 16..9 * 16].copy_from_slice(&hash_token(&tokens.manuf_to_prod.0));
    output[9 * 16..10 * 16].copy_from_slice(&hash_token(&tokens.prod_to_prod_end.0));
    output[10 * 16..11 * 16].copy_from_slice(&hash_token(&tokens.rma.0));

    otp_scramble_data(
        &mut output[..LIFECYCLE_TOKENS_MEM_SIZE - DIGEST_SIZE],
        LC_TOKENS_KEY_IDX,
    )?;

    let digest = otp_digest(
        &output[..LIFECYCLE_TOKENS_MEM_SIZE - DIGEST_SIZE],
        OTP_IV,
        OTP_CNST,
    );
    output[LIFECYCLE_TOKENS_MEM_SIZE - DIGEST_SIZE..].copy_from_slice(&digest.to_le_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use mcu_rom_common::{LifecycleRawTokens, LifecycleToken};

    use super::*;

    #[test]
    fn test_otp_unscramble_token() {
        let raw_token = LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());
        let tokens = LifecycleRawTokens {
            test_unlock: [raw_token; 7],
            manuf: raw_token,
            manuf_to_prod: raw_token,
            prod_to_prod_end: raw_token,
            rma: raw_token,
        };
        let mut memory = otp_generate_lifecycle_tokens_mem(&tokens).unwrap();
        otp_unscramble_data(&mut memory[..16], LC_TOKENS_KEY_IDX).unwrap();
        let expected_hashed_token: [u8; 16] = 0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes();
        assert_eq!(&memory[..16], &expected_hashed_token);
    }

    #[test]
    fn test_otp_generate_lifecycle_tokens_mem() {
        let raw_token = LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());
        let tokens = LifecycleRawTokens {
            test_unlock: [raw_token; 7],
            manuf: raw_token,
            manuf_to_prod: raw_token,
            prod_to_prod_end: raw_token,
            rma: raw_token,
        };
        let memory = otp_generate_lifecycle_tokens_mem(&tokens).unwrap();

        let expected: [u8; 184] = [
            0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c,
            0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1,
            0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27,
            0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae,
            0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b,
            0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c,
            0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84,
            0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd,
            0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c,
            0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1,
            0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27,
            0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae,
            0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x79, 0xf0, 0x7f, 0x3a, 0x7b, 0x09,
            0x96, 0xe3,
        ];

        assert_eq!(memory, expected);
    }

    #[test]
    fn test_hash_token() {
        let raw_token: [u8; 16] = 0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes();
        let expected_hashed_token: [u8; 16] = 0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes();
        assert_eq!(hash_token(&raw_token), expected_hashed_token);
    }

    #[test]
    fn test_lifecycle_unlocked1() {
        let memory = lc_generate_memory(LifecycleControllerState::TestUnlocked0, 1).unwrap();
        let expected: [u8; LIFECYCLE_MEM_SIZE] = [
            0xdf, 0xb6, 0xc4, 0x5a, 0x24, 0x1f, 0x85, 0xce, 0x9f, 0x42, 0x22, 0x9e, 0x86, 0x27,
            0x46, 0x2f, 0xdb, 0x02, 0xc6, 0x70, 0x12, 0x42, 0xf1, 0x4b, 0x41, 0x89, 0x11, 0x80,
            0x04, 0x5c, 0x09, 0xc2, 0x6c, 0x52, 0x74, 0x42, 0x67, 0xc0, 0x4a, 0xa0, 0x55, 0x92,
            0x1b, 0x94, 0x61, 0xbb, 0x07, 0xda, 0xee, 0x75, 0xb4, 0x07, 0xd2, 0x31, 0x4d, 0x2e,
            0xf8, 0x41, 0x85, 0xac, 0x8c, 0x99, 0x0f, 0x53, 0x60, 0x71, 0x63, 0x2c, 0x08, 0x6d,
            0x4c, 0x92, 0x40, 0x70, 0xbe, 0x92, 0xd2, 0x94, 0x8d, 0x62, 0x28, 0xb2, 0x71, 0x1e,
            0x9b, 0x2d, 0x8c, 0x4d,
        ];
        assert_eq!(memory, expected);
    }

    #[test]
    fn test_lifecycle_manufacturing() {
        let memory = lc_generate_memory(LifecycleControllerState::Dev, 2).unwrap();
        let expected: [u8; LIFECYCLE_MEM_SIZE] = [
            0xdf, 0xb6, 0xf4, 0xfa, 0x24, 0x1f, 0x85, 0xce, 0x9f, 0x42, 0x22, 0x9e, 0x86, 0x27,
            0x46, 0x2f, 0xdb, 0x02, 0xc6, 0x70, 0x12, 0x42, 0xf1, 0x4b, 0x41, 0x89, 0x11, 0x80,
            0x04, 0x5c, 0x09, 0xc2, 0x6c, 0x52, 0x74, 0x42, 0x67, 0xc0, 0x4a, 0xa0, 0x55, 0x92,
            0x1b, 0x94, 0x61, 0xbb, 0x07, 0xda, 0xee, 0x75, 0xfe, 0x0f, 0xfe, 0x7b, 0x6f, 0x3f,
            0xfc, 0x5f, 0x9f, 0xfd, 0x9f, 0xf9, 0x6f, 0xdb, 0x7f, 0x73, 0x6f, 0x6c, 0x9e, 0x6f,
            0xdc, 0xd3, 0x52, 0x77, 0xfe, 0xf2, 0xd3, 0xbd, 0xcd, 0x6f, 0x28, 0xb2, 0x71, 0x1e,
            0x9b, 0x2d, 0x8c, 0x4d,
        ];
        assert_eq!(memory, expected);
    }

    #[test]
    fn test_decode_roundtrip_all_states() {
        for state_val in 0..=20u8 {
            let state = LifecycleControllerState::from(state_val);
            let memory = lc_generate_memory(state, 1).unwrap();
            let (decoded_state, decoded_count) = lc_decode_memory(&memory).unwrap();
            assert_eq!(
                decoded_state, state,
                "state roundtrip failed for {state_val}"
            );
            assert_eq!(
                decoded_count, 1,
                "count roundtrip failed for state {state_val}"
            );
        }
    }

    #[test]
    fn test_decode_roundtrip_all_counts() {
        for count in 0..=24u8 {
            let memory = lc_generate_memory(LifecycleControllerState::Prod, count).unwrap();
            let (decoded_state, decoded_count) = lc_decode_memory(&memory).unwrap();
            assert_eq!(decoded_state, LifecycleControllerState::Prod);
            assert_eq!(
                decoded_count, count,
                "count roundtrip failed for count {count}"
            );
        }
    }

    #[test]
    fn test_decode_raw_state() {
        let memory = lc_generate_memory(LifecycleControllerState::Raw, 0).unwrap();
        let (state, count) = lc_decode_memory(&memory).unwrap();
        assert_eq!(state, LifecycleControllerState::Raw);
        assert_eq!(count, 0);
    }
}
