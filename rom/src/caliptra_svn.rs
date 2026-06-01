// Licensed under the Apache-2.0 license

//! Persist Caliptra Core's runtime SVN floor into OTP.
//!
//! Caliptra Core cannot write its own fuses, so after Caliptra's
//! runtime mailbox is ready MCU ROM queries `FW_INFO` and advances
//! `CPTRA_CORE_RUNTIME_SVN` to the reported `min_fw_svn`. Skipped
//! when `CPTRA_CORE_ANTI_ROLLBACK_DISABLE` is set.

use crate::fatal_error;
use caliptra_api::mailbox::{CommandId, FwInfoResp, MailboxReqHeader};
use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::fuses;
use caliptra_mcu_romtime::{CaliptraSoC, Otp};
use core::fmt::Write;
use zerocopy::{FromBytes, IntoBytes};

/// `CPTRA_CORE_RUNTIME_SVN`: 128 raw bits, linear-OR.
const RUNTIME_SVN_BITS: u32 = 128;

/// Must only be called after Caliptra Core's runtime mailbox is ready.
pub(crate) fn process_caliptra_runtime_svn_burn(otp: &Otp, soc_manager: &mut CaliptraSoC) {
    if !anti_rollback_enabled(otp) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] anti-rollback off; skipping CPTRA_CORE_RUNTIME_SVN burn"
        );
        return;
    }

    let min_fw_svn = query_min_fw_svn(soc_manager);
    if min_fw_svn > RUNTIME_SVN_BITS {
        caliptra_mcu_romtime::println!("[mcu-rom] FW_INFO min_fw_svn {} too large", min_fw_svn);
        fatal_error(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR);
    }

    let current_words = read_runtime_svn_words(otp);
    let current = decode_runtime_svn(&current_words);
    if min_fw_svn <= current {
        return;
    }

    let target_words = encode_runtime_svn(min_fw_svn);
    let base_word = fuses::OTP_CPTRA_CORE_RUNTIME_SVN.byte_offset / 4;
    for (i, (cur, tgt)) in current_words.iter().zip(target_words.iter()).enumerate() {
        if *cur != *tgt && otp.write_word(base_word + i, *tgt).is_err() {
            burn_fatal();
        }
    }

    let new_svn = decode_runtime_svn(&read_runtime_svn_words(otp));
    if new_svn < min_fw_svn {
        burn_fatal();
    }
    caliptra_mcu_romtime::println!(
        "[mcu-rom] Burned CPTRA_CORE_RUNTIME_SVN: {} -> {}",
        current,
        new_svn
    );
}

fn burn_fatal() -> ! {
    caliptra_mcu_romtime::println!("[mcu-rom] CPTRA_CORE_RUNTIME_SVN burn failed");
    fatal_error(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR);
}

fn anti_rollback_enabled(otp: &Otp) -> bool {
    match otp.read_cptra_core_anti_rollback_disable() {
        Ok(raw) => raw.iter().all(|b| *b == 0),
        Err(_) => burn_fatal(),
    }
}

fn query_min_fw_svn(soc_manager: &mut CaliptraSoC) -> u32 {
    // Safety: `MailboxReqHeader` is `repr(C)` with size 4; transmuting
    // an all-zero header to `[u32; 1]` is sound.
    let mut req_u32: [u32; core::mem::size_of::<MailboxReqHeader>() / 4] =
        unsafe { core::mem::transmute(MailboxReqHeader { chksum: 0 }) };
    let mut resp_u32 = [0u32; core::mem::size_of::<FwInfoResp>() / 4];

    if soc_manager
        .exec_mailbox_req_u32(CommandId::FW_INFO.into(), &mut req_u32, &mut resp_u32)
        .is_err()
    {
        burn_fatal();
    }

    match FwInfoResp::ref_from_bytes(resp_u32.as_bytes()) {
        Ok(resp) => resp.min_fw_svn,
        Err(_) => burn_fatal(),
    }
}

fn read_runtime_svn_words(otp: &Otp) -> [u32; 4] {
    let bytes = match otp.read_cptra_core_runtime_svn() {
        Ok(v) => v,
        Err(_) => burn_fatal(),
    };
    let mut words = [0u32; 4];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    words
}

fn decode_runtime_svn(words: &[u32; 4]) -> u32 {
    let mut total = 0u32;
    for w in words.iter() {
        let ones = (!*w).trailing_zeros();
        total += ones;
        if ones < 32 {
            return total;
        }
    }
    total
}

fn encode_runtime_svn(svn: u32) -> [u32; 4] {
    let mut words = [0u32; 4];
    let mut remaining = svn.min(RUNTIME_SVN_BITS);
    for w in words.iter_mut() {
        let n = remaining.min(32);
        *w = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        remaining -= n;
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_runtime_svn_handles_zero() {
        assert_eq!(decode_runtime_svn(&[0; 4]), 0);
    }

    #[test]
    fn encode_runtime_svn_zero_is_empty() {
        assert_eq!(encode_runtime_svn(0), [0; 4]);
    }

    #[test]
    fn encode_decode_roundtrip() {
        for svn in [1u32, 7, 31, 32, 33, 63, 64, 65, 127, 128] {
            assert_eq!(decode_runtime_svn(&encode_runtime_svn(svn)), svn);
        }
    }

    #[test]
    fn encode_runtime_svn_max_is_all_ones() {
        assert_eq!(encode_runtime_svn(RUNTIME_SVN_BITS), [u32::MAX; 4]);
    }
}
