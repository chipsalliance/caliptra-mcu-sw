// Licensed under the Apache-2.0 license

//! Burn the Caliptra-owned SVN floors requested by the MCU runtime SVN
//! header: `CPTRA_CORE_RUNTIME_SVN` and `CPTRA_CORE_SOC_MANIFEST_SVN`.
//!
//! Caliptra Core cannot write its own fuses, so MCU ROM is the OTP
//! writer for the subsystem. The new floors come from the authenticated
//! SVN header. For the Caliptra runtime floor, MCU ROM cross-checks the
//! header's self-attested running SVN against `FW_INFO.fw_svn`. The SoC
//! manifest SVN is not exposed by `FW_INFO`, so the header's
//! self-attested value (validated as `>= min_svn`) is the only guard.

use crate::{fatal_error, RomEnv};
use caliptra_api::mailbox::{CommandId, FwInfoResp, MailboxReqHeader};
use caliptra_mcu_error::McuError;
use caliptra_mcu_registers_generated::fuses::{
    FuseEntryInfo, OTP_CPTRA_CORE_RUNTIME_SVN, OTP_CPTRA_CORE_SOC_MANIFEST_SVN,
};
use caliptra_mcu_romtime::{CaliptraSoC, McuComponentSvnManifest, Otp};
use core::fmt::Write;
use zerocopy::{FromBytes, IntoBytes};

/// Both fuses are 128 raw bits with linear-OR semantics: the logical
/// floor equals the number of trailing 1 bits.
pub(crate) const CALIPTRA_SVN_BITS: u32 = 128;

/// Validate the header's Caliptra-owned floors against `FW_INFO` before
/// any OTP write. The only such check is that the runtime floor doesn't
/// exceed the running Caliptra runtime SVN (which would brick the next
/// boot); the SoC manifest SVN is not exposed by `FW_INFO`. No OTP
/// writes. Caller must have verified `CPTRA_CORE_ANTI_ROLLBACK_DISABLE`
/// is not set.
pub(crate) fn check_caliptra_owned_svns(env: &mut RomEnv, manifest: &McuComponentSvnManifest) {
    if manifest.caliptra_runtime_min_svn == 0 {
        return;
    }
    let fw_svn = query_fw_svn(&mut env.soc_manager);
    if fw_svn < manifest.caliptra_runtime_min_svn.into() {
        caliptra_mcu_romtime::println!(
            "[mcu-rom] SVN header caliptra_runtime_min_svn {} > FW_INFO.fw_svn {}",
            manifest.caliptra_runtime_min_svn,
            fw_svn
        );
        fatal_error(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR);
    }
}

/// Apply the header's Caliptra-owned SVN burns. Caller must have run
/// [`check_caliptra_owned_svns`] first; only OTP HW errors fatal here.
pub(crate) fn burn_caliptra_owned_svns(env: &mut RomEnv, manifest: &McuComponentSvnManifest) {
    if manifest.caliptra_runtime_min_svn > 0 {
        burn_svn(
            &env.otp,
            OTP_CPTRA_CORE_RUNTIME_SVN,
            manifest.caliptra_runtime_min_svn.into(),
        );
    }
    if manifest.soc_manifest_min_svn > 0 {
        burn_svn(
            &env.otp,
            OTP_CPTRA_CORE_SOC_MANIFEST_SVN,
            manifest.soc_manifest_min_svn.into(),
        );
    }
}

fn burn_fatal() -> ! {
    caliptra_mcu_romtime::println!("[mcu-rom] Caliptra-owned SVN burn failed");
    fatal_error(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR);
}

fn query_fw_svn(soc_manager: &mut CaliptraSoC) -> u32 {
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
        Ok(resp) => resp.fw_svn,
        Err(_) => burn_fatal(),
    }
}

/// Advance `entry` to `target` (with read-back verification) when it
/// exceeds the current fuse floor.
fn burn_svn(otp: &Otp, entry: &'static FuseEntryInfo, target: u32) {
    if target > CALIPTRA_SVN_BITS {
        caliptra_mcu_romtime::println!("[mcu-rom] {} target {} too large", entry.name, target);
        fatal_error(McuError::ROM_CALIPTRA_RUNTIME_SVN_BURN_ERROR);
    }

    let current_words = read_svn_words(otp, entry);
    let current = decode_svn(&current_words);
    if target <= current {
        return;
    }

    let target_words = encode_svn(target);
    let base_word = entry.byte_offset / 4;
    for (i, (cur, tgt)) in current_words.iter().zip(target_words.iter()).enumerate() {
        if *cur != *tgt && otp.write_word(base_word + i, *tgt).is_err() {
            burn_fatal();
        }
    }

    let new_svn = decode_svn(&read_svn_words(otp, entry));
    if new_svn < target {
        burn_fatal();
    }
    caliptra_mcu_romtime::println!(
        "[mcu-rom] Burned {}: {} -> {}",
        entry.name,
        current,
        new_svn
    );
}

fn read_svn_words(otp: &Otp, entry: &FuseEntryInfo) -> [u32; 4] {
    let mut bytes = [0u8; 16];
    if otp.read_entry_raw(entry, &mut bytes).is_err() {
        burn_fatal();
    }
    let mut words = [0u32; 4];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    words
}

fn decode_svn(words: &[u32; 4]) -> u32 {
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

fn encode_svn(svn: u32) -> [u32; 4] {
    let mut words = [0u32; 4];
    let mut remaining = svn.min(CALIPTRA_SVN_BITS);
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
    fn decode_svn_handles_zero() {
        assert_eq!(decode_svn(&[0; 4]), 0);
    }

    #[test]
    fn encode_svn_zero_is_empty() {
        assert_eq!(encode_svn(0), [0; 4]);
    }

    #[test]
    fn encode_decode_roundtrip() {
        for svn in [1u32, 7, 31, 32, 33, 63, 64, 65, 127, 128] {
            assert_eq!(decode_svn(&encode_svn(svn)), svn);
        }
    }

    #[test]
    fn encode_svn_max_is_all_ones() {
        assert_eq!(encode_svn(CALIPTRA_SVN_BITS), [u32::MAX; 4]);
    }
}
