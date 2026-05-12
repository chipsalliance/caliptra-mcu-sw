/*++

Licensed under the Apache-2.0 license.

File Name:

    stable_owner_key.rs

Abstract:

    Stable owner key derivation helpers used during ROM cold boot.

--*/

use crate::{fatal_error, Cmk, RomEnv};
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmStableKeyType, CommandId,
};
use mcu_error::{McuError, McuResult};
use registers_generated::{fuses, soc};
use romtime::otp::{Otp, HEK_OFFSETS, HEK_SEED_SIZE, HEK_ZER_MARKER_OFFSET};
use romtime::{McuRomBootStatus, StaticRef};
use tock_registers::interfaces::{Readable, Writeable};
use zerocopy::transmute;

const STABLE_OWNER_KEY_PERSONALIZATION_SEED_SIZE: usize = 32;
const STABLE_OWNER_KEY_STRAP_INDEX: usize = 3;
const STABLE_OWNER_KEY_STRAP_MASK: u32 = 1;
const STABLE_OWNER_KEY_OTP_DIGEST_IV: u64 = 0x90C7F21F6224F027u64;
const STABLE_OWNER_KEY_OTP_DIGEST_CONST: u128 = 0xF98C48B1F93772844A22D4B78FE0266Fu128;

pub(crate) fn enable_owner_key_strap(registers: StaticRef<soc::regs::Soc>) {
    // Caliptra ROM gates owner stable key availability on SS_STRAP_GENERIC[3] bit 0.
    let strap = registers.ss_strap_generic[STABLE_OWNER_KEY_STRAP_INDEX].get();
    registers.ss_strap_generic[STABLE_OWNER_KEY_STRAP_INDEX]
        .set(strap | STABLE_OWNER_KEY_STRAP_MASK);
}

fn write_hek_seed(registers: StaticRef<soc::regs::Soc>, seed: &[u8]) {
    for (reg, word) in
        registers
            .fuse_hek_seed
            .iter()
            .zip(seed.chunks_exact(core::mem::size_of::<u32>()).map(|w| {
                u32::from_le_bytes(
                    w.try_into()
                        .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_WRITE_WORD_ERROR)),
                )
            }))
    {
        reg.set(word);
    }
}

fn fill_hek_seed(registers: StaticRef<soc::regs::Soc>, value: u32) {
    for word in registers.fuse_hek_seed.iter() {
        word.set(value);
    }
}

pub(crate) fn set_hek_fuses(registers: StaticRef<soc::regs::Soc>, otp: &Otp) {
    romtime::println!("[mcu-fuse-write] Attempting to write stable owner key HEK fuses");

    let mut seed = [0u8; 48];
    for slot in 0..HEK_OFFSETS.len() {
        otp.read_hek_seed(slot, &mut seed)
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));

        if seed.iter().all(|&byte| byte == 0) || seed.iter().all(|&byte| byte == 0xFF) {
            continue;
        }

        let byte_offset = *HEK_OFFSETS
            .get(slot)
            .unwrap_or_else(|| fatal_error(McuError::ROM_OTP_INVALID_DATA_ERROR));
        let partition = fuses::OtpPartitionInfo {
            name: "cptra_ss_lock_hek_prod_seed",
            byte_offset,
            byte_size: HEK_ZER_MARKER_OFFSET,
            sw_digest: true,
            hw_digest: false,
            digest_offset: Some(byte_offset + HEK_SEED_SIZE),
        };
        let expected_digest = u64::from_le_bytes(
            seed[HEK_SEED_SIZE..HEK_ZER_MARKER_OFFSET]
                .try_into()
                .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_INVALID_DATA_ERROR)),
        );
        let computed_digest = otp
            .compute_sw_digest(
                &partition,
                STABLE_OWNER_KEY_OTP_DIGEST_IV,
                STABLE_OWNER_KEY_OTP_DIGEST_CONST,
            )
            .unwrap_or_else(|_| fatal_error(McuError::ROM_OTP_READ_ERROR));

        if computed_digest == expected_digest {
            write_hek_seed(registers, &seed[..HEK_SEED_SIZE]);
            romtime::println!(
                "[mcu-fuse-write] Finished writing stable owner key HEK fuse slot {}",
                slot
            );
            return;
        }

        romtime::println!(
            "[mcu-fuse-write] HEK software digest mismatch! Slot {}",
            slot
        );
    }

    fill_hek_seed(registers, 0);
    romtime::println!("[mcu-fuse-write] No valid stable owner key HEK fuse slot found");
}

fn read_personalization_seed(
    env: &RomEnv,
) -> McuResult<[u8; STABLE_OWNER_KEY_PERSONALIZATION_SEED_SIZE]> {
    let mut seed = [0u8; STABLE_OWNER_KEY_PERSONALIZATION_SEED_SIZE];
    if fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED.byte_size != seed.len() {
        return Err(McuError::ROM_COLD_BOOT_STABLE_OWNER_KEY_DERIVATION_ERROR);
    }
    env.otp
        .read_entry_raw(fuses::STABLE_OWNER_KEY_PERSONALIZATION_SEED, &mut seed)
        .map_err(|_| McuError::ROM_COLD_BOOT_STABLE_OWNER_KEY_DERIVATION_ERROR)?;
    Ok(seed)
}

pub(crate) fn derive_stable_owner_key(env: &mut RomEnv) -> McuResult<Cmk> {
    romtime::println!("[mcu-rom] Deriving stable owner key");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::StableOwnerKeyDerivationStarted.into());

    let mut resp = [0u32; core::mem::size_of::<CmDeriveStableKeyResp>() / 4];
    let personalization_seed = read_personalization_seed(env)?;
    let req = CmDeriveStableKeyReq {
        info: personalization_seed,
        key_type: CmStableKeyType::OwnerKey.into(),
        ..Default::default()
    };
    let mut req32: [u32; core::mem::size_of::<CmDeriveStableKeyReq>() / 4] = transmute!(req);

    if let Err(err) = env.soc_manager.exec_mailbox_req_u32(
        CommandId::CM_DERIVE_STABLE_KEY.into(),
        &mut req32,
        &mut resp,
    ) {
        romtime::println!("[mcu-rom] Error deriving stable owner key: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_STABLE_OWNER_KEY_DERIVATION_ERROR);
    }

    let resp: CmDeriveStableKeyResp = transmute!(resp);
    let cmk = Cmk(transmute!(resp.cmk));

    romtime::println!("[mcu-rom] Stable owner key derived successfully");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::StableOwnerKeyDerivationComplete.into());
    Ok(cmk)
}
