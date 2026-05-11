/*++

Licensed under the Apache-2.0 license.

File Name:

    stable_owner_key.rs

Abstract:

    Stable owner key derivation helpers used during ROM cold boot.

--*/

use crate::{Cmk, RomEnv};
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmStableKeyType, CommandId,
};
use mcu_error::{McuError, McuResult};
use registers_generated::fuses;
use romtime::McuRomBootStatus;
use zerocopy::transmute;

const STABLE_OWNER_KEY_PERSONALIZATION_SEED_SIZE: usize = 32;

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
