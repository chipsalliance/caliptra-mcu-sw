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
use romtime::otp::CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_SIZE;
use romtime::McuRomBootStatus;
use zerocopy::transmute;

// Provisional source until the stable owner key personalization seed fuse is assigned.
const STABLE_OWNER_KEY_PERSONALIZATION_SEED_FUSE_INDEX: usize = 15;

fn read_personalization_seed(
    env: &RomEnv,
) -> McuResult<[u8; CPTRA_SS_VENDOR_SPECIFIC_NON_SECRET_FUSE_SIZE]> {
    env.otp
        .read_cptra_ss_vendor_specific_non_secret_fuse(
            STABLE_OWNER_KEY_PERSONALIZATION_SEED_FUSE_INDEX,
        )
        .map_err(|_| McuError::ROM_COLD_BOOT_STABLE_OWNER_KEY_DERIVATION_ERROR)
}

pub(crate) fn derive_stable_owner_key(env: &mut RomEnv) -> McuResult<Cmk> {
    romtime::println!("[mcu-rom] Deriving stable owner key");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::HekOwnerKeyDerivationStarted.into());

    // TODO: Replace with CmStableKeyType::OwnerKey once caliptra-sw rev is bumped
    const CM_STABLE_KEY_TYPE_OWNER_KEY: u32 = 3;
    let owner_key_type = CmStableKeyType::from(CM_STABLE_KEY_TYPE_OWNER_KEY);
    if owner_key_type == CmStableKeyType::Reserved {
        romtime::println!(
            "[mcu-rom] Stable owner key type is not supported by this Caliptra Core rev"
        );
        return Err(McuError::ROM_COLD_BOOT_STABLE_OWNER_KEY_DERIVATION_ERROR);
    }

    let mut resp = [0u32; core::mem::size_of::<CmDeriveStableKeyResp>() / 4];
    let personalization_seed = read_personalization_seed(env)?;
    let req = CmDeriveStableKeyReq {
        info: personalization_seed,
        key_type: owner_key_type.into(),
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
        .set_flow_checkpoint(McuRomBootStatus::HekOwnerKeyDerivationComplete.into());
    Ok(cmk)
}
