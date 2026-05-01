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
use romtime::McuRomBootStatus;
use zerocopy::transmute;

// TODO: Add the HEK personalization seed fuse to the fuse map and read this
// value from OTP instead of using a ROM-local placeholder.
const STABLE_OWNER_KEY_PERSONALIZATION_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

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
    let req = CmDeriveStableKeyReq {
        info: STABLE_OWNER_KEY_PERSONALIZATION_SEED,
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
