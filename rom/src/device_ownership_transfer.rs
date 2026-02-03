/*++

Licensed under the Apache-2.0 license.

File Name:

    device_ownership_transfer.rs

Abstract:

    Handles Device Ownership Transfer (DOT) flows in the ROM.

--*/

use crate::fuses::OwnerPkHash;
use crate::{McuRomBootStatus, RomEnv};
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacResp, CmStableKeyType,
    CommandId, MailboxReqHeader,
};
use mcu_error::{McuError, McuResult};
use romtime::otp::Otp;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

const DOT_LABEL: &[u8] = b"Caliptra DOT stable key";

#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct LakPkHash(pub [u32; 12]);

pub trait OwnerPolicy {}

#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecoveryPkHash(pub [u32; 12]);

#[derive(Clone, Default)]
pub struct DotFuses {
    pub enabled: bool,
    pub burned: u16,
    pub total: u16,
    pub recovery_pk_hash: Option<RecoveryPkHash>,
}

impl DotFuses {
    pub fn is_locked(&self) -> bool {
        self.burned & 1 == 1
    }
    pub fn is_unlocked(&self) -> bool {
        self.burned & 1 == 0
    }
}

/// Loads the owner public key hash from OTP.
///
/// This retrieves the owner PK hash from the OTP fuses, a.k.a., the
/// Code Authentication Key (CAK). This hash is used to
/// verify the owner's identity during device authentication.
///
/// # Arguments
/// * `otp` - OTP driver
///
/// # Returns
/// * `Some(OwnerPkHash)` - The owner public key hash if successfully loaded.
/// * `None` - If the fuse data cannot be read or converted to the expected format.
pub fn load_owner_pkhash(otp: &Otp) -> Option<OwnerPkHash> {
    let hash: [u8; 48] = otp.read_cptra_ss_owner_pk_hash().ok()?;
    let hash: [u32; 12] = transmute!(hash);
    Some(OwnerPkHash(hash))
}

/// Caliptra Cryptographic Mailbox Key (CMK) handle.
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct Cmk(pub [u32; 32]);

/// DOT Effective Key derived from DOT_ROOT_KEY and DOT_FUSE_ARRAY state.
///
/// This key is used to authenticate DOT blobs via HMAC.
pub struct DotEffectiveKey(pub Cmk);

/// The DOT blob data structure containing ownership credentials and locking keys.
///
/// This cryptographically authenticated structure is stored in external flash
/// and contains the CAK and LAK, sealed with the DOT_EFFECTIVE_KEY via HMAC.
/// The blob persists ownership across power cycles when in the Locked state.
#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DotBlob {
    /// Version or format identifier for the DOT blob structure
    pub version: u32,

    /// Code Authentication Key (CAK) - Owner's public key for image verification.
    pub cak: OwnerPkHash,

    /// Lock Authentication Key (LAK) - Key used for lock/unlock/disable operations.
    pub lak_pub: LakPkHash,

    /// Unlock method metadata - indicates how the blob should be unlocked
    /// Used to generate challenge in DOT_UNLOCK_CHALLENGE
    pub unlock_method: UnlockMethod,

    /// Reserved for future use and padding.
    pub reserved: [u8; 3],

    /// HMAC tag authenticating the entire DOT blob
    /// Computed using DOT_EFFECTIVE_KEY.
    pub hmac: [u32; 16],
}

/// Specifies the method used for unlocking a locked DOT state.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct UnlockMethod(u8);

/// Standard challenge-response unlock method.
pub const CHALLENGE_RESPONSE: UnlockMethod = UnlockMethod(1);
// TODO: define the rest

impl DotBlob {
    /// Returns the Code Authentication Key (CAK) if present.
    pub fn cak(&self) -> Option<&OwnerPkHash> {
        if self.cak.0.iter().all(|&x| x == 0) {
            None
        } else {
            Some(&self.cak)
        }
    }

    /// Returns the Lock Authentication Key (LAK) public key if present.
    pub fn lak(&self) -> Option<&LakPkHash> {
        if self.lak_pub.0.iter().all(|&x| x == 0) {
            None
        } else {
            Some(&self.lak_pub)
        }
    }
}

/// Main Device Ownership Transfer flow executed during ROM boot.
///
/// This function orchestrates the DOT process, which includes:
/// 1. Deriving the DOT_EFFECTIVE_KEY from hardware secrets and fuse state
/// 2. Verifying the DOT blob authenticity using HMAC
/// 3. Burning DOT fuses if a state transition is pending
/// 4. Determining the final owner based on fuse state and DOT blob
///
/// # Arguments
/// * `env` - Mutable reference to the ROM environment containing hardware interfaces.
/// * `dot_fuses` - DOT fuse data.
/// * `blob` - DOT blob loaded from storage.
/// * `stable_key_type` - The type of stable key to derive to verify the DOT blob with.
///
/// # Returns
/// * `Ok(OwnerPkHash)` - The determined owner's public key hash on success.
/// * `Err(McuError)` - If any step of the DOT flow fails.
pub fn dot_flow(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    blob: &DotBlob,
    stable_key_type: CmStableKeyType,
) -> McuResult<Option<OwnerPkHash>> {
    romtime::println!("[mcu-rom-dot] Performing Device Ownership Transfer flow");
    romtime::println!(
        "[mcu-rom-dot] DOT raw blob: {}",
        romtime::HexBytes(blob.as_bytes())
    );
    romtime::println!("[mcu-rom-dot] {:x?}", blob);
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferStarted.into());

    let dot_effective_key = derive_stable_key_flow(env, dot_fuses, stable_key_type)?;

    verify_dot_blob(env, blob, &dot_effective_key)?;

    burn_dot_fuses(env, dot_fuses, blob)?;

    let _owner = dot_determine_owner(env, dot_fuses, blob)?;

    romtime::println!("[mcu-rom] Device Ownership Transfer complete");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferComplete.into());

    // TODO: incorporate this into the DOT flow
    Ok(load_owner_pkhash(&env.otp))
}

/// Derives the DOT Effective Key using Caliptra's stable key derivation mailbox command.
///
/// The DOT_EFFECTIVE_KEY is derived from the Caliptra stable key (which is unique
/// to the device) and the DOT_FUSE_ARRAY state. This key is used to authenticate
/// DOT blobs via HMAC.
///
/// # Arguments
/// * `env` - environment.
/// * `dot_fuses` - DOT fuse state.
/// * `key_type` - The type of stable key to derive to verify the DOT blob with.
///
/// # Returns
/// * `Ok(DotEffectiveKey)` - The derived effective key handle (CMK) on success.
/// * `Err(McuError)` - If key derivation fails.
pub fn derive_stable_key_flow(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    key_type: CmStableKeyType,
) -> McuResult<DotEffectiveKey> {
    romtime::println!("[mcu-rom] Deriving DOT stable key");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipDeriveStableKey.into());
    let dot_effective_key = cm_derive_stable_key(env, dot_fuses, key_type)?;
    romtime::println!("[mcu-rom] DOT stable key derived successfully");
    Ok(dot_effective_key)
}

/// Calls Caliptra to derive the DOT Effective Key using the stable key derivation command.
fn cm_derive_stable_key(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    key_type: CmStableKeyType,
) -> McuResult<DotEffectiveKey> {
    // construct the label as fixed label + 16-bit fuse value
    let mut info = [0u8; 32];
    const LABEL_LEN: usize = DOT_LABEL.len();
    info[..LABEL_LEN].copy_from_slice(DOT_LABEL);
    let fuse_slice: [u8; 2] = dot_fuses.burned.to_le_bytes();
    // copy_from_slice wants to insert a panic for some reason
    info[LABEL_LEN] = fuse_slice[0];
    info[LABEL_LEN + 1] = fuse_slice[1];

    let mut resp = [0u32; core::mem::size_of::<CmDeriveStableKeyResp>() / 4];
    let req = CmDeriveStableKeyReq {
        info,
        key_type: key_type.into(),
        ..Default::default()
    };
    let mut req32: [u32; core::mem::size_of::<CmDeriveStableKeyReq>() / 4] = transmute!(req);

    if let Err(err) = env.soc_manager.exec_mailbox_req_u32(
        CommandId::CM_DERIVE_STABLE_KEY.into(),
        &mut req32,
        &mut resp,
    ) {
        romtime::println!("[mcu-rom] Error deriving DOT stable key: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }
    let resp: CmDeriveStableKeyResp = transmute!(resp);
    let dot_effective_key = DotEffectiveKey(Cmk(transmute!(resp.cmk)));
    Ok(dot_effective_key)
}

// CM_HMAC copy with smaller data
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub hash_algorithm: u32,
    pub data_size: u32,
    pub data: [u8; core::mem::size_of::<DotBlob>()],
}

impl Default for CmHmacReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            hash_algorithm: 0,
            data_size: 0,
            data: [0u8; core::mem::size_of::<DotBlob>()],
        }
    }
}

/// Calls Caliptra to compute an HMAC.
fn cm_hmac(env: &mut RomEnv, key: &Cmk, data: &[u8]) -> McuResult<[u32; 16]> {
    let mut resp = [0u32; core::mem::size_of::<CmHmacResp>() / 4];
    let mut req = CmHmacReq {
        cmk: transmute!(key.0),
        hash_algorithm: CmHashAlgorithm::Sha512.into(),
        data_size: data.len() as u32,
        ..Default::default()
    };
    let len = data.len();
    if len > req.data.len() {
        romtime::println!(
            "[mcu-rom-dot] Cannot HMAC more than {} bytes",
            req.data.len()
        );
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }
    // should be impossible for this slice to fail but the compiler seems to generate a panic
    req.data
        .get_mut(..len)
        .ok_or(McuError::ROM_COLD_BOOT_DOT_ERROR)?
        .copy_from_slice(&data[..len]);

    let mut req: [u32; core::mem::size_of::<CmHmacReq>() / 4] = transmute!(req);

    if let Err(err) =
        env.soc_manager
            .exec_mailbox_req_u32(CommandId::CM_HMAC.into(), &mut req, &mut resp)
    {
        romtime::println!("[mcu-rom] Error computing HMAC: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }
    let resp: CmHmacResp = transmute!(resp);
    Ok(transmute!(resp.mac))
}

/// Verifies the authenticity of a DOT blob using HMAC.
///
/// This function authenticates the DOT blob by computing an HMAC over its
/// contents using the DOT_EFFECTIVE_KEY and comparing it to the stored HMAC tag.
/// This ensures the blob has not been tampered with and is bound to this specific
/// device and fuse state.
///
/// # Arguments
/// * `env` - ROM environment.
/// * `blob` - DOT blob to verify
/// * `key` - The DOT_EFFECTIVE_KEY to use for HMAC verification.
///
/// # Returns
/// * `Ok(())` - If the DOT blob is authentic.
/// * `Err(McuError)` - If HMAC verification fails (blob is corrupted or invalid).
pub fn verify_dot_blob(env: &mut RomEnv, blob: &DotBlob, key: &DotEffectiveKey) -> McuResult<()> {
    let blob_data = blob.as_bytes();
    // compute the HMAC over everything except the HMAC itself
    let blob_data = &blob_data[..blob_data.len() - (blob.hmac.len() * 4)];
    let verify = cm_hmac(env, &key.0, blob_data)?;
    if !constant_time_eq::constant_time_eq(verify.as_bytes(), blob.hmac.as_bytes()) {
        romtime::println!("[mcu-rom] DOT blob HMAC did not match");
        return Err(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR);
    }
    Ok(())
}

/// Determines the owner based on DOT state and fuse contents.
///
/// This function decides which owner public key hash to use based on:
/// - The current DOT_FUSE_ARRAY state
/// - The contents of the DOT blob
/// - The owner public key hash stored in fuses
///
/// # Arguments
/// * `_env` - Mutable reference to the ROM environment.
/// * `_dot_fuses` - DOT fuse state.
/// * `_blob` - DOT blob
///
/// # Returns
/// * `Ok(OwnerPkHash)` - The determined owner's public key hash.
/// * `Err(McuError)` - If owner determination fails.
fn dot_determine_owner(
    _env: &mut RomEnv,
    _dot_fuses: &DotFuses,
    _blob: &DotBlob,
) -> McuResult<Option<OwnerPkHash>> {
    // TODO: implement
    Ok(None)
}

/// Burns DOT fuses to complete a pending state transition.
///
/// This function is called when a state change is needed based on the current
/// fuses and DOT blob.
///
/// Fuse burning is a one-time operation per bit and cannot be reversed.
/// This function should only be called after all preconditions are validated.
///
/// # Arguments
/// * `env` - Mutable reference to the ROM environment.
/// * `dot_fuses` - Current DOT fuse state.
/// * `blob` - DOT blob.
///
/// # Returns
/// * `Ok(())` - If fuse burning succeeds or no transition is needed.
/// * `Err(McuError)` - If fuse burning fails.
fn burn_dot_fuses(_env: &mut RomEnv, _fuses: &DotFuses, _blob: &DotBlob) -> McuResult<()> {
    // TOOD: implement
    Ok(())
}
