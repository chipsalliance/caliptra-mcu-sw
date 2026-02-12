/*++

Licensed under the Apache-2.0 license.

File Name:

    device_ownership_transfer.rs

Abstract:

    Handles Device Ownership Transfer (DOT) flows in the ROM.

--*/

use crate::fuses::OwnerPkHash;
use crate::otp::Otp;
use crate::{McuRomBootStatus, RomEnv};
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacResp, CmStableKeyType,
    CommandId, MailboxReqHeader,
};
use mcu_error::{McuError, McuResult};
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

    /// Load DOT fuses from OTP using the generated FuseEntryInfo constants.
    pub fn load_from_otp(otp: &Otp) -> McuResult<Self> {
        use registers_generated::fuses;

        // dot_initialized: LinearMajorityVote(1 bit, 3x) → logical 0 or 1
        let enabled = otp.read_entry(fuses::DOT_INITIALIZED)? != 0;

        // dot_fuse_array: OneHot(256 bits) → count of burned bits
        // This is a multi-word field; read raw and count ones
        let mut raw = [0u8; 32];
        otp.read_entry_raw(fuses::DOT_FUSE_ARRAY, &mut raw)?;
        let burned = raw.iter().map(|b| b.count_ones() as u16).sum::<u16>();

        // vendor_recovery_pk_hash: 48 bytes (384 bits), spans 2 OTP slots
        // Read first 32 bytes from slot 0, then 16 from slot 1
        let mut pk_buf = [0u8; 48];
        otp.read_entry_raw(fuses::VENDOR_RECOVERY_PK_HASH, &mut pk_buf[..32])?;
        // Second 16 bytes are in the next OTP slot
        let next_offset =
            fuses::VENDOR_RECOVERY_PK_HASH.byte_offset + fuses::VENDOR_RECOVERY_PK_HASH.byte_size;
        otp.read_otp_data(next_offset, &mut pk_buf[32..48])?;

        let recovery_pk_hash = if pk_buf.iter().all(|&b| b == 0) {
            None
        } else {
            let hash: [u32; 12] = zerocopy::transmute!(pk_buf);
            Some(RecoveryPkHash(hash))
        };

        Ok(DotFuses {
            enabled,
            burned,
            total: 256,
            recovery_pk_hash,
        })
    }
}

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

    let dot_owner = dot_determine_owner(env, dot_fuses, blob)?;

    romtime::println!("[mcu-rom] Device Ownership Transfer complete");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferComplete.into());

    // Return the owner determined by DOT flow if available, otherwise fall back to main fuses
    Ok(dot_owner.or_else(|| load_owner_pkhash(&env.otp)))
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
    // Construct the label as fixed label + 16-bit fuse value.
    // Per spec, EVEN state (unlocked) derives with (n+1) for next DOT_BLOB sealing,
    // while ODD state (locked) derives with (n) for current DOT_BLOB authentication.
    let derivation_value = if dot_fuses.is_unlocked() {
        dot_fuses.burned + 1
    } else {
        dot_fuses.burned
    };
    let mut info = [0u8; 32];
    const LABEL_LEN: usize = DOT_LABEL.len();
    info[..LABEL_LEN].copy_from_slice(DOT_LABEL);
    let fuse_slice: [u8; 2] = derivation_value.to_le_bytes();
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
/// - The current DOT_FUSE_ARRAY state (locked/disabled vs unlocked/uninitialized)
/// - The contents of the DOT blob (CAK presence)
///
/// The logic follows:
/// - ODD state with CAK (Locked): use CAK from DOT blob
/// - ODD state without CAK (Disabled): no owner (device boots without code auth)
/// - EVEN state (Uninitialized/Volatile): no owner from DOT (comes from Ownership_Storage)
/// - DOT not enabled: no owner from DOT
///
/// # Arguments
/// * `_env` - Mutable reference to the ROM environment.
/// * `dot_fuses` - DOT fuse state.
/// * `blob` - DOT blob containing CAK and other ownership data.
///
/// # Returns
/// * `Ok(Option<OwnerPkHash>)` - The determined owner's public key hash.
/// * `Err(McuError)` - If owner determination fails.
fn dot_determine_owner(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    blob: &DotBlob,
) -> McuResult<Option<OwnerPkHash>> {
    romtime::println!("[mcu-rom-dot] Determining device owner");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipDetermineOwner.into());

    if !dot_fuses.enabled {
        romtime::println!("[mcu-rom-dot] DOT not enabled, no owner from DOT");
        return Ok(None);
    }

    if dot_fuses.is_locked() {
        // Device is in ODD state (Locked or Disabled)
        if let Some(cak) = blob.cak() {
            // Locked state: CAK present in DOT blob
            romtime::println!("[mcu-rom-dot] Device locked, using CAK from DOT blob");
            Ok(Some(cak.clone()))
        } else {
            // Disabled state: ODD with no CAK means ownership is locked but no code
            // authentication is enforced. The owner retains control via LAK.
            romtime::println!("[mcu-rom-dot] Device in Disabled state (ODD, no CAK)");
            Ok(None)
        }
    } else {
        // Device is in EVEN state (Uninitialized/Volatile).
        // In EVEN state, ownership comes from Ownership_Storage (volatile), not from
        // DOT_BLOB. The DOT_BLOB in EVEN state is only used for verification/sealing
        // purposes during state transitions, not for determining the current owner.
        romtime::println!("[mcu-rom-dot] Device in EVEN state, no persistent owner from DOT");
        Ok(None)
    }
}

/// Burns DOT fuses to complete a pending state transition.
///
/// This function is called when a state change is needed based on the current
/// fuses and DOT blob. It determines if a transition is needed and burns the
/// appropriate fuse bits to advance the DOT state machine.
///
/// Fuse burning operations:
/// - Lock transition: burn the LSB of the fuse array to transition to locked state
/// - Unlock transition: burn additional fuses based on unlock method and challenges
/// - Disable transition: burn fuses to permanently disable DOT
///
/// Fuse burning is a one-time operation per bit and cannot be reversed.
/// This function should only be called after all preconditions are validated.
///
/// # Arguments
/// * `env` - Mutable reference to the ROM environment.
/// * `dot_fuses` - Current DOT fuse state.
/// * `blob` - DOT blob containing transition requirements.
///
/// # Returns
/// * `Ok(())` - If fuse burning succeeds or no transition is needed.
/// * `Err(McuError)` - If fuse burning fails.
fn burn_dot_fuses(env: &mut RomEnv, dot_fuses: &DotFuses, blob: &DotBlob) -> McuResult<()> {
    romtime::println!("[mcu-rom-dot] Checking for DOT fuse burn requirements");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipBurnFuses.into());

    if !dot_fuses.enabled {
        romtime::println!("[mcu-rom-dot] DOT not enabled, no fuse burning needed");
        return Ok(());
    }

    // Determine if we need to transition states based on blob contents and current state.
    // TODO: This transition should be gated by Ownership_Storage desired state, not just
    // blob contents. Per spec, RT issues DOT_LOCK/DOT_DISABLE which writes the desired
    // DOT_FUSE_ARRAY state to Ownership_Storage. ROM should read that desired state on
    // reboot and only burn fuses if a transition is pending. Ownership_Storage registers
    // are not yet available in ROM, so this check is deferred.
    let needs_lock_transition =
        dot_fuses.is_unlocked() && blob.cak().is_some() && blob.lak().is_some();

    if needs_lock_transition {
        romtime::println!("[mcu-rom-dot] DOT state transition needed: unlocked -> locked");

        burn_dot_lock_fuse(env, dot_fuses)?;

        romtime::println!("[mcu-rom-dot] DOT lock fuse burned successfully");
        romtime::println!("[mcu-rom-dot] Transition to locked state complete");
    } else {
        romtime::println!("[mcu-rom-dot] No DOT state transition required");
    }

    Ok(())
}

/// Burns the next DOT fuse bit to advance the DOT_FUSE_ARRAY counter.
///
/// This function uses the OTP DAI interface to write to the vendor non-secret
/// production partition. The fuse array uses 1 bit per state change, and the
/// next unburned bit is determined by the current burned count.
///
/// # Arguments
/// * `env` - ROM environment containing OTP controller access.
/// * `dot_fuses` - Current DOT fuse state (used to determine which bit to burn next).
///
/// # Returns
/// * `Ok(())` - If the fuse was successfully burned.
/// * `Err(McuError)` - If the OTP write operation fails.
fn burn_dot_lock_fuse(env: &RomEnv, dot_fuses: &DotFuses) -> McuResult<()> {
    use registers_generated::fuses;
    // Each state transition burns the next sequential bit in the dot_fuse_array.
    let next_bit = dot_fuses.burned as u32;
    if next_bit >= (dot_fuses.total as u32) {
        romtime::println!("[mcu-rom-dot] No more DOT fuse bits available");
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    // Calculate which word and bit within that word to burn.
    let word_index = next_bit / 32;
    let bit_in_word = next_bit % 32;

    let fuse_array_word_addr = (fuses::DOT_FUSE_ARRAY.byte_offset / 4) + word_index as usize;

    // Read the current value at this word address.
    let current_value = env.otp.read_word(fuse_array_word_addr)?;

    let new_value = current_value | (1u32 << bit_in_word);

    romtime::println!(
        "[mcu-rom-dot] Burning DOT lock fuse at word addr {:#x}, value {:#x} -> {:#x}",
        fuse_array_word_addr,
        current_value,
        new_value
    );

    env.otp.write_word(fuse_array_word_addr, new_value)?;

    Ok(())
}
