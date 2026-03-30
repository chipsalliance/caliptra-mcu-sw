/*++

Licensed under the Apache-2.0 license.

File Name:

    device_ownership_transfer.rs

Abstract:

    Handles Device Ownership Transfer (DOT) flows in the ROM.

--*/

use crate::fuses::OwnerPkHash;
use crate::RomEnv;
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacResp, CmStableKeyType,
    CommandId,
};
use mcu_error::{McuError, McuResult};
use romtime::otp::Otp;
use romtime::McuRomBootStatus;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

const DOT_LABEL: &[u8; 23] = b"Caliptra DOT stable key";

/// Copy `src` into `dst` without pulling in a panic path.
///
/// `[u8]::copy_from_slice` contains a length-mismatch panic that the
/// compiler sometimes cannot optimise away.  This helper returns an
/// error instead, keeping the ROM binary provably panic-free.
fn copy_slice(dst: &mut [u8], src: &[u8]) -> McuResult<()> {
    if dst.len() != src.len() {
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    Ok(())
}

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
const ZERO_OWNER_PK_HASH: OwnerPkHash = OwnerPkHash([0u32; 12]);

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
/// Uses `start_mailbox_req_bytes` + `finish_mailbox_resp_bytes` to stream.
fn cm_derive_stable_key(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    key_type: CmStableKeyType,
) -> McuResult<DotEffectiveKey> {
    use caliptra_api::mailbox::CMK_SIZE_BYTES;

    // Construct the label as fixed label + 16-bit fuse value.
    // Per spec, EVEN state (unlocked) derives with (n+1) for next DOT_BLOB sealing,
    // while ODD state (locked) derives with (n) for current DOT_BLOB authentication.
    let derivation_value = if dot_fuses.is_unlocked() {
        dot_fuses.burned + 1
    } else {
        dot_fuses.burned
    };
    let mut req = CmDeriveStableKeyReq {
        info: [0u8; 32],
        key_type: key_type.into(),
        ..Default::default()
    };
    const LABEL_LEN: usize = DOT_LABEL.len();
    copy_slice(&mut req.info[..LABEL_LEN], DOT_LABEL)?;
    let fuse_slice: [u8; 2] = derivation_value.to_le_bytes();
    req.info[LABEL_LEN] = fuse_slice[0];
    req.info[LABEL_LEN + 1] = fuse_slice[1];

    let cmd: u32 = CommandId::CM_DERIVE_STABLE_KEY.into();
    let chksum = caliptra_api::calc_checksum(cmd, &req.as_bytes()[4..]);
    req.hdr.chksum = chksum;

    if let Err(err) = env.soc_manager.start_mailbox_req_bytes(cmd, req.as_bytes()) {
        romtime::println!("[mcu-rom] Error deriving DOT stable key: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    // CmDeriveStableKeyResp = hdr(8) + cmk(128) = 136 bytes
    let mut resp_buf = [0u8; core::mem::size_of::<CmDeriveStableKeyResp>()];
    if let Err(err) = env.soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!("[mcu-rom] Error deriving DOT stable key: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    // Extract CMK (128 bytes = 32 u32 words) from response after the 8-byte header.
    let cmk_bytes: [u8; CMK_SIZE_BYTES] = match resp_buf.get(8..8 + CMK_SIZE_BYTES) {
        Some(src) => match src.try_into() {
            Ok(arr) => arr,
            Err(_) => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
        },
        None => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
    };
    Ok(DotEffectiveKey(Cmk(zerocopy::transmute!(cmk_bytes))))
}

/// Calls Caliptra to compute an HMAC.  Builds the request in a flat byte
/// buffer and sends it via `start_mailbox_req_bytes`, matching the proven
/// pattern used by `cm_derive_stable_key` and `cm_import_aes_key`.
///
/// The data length must not exceed [`CM_HMAC_MAX_DATA`] bytes.
fn cm_hmac(env: &mut RomEnv, key: &Cmk, data: &[u8]) -> McuResult<[u32; 16]> {
    use caliptra_api::mailbox::CMK_SIZE_BYTES;

    // Maximum data payload supported by this helper.  Sized to fit DOT blob
    // contents (104 bytes) with generous headroom.
    const CM_HMAC_MAX_DATA: usize = 256;

    if data.len() > CM_HMAC_MAX_DATA {
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    let cmd: u32 = CommandId::CM_HMAC.into();
    let hash_algorithm: u32 = CmHashAlgorithm::Sha512.into();
    let data_size: u32 = data.len() as u32;

    // Build the flat request buffer:
    //   [chksum:4] [cmk:128] [hash_algorithm:4] [data_size:4] [data:N]
    const HDR: usize = 4; // MailboxReqHeader (chksum only)
    let req_len = HDR + CMK_SIZE_BYTES + 4 + 4 + data.len();
    // Fixed buffer large enough for the maximum request size.
    let mut buf = [0u8; HDR + CMK_SIZE_BYTES + 4 + 4 + CM_HMAC_MAX_DATA];

    let mut off = HDR; // skip chksum; will fill it after payload
                       // cmk – serialise each u32 word in native byte order (matches write_data)
    for &w in key.0.iter() {
        if let Some(dst) = buf.get_mut(off..off + 4) {
            copy_slice(dst, &w.to_ne_bytes())?;
        }
        off += 4;
    }
    // hash_algorithm (LE)
    if let Some(dst) = buf.get_mut(off..off + 4) {
        copy_slice(dst, &hash_algorithm.to_le_bytes())?;
    }
    off += 4;
    // data_size (LE)
    if let Some(dst) = buf.get_mut(off..off + 4) {
        copy_slice(dst, &data_size.to_le_bytes())?;
    }
    off += 4;
    // data
    if let Some(dst) = buf.get_mut(off..off + data.len()) {
        copy_slice(dst, data)?;
    }

    // Compute and store checksum over payload bytes (everything after chksum).
    let chksum = caliptra_api::calc_checksum(
        cmd,
        match buf.get(HDR..req_len) {
            Some(b) => b,
            None => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
        },
    );
    if let Some(dst) = buf.get_mut(0..4) {
        copy_slice(dst, &chksum.to_le_bytes())?;
    }

    // Send the request using the same API as cm_derive_stable_key.
    let req_bytes = match buf.get(..req_len) {
        Some(b) => b,
        None => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
    };
    if let Err(err) = env.soc_manager.start_mailbox_req_bytes(cmd, req_bytes) {
        romtime::println!("[mcu-rom] Error computing HMAC: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    // Read response – CmHmacResp is MailboxRespHeaderVarSize(12) + mac(64) = 76 bytes.
    let mut resp_buf = [0u8; core::mem::size_of::<CmHmacResp>()];
    if let Err(err) = env.soc_manager.finish_mailbox_resp_bytes(&mut resp_buf) {
        romtime::println!("[mcu-rom] Error computing HMAC: {:?}", err);
        return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
    }

    // Extract the 64-byte MAC starting after the var-size header (12 bytes).
    let mac_bytes: [u8; 64] = match resp_buf.get(12..76) {
        Some(b) => match b.try_into() {
            Ok(arr) => arr,
            Err(_) => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
        },
        None => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
    };
    Ok(zerocopy::transmute!(mac_bytes))
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

        burn_dot_lock_fuse(&env.otp, dot_fuses)?;

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
/// * `otp` - OTP controller for fuse read/write access.
/// * `dot_fuses` - Current DOT fuse state (used to determine which bit to burn next).
///
/// # Returns
/// * `Ok(())` - If the fuse was successfully burned.
/// * `Err(McuError)` - If the OTP write operation fails.
fn burn_dot_lock_fuse(otp: &Otp, dot_fuses: &DotFuses) -> McuResult<()> {
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
    let current_value = otp.read_word(fuse_array_word_addr)?;

    let new_value = current_value | (1u32 << bit_in_word);

    romtime::println!(
        "[mcu-rom-dot] Burning DOT lock fuse at word addr {:#x}, value {:#x} -> {:#x}",
        fuse_array_word_addr,
        current_value,
        new_value
    );

    otp.write_word(fuse_array_word_addr, new_value)?;

    Ok(())
}

/// Writes a recovery DOT blob to flash when DOT is enabled but the existing
/// blob is blank or corrupted.  The recovery blob uses a zeroed CAK (no owner)
/// and zeroed LAK, sealed with the current DOT effective key so that the
/// device can proceed through the normal DOT flow on next boot and recover
/// via a DOT recovery operation.
pub fn write_recovery_dot_blob(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    dot_flash: Option<&dyn crate::flash::hil::FlashStorage>,
) -> McuResult<()> {
    romtime::println!("[mcu-rom-dot] Writing recovery DOT blob for blank/corrupt flash");
    create_and_seal_dot_blob(
        env,
        dot_fuses,
        &ZERO_OWNER_PK_HASH,
        &LakPkHash([0u32; 12]),
        dot_flash,
    )
}

/// Creates, HMAC-seals, and writes a DOT blob to flash storage.
///
/// This is used by manifest DOT commands (LOCK, DISABLE, ROTATE) to persist
/// ownership credentials alongside the fuse burn.
fn create_and_seal_dot_blob(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    cak: &OwnerPkHash,
    lak: &LakPkHash,
    dot_flash: Option<&dyn crate::flash::hil::FlashStorage>,
) -> McuResult<()> {
    use caliptra_api::mailbox::CmStableKeyType;

    // Derive the effective key for the target (post-burn) state.
    let dot_effective_key = derive_stable_key_flow(env, dot_fuses, CmStableKeyType::IDevId)?;

    // Build the blob payload (everything except the HMAC tag).
    let mut blob = DotBlob {
        version: 1,
        cak: cak.clone(),
        lak_pub: lak.clone(),
        unlock_method: CHALLENGE_RESPONSE,
        reserved: [0u8; 3],
        hmac: [0u32; 16],
    };

    // Compute HMAC over the blob contents (excluding the hmac field itself).
    let blob_bytes = blob.as_bytes();
    let hmac_len = blob_bytes.len() - core::mem::size_of_val(&blob.hmac);
    let hmac_data = match blob_bytes.get(..hmac_len) {
        Some(d) => d,
        None => return Err(McuError::ROM_COLD_BOOT_DOT_ERROR),
    };
    let hmac_tag = cm_hmac(env, &dot_effective_key.0, hmac_data)?;
    blob.hmac = hmac_tag;

    // Write the sealed DOT blob to flash.
    if let Some(flash) = dot_flash {
        if let Err(err) = flash.write(blob.as_bytes(), 0) {
            romtime::println!(
                "[mcu-rom-dot] Failed to write DOT blob to flash: {}",
                romtime::HexWord(usize::from(err) as u32)
            );
            return Err(McuError::ROM_COLD_BOOT_DOT_ERROR);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Firmware manifest DOT command section
// ---------------------------------------------------------------------------

/// Magic number identifying a firmware manifest DOT command section.
pub const FW_MANIFEST_DOT_MAGIC: u32 = 0x444F_5443; // "DOTC"

/// Maximum number of DOT commands in a single manifest section.
pub const MAX_FW_MANIFEST_DOT_COMMANDS: usize = 8;

// DOT command codes used inside [`FwManifestDotSection::commands`].
/// No-operation / padding.
pub const FW_MANIFEST_DOT_CMD_NOP: u8 = 0;
/// Lock: transition from unlocked (EVEN) to locked (ODD).
pub const FW_MANIFEST_DOT_CMD_LOCK: u8 = 1;
/// Unlock: transition from locked (ODD) to unlocked (EVEN).
pub const FW_MANIFEST_DOT_CMD_UNLOCK: u8 = 2;
/// Rotate: burn two fuses to advance the DOT effective key while
/// preserving the current lock/unlock parity.  Uses `min_fuse_count`
/// for idempotency – the rotation is only applied when the current
/// burned count is below `min_fuse_count`.
pub const FW_MANIFEST_DOT_CMD_ROTATE: u8 = 3;
/// Disable: ensure the device is in ODD (locked/disabled) state.
/// Functionally identical to LOCK at the fuse level; the DOT blob
/// determines whether the ODD state means "locked" (CAK present) or
/// "disabled" (no CAK).
pub const FW_MANIFEST_DOT_CMD_DISABLE: u8 = 4;

/// Optional section that can be prepended to the MCU firmware image
/// to request DOT state transitions during firmware updates.
///
/// The ROM always checks the start of MCU SRAM for the magic number.
/// If the magic does not match, the section is silently ignored and
/// no DOT commands are executed.  When present, the actual firmware
/// follows immediately after this section.
///
/// All commands are **idempotent**: a command that does not apply to the
/// current DOT fuse state is skipped without error.
///
/// Size: 128 bytes (naturally aligned, 4 bytes reserved padding).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FwManifestDotSection {
    /// Must be [`FW_MANIFEST_DOT_MAGIC`] for the section to be recognised.
    pub magic: u32,
    /// Ones-complement checksum of all bytes after this field.
    /// Computed as `!sum_of_le_u32_words(bytes[8..])`.
    pub checksum: u32,
    /// Section format version (must be 1).
    pub version: u32,
    /// Number of valid entries in `commands` (≤ [`MAX_FW_MANIFEST_DOT_COMMANDS`]).
    pub num_commands: u32,
    /// For the ROTATE command: the minimum burned-fuse count after which
    /// rotation is considered already applied.  Ignored by other commands.
    pub min_fuse_count: u32,
    /// Up to [`MAX_FW_MANIFEST_DOT_COMMANDS`] command bytes, executed in order.
    pub commands: [u8; MAX_FW_MANIFEST_DOT_COMMANDS],
    /// Code Authentication Key (owner PK hash) for LOCK/ROTATE commands.
    /// Set to all zeros when not applicable.
    pub cak: [u32; 12],
    /// Lock Authentication Key (public hash) for LOCK/DISABLE commands.
    /// Set to all zeros when not applicable.
    pub lak: [u32; 12],
    /// Reserved padding (must be zero).
    pub _reserved: [u8; 4],
}

/// Size of [`FwManifestDotSection`] in bytes.
pub const FW_MANIFEST_DOT_SECTION_SIZE: usize = core::mem::size_of::<FwManifestDotSection>();

impl FwManifestDotSection {
    /// Verify the ones-complement checksum covering bytes 8..end of the section.
    pub fn verify_checksum(&self) -> bool {
        let bytes = self.as_bytes();
        // Sum all u32 words from offset 4 (checksum field itself + payload).
        // If the checksum is correct, the total including the checksum word
        // equals 0xFFFF_FFFF.
        let sum = bytes[4..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .fold(0u32, |acc, w| acc.wrapping_add(w));
        sum == 0xFFFF_FFFF
    }

    /// Compute the checksum for this section and return an updated copy.
    pub fn with_checksum(mut self) -> Self {
        self.checksum = 0;
        let bytes = self.as_bytes();
        let payload_sum = bytes[8..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .fold(0u32, |acc, w| acc.wrapping_add(w));
        self.checksum = !payload_sum;
        self
    }
}

/// Parses and executes DOT commands from an optional firmware manifest section.
///
/// Each command inspects the current DOT fuse state (re-read from OTP before
/// every command) and only acts when the requested transition is applicable.
/// This makes every command idempotent: re-running the same manifest after a
/// power cycle will not burn additional fuses.
///
/// For LOCK/DISABLE/ROTATE commands, the manifest carries the CAK (owner PK
/// hash) and LAK (locking key) which are written into the DOT blob alongside
/// the fuse burn.
///
/// # Arguments
/// * `env`     – ROM environment (OTP, SoC manager for Caliptra mailbox, etc.).
/// * `section` – The firmware manifest DOT section parsed from the image header.
/// * `dot_flash` – Optional DOT flash driver for writing the DOT blob.
///
/// # Returns
/// * `Ok(())` on success (including when all commands are no-ops).
/// * `Err(McuError)` on an unrecoverable error (unsupported version, OTP failure).
pub fn process_fw_manifest_dot_commands(
    env: &mut RomEnv,
    section: &FwManifestDotSection,
    dot_flash: Option<&dyn crate::flash::hil::FlashStorage>,
) -> McuResult<()> {
    if section.magic != FW_MANIFEST_DOT_MAGIC {
        // Not a DOT manifest section – silently skip.
        return Ok(());
    }

    if !section.verify_checksum() {
        romtime::println!("[mcu-rom-dot] Firmware manifest DOT checksum mismatch");
        return Err(McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR);
    }

    if section.version != 1 {
        romtime::println!(
            "[mcu-rom-dot] Unsupported fw manifest DOT version: {}",
            section.version
        );
        return Err(McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR);
    }

    romtime::println!("[mcu-rom-dot] Processing manifest DOT commands");

    let num_commands = section.num_commands as usize;
    if num_commands > MAX_FW_MANIFEST_DOT_COMMANDS {
        return Err(McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR);
    }

    // Reject manifests that contain both LOCK and UNLOCK commands.
    // Allowing both would rapidly burn through DOT fuses on every reset.
    let cmds = match section.commands.get(..num_commands) {
        Some(c) => c,
        None => return Err(McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR),
    };
    let has_lock = cmds
        .iter()
        .any(|&c| c == FW_MANIFEST_DOT_CMD_LOCK || c == FW_MANIFEST_DOT_CMD_DISABLE);
    let has_unlock = cmds.iter().any(|&c| c == FW_MANIFEST_DOT_CMD_UNLOCK);
    if has_lock && has_unlock {
        romtime::println!("[mcu-rom-dot] Fatal: both LOCK/DISABLE and UNLOCK present in manifest");
        return Err(McuError::ROM_COLD_BOOT_FW_MANIFEST_DOT_ERROR);
    }

    for &cmd in cmds {
        // Reload fuse state – a previous command may have changed it.
        let dot_fuses = DotFuses::load_from_otp(&env.otp)?;

        if !dot_fuses.enabled && cmd != FW_MANIFEST_DOT_CMD_NOP {
            return Ok(());
        }

        match cmd {
            FW_MANIFEST_DOT_CMD_NOP => {}

            FW_MANIFEST_DOT_CMD_LOCK => {
                // LOCK: transition EVEN → ODD, install CAK + LAK into DOT blob.
                if dot_fuses.is_unlocked() {
                    create_and_seal_dot_blob(
                        env,
                        &dot_fuses,
                        &OwnerPkHash(section.cak),
                        &LakPkHash(section.lak),
                        dot_flash,
                    )?;
                    burn_dot_lock_fuse(&env.otp, &dot_fuses)?;
                }
            }

            FW_MANIFEST_DOT_CMD_DISABLE => {
                // DISABLE: like LOCK but with zeroed CAK (no code auth).
                if dot_fuses.is_unlocked() {
                    create_and_seal_dot_blob(
                        env,
                        &dot_fuses,
                        &ZERO_OWNER_PK_HASH,
                        &LakPkHash(section.lak),
                        dot_flash,
                    )?;
                    burn_dot_lock_fuse(&env.otp, &dot_fuses)?;
                }
            }

            FW_MANIFEST_DOT_CMD_UNLOCK => {
                // UNLOCK: transition ODD → EVEN, write an unlock DOT blob.
                // A blank/missing DOT blob is a fatal error when DOT is
                // enabled, so we must always leave a valid sealed blob.
                if dot_fuses.is_locked() {
                    burn_dot_lock_fuse(&env.otp, &dot_fuses)?;
                    // Re-read fuse state after the burn (now EVEN = unlocked).
                    let new_fuses = DotFuses::load_from_otp(&env.otp)?;
                    // Write an unlock DOT blob: zero CAK (no owner), keep LAK.
                    create_and_seal_dot_blob(
                        env,
                        &new_fuses,
                        &ZERO_OWNER_PK_HASH,
                        &LakPkHash(section.lak),
                        dot_flash,
                    )?;
                }
            }

            FW_MANIFEST_DOT_CMD_ROTATE => {
                // ROTATE: burn 2 fuses, re-seal DOT blob with new effective key.
                if (dot_fuses.burned as u32) < section.min_fuse_count {
                    burn_dot_lock_fuse(&env.otp, &dot_fuses)?;
                    let new_fuses = DotFuses::load_from_otp(&env.otp)?;
                    burn_dot_lock_fuse(&env.otp, &new_fuses)?;
                    // Re-seal the DOT blob with the rotated effective key.
                    let rotated_fuses = DotFuses::load_from_otp(&env.otp)?;
                    create_and_seal_dot_blob(
                        env,
                        &rotated_fuses,
                        &OwnerPkHash(section.cak),
                        &LakPkHash(section.lak),
                        dot_flash,
                    )?;
                }
            }

            _ => {}
        }
    }

    romtime::println!("[mcu-rom-dot] Manifest DOT processing complete");
    Ok(())
}
