/*++

Licensed under the Apache-2.0 license.

File Name:

    device_ownership_transfer.rs

Abstract:

    Handles Device Ownership Transfer (DOT) flows in the ROM.

--*/

use crate::fuses::OwnerPkHash;
use crate::hil::FlashStorage;
use crate::RomEnv;
use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmHashAlgorithm, CmHmacResp, CmShaReqHdr,
    CmShaResp, CmStableKeyType, CommandId, EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader,
};
#[cfg(all(not(test), feature = "cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_mcu_error::{McuError, McuResult};
use caliptra_mcu_romtime::otp::Otp;
use caliptra_mcu_romtime::{HexWord, McuRomBootStatus};
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

const DOT_LABEL: &[u8; 23] = b"Caliptra DOT stable key";
pub const DOT_BLOB_SIZE: usize = core::mem::size_of::<DotBlob>();

#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct LakPkHash(pub [u32; 12]);

pub trait OwnerPolicy {}

#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RecoveryPkHash(pub [u32; 12]);

/// Convert a 48-byte recovery PK hash payload read from OTP into a
/// [`RecoveryPkHash`] by reversing the bytes within each 4-byte word.
///
/// The vendor recovery PK hash fuse uses the same on-OTP layout as
/// caliptra-sw's `cptra_ss_owner_pk_hash` and debug-unlock vendor PK hash
/// fuses: each 4-byte word is stored byte-reversed relative to the natural
/// (FIPS-standard) SHA-384 byte order. After reversing within each word,
/// `transmute!(recovery_pk_hash.0)` yields the SHA-384 digest bytes in
/// natural order, so it can be compared directly against the output of
/// Caliptra's CM_SHA / SHA-384 mailbox command.
///
/// Aligning these three fuses on a single layout means an integrator can
/// burn the same 48-byte value into any of them (e.g., for testing or for
/// a shared trust anchor) without having to track per-fuse byte-order
/// quirks.
fn recovery_pk_hash_from_otp_bytes(mut bytes: [u8; 48]) -> RecoveryPkHash {
    for chunk in bytes.chunks_exact_mut(4) {
        chunk.reverse();
    }
    let hash: [u32; 12] = zerocopy::transmute!(bytes);
    RecoveryPkHash(hash)
}

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
        use caliptra_mcu_registers_generated::fuses;

        // dot_initialized: LinearOr(1 bit, 3x) → logical 0 or 1
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
            Some(recovery_pk_hash_from_otp_bytes(pk_buf))
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
    /// DOT blob data protected by the hmac
    pub fields: DotBlobFields,
    /// HMAC tag authenticating the entire DOT blob
    /// Computed using DOT_EFFECTIVE_KEY.
    pub hmac: [u32; 16],
}

#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DotBlobFields {
    /// Version or format identifier for the DOT blob structure
    pub version: u32,

    /// Code Authentication Key (CAK) - Owner's public key for image verification.
    pub cak: OwnerPkHash,

    /// Lock Authentication Key (LAK) - Key used for lock/unlock/disable operations.
    pub lak_pub: LakPkHash,

    /// Unlock method metadata - indicates how the blob should be unlocked
    /// Used to generate challenge in DOT_UNLOCK_CHALLENGE
    pub unlock_method: UnlockMethod,
    pub reserved: [u8; 3],
}

impl Default for DotBlobFields {
    fn default() -> Self {
        Self {
            version: 0,
            cak: OwnerPkHash([0u32; 12]),
            lak_pub: LakPkHash([0u32; 12]),
            unlock_method: UnlockMethod::default(),
            reserved: [0u8; 3],
        }
    }
}

/// Specifies the method used for unlocking a locked DOT state.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq,
)]
pub struct UnlockMethod(u8);

/// Standard challenge-response unlock method.
pub const CHALLENGE_RESPONSE: UnlockMethod = UnlockMethod(1);
const ZERO_OWNER_PK_HASH: OwnerPkHash = OwnerPkHash([0u32; 12]);

impl DotBlob {
    /// Returns the Code Authentication Key (CAK) if present.
    pub fn cak(&self) -> Option<&OwnerPkHash> {
        if self.fields.cak.0.iter().all(|&x| x == 0) {
            None
        } else {
            Some(&self.fields.cak)
        }
    }

    /// Returns the Lock Authentication Key (LAK) public key if present.
    pub fn lak(&self) -> Option<&LakPkHash> {
        if self.fields.lak_pub.0.iter().all(|&x| x == 0) {
            None
        } else {
            Some(&self.fields.lak_pub)
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
#[inline(never)]
pub fn dot_flow(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    blob: &DotBlob,
    stable_key_type: CmStableKeyType,
) -> McuResult<Option<OwnerPkHash>> {
    caliptra_mcu_romtime::println!("[mcu-rom-dot] Performing Device Ownership Transfer flow");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipTransferStarted.into());

    let dot_effective_key = derive_stable_key_flow(env, dot_fuses, stable_key_type)?;

    verify_dot_blob(&mut env.soc_manager, blob, &dot_effective_key)?;

    burn_dot_fuses(env, dot_fuses, blob)?;

    let dot_owner = dot_determine_owner(env, dot_fuses, blob)?;

    caliptra_mcu_romtime::println!("[mcu-rom] Device Ownership Transfer complete");
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
    caliptra_mcu_romtime::println!("[mcu-rom] Deriving DOT stable key");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipDeriveStableKey.into());
    let dot_effective_key = cm_derive_stable_key(env, dot_fuses, key_type)?;
    caliptra_mcu_romtime::println!("[mcu-rom] DOT stable key derived successfully");
    Ok(dot_effective_key)
}

/// Calls Caliptra to derive the DOT Effective Key using the stable key derivation command.
fn cm_derive_stable_key(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    key_type: CmStableKeyType,
) -> McuResult<DotEffectiveKey> {
    cm_derive_stable_key_impl(&mut env.soc_manager, dot_fuses, key_type)
}

pub(crate) fn cm_derive_stable_key_impl(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
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
    let mut i = 0;
    while i < LABEL_LEN {
        info[i] = DOT_LABEL[i];
        i += 1;
    }
    let fuse_slice: [u8; 2] = derivation_value.to_le_bytes();
    info[LABEL_LEN] = fuse_slice[0];
    info[LABEL_LEN + 1] = fuse_slice[1];

    let mut resp = [0u32; core::mem::size_of::<CmDeriveStableKeyResp>() / 4];
    let req = CmDeriveStableKeyReq {
        info,
        key_type: key_type.into(),
        ..Default::default()
    };
    let mut req32: [u32; core::mem::size_of::<CmDeriveStableKeyReq>() / 4] = transmute!(req);

    if soc_manager
        .exec_mailbox_req_u32(
            CommandId::CM_DERIVE_STABLE_KEY.into(),
            &mut req32,
            &mut resp,
        )
        .is_err()
    {
        return Err(McuError::ROM_DOT_DERIVE_STABLE_KEY_FAILED);
    }
    let resp: CmDeriveStableKeyResp = transmute!(resp);
    let dot_effective_key = DotEffectiveKey(Cmk(transmute!(resp.cmk)));
    Ok(dot_effective_key)
}

// CM_HMAC copy with smaller data to save stack space
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacDotBlobReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub hash_algorithm: u32,
    pub data_size: u32,
    pub data: DotBlobFields,
}

/// Calls Caliptra to compute an HMAC over DotBlobFields.
pub(crate) fn cm_hmac(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    key: &Cmk,
    fields: &DotBlobFields,
) -> McuResult<[u32; 16]> {
    let mut resp = [0u32; core::mem::size_of::<CmHmacResp>() / 4];
    let req = CmHmacDotBlobReq {
        cmk: transmute!(key.0),
        hash_algorithm: CmHashAlgorithm::Sha512.into(),
        data_size: core::mem::size_of::<DotBlobFields>() as u32,
        data: fields.clone(),
        ..Default::default()
    };
    let mut req: [u32; core::mem::size_of::<CmHmacDotBlobReq>() / 4] = transmute!(req);

    if soc_manager
        .exec_mailbox_req_u32(CommandId::CM_HMAC.into(), &mut req, &mut resp)
        .is_err()
    {
        return Err(McuError::ROM_DOT_HMAC_FAILED);
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
#[cfg_attr(all(not(test), feature = "cfi"), cfi_mod_fn)]
pub fn verify_dot_blob(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    blob: &DotBlob,
    key: &DotEffectiveKey,
) -> McuResult<()> {
    let verify = cm_hmac(soc_manager, &key.0, &blob.fields)?;
    if !constant_time_eq::constant_time_eq(verify.as_bytes(), blob.hmac.as_bytes()) {
        caliptra_mcu_romtime::println!("[mcu-rom] DOT blob HMAC did not match");
        return Err(McuError::ROM_COLD_BOOT_DOT_BLOB_CORRUPT_ERROR);
    }

    cfi_assert!(cfi_launder(constant_time_eq::constant_time_eq(
        verify.as_bytes(),
        blob.hmac.as_bytes()
    )));

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
    caliptra_mcu_romtime::println!("[mcu-rom-dot] Determining device owner");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipDetermineOwner.into());

    if !dot_fuses.enabled {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] DOT not enabled, no owner from DOT");
        return Ok(None);
    }

    if dot_fuses.is_locked() {
        // Device is in ODD state (Locked or Disabled)
        if let Some(cak) = blob.cak() {
            // Locked state: CAK present in DOT blob
            caliptra_mcu_romtime::println!("[mcu-rom-dot] Device locked, using CAK from DOT blob");
            Ok(Some(cak.clone()))
        } else {
            // Disabled state: ODD with no CAK means ownership is locked but no code
            // authentication is enforced. The owner retains control via LAK.
            caliptra_mcu_romtime::println!("[mcu-rom-dot] Device in Disabled state (ODD, no CAK)");
            Ok(None)
        }
    } else {
        // Device is in EVEN state (Uninitialized/Volatile).
        // In EVEN state, ownership comes from Ownership_Storage (volatile), not from
        // DOT_BLOB. The DOT_BLOB in EVEN state is only used for verification/sealing
        // purposes during state transitions, not for determining the current owner.
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] Device in EVEN state, no persistent owner from DOT"
        );
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
    caliptra_mcu_romtime::println!("[mcu-rom-dot] Checking for DOT fuse burn requirements");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DeviceOwnershipBurnFuses.into());

    if !dot_fuses.enabled {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] DOT not enabled, no fuse burning needed");
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
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] DOT state transition needed: unlocked -> locked"
        );

        burn_dot_lock_fuse(&env.otp, dot_fuses)?;

        caliptra_mcu_romtime::println!("[mcu-rom-dot] DOT lock fuse burned successfully");
        caliptra_mcu_romtime::println!("[mcu-rom-dot] Transition to locked state complete");
    } else {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] No DOT state transition required");
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
pub(crate) fn burn_dot_lock_fuse(otp: &Otp, dot_fuses: &DotFuses) -> McuResult<()> {
    use caliptra_mcu_registers_generated::fuses;
    // Each state transition burns the next sequential bit in the dot_fuse_array.
    let next_bit = dot_fuses.burned as u32;
    if next_bit >= (dot_fuses.total as u32) {
        return Err(McuError::ROM_DOT_NO_MORE_FUSE_BITS);
    }

    // Calculate which word and bit within that word to burn.
    let word_index = next_bit / 32;
    let bit_in_word = next_bit % 32;

    let fuse_array_word_addr = (fuses::DOT_FUSE_ARRAY.byte_offset / 4) + word_index as usize;

    // Read the current value at this word address.
    let current_value = otp.read_word(fuse_array_word_addr)?;

    let new_value = current_value | (1u32 << bit_in_word);

    caliptra_mcu_romtime::println!(
        "[mcu-rom-dot] Burning DOT lock fuse at word addr {:#x}, value {:#x} -> {:#x}",
        fuse_array_word_addr,
        current_value,
        new_value
    );

    otp.write_word(fuse_array_word_addr, new_value)?;

    Ok(())
}

#[repr(C)]
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct EccP384PublicKey {
    pub x: [u32; 12],
    pub y: [u32; 12],
}

pub const MLDSA87_PUB_KEY_SIZE_DWORDS: usize = 2592 / 4;
pub const MLDSA87_SIGNATURE_SIZE_DWORDS: usize = 4628 / 4;

/// Override request containing vendor public keys for verification.
pub struct OverrideRequest<'a> {
    pub ecc_pub_key: EccP384PublicKey,
    pub mldsa_pub_key: &'a [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
}

/// Override challenge response containing vendor public keys and dual signatures over the challenge.
pub struct OverrideChallengeResponse<'a> {
    pub ecc_pub_key: EccP384PublicKey,
    pub ecc_signature_r: [u8; 48],
    pub ecc_signature_s: [u8; 48],
    pub mldsa_signature: &'a [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
    pub mldsa_pub_key: &'a [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
}

/// Authentication parameters for a DOT override challenge/response.
///
/// Bundles the parsed cryptographic material needed to verify an override
/// response, shared by both the MCI mailbox and I3C services flows.
pub(crate) struct OverrideAuth<'a> {
    pub ecc_key: &'a EccP384PublicKey,
    pub ecc_sig_r: &'a [u8; 48],
    pub ecc_sig_s: &'a [u8; 48],
    pub mldsa_pub_key: &'a [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    pub mldsa_signature: &'a [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
    pub challenge: &'a [u8; 48],
}

/// Transport trait for DOT recovery and override communication.
///
/// Abstracts the communication channel between ROM and the BMC for
/// DOT_OVERRIDE operations. Implementations may use MCI mailbox 0,
/// a SoC-specific mailbox, or I3C.
pub trait RecoveryTransport {
    /// Wait for a DOT_UNLOCK_CHALLENGE request from the BMC.
    ///
    /// Returns the VendorKey public keys that will be used for signature verification.
    fn wait_for_override_request(&self) -> McuResult<OverrideRequest<'_>>;

    /// Send a challenge nonce to the BMC.
    fn send_challenge(&self, challenge: &[u8; 48]) -> McuResult<()>;

    /// Receive the signed challenge response from the BMC.
    fn receive_override_response(&self) -> McuResult<OverrideChallengeResponse<'_>>;

    /// Notify the BMC of the final override result.
    ///
    /// Must be called after `receive_override_response` returns `Ok` to
    /// acknowledge the DOT_OVERRIDE command back to the sender.  Pass `true`
    /// when the override completed successfully, or `false` if signature
    /// verification or fuse/flash operations failed.
    fn notify_override_result(&self, success: bool);
}

// ---------------------------------------------------------------------------
// Shared DOT override helpers (used by both MCI and I3C flows)
// ---------------------------------------------------------------------------

/// Compute the SHA-384 of a vendor public key pair using the caliptra-sw
/// owner-PK-hash convention (the same convention used by
/// `cptra_ss_owner_pk_hash` and the debug-unlock vendor PK hash).
///
/// Inputs are the public keys in **natural FIPS byte order**, as the host
/// sends them over the mailbox / I3C wire — `ecc_pub_key.x[i]` /
/// `.y[i]` is `u32::from_le_bytes` of the four natural ECC bytes at offset
/// `i*4`, and `mldsa_pub_key[i]` is `u32::from_le_bytes` of the four
/// natural MLDSA bytes at offset `i*4`.
///
/// The bytes that go through SHA-384 must match caliptra-sw's image
/// generator. From `image/gen/src/lib.rs::to_hw_format` and
/// `image/crypto/src/rustcrypto.rs`, caliptra-sw stores the ECC public key
/// as `[u32::from_be_bytes(natural_chunk), ...]` but the MLDSA public key
/// as `[u32::from_le_bytes(natural_chunk), ...]`. On a little-endian
/// target, this means the SHA input bytes are:
///
///   per_dword_reversed(natural ECC bytes) || natural MLDSA bytes
///
/// This helper reproduces that exactly by `u32::swap_bytes`-ing each ECC
/// word before feeding it to `cm_sha384` (which hashes the raw memory
/// bytes of the u32 words on the caliptra side). The MLDSA words are
/// passed through unchanged.
pub(crate) fn cm_owner_pk_hash_sha384(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    ecc_pub_key: &EccP384PublicKey,
    mldsa_pub_key: &[u32],
) -> McuResult<[u8; SHA384_DIGEST_SIZE]> {
    let mut ecc_swapped = [0u32; 24];
    let mut i = 0;
    while i < 12 {
        ecc_swapped[i] = ecc_pub_key.x[i].swap_bytes();
        ecc_swapped[12 + i] = ecc_pub_key.y[i].swap_bytes();
        i += 1;
    }
    cm_sha384(soc_manager, &[&ecc_swapped, mldsa_pub_key])
}

/// Verify that the vendor public keys match `recovery_pk_hash` and that
/// both signatures (ECDSA P-384 + MLDSA-87) are valid over the challenge.
///
/// This is the core cryptographic verification shared between the MCI
/// mailbox override flow and the I3C services override flow.
pub(crate) fn verify_override_response(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    recovery_pk_hash: &RecoveryPkHash,
    auth: &OverrideAuth<'_>,
) -> McuResult<()> {
    // Verify PK hash matches OTP fuses, using the caliptra-sw owner-PK-hash
    // convention (per-dword-reversed ECC || natural MLDSA).
    let computed_hash = cm_owner_pk_hash_sha384(soc_manager, auth.ecc_key, auth.mldsa_pub_key)?;

    let fuse_hash_bytes: [u8; 48] = transmute!(recovery_pk_hash.0);
    if !constant_time_eq::constant_time_eq(&computed_hash, &fuse_hash_bytes) {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] Override response PK hash mismatch");
        return Err(McuError::ROM_DOT_OVERRIDE_PK_HASH_MISMATCH);
    }

    // Verify ECDSA signature over SHA-384(challenge)
    let challenge_u32: [u32; 12] = transmute!(*auth.challenge);
    let challenge_hash = cm_sha384(soc_manager, &[&challenge_u32])?;

    cm_ecdsa384_verify(
        soc_manager,
        auth.ecc_key,
        auth.ecc_sig_r,
        auth.ecc_sig_s,
        &challenge_hash,
    )
    .inspect_err(|_e| {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] Override ECDSA signature verification failed"
        );
    })?;

    // Verify MLDSA-87 signature over raw challenge
    cm_mldsa87_verify(
        soc_manager,
        auth.mldsa_pub_key,
        auth.mldsa_signature,
        &challenge_u32,
    )
    .inspect_err(|_e| {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] Override MLDSA signature verification failed"
        );
    })?;

    Ok(())
}

/// After a successful override verification, burn the DOT lock fuse and
/// write an empty DOT blob sealed with the new EVEN-state key.
pub(crate) fn apply_override(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    otp: &Otp,
    dot_fuses: &DotFuses,
    dot_flash: &dyn FlashStorage,
    stable_key_type: CmStableKeyType,
) -> McuResult<()> {
    burn_dot_lock_fuse(otp, dot_fuses)?;

    // Derive the EVEN-state key (fuse count + 1) for the new blob
    let even_fuses = DotFuses {
        enabled: dot_fuses.enabled,
        burned: dot_fuses.burned + 1,
        total: dot_fuses.total,
        recovery_pk_hash: dot_fuses.recovery_pk_hash.clone(),
    };
    let even_key = cm_derive_stable_key_impl(soc_manager, &even_fuses, stable_key_type)?;

    let mut new_blob = DotBlob {
        fields: DotBlobFields::default(),
        hmac: [0u32; 16],
    };
    new_blob.fields.version = 1;
    let hmac = cm_hmac(soc_manager, &even_key.0, &new_blob.fields)?;
    new_blob.hmac = hmac;

    dot_flash
        .write(new_blob.as_bytes(), 0)
        .map_err(|_| McuError::ROM_DOT_RECOVERY_FLASH_WRITE_ERROR)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Caliptra crypto helper: SHA-384 (one-shot CM_SHA command)
// ---------------------------------------------------------------------------

/// SHA-384 hash output size.
const SHA384_DIGEST_SIZE: usize = 48;

/// Computes SHA-384 hash by streaming `&[u32]` data parts to Caliptra's
/// CM_SHA command via `exec_mailbox_req_u32_parts`.  This avoids copying
/// large buffers (e.g. MLDSA public keys) onto the stack.
pub(crate) fn cm_sha384(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    data_parts: &[&[u32]],
) -> McuResult<[u8; SHA384_DIGEST_SIZE]> {
    let total_data_bytes: usize = data_parts.iter().map(|p| p.len() * 4).sum();

    let mut hdr: [u32; core::mem::size_of::<CmShaReqHdr>() / 4] = transmute!(CmShaReqHdr {
        hdr: MailboxReqHeader::default(),
        hash_algorithm: CmHashAlgorithm::Sha384.into(),
        input_size: total_data_bytes as u32,
    });

    let mut resp32: [u32; core::mem::size_of::<CmShaResp>() / 4] = transmute!(CmShaResp::default());

    if let Err(err) = soc_manager.exec_mailbox_req_u32_parts(
        CommandId::CM_SHA.into(),
        &mut hdr,
        data_parts,
        &mut resp32,
    ) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] CM_SHA failed: {}",
            HexWord(crate::err_code(&err))
        );
        return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
    }

    let resp: CmShaResp = transmute!(resp32);
    let src = resp
        .hash
        .get(..SHA384_DIGEST_SIZE)
        .ok_or(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED)?;
    let mut hash = [0u8; SHA384_DIGEST_SIZE];
    for (d, s) in hash.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    Ok(hash)
}

/// Generates random bytes using Caliptra's CM_RANDOM_GENERATE command.
pub(crate) fn cm_random_generate(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
) -> McuResult<[u8; 48]> {
    #[repr(C)]
    #[derive(Default, IntoBytes, FromBytes, KnownLayout, Immutable)]
    struct CmRandomReq {
        hdr: MailboxReqHeader,
        size: u32,
    }

    // Response: varsize header (chksum + fips_status + data_len) + 48 bytes data
    #[repr(C)]
    #[derive(IntoBytes, FromBytes, KnownLayout, Immutable)]
    struct CmRandomResp {
        chksum: u32,
        fips_status: u32,
        data_len: u32,
        data: [u8; 48],
    }

    impl Default for CmRandomResp {
        fn default() -> Self {
            Self {
                chksum: 0,
                fips_status: 0,
                data_len: 0,
                data: [0u8; 48],
            }
        }
    }

    let req = CmRandomReq {
        size: 48,
        ..Default::default()
    };
    let mut req32: [u32; core::mem::size_of::<CmRandomReq>() / 4] = transmute!(req);
    let mut resp32: [u32; core::mem::size_of::<CmRandomResp>() / 4] =
        transmute!(CmRandomResp::default());

    if let Err(err) = soc_manager.exec_mailbox_req_u32(
        CommandId::CM_RANDOM_GENERATE.into(),
        &mut req32,
        &mut resp32,
    ) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] CM_RANDOM_GENERATE failed: {}",
            HexWord(crate::err_code(&err))
        );
        return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
    }
    let resp: CmRandomResp = transmute!(resp32);
    Ok(resp.data)
}

/// Verifies an ECDSA P-384 signature using Caliptra's ECDSA384_SIGNATURE_VERIFY command.
///
/// This ROM command takes raw public key coordinates (not a CMK handle).
pub(crate) fn cm_ecdsa384_verify(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    pub_key: &EccP384PublicKey,
    signature_r: &[u8; 48],
    signature_s: &[u8; 48],
    hash: &[u8; 48],
) -> McuResult<()> {
    let mut pub_key_x = [0u8; 48];
    let mut pub_key_y = [0u8; 48];
    let mut i = 0;
    while i < 12 {
        let xb = pub_key.x[i].to_le_bytes();
        let yb = pub_key.y[i].to_le_bytes();
        let mut j = 0;
        while j < 4 {
            pub_key_x[i * 4 + j] = xb[j];
            pub_key_y[i * 4 + j] = yb[j];
            j += 1;
        }
        i += 1;
    }
    let req = EcdsaVerifyReq {
        hdr: Default::default(),
        pub_key_x,
        pub_key_y,
        signature_r: *signature_r,
        signature_s: *signature_s,
        hash: *hash,
    };
    let mut req32: [u32; core::mem::size_of::<EcdsaVerifyReq>() / 4] = transmute!(req);
    let mut resp32: [u32; core::mem::size_of::<MailboxRespHeader>() / 4] =
        transmute!(MailboxRespHeader::default());

    if let Err(err) = soc_manager.exec_mailbox_req_u32(
        CommandId::ECDSA384_SIGNATURE_VERIFY.into(),
        &mut req32,
        &mut resp32,
    ) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] ECDSA384_SIGNATURE_VERIFY failed: {}",
            HexWord(crate::err_code(&err))
        );
        return Err(McuError::ROM_DOT_OVERRIDE_SIG_VERIFY_FAILED);
    }
    Ok(())
}

/// Verifies an MLDSA87 signature using Caliptra's MLDSA87_SIGNATURE_VERIFY command.
///
/// The public key and signature are passed as `&[u32]` slices and streamed
/// directly to the mailbox to avoid an ~11 KB stack allocation.
pub(crate) fn cm_mldsa87_verify(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    pub_key: &[u32],
    signature: &[u32],
    message: &[u32],
) -> McuResult<()> {
    if pub_key.len() != MLDSA87_PUB_KEY_SIZE_DWORDS
        || signature.len() != MLDSA87_SIGNATURE_SIZE_DWORDS
    {
        return Err(McuError::ROM_DOT_OVERRIDE_SIG_VERIFY_FAILED);
    }

    // Build the small parts that live on the stack:
    //   part 0: pub_key  (borrowed)
    //   part 1: signature (borrowed)
    //   part 2: message_size (u32) + message data (u32 words)
    let mut hdr = [0u32; core::mem::size_of::<MailboxReqHeader>() / 4];
    let message_bytes = (message.len() * 4) as u32;
    // message_size word + message data; 64 u32s supports messages up to 252 bytes
    const MAX_MSG_WORDS: usize = 64;
    if message.len() > MAX_MSG_WORDS - 1 {
        return Err(McuError::ROM_DOT_OVERRIDE_SIG_VERIFY_FAILED);
    }
    let mut msg_part = [0u32; MAX_MSG_WORDS];
    msg_part[0] = message_bytes;
    let mut i = 0;
    while i < message.len() {
        msg_part[i + 1] = message[i];
        i += 1;
    }
    let msg_slice: &[u32] = &msg_part[..1 + message.len()];

    let data_parts: &[&[u32]] = &[pub_key, signature, msg_slice];
    let mut resp32: [u32; core::mem::size_of::<MailboxRespHeader>() / 4] =
        transmute!(MailboxRespHeader::default());

    if let Err(err) = soc_manager.exec_mailbox_req_u32_parts(
        CommandId::MLDSA87_SIGNATURE_VERIFY.into(),
        &mut hdr,
        data_parts,
        &mut resp32,
    ) {
        caliptra_mcu_romtime::println!(
            "[mcu-rom-dot] MLDSA87_SIGNATURE_VERIFY failed: {}",
            HexWord(crate::err_code(&err))
        );
        return Err(McuError::ROM_DOT_OVERRIDE_SIG_VERIFY_FAILED);
    }
    Ok(())
}

/// Trait for providing a backup DOT blob during recovery.
///
/// When a device is in ODD state (locked) but the DOT blob is corrupted,
/// a recovery agent (e.g., BMC) can provide a backup DOT blob to restore
/// the device to a working locked state.
///
/// Implementors should retrieve the backup DOT blob from the recovery agent
/// and return it as raw bytes matching the `DotBlob` layout.
pub trait DotRecoveryHandler {
    /// Read a backup DOT blob from the recovery agent.
    ///
    /// Returns the raw bytes of a backup DOT blob that will be authenticated
    /// against the current DOT_EFFECTIVE_KEY before being written to flash.
    fn read_recovery_blob(&self) -> McuResult<[u8; DOT_BLOB_SIZE]>;
}

/// A `DotRecoveryHandler` that returns a blob already held in memory.
/// Used by the I3C services handler where the blob has been fully received
/// and reassembled before recovery begins.
pub struct BufferedRecoveryHandler {
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl DotRecoveryHandler for BufferedRecoveryHandler {
    fn read_recovery_blob(&self) -> McuResult<[u8; DOT_BLOB_SIZE]> {
        Ok(self.blob)
    }
}

/// Authenticate a recovery blob and write it to flash.
///
/// This is the shared core of DOT_RECOVERY used by both
/// `dot_recovery_flow` (MCI path) and the I3C services handler.
pub(crate) fn verify_and_write_recovery_blob(
    soc_manager: &mut caliptra_mcu_romtime::CaliptraSoC,
    dot_fuses: &DotFuses,
    blob_bytes: &[u8; DOT_BLOB_SIZE],
    dot_flash: &dyn FlashStorage,
    stable_key_type: CmStableKeyType,
) -> McuResult<()> {
    let backup_blob: DotBlob = transmute!(*blob_bytes);
    let dot_effective_key = cm_derive_stable_key_impl(soc_manager, dot_fuses, stable_key_type)?;
    verify_dot_blob(soc_manager, &backup_blob, &dot_effective_key)?;
    dot_flash
        .write(blob_bytes, 0)
        .map_err(|_| McuError::ROM_DOT_RECOVERY_FLASH_WRITE_ERROR)?;
    Ok(())
}

/// Performs DOT recovery by authenticating a backup blob and writing it to flash.
///
/// This implements the DOT_RECOVERY flow from the spec:
/// 1. Get backup DOT blob from recovery handler
/// 2. Derive DOT_EFFECTIVE_KEY
/// 3. Authenticate backup blob via HMAC
/// 4. Write authenticated blob to flash
///
/// After this function returns successfully, the caller should request a
/// subsystem reset so the next boot will find a valid DOT blob.
pub fn dot_recovery_flow(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    recovery_handler: &dyn DotRecoveryHandler,
    dot_flash: &dyn FlashStorage,
    stable_key_type: CmStableKeyType,
) -> McuResult<()> {
    caliptra_mcu_romtime::println!("[mcu-rom-dot] Starting DOT recovery flow");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotRecoveryStarted.into());

    let backup_blob_bytes = recovery_handler.read_recovery_blob()?;

    verify_and_write_recovery_blob(
        &mut env.soc_manager,
        dot_fuses,
        &backup_blob_bytes,
        dot_flash,
        stable_key_type,
    )
    .inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotRecoveryFailed.into());
    })?;

    caliptra_mcu_romtime::println!("[mcu-rom-dot] DOT recovery complete, reset required");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotRecoveryComplete.into());

    Ok(())
}

/// Performs DOT override with challenge/response authentication.
///
/// This implements the DOT_OVERRIDE flow:
/// 1. Wait for override request from BMC (includes VendorKey public keys: ECC + MLDSA)
/// 2. Verify device is in ODD (locked) state
/// 3. Verify vendor public key hash matches vendor recovery PK hash in OTP fuses
/// 4. Generate random challenge and send to BMC
/// 5. Receive and verify ECDSA P-384 and MLDSA-87 signatures over challenge
/// 6. Burn DOT fuse (n→n+1) to transition to EVEN state
/// 7. Write a new empty DOT blob (no CAK/LAK) HMAC'd with the new EVEN-state key
///
/// After success, the caller should trigger a warm reset.
pub fn dot_override_challenge_flow(
    env: &mut RomEnv,
    dot_fuses: &DotFuses,
    transport: &dyn RecoveryTransport,
    dot_flash: &dyn FlashStorage,
    stable_key_type: CmStableKeyType,
) -> McuResult<()> {
    caliptra_mcu_romtime::println!("[mcu-rom-dot] Starting DOT override flow");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotOverrideStarted.into());

    if !dot_fuses.is_locked() {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
        return Err(McuError::ROM_DOT_OVERRIDE_NOT_LOCKED);
    }

    let recovery_pk_hash = match dot_fuses.recovery_pk_hash.as_ref() {
        Some(hash) => hash,
        None => {
            env.mci
                .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
            return Err(McuError::ROM_DOT_OVERRIDE_NO_RECOVERY_PK_HASH);
        }
    };

    let request = transport.wait_for_override_request().inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    // Verify vendor public key hash matches recovery PK hash in OTP fuses
    // using the caliptra-sw owner-PK-hash convention (per-dword-reversed
    // ECC || natural MLDSA).
    let computed_hash = cm_owner_pk_hash_sha384(
        &mut env.soc_manager,
        &request.ecc_pub_key,
        request.mldsa_pub_key,
    )
    .inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    let fuse_hash_bytes: [u8; 48] = transmute!(recovery_pk_hash.0);
    if !constant_time_eq::constant_time_eq(&computed_hash, &fuse_hash_bytes) {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] Vendor recovery PK hash mismatch");
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
        return Err(McuError::ROM_DOT_OVERRIDE_PK_HASH_MISMATCH);
    }

    // Generate and send challenge
    let challenge = cm_random_generate(&mut env.soc_manager).inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    transport.send_challenge(&challenge).inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotOverrideChallengeSent.into());

    // Receive and verify signed response
    let response = transport.receive_override_response().inspect_err(|_e| {
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    let auth = OverrideAuth {
        ecc_key: &response.ecc_pub_key,
        ecc_sig_r: &response.ecc_signature_r,
        ecc_sig_s: &response.ecc_signature_s,
        mldsa_pub_key: response.mldsa_pub_key,
        mldsa_signature: response.mldsa_signature,
        challenge: &challenge,
    };

    verify_override_response(&mut env.soc_manager, recovery_pk_hash, &auth).inspect_err(|_e| {
        transport.notify_override_result(false);
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotOverrideSigVerified.into());

    // Burn DOT fuse and write empty blob
    apply_override(
        &mut env.soc_manager,
        &env.otp,
        dot_fuses,
        dot_flash,
        stable_key_type,
    )
    .inspect_err(|_e| {
        transport.notify_override_result(false);
        env.mci
            .set_flow_checkpoint(McuRomBootStatus::DotOverrideFailed.into());
    })?;

    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotOverrideBlobWritten.into());

    transport.notify_override_result(true);
    caliptra_mcu_romtime::println!("[mcu-rom-dot] DOT override complete");
    env.mci
        .set_flow_checkpoint(McuRomBootStatus::DotOverrideComplete.into());

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
    caliptra_mcu_romtime::println!(
        "[mcu-rom-dot] Writing recovery DOT blob for blank/corrupt flash"
    );
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
        fields: DotBlobFields {
            version: 1,
            cak: cak.clone(),
            lak_pub: lak.clone(),
            unlock_method: CHALLENGE_RESPONSE,
            reserved: [0u8; 3],
        },
        hmac: [0u32; 16],
    };

    // Compute HMAC over the blob fields (everything except the HMAC tag).
    let hmac_tag = cm_hmac(&mut env.soc_manager, &dot_effective_key.0, &blob.fields)?;
    blob.hmac = hmac_tag;

    // Write the sealed DOT blob to flash.
    if let Some(flash) = dot_flash {
        if flash.write(blob.as_bytes(), 0).is_err() {
            return Err(McuError::ROM_DOT_FLASH_WRITE_FAILED);
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
        return Err(McuError::ROM_FW_MANIFEST_DOT_CHECKSUM_MISMATCH);
    }

    if section.version != 1 {
        return Err(McuError::ROM_FW_MANIFEST_DOT_UNSUPPORTED_VERSION);
    }

    caliptra_mcu_romtime::println!("[mcu-rom-dot] Processing manifest DOT commands");

    let num_commands = section.num_commands as usize;
    if num_commands > MAX_FW_MANIFEST_DOT_COMMANDS {
        return Err(McuError::ROM_FW_MANIFEST_DOT_TOO_MANY_COMMANDS);
    }

    // Reject manifests that contain both LOCK and UNLOCK commands.
    // Allowing both would rapidly burn through DOT fuses on every reset.
    let cmds = match section.commands.get(..num_commands) {
        Some(c) => c,
        None => return Err(McuError::ROM_FW_MANIFEST_DOT_COMMANDS_INVALID),
    };
    let has_lock = cmds
        .iter()
        .any(|&c| c == FW_MANIFEST_DOT_CMD_LOCK || c == FW_MANIFEST_DOT_CMD_DISABLE);
    let has_unlock = cmds.iter().any(|&c| c == FW_MANIFEST_DOT_CMD_UNLOCK);
    if has_lock && has_unlock {
        return Err(McuError::ROM_FW_MANIFEST_DOT_CONFLICTING_COMMANDS);
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
                    // Pre-compute the post-burn fuse state so we can seal the
                    // blob before touching the fuses.
                    let post_burn_fuses = DotFuses {
                        burned: dot_fuses.burned + 1,
                        ..dot_fuses.clone()
                    };
                    create_and_seal_dot_blob(
                        env,
                        &post_burn_fuses,
                        &ZERO_OWNER_PK_HASH,
                        &LakPkHash(section.lak),
                        dot_flash,
                    )?;
                    // If we have a power loss here before the fuse is burned,
                    // then the HMAC seal on the DOT blob will be invalid.
                    burn_dot_lock_fuse(&env.otp, &dot_fuses)?;
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

            _ => {
                return Err(McuError::ROM_FW_MANIFEST_DOT_UNKNOWN_COMMAND);
            }
        }
    }

    caliptra_mcu_romtime::println!("[mcu-rom-dot] Manifest DOT processing complete");
    Ok(())
}

/// Policy for handling errors from a [`DotLockedRecoveryHandler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotLockedRecoveryErrorPolicy {
    /// On error, skip this handler and try the next one.
    Continue,
    /// Retry up to N times, then fall through to the next handler.
    Retry(core::num::NonZeroU8),
}

/// A handler that attempts to recover from DOT locked state.
///
/// Integrators provide an ordered list of these handlers so the ROM tries
/// each recovery mechanism in the integrator-chosen order.  If a handler
/// succeeds it should write the DOT blob to flash and return `Ok(())`;
/// the caller will then trigger a warm reset.
pub trait DotLockedRecoveryHandler {
    /// Attempt to recover from DOT locked state.
    fn attempt(&self, env: &mut RomEnv, ctx: &DotLockedRecoveryContext<'_>) -> McuResult<()>;
}

/// Shared context passed to every [`DotLockedRecoveryHandler`].
pub struct DotLockedRecoveryContext<'a> {
    pub dot_fuses: &'a DotFuses,
    pub dot_flash: &'a dyn FlashStorage,
    pub key_type: CmStableKeyType,
}

/// A [`DotLockedRecoveryHandler`] paired with its error-handling policy.
pub struct DotLockedRecoveryEntry<'a> {
    pub handler: &'a dyn DotLockedRecoveryHandler,
    pub policy: DotLockedRecoveryErrorPolicy,
}

/// Manages a sequence of [`DotLockedRecoveryEntry`]s, iterating through them
/// according to each entry's error policy.
pub struct DotLockedRecoveryManager<'a> {
    entries: &'a [DotLockedRecoveryEntry<'a>],
    current: usize,
    retries: u8,
}

impl<'a> DotLockedRecoveryManager<'a> {
    pub fn new(entries: &'a [DotLockedRecoveryEntry<'a>]) -> Self {
        Self {
            entries,
            current: 0,
            retries: 0,
        }
    }

    /// Run through the handler chain.  Stops and returns `Ok(())` on the
    /// first successful handler.  Returns the last error if all are
    /// exhausted.
    pub fn run(&mut self, env: &mut RomEnv, ctx: &DotLockedRecoveryContext<'_>) -> McuResult<()> {
        let mut last_err = McuError::ROM_COLD_BOOT_DOT_NO_RECOVERY_HANDLERS;
        while self.current < self.entries.len() {
            let entry = &self.entries[self.current];
            match entry.handler.attempt(env, ctx) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_err = err;
                    caliptra_mcu_romtime::println!(
                        "[mcu-rom-dot] locked-state handler failed: {}",
                        HexWord(err.into())
                    );
                    self.retries += 1;
                    match entry.policy {
                        DotLockedRecoveryErrorPolicy::Continue => {
                            self.current += 1;
                            self.retries = 0;
                        }
                        DotLockedRecoveryErrorPolicy::Retry(n) => {
                            if self.retries >= n.get() {
                                self.current += 1;
                                self.retries = 0;
                            }
                        }
                    }
                }
            }
        }
        Err(last_err)
    }
}

/// A [`DotLockedRecoveryHandler`] that recovers via a backup DOT blob
/// obtained from a [`DotRecoveryHandler`].
pub struct BackupBlobRecoveryHandler<'a> {
    pub recovery_handler: &'a dyn DotRecoveryHandler,
}

impl DotLockedRecoveryHandler for BackupBlobRecoveryHandler<'_> {
    fn attempt(&self, env: &mut RomEnv, ctx: &DotLockedRecoveryContext<'_>) -> McuResult<()> {
        caliptra_mcu_romtime::println!("[mcu-rom-dot] Attempting backup-blob recovery");
        dot_recovery_flow(
            env,
            ctx.dot_fuses,
            self.recovery_handler,
            ctx.dot_flash,
            ctx.key_type,
        )
    }
}

/// A [`DotLockedRecoveryHandler`] that recovers via the DOT override
/// challenge/response protocol using a [`RecoveryTransport`].
pub struct OverrideChallengeRecoveryHandler<'a> {
    pub transport: &'a dyn crate::RecoveryTransport,
    pub wdt_timeout: u64,
}

impl DotLockedRecoveryHandler for OverrideChallengeRecoveryHandler<'_> {
    fn attempt(&self, env: &mut RomEnv, ctx: &DotLockedRecoveryContext<'_>) -> McuResult<()> {
        if self.wdt_timeout > 0 {
            env.mci.configure_wdt(self.wdt_timeout, 1);
        }
        caliptra_mcu_romtime::println!("[mcu-rom-dot] Attempting override challenge/response");
        dot_override_challenge_flow(
            env,
            ctx.dot_fuses,
            self.transport,
            ctx.dot_flash,
            ctx.key_type,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All-zero OTP bytes must yield an all-zero `RecoveryPkHash`. (The
    /// `load_from_otp` caller uses this to distinguish "fuse not burned"
    /// from "fuse burned with some hash value", so the byte-reversal must
    /// not change the zero detection contract.)
    #[test]
    fn recovery_pk_hash_zero_input_round_trips() {
        let hash = recovery_pk_hash_from_otp_bytes([0u8; 48]);
        assert_eq!(hash.0, [0u32; 12]);
    }

    /// A known pattern in OTP must come back as the same logical hash bytes
    /// in natural (FIPS) SHA-384 order when viewed through
    /// `transmute!(recovery_pk_hash.0)`.
    ///
    /// The OTP bytes are stored byte-reversed within each 4-byte word
    /// (caliptra-sw fuse layout), so reading bytes `[0x03, 0x02, 0x01, 0x00, ...]`
    /// from OTP must yield natural bytes `[0x00, 0x01, 0x02, 0x03, ...]`.
    #[test]
    fn recovery_pk_hash_reverses_each_word() {
        let mut otp_bytes = [0u8; 48];
        for (i, b) in otp_bytes.iter_mut().enumerate() {
            // In each 4-byte word, the OTP bytes are reversed: word i contains
            // bytes [i*4+3, i*4+2, i*4+1, i*4+0] of the natural-order hash.
            let word = i / 4;
            let pos_in_word = i % 4;
            *b = (word * 4 + (3 - pos_in_word)) as u8;
        }

        let hash = recovery_pk_hash_from_otp_bytes(otp_bytes);
        let natural_bytes: [u8; 48] = zerocopy::transmute!(hash.0);

        let mut expected = [0u8; 48];
        for (i, b) in expected.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(natural_bytes, expected);
    }

    /// Applying the byte-reversal twice must reproduce the original input.
    /// This guards against accidentally introducing an asymmetric transform.
    #[test]
    fn recovery_pk_hash_reverses_are_involutive() {
        let mut input = [0u8; 48];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i.wrapping_mul(37) ^ 0xa5) as u8;
        }

        let first = recovery_pk_hash_from_otp_bytes(input);
        let first_bytes: [u8; 48] = zerocopy::transmute!(first.0);
        let second = recovery_pk_hash_from_otp_bytes(first_bytes);
        let second_bytes: [u8; 48] = zerocopy::transmute!(second.0);

        assert_eq!(second_bytes, input);
    }

    /// Verify that the recovery PK hash uses the same fuse layout as the
    /// caliptra-sw `cptra_ss_owner_pk_hash` convention: storing the hash
    /// as `[u32; 12]` of big-endian-decoded 4-byte chunks.
    ///
    /// This is the property that lets an integrator burn the same 48-byte
    /// value into `cptra_ss_owner_pk_hash`, the debug-unlock vendor PK hash,
    /// or `vendor_recovery_pk_hash` and have them all be interpreted as the
    /// same logical hash.
    #[test]
    fn recovery_pk_hash_matches_owner_pk_hash_fuse_layout() {
        // Take an arbitrary 48-byte hash in natural SHA-384 byte order.
        let mut natural = [0u8; 48];
        for (i, b) in natural.iter_mut().enumerate() {
            *b = ((i * 7) ^ 0x5c) as u8;
        }

        // Compute the [u32; 12] representation using the caliptra-sw fuse
        // convention (big-endian decode of each 4-byte chunk).
        let mut caliptra_sw_words = [0u32; 12];
        for (i, chunk) in natural.chunks_exact(4).enumerate() {
            caliptra_sw_words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // The OTP byte layout for both fuses: take the [u32; 12] words and
        // store them little-endian (the natural byte storage on RV32 LE).
        let mut otp_bytes = [0u8; 48];
        for (i, word) in caliptra_sw_words.iter().enumerate() {
            otp_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        // Loading via `recovery_pk_hash_from_otp_bytes` must round-trip to
        // the FIPS-natural bytes so it can be compared against the SHA-384
        // digest produced by Caliptra.
        let hash = recovery_pk_hash_from_otp_bytes(otp_bytes);
        let recovered_natural: [u8; 48] = zerocopy::transmute!(hash.0);
        assert_eq!(recovered_natural, natural);
    }

    /// Documented example: the natural FIPS-order owner PK hash value
    /// `48afdb073c5e0d4ee46490468ef81f2cf57249b6e76a28f5fca4de696a7d3e2ed3efc4e6774318543e95307a54988bd7`
    /// must be burned into the fuse as the per-dword-reversed bytes
    /// `07dbaf484e0d5e3c469064e42c1ff88eb64972f5f5286ae769dea4fc2e3e7d6ae6c4efd35418437777a30953ed78b9854`.
    ///
    /// When the MCU reads those fuse bytes from OTP and converts them
    /// through `recovery_pk_hash_from_otp_bytes`, the resulting
    /// `transmute!(recovery_pk_hash.0)` must equal the documented natural
    /// hash. This is the value that `cm_owner_pk_hash_sha384` produces and
    /// that the comparison in `verify_override_response` checks against.
    #[test]
    fn recovery_pk_hash_documented_example() {
        const NATURAL_HASH: [u8; 48] = [
            0x48, 0xaf, 0xdb, 0x07, 0x3c, 0x5e, 0x0d, 0x4e, 0xe4, 0x64, 0x90, 0x46, 0x8e, 0xf8,
            0x1f, 0x2c, 0xf5, 0x72, 0x49, 0xb6, 0xe7, 0x6a, 0x28, 0xf5, 0xfc, 0xa4, 0xde, 0x69,
            0x6a, 0x7d, 0x3e, 0x2e, 0xd3, 0xef, 0xc4, 0xe6, 0x77, 0x43, 0x18, 0x54, 0x3e, 0x95,
            0x30, 0x7a, 0x54, 0x98, 0x8b, 0xd7,
        ];
        const FUSE_BYTES: [u8; 48] = [
            0x07, 0xdb, 0xaf, 0x48, 0x4e, 0x0d, 0x5e, 0x3c, 0x46, 0x90, 0x64, 0xe4, 0x2c, 0x1f,
            0xf8, 0x8e, 0xb6, 0x49, 0x72, 0xf5, 0xf5, 0x28, 0x6a, 0xe7, 0x69, 0xde, 0xa4, 0xfc,
            0x2e, 0x3e, 0x7d, 0x6a, 0xe6, 0xc4, 0xef, 0xd3, 0x54, 0x18, 0x43, 0x77, 0x7a, 0x30,
            0x95, 0x3e, 0xd7, 0x8b, 0x98, 0x54,
        ];

        // Sanity check the constants: FUSE_BYTES is per-dword reverse of NATURAL_HASH.
        for i in 0..12 {
            for j in 0..4 {
                assert_eq!(FUSE_BYTES[i * 4 + j], NATURAL_HASH[i * 4 + (3 - j)]);
            }
        }

        let hash = recovery_pk_hash_from_otp_bytes(FUSE_BYTES);
        let recovered: [u8; 48] = zerocopy::transmute!(hash.0);
        assert_eq!(recovered, NATURAL_HASH);
    }

    /// `cm_owner_pk_hash_sha384` operates on a stack-resident `[u32; 24]`
    /// built by `swap_bytes`-ing each ECC u32 word. This unit test pins
    /// down that swap_bytes is what's needed.
    ///
    /// On a little-endian target, the host-supplied ECC pubkey x-coordinate
    /// bytes `[X0, X1, X2, X3, ...]` are read into `EccP384PublicKey.x[i]`
    /// as `u32::from_le_bytes([X0, X1, X2, X3])`. After `swap_bytes()` we
    /// get `u32::from_be_bytes([X0, X1, X2, X3])`. When that u32 is sent
    /// over the mailbox and stored in caliptra's memory on a LE target,
    /// the bytes that go through SHA are `[X3, X2, X1, X0]` — i.e., the
    /// per-dword-reversed natural ECC bytes that caliptra-sw's
    /// `to_hw_format` (using `u32::from_be_bytes`) produces in the image
    /// generator.
    #[test]
    fn owner_pk_hash_ecc_swap_bytes_matches_to_hw_format() {
        let natural_bytes: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3];

        // The way the host packs ECC bytes into u32 over the mailbox.
        let host_word_0 = u32::from_le_bytes([0xA0, 0xA1, 0xA2, 0xA3]);

        // After swap_bytes (what cm_owner_pk_hash_sha384 does to ECC u32s).
        let swapped = host_word_0.swap_bytes();
        assert_eq!(swapped, u32::from_be_bytes([0xA0, 0xA1, 0xA2, 0xA3]));

        // The bytes that end up flowing through SHA on caliptra's LE side.
        let bytes_through_sha = swapped.to_le_bytes();
        assert_eq!(bytes_through_sha, [0xA3, 0xA2, 0xA1, 0xA0]);

        // This is exactly the per-dword reversal of the natural bytes.
        let mut expected = [0u8; 4];
        expected.copy_from_slice(&natural_bytes[..4]);
        expected.reverse();
        assert_eq!(bytes_through_sha, expected);
    }
}
