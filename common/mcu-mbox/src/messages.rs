// Licensed under the Apache-2.0 license

use caliptra_image_types::{ECC384_SCALAR_BYTE_SIZE, MLDSA87_SIGNATURE_BYTE_SIZE};
use caliptra_mcu_registers_generated::fuses::{
    OTP_CPTRA_CORE_VENDOR_PK_HASH_0, OTP_CPTRA_SS_OWNER_PK_HASH,
};
use core::convert::From;
use core::mem::size_of;
use core::num::NonZeroU32;
use mcu_caliptra_api::mailbox::CommandId as CaliptraCommandId;
pub use mcu_caliptra_api::mailbox::{
    calc_checksum, verify_checksum, CmAesDecryptInitReq, CmAesDecryptUpdateReq,
    CmAesEncryptInitReq, CmAesEncryptInitResp, CmAesEncryptInitRespHeader, CmAesEncryptUpdateReq,
    CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptFinalRespHeader,
    CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq,
    CmAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateRespHeader, CmAesGcmEncryptFinalReq,
    CmAesGcmEncryptFinalResp, CmAesGcmEncryptFinalRespHeader, CmAesGcmEncryptInitReq,
    CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp,
    CmAesGcmEncryptUpdateRespHeader, CmAesMode, CmAesResp, CmAesRespHeader, CmDeleteReq,
    CmEcdhFinishReq, CmEcdhFinishResp, CmEcdhGenerateReq, CmEcdhGenerateResp, CmEcdsaPublicKeyReq,
    CmEcdsaPublicKeyResp, CmEcdsaSignReq, CmEcdsaSignResp, CmEcdsaVerifyReq, CmHkdfExpandReq,
    CmHkdfExpandResp, CmHkdfExtractReq, CmHkdfExtractResp, CmHmacKdfCounterReq,
    CmHmacKdfCounterResp, CmHmacReq, CmHmacResp, CmImportReq, CmImportResp, CmKeyUsage,
    CmMldsaPublicKeyReq, CmMldsaPublicKeyResp, CmMldsaSignReq, CmMldsaSignResp, CmMldsaVerifyReq,
    CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq, CmShaFinalReq, CmShaFinalResp,
    CmShaInitReq, CmShaInitResp, CmShaUpdateReq, CmStatusResp, Cmk, EcdsaVerifyReq, LmsVerifyReq,
    MailboxReqHeader, MailboxRespHeader, MailboxRespHeaderVarSize,
    ProductionAuthDebugUnlockChallenge, ProductionAuthDebugUnlockReq,
    ProductionAuthDebugUnlockToken, ResponseVarSize, CMB_AES_ENCRYPTED_CONTEXT_SIZE,
    CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, CMB_HMAC_MAX_SIZE,
    MAX_CMB_DATA_SIZE,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

pub const MAX_RESP_DATA_SIZE: usize = 4 * 1024;
pub const MAX_FW_VERSION_STR_LEN: usize = 32;
pub const DEVICE_CAPS_SIZE: usize = 36;
pub const DOT_BLOB_SIZE: usize = 168;
pub const MAX_UUID_SIZE: usize = 32;
pub const MAX_FUSE_DATA_BYTES: usize = 512;
pub const MAX_FUSE_DATA_WORDS: usize = MAX_FUSE_DATA_BYTES / 4;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct McuMboxError(pub NonZeroU32);
pub type McuMboxResult<T> = Result<T, McuMboxError>;

impl McuMboxError {
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("McuMboxError cannot be 0"),
        }
    }
    // add a new error type
    pub const MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE: McuMboxError = Self::new_const(0x0000_0001);
    pub const MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT: McuMboxError = Self::new_const(0x0000_0002);
    pub const MCU_RUNTIME_INSUFFICIENT_MEMORY: McuMboxError = Self::new_const(0x0000_0003);
    pub const MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE: McuMboxError = Self::new_const(0x0000_0004);
}

/// A trait implemented by request types. Describes the associated command ID
/// and response type.
pub trait Request: IntoBytes + FromBytes + Immutable + KnownLayout {
    const ID: CommandId;
    type Resp: Response;
}

/// A trait implemented by response types.
pub trait Response: IntoBytes + FromBytes
where
    Self: Sized,
{
    /// The minimum size (in bytes) of this response. Transports that receive at
    /// least this much data should pad the missing data with zeroes. If they
    /// receive fewer bytes than MIN_SIZE, they should error.
    const MIN_SIZE: usize = core::mem::size_of::<Self>();
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const MC_FIRMWARE_VERSION: Self = Self(0x4D46_5756); // "MFWV"
    pub const MC_DEVICE_CAPABILITIES: Self = Self(0x4D43_4150); // "MCAP"
    pub const MC_GET_LOG: Self = Self(0x4D47_4C47); // "MGLG"
    pub const MC_CLEAR_LOG: Self = Self(0x4D43_4C47); // "MCLG"
    pub const MC_FIPS_SELF_TEST_START: Self = Self(0x4D46_5354); // "MFST"
    pub const MC_FIPS_SELF_TEST_GET_RESULTS: Self = Self(0x4D46_4752); // "MFGR"
    pub const MC_FIPS_PERIODIC_ENABLE: Self = Self(0x4D46_5045); // "MFPE"
    pub const MC_FIPS_PERIODIC_STATUS: Self = Self(0x4D46_5053); // "MFPS"
    pub const MC_SHA_INIT: Self = Self(0x4D43_5349); // "MCSI"
    pub const MC_SHA_UPDATE: Self = Self(0x4D43_5355); // "MCSU"
    pub const MC_SHA_FINAL: Self = Self(0x4D43_5346); // "MCSF"
    pub const MC_HMAC: Self = Self(0x4D43_484D); // "MCHM"
    pub const MC_HMAC_KDF_COUNTER: Self = Self(0x4D43_4B43); // "MCKC"
    pub const MC_HKDF_EXTRACT: Self = Self(0x4D43_4B54); // "MCKT"
    pub const MC_HKDF_EXPAND: Self = Self(0x4D43_4B50); // "MCKP"
    pub const MC_AES_ENCRYPT_INIT: Self = Self(0x4D43_4349); // "MCCI"
    pub const MC_AES_ENCRYPT_UPDATE: Self = Self(0x4D43_4355); // "MCCU"
    pub const MC_AES_DECRYPT_INIT: Self = Self(0x4D43_414A); // "MCAJ"
    pub const MC_AES_DECRYPT_UPDATE: Self = Self(0x4D43_4155); // "MCAU"
    pub const MC_AES_GCM_ENCRYPT_INIT: Self = Self(0x4D43_4749); // "MCGI"
    pub const MC_AES_GCM_ENCRYPT_UPDATE: Self = Self(0x4D43_4755); // "MCGU"
    pub const MC_AES_GCM_ENCRYPT_FINAL: Self = Self(0x4D43_4746); // "MCGF"
    pub const MC_AES_GCM_DECRYPT_INIT: Self = Self(0x4D43_4449); // "MCDI"
    pub const MC_AES_GCM_DECRYPT_UPDATE: Self = Self(0x4D43_4455); // "MCDU"
    pub const MC_AES_GCM_DECRYPT_FINAL: Self = Self(0x4D43_4446); // "MCDF"
    pub const MC_RANDOM_STIR: Self = Self(0x4D43_5253); // "MCRS"
    pub const MC_RANDOM_GENERATE: Self = Self(0x4D43_5247); // "MCRG"
    pub const MC_IMPORT: Self = Self(0x4D43_494D); // "MCIM"
    pub const MC_DELETE: Self = Self(0x4D43_444C); // "MCDL"
    pub const MC_CM_STATUS: Self = Self(0x4D43_5354); // "MCST"
    pub const MC_ECDH_GENERATE: Self = Self(0x4D43_4547); // "MCEG"
    pub const MC_ECDH_FINISH: Self = Self(0x4D43_4546); // "MCEF"
    pub const MC_ECDSA_CMK_PUBLIC_KEY: Self = Self(0x4D43_4550); // "MCEP"
    pub const MC_ECDSA_CMK_SIGN: Self = Self(0x4D43_4553); // "MCES"
    pub const MC_ECDSA_CMK_VERIFY: Self = Self(0x4D43_4556); // "MCEV"
    pub const MC_ECDSA384_SIG_VERIFY: Self = Self(0x4D45_4356); // "MECV"
    pub const MC_LMS_SIG_VERIFY: Self = Self(0x4D4C_4D56); // "MLMV"

    // MLDSA CMK commands (MML prefix avoids collision with MC_FUSE_INCREASE_CALIPTRA_MIN_SVN "MCMS")
    pub const MC_MLDSA_CMK_PUBLIC_KEY: Self = Self(0x4D4D_4C50); // "MMLP"
    pub const MC_MLDSA_CMK_SIGN: Self = Self(0x4D4D_4C53); // "MMLS"
    pub const MC_MLDSA_CMK_VERIFY: Self = Self(0x4D4D_4C56); // "MMLV"

    // Debug Unlock commands
    pub const MC_PROD_DEBUG_UNLOCK_REQ: Self = Self(0x4D50_5552); // "MPUR"
    pub const MC_PROD_DEBUG_UNLOCK_TOKEN: Self = Self(0x4D50_5554); // "MPUT"

    // In-Field Fuse Programming commands
    pub const MC_FUSE_READ: Self = Self(0x4946_5052); // "IFPR"
    pub const MC_FUSE_WRITE: Self = Self(0x4946_5057); // "IFPW"
    pub const MC_FUSE_LOCK_PARTITION: Self = Self(0x4946_504B); // "IFPK"

    // Authorized commands
    pub const MC_GET_AUTH_CMD_CHALLENGE: Self = Self(0x4D414343); // "MACC"
    pub const MC_PROVISION_VENDOR_PK_HASH: Self = Self(0x5056_504b); // "PVPK"
    pub const MC_PROVISION_OWNER_PK_HASH: Self = Self(0x504F_504B); // "POPK"
    pub const MC_FUSE_INCREASE_CALIPTRA_MIN_SVN: Self = Self(0x4D43_4D53); // "MCMS"
    pub const MC_FE_PROG: Self = Self(0x4D43_4650); // "MCFP"
    pub const MC_FUSE_REVOKE_VENDOR_PUB_KEY: Self = Self(0x4D52_564B); // "MRVK"
    pub const MC_FUSE_REVOKE_VENDOR_PK_HASH: Self = Self(0x5256_4b48); // "RVKH"

    // Certificate commands
    pub const MC_EXPORT_ATTESTED_CSR: Self = Self(0x4D45_4143); // "MEAC"

    // Attestation commands
    pub const MC_GET_ATTESTATION: Self = Self(0x4D47_4154); // "MGAT"

    // The outer family ID is used as the MCI command and authorization domain.
    // The FourCC values below are little-endian u32 subcommands in its payload.
    pub const MC_DEVICE_OWNERSHIP_TRANSFER: Self = Self(0x0000_0011);
    pub const MC_DOT_LOCK: Self = Self(0x4D44_4C4B); // "MDLK"
    pub const MC_DOT_DISABLE: Self = Self(0x4D44_4453); // "MDDS"
    pub const MC_DOT_ROTATE: Self = Self(0x4D44_5254); // "MDRT"
    pub const MC_DOT_RECOVERY: Self = Self(0x4D44_5243); // "MDRC"
    pub const MC_DOT_STATUS: Self = Self(0x4D44_5354); // "MDST"
    pub const MC_DOT_UNLOCK_CHALLENGE: Self = Self(0x4D44_5543); // "MDUC"
    pub const MC_DOT_UNLOCK: Self = Self(0x4D44_554C); // "MDUL"
    pub const MC_GET_DOT_BACKUP_BLOB: Self = Self(0x4D44_4242); // "MDBB"
    pub const MC_DOT_OVERRIDE_CHALLENGE: Self = Self(0x444F_5457); // "DOTW"
    pub const MC_DOT_OVERRIDE: Self = Self(0x444F_5458); // "DOTX"
}

impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}
// Contains all the possible MCU mailbox request structs
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum McuMailboxReq {
    FirmwareVersion(FirmwareVersionReq),
    DeviceCaps(DeviceCapsReq),
    GetLog(GetLogReq),
    ClearLog(ClearLogReq),
    FipsSelfTestStart(McuFipsSelfTestStartReq),
    FipsSelfTestGetResults(McuFipsSelfTestGetResultsReq),
    FipsPeriodicEnable(McuFipsPeriodicEnableReq),
    FipsPeriodicStatus(McuFipsPeriodicStatusReq),
    ShaInit(McuShaInitReq),
    ShaUpdate(McuShaUpdateReq),
    ShaFinal(McuShaFinalReq),
    Hmac(McuHmacReq),
    HmacKdfCounter(McuHmacKdfCounterReq),
    HkdfExtract(McuHkdfExtractReq),
    HkdfExpand(McuHkdfExpandReq),
    AesEncryptInit(McuAesEncryptInitReq),
    AesEncryptUpdate(McuAesEncryptUpdateReq),
    AesDecryptInit(McuAesDecryptInitReq),
    AesDecryptUpdate(McuAesDecryptUpdateReq),
    AesGcmEncryptInit(McuAesGcmEncryptInitReq),
    AesGcmEncryptUpdate(McuAesGcmEncryptUpdateReq),
    AesGcmEncryptFinal(McuAesGcmEncryptFinalReq),
    AesGcmDecryptInit(McuAesGcmDecryptInitReq),
    AesGcmDecryptUpdate(McuAesGcmDecryptUpdateReq),
    AesGcmDecryptFinal(McuAesGcmDecryptFinalReq),
    Import(McuCmImportReq),
    Delete(McuCmDeleteReq),
    CmStatus(McuCmStatusReq),
    RandomStir(McuRandomStirReq),
    RandomGenerate(McuRandomGenerateReq),
    EcdhGenerate(McuEcdhGenerateReq),
    EcdhFinish(McuEcdhFinishReq),
    EcdsaCmkPublicKey(McuEcdsaCmkPublicKeyReq),
    EcdsaCmkSign(McuEcdsaCmkSignReq),
    EcdsaCmkVerify(McuEcdsaCmkVerifyReq),
    Ecdsa384SigVerify(McuEcdsa384SigVerifyReq),
    LmsSigVerify(McuLmsSigVerifyReq),
    MldsaCmkPublicKey(McuMldsaCmkPublicKeyReq),
    MldsaCmkSign(McuMldsaCmkSignReq),
    MldsaCmkVerify(McuMldsaCmkVerifyReq),
    // Debug Unlock
    ProdDebugUnlockReq(McuProdDebugUnlockReqReq),
    ProdDebugUnlockToken(McuProdDebugUnlockTokenReq),
    // In-Field Fuse Programming
    FuseRead(FuseReadReq),
    FuseWrite(FuseWriteReq),
    FuseLockPartition(FuseLockPartitionReq),
    FuseIncreaseCaliptraMinSvn(FuseIncreaseCaliptraMinSvnReq),
    FeProg(McuFeProgReq),
    GetAuthCmdChallenge(GetAuthCmdChallengeReq),
    FuseRevokeVendorPubKey(FuseRevokeVendorPubKeyReq),
    ProvisionVendorPkHash(ProvisionVendorPkHashReq),
    ProvisionOwnerPkHash(ProvisionOwnerPkHashReq),
    FuseRevokeVendorPkHash(FuseRevokeVendorPkHashReq),
    // Certificate commands
    ExportAttestedCsr(ExportAttestedCsrReq),
    GetAttestation(GetAttestationReq),
    // Device Ownership Transfer commands
    DotLock(DotLockReq),
    DotDisable(DotDisableReq),
    DotRotate(DotRotateReq),
    DotRecovery(DotRecoveryReq),
    DotStatus(DotStatusReq),
    DotOverrideChallenge(DotOverrideChallengeReq),
    DotOverride(DotOverrideReq),
    DotUnlockChallenge(DotUnlockChallengeReq),
    DotUnlock(DotUnlockReq),
    GetDotBackupBlob(GetDotBackupBlobReq),
}

impl McuMailboxReq {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_bytes()),
            McuMailboxReq::DeviceCaps(req) => Ok(req.as_bytes()),
            McuMailboxReq::GetLog(req) => Ok(req.as_bytes()),
            McuMailboxReq::ClearLog(req) => Ok(req.as_bytes()),
            McuMailboxReq::FipsSelfTestStart(req) => Ok(req.as_bytes()),
            McuMailboxReq::FipsSelfTestGetResults(req) => Ok(req.as_bytes()),
            McuMailboxReq::FipsPeriodicEnable(req) => Ok(req.as_bytes()),
            McuMailboxReq::FipsPeriodicStatus(req) => Ok(req.as_bytes()),
            McuMailboxReq::ShaInit(req) => req.as_bytes_partial(),
            McuMailboxReq::ShaUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::ShaFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::Hmac(req) => req.as_bytes_partial(),
            McuMailboxReq::HmacKdfCounter(req) => req.as_bytes_partial(),
            McuMailboxReq::HkdfExtract(req) => Ok(req.as_bytes()),
            McuMailboxReq::HkdfExpand(req) => req.as_bytes_partial(),
            McuMailboxReq::AesEncryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesEncryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesDecryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesDecryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmEncryptFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptInit(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptUpdate(req) => req.as_bytes_partial(),
            McuMailboxReq::AesGcmDecryptFinal(req) => req.as_bytes_partial(),
            McuMailboxReq::Import(req) => req.as_bytes_partial(),
            McuMailboxReq::Delete(req) => Ok(req.as_bytes()),
            McuMailboxReq::CmStatus(req) => Ok(req.as_bytes()),
            McuMailboxReq::RandomStir(req) => req.as_bytes_partial(),
            McuMailboxReq::RandomGenerate(req) => Ok(req.as_bytes()),
            McuMailboxReq::EcdhGenerate(req) => Ok(req.as_bytes()),
            McuMailboxReq::EcdhFinish(req) => Ok(req.as_bytes()),
            McuMailboxReq::EcdsaCmkPublicKey(req) => Ok(req.as_bytes()),
            McuMailboxReq::EcdsaCmkSign(req) => req.as_bytes_partial(),
            McuMailboxReq::EcdsaCmkVerify(req) => req.as_bytes_partial(),
            McuMailboxReq::Ecdsa384SigVerify(req) => Ok(req.as_bytes()),
            McuMailboxReq::LmsSigVerify(req) => Ok(req.as_bytes()),
            McuMailboxReq::MldsaCmkPublicKey(req) => Ok(req.as_bytes()),
            McuMailboxReq::MldsaCmkSign(req) => req.as_bytes_partial(),
            McuMailboxReq::MldsaCmkVerify(req) => req.as_bytes_partial(),
            McuMailboxReq::ProdDebugUnlockReq(req) => Ok(req.as_bytes()),
            McuMailboxReq::ProdDebugUnlockToken(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseRead(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseWrite(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseLockPartition(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseIncreaseCaliptraMinSvn(req) => Ok(req.as_bytes()),
            McuMailboxReq::FeProg(req) => Ok(req.as_bytes()),
            McuMailboxReq::GetAuthCmdChallenge(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseRevokeVendorPubKey(req) => Ok(req.as_bytes()),
            McuMailboxReq::ProvisionVendorPkHash(req) => Ok(req.as_bytes()),
            McuMailboxReq::ProvisionOwnerPkHash(req) => Ok(req.as_bytes()),
            McuMailboxReq::FuseRevokeVendorPkHash(req) => Ok(req.as_bytes()),
            McuMailboxReq::ExportAttestedCsr(req) => Ok(req.as_bytes()),
            McuMailboxReq::GetAttestation(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotLock(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotDisable(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotRotate(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotRecovery(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotStatus(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotOverrideChallenge(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotOverride(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotUnlockChallenge(req) => Ok(req.as_bytes()),
            McuMailboxReq::DotUnlock(req) => Ok(req.as_bytes()),
            McuMailboxReq::GetDotBackupBlob(req) => Ok(req.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxReq::FirmwareVersion(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DeviceCaps(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::GetLog(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ClearLog(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FipsSelfTestStart(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FipsSelfTestGetResults(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FipsPeriodicEnable(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FipsPeriodicStatus(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ShaInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::ShaUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::ShaFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Hmac(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::HmacKdfCounter(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::HkdfExtract(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::HkdfExpand(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesEncryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesEncryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesDecryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesDecryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmEncryptFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptInit(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptUpdate(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::AesGcmDecryptFinal(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Import(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Delete(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::CmStatus(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::RandomStir(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::RandomGenerate(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::EcdhGenerate(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::EcdhFinish(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::EcdsaCmkPublicKey(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::EcdsaCmkSign(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::EcdsaCmkVerify(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::Ecdsa384SigVerify(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::LmsSigVerify(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::MldsaCmkPublicKey(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::MldsaCmkSign(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::MldsaCmkVerify(req) => req.as_bytes_partial_mut(),
            McuMailboxReq::ProdDebugUnlockReq(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ProdDebugUnlockToken(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseRead(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseWrite(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseLockPartition(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseIncreaseCaliptraMinSvn(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FeProg(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::GetAuthCmdChallenge(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseRevokeVendorPubKey(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ProvisionVendorPkHash(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ProvisionOwnerPkHash(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::FuseRevokeVendorPkHash(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::ExportAttestedCsr(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::GetAttestation(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotLock(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotDisable(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotRotate(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotRecovery(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotStatus(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotOverrideChallenge(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotOverride(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotUnlockChallenge(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::DotUnlock(req) => Ok(req.as_mut_bytes()),
            McuMailboxReq::GetDotBackupBlob(req) => Ok(req.as_mut_bytes()),
        }
    }

    pub fn cmd_code(&self) -> CommandId {
        match self {
            McuMailboxReq::FirmwareVersion(_) => CommandId::MC_FIRMWARE_VERSION,
            McuMailboxReq::DeviceCaps(_) => CommandId::MC_DEVICE_CAPABILITIES,
            McuMailboxReq::GetLog(_) => CommandId::MC_GET_LOG,
            McuMailboxReq::ClearLog(_) => CommandId::MC_CLEAR_LOG,
            McuMailboxReq::FipsSelfTestStart(_) => CommandId::MC_FIPS_SELF_TEST_START,
            McuMailboxReq::FipsSelfTestGetResults(_) => CommandId::MC_FIPS_SELF_TEST_GET_RESULTS,
            McuMailboxReq::FipsPeriodicEnable(_) => CommandId::MC_FIPS_PERIODIC_ENABLE,
            McuMailboxReq::FipsPeriodicStatus(_) => CommandId::MC_FIPS_PERIODIC_STATUS,
            McuMailboxReq::ShaInit(_) => CommandId::MC_SHA_INIT,
            McuMailboxReq::ShaUpdate(_) => CommandId::MC_SHA_UPDATE,
            McuMailboxReq::ShaFinal(_) => CommandId::MC_SHA_FINAL,
            McuMailboxReq::Hmac(_) => CommandId::MC_HMAC,
            McuMailboxReq::HmacKdfCounter(_) => CommandId::MC_HMAC_KDF_COUNTER,
            McuMailboxReq::HkdfExtract(_) => CommandId::MC_HKDF_EXTRACT,
            McuMailboxReq::HkdfExpand(_) => CommandId::MC_HKDF_EXPAND,
            McuMailboxReq::AesEncryptInit(_) => CommandId::MC_AES_ENCRYPT_INIT,
            McuMailboxReq::AesEncryptUpdate(_) => CommandId::MC_AES_ENCRYPT_UPDATE,
            McuMailboxReq::AesDecryptInit(_) => CommandId::MC_AES_DECRYPT_INIT,
            McuMailboxReq::AesDecryptUpdate(_) => CommandId::MC_AES_DECRYPT_UPDATE,
            McuMailboxReq::AesGcmEncryptInit(_) => CommandId::MC_AES_GCM_ENCRYPT_INIT,
            McuMailboxReq::AesGcmEncryptUpdate(_) => CommandId::MC_AES_GCM_ENCRYPT_UPDATE,
            McuMailboxReq::AesGcmEncryptFinal(_) => CommandId::MC_AES_GCM_ENCRYPT_FINAL,
            McuMailboxReq::AesGcmDecryptInit(_) => CommandId::MC_AES_GCM_DECRYPT_INIT,
            McuMailboxReq::AesGcmDecryptUpdate(_) => CommandId::MC_AES_GCM_DECRYPT_UPDATE,
            McuMailboxReq::AesGcmDecryptFinal(_) => CommandId::MC_AES_GCM_DECRYPT_FINAL,
            McuMailboxReq::Import(_) => CommandId::MC_IMPORT,
            McuMailboxReq::Delete(_) => CommandId::MC_DELETE,
            McuMailboxReq::CmStatus(_) => CommandId::MC_CM_STATUS,
            McuMailboxReq::RandomStir(_) => CommandId::MC_RANDOM_STIR,
            McuMailboxReq::RandomGenerate(_) => CommandId::MC_RANDOM_GENERATE,
            McuMailboxReq::EcdhGenerate(_) => CommandId::MC_ECDH_GENERATE,
            McuMailboxReq::EcdhFinish(_) => CommandId::MC_ECDH_FINISH,
            McuMailboxReq::EcdsaCmkPublicKey(_) => CommandId::MC_ECDSA_CMK_PUBLIC_KEY,
            McuMailboxReq::EcdsaCmkSign(_) => CommandId::MC_ECDSA_CMK_SIGN,
            McuMailboxReq::EcdsaCmkVerify(_) => CommandId::MC_ECDSA_CMK_VERIFY,
            McuMailboxReq::Ecdsa384SigVerify(_) => CommandId::MC_ECDSA384_SIG_VERIFY,
            McuMailboxReq::LmsSigVerify(_) => CommandId::MC_LMS_SIG_VERIFY,
            McuMailboxReq::MldsaCmkPublicKey(_) => CommandId::MC_MLDSA_CMK_PUBLIC_KEY,
            McuMailboxReq::MldsaCmkSign(_) => CommandId::MC_MLDSA_CMK_SIGN,
            McuMailboxReq::MldsaCmkVerify(_) => CommandId::MC_MLDSA_CMK_VERIFY,
            McuMailboxReq::ProdDebugUnlockReq(_) => CommandId::MC_PROD_DEBUG_UNLOCK_REQ,
            McuMailboxReq::ProdDebugUnlockToken(_) => CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN,
            McuMailboxReq::FuseRead(_) => CommandId::MC_FUSE_READ,
            McuMailboxReq::FuseWrite(_) => CommandId::MC_FUSE_WRITE,
            McuMailboxReq::FuseLockPartition(_) => CommandId::MC_FUSE_LOCK_PARTITION,
            McuMailboxReq::FuseIncreaseCaliptraMinSvn(_) => {
                CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN
            }
            McuMailboxReq::FeProg(_) => CommandId::MC_FE_PROG,
            McuMailboxReq::GetAuthCmdChallenge(_) => CommandId::MC_GET_AUTH_CMD_CHALLENGE,
            McuMailboxReq::FuseRevokeVendorPubKey(_) => CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY,
            McuMailboxReq::ProvisionVendorPkHash(_) => CommandId::MC_PROVISION_VENDOR_PK_HASH,
            McuMailboxReq::ProvisionOwnerPkHash(_) => CommandId::MC_PROVISION_OWNER_PK_HASH,
            McuMailboxReq::FuseRevokeVendorPkHash(_) => CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH,
            McuMailboxReq::ExportAttestedCsr(_) => CommandId::MC_EXPORT_ATTESTED_CSR,
            McuMailboxReq::GetAttestation(_) => CommandId::MC_GET_ATTESTATION,
            McuMailboxReq::DotLock(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotDisable(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotRotate(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotRecovery(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotStatus(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotOverrideChallenge(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotOverride(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotUnlockChallenge(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::DotUnlock(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
            McuMailboxReq::GetDotBackupBlob(_) => CommandId::MC_DEVICE_OWNERSHIP_TRANSFER,
        }
    }

    // Calculate and set the checksum for a request payload
    pub fn populate_chksum(&mut self) -> McuMboxResult<()> {
        // Calc checksum, use the size override if provided
        let checksum = calc_checksum(
            self.cmd_code().into(),
            &self.as_bytes()?[size_of::<i32>()..],
        );

        let hdr: &mut MailboxReqHeader = MailboxReqHeader::mut_from_bytes(
            &mut self.as_mut_bytes()?[..size_of::<MailboxReqHeader>()],
        )
        .map_err(|_| McuMboxError::MCU_RUNTIME_INSUFFICIENT_MEMORY)?;

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

// Contains all the possible MCU mailbox response structs
#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum McuMailboxResp {
    Header(MailboxRespHeader),
    FirmwareVersion(FirmwareVersionResp),
    DeviceCaps(DeviceCapsResp),
    GetLog(GetLogResp),
    ClearLog(ClearLogResp),
    FipsSelfTestStart(McuFipsSelfTestStartResp),
    FipsSelfTestGetResults(McuFipsSelfTestGetResultsResp),
    FipsPeriodicEnable(McuFipsPeriodicEnableResp),
    FipsPeriodicStatus(McuFipsPeriodicStatusResp),
    ShaInit(McuShaInitResp),
    ShaUpdate(McuShaInitResp),
    ShaFinal(McuShaFinalResp),
    Hmac(McuHmacResp),
    HmacKdfCounter(McuHmacKdfCounterResp),
    HkdfExtract(McuHkdfExtractResp),
    HkdfExpand(McuHkdfExpandResp),
    AesEncryptInit(McuAesEncryptInitResp),
    AesEncryptUpdate(McuAesEncryptUpdateResp),
    AesDecryptInit(McuAesDecryptInitResp),
    AesDecryptUpdate(McuAesDecryptUpdateResp),
    AesGcmEncryptInit(McuAesGcmEncryptInitResp),
    AesGcmEncryptUpdate(McuAesGcmEncryptUpdateResp),
    AesGcmEncryptFinal(McuAesGcmEncryptFinalResp),
    AesGcmDecryptInit(McuAesGcmDecryptInitResp),
    AesGcmDecryptUpdate(McuAesGcmDecryptUpdateResp),
    AesGcmDecryptFinal(McuAesGcmDecryptFinalResp),
    Import(McuCmImportResp),
    Delete(McuCmDeleteResp),
    CmStatus(McuCmStatusResp),
    RandomStir(McuRandomStirResp),
    RandomGenerate(McuRandomGenerateResp),
    EcdhGenerate(McuEcdhGenerateResp),
    EcdhFinish(McuEcdhFinishResp),
    EcdsaCmkPublicKey(McuEcdsaCmkPublicKeyResp),
    EcdsaCmkSign(McuEcdsaCmkSignResp),
    EcdsaCmkVerify(McuEcdsaCmkVerifyResp),
    Ecdsa384SigVerify(McuEcdsa384SigVerifyResp),
    LmsSigVerify(McuLmsSigVerifyResp),
    MldsaCmkPublicKey(McuMldsaCmkPublicKeyResp),
    MldsaCmkSign(McuMldsaCmkSignResp),
    MldsaCmkVerify(McuMldsaCmkVerifyResp),
    // Debug Unlock
    ProdDebugUnlockReq(McuProdDebugUnlockReqResp),
    ProdDebugUnlockToken(McuProdDebugUnlockTokenResp),
    // In-Field Fuse Programming
    FuseRead(FuseReadResp),
    FuseWrite(FuseWriteResp),
    FuseLockPartition(FuseLockPartitionResp),
    GetAuthCmdChallenge(GetAuthCmdChallengeResp),
    FuseRevokeVendorPubKey(FuseRevokeVendorPubKeyResp),
    ProvisionVendorPkHash(ProvisionVendorPkHashResp),
    ProvisionOwnerPkHash(ProvisionOwnerPkHashResp),
    FuseRevokeVendorPkHash(FuseRevokeVendorPkHashResp),
    // Certificate commands
    ExportAttestedCsr(ExportAttestedCsrResp),
    // Device Ownership Transfer commands
    DotLock(DotLockResp),
    DotDisable(DotDisableResp),
    DotRotate(DotRotateResp),
    DotRecovery(DotRecoveryResp),
    DotStatus(DotStatusResp),
    DotOverrideChallenge(DotOverrideChallengeResp),
    DotOverride(DotOverrideResp),
    DotUnlockChallenge(DotUnlockChallengeResp),
    DotUnlock(DotUnlockResp),
    GetDotBackupBlob(GetDotBackupBlobResp),
}

/// A trait for responses with variable size data.
pub trait McuResponseVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn data(&self) -> McuMboxResult<&[u8]> {
        let (hdr, data) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)?;
        data.get(..hdr.data_len as usize)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn partial_len(&self) -> McuMboxResult<usize> {
        let (hdr, _) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)?;
        Ok(core::mem::size_of::<MailboxRespHeaderVarSize>() + hdr.data_len as usize)
    }

    fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
        self.as_bytes()
            .get(..self.partial_len()?)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }

    fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
        let partial_len = self.partial_len()?;
        self.as_mut_bytes()
            .get_mut(..partial_len)
            .ok_or(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
    }
}
impl<T: McuResponseVarSize> Response for T {
    const MIN_SIZE: usize = core::mem::size_of::<MailboxRespHeaderVarSize>();
}

// Macro to implement McuResponseVarSize for tuple response wrappers
macro_rules! impl_mcu_response_varsize {
    ($wrapper:ty, $inner:ty) => {
        impl McuResponseVarSize for $wrapper {
            fn data(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .data()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn partial_len(&self) -> McuMboxResult<usize> {
                self.0
                    .partial_len()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .as_bytes_partial()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
                self.0
                    .as_bytes_partial_mut()
                    .map_err(|_| McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_LARGE)
            }
        }
    };
}

impl McuMailboxResp {
    pub fn as_bytes(&self) -> McuMboxResult<&[u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial(),
            McuMailboxResp::DeviceCaps(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::GetLog(resp) => resp.as_bytes_partial(),
            McuMailboxResp::ClearLog(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FipsSelfTestStart(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FipsSelfTestGetResults(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FipsPeriodicEnable(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FipsPeriodicStatus(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ShaInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ShaUpdate(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ShaFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::Hmac(resp) => resp.as_bytes_partial(),
            McuMailboxResp::HmacKdfCounter(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::HkdfExtract(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::HkdfExpand(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesEncryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesEncryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesDecryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesDecryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmEncryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesGcmEncryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmEncryptFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmDecryptInit(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::AesGcmDecryptUpdate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::AesGcmDecryptFinal(resp) => resp.as_bytes_partial(),
            McuMailboxResp::Import(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::Delete(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::CmStatus(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::RandomStir(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::RandomGenerate(resp) => resp.as_bytes_partial(),
            McuMailboxResp::EcdhGenerate(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::EcdhFinish(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::EcdsaCmkPublicKey(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::EcdsaCmkSign(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::EcdsaCmkVerify(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::Ecdsa384SigVerify(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::LmsSigVerify(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::MldsaCmkPublicKey(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::MldsaCmkSign(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::MldsaCmkVerify(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ProdDebugUnlockReq(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ProdDebugUnlockToken(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FuseRead(resp) => resp.as_bytes_partial(),
            McuMailboxResp::FuseWrite(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FuseLockPartition(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::GetAuthCmdChallenge(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FuseRevokeVendorPubKey(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ProvisionVendorPkHash(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ProvisionOwnerPkHash(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::FuseRevokeVendorPkHash(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::ExportAttestedCsr(resp) => resp.as_bytes_partial(),
            McuMailboxResp::DotLock(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotDisable(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotRotate(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotRecovery(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotStatus(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotOverrideChallenge(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotOverride(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotUnlockChallenge(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::DotUnlock(resp) => Ok(resp.as_bytes()),
            McuMailboxResp::GetDotBackupBlob(resp) => Ok(resp.as_bytes()),
        }
    }

    pub fn as_mut_bytes(&mut self) -> McuMboxResult<&mut [u8]> {
        match self {
            McuMailboxResp::Header(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FirmwareVersion(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::DeviceCaps(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::GetLog(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::ClearLog(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FipsSelfTestStart(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FipsSelfTestGetResults(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FipsPeriodicEnable(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FipsPeriodicStatus(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ShaInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ShaUpdate(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ShaFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::Hmac(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::HmacKdfCounter(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::HkdfExtract(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::HkdfExpand(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmEncryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesGcmEncryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmEncryptFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmDecryptInit(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::AesGcmDecryptUpdate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::AesGcmDecryptFinal(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::Import(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::Delete(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::CmStatus(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::RandomStir(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::RandomGenerate(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::EcdhGenerate(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::EcdhFinish(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::EcdsaCmkPublicKey(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::EcdsaCmkSign(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::EcdsaCmkVerify(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::Ecdsa384SigVerify(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::LmsSigVerify(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::MldsaCmkPublicKey(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::MldsaCmkSign(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::MldsaCmkVerify(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ProdDebugUnlockReq(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ProdDebugUnlockToken(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FuseRead(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::FuseWrite(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FuseLockPartition(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::GetAuthCmdChallenge(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FuseRevokeVendorPubKey(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ProvisionVendorPkHash(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ProvisionOwnerPkHash(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::FuseRevokeVendorPkHash(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::ExportAttestedCsr(resp) => resp.as_bytes_partial_mut(),
            McuMailboxResp::DotLock(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotDisable(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotRotate(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotRecovery(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotStatus(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotOverrideChallenge(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotOverride(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotUnlockChallenge(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::DotUnlock(resp) => Ok(resp.as_mut_bytes()),
            McuMailboxResp::GetDotBackupBlob(resp) => Ok(resp.as_mut_bytes()),
        }
    }

    /// Calculate and set the checksum for a response payload.
    pub fn populate_chksum(&mut self) -> McuMboxResult<()> {
        // Calc checksum, use the size override if provided
        let resp_bytes = self.as_bytes()?;
        if size_of::<u32>() >= resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT);
        }
        let checksum = calc_checksum(0, &resp_bytes[size_of::<u32>()..]);

        let mut_resp_bytes = self.as_mut_bytes()?;
        if size_of::<MailboxRespHeader>() > mut_resp_bytes.len() {
            return Err(McuMboxError::MCU_MBOX_RESPONSE_DATA_LEN_TOO_SHORT);
        }
        let hdr: &mut MailboxRespHeader = MailboxRespHeader::mut_from_bytes(
            &mut mut_resp_bytes[..size_of::<MailboxRespHeader>()],
        )
        .map_err(|_| McuMboxError::MCU_RUNTIME_INSUFFICIENT_MEMORY)?;

        // Set the chksum field
        hdr.chksum = checksum;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FwIndex {
    CaliptraCore,
    McuRuntime,
    SoC,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVersionReq {
    pub hdr: MailboxReqHeader,
    pub index: u32,
}
impl Request for FirmwareVersionReq {
    const ID: CommandId = CommandId::MC_FIRMWARE_VERSION;
    type Resp = FirmwareVersionResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct FirmwareVersionResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub version: [u8; MAX_FW_VERSION_STR_LEN], // variable length
}
impl McuResponseVarSize for FirmwareVersionResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceCapsReq {
    pub hdr: MailboxReqHeader,
}
impl Request for DeviceCapsReq {
    const ID: CommandId = CommandId::MC_DEVICE_CAPABILITIES;
    type Resp = DeviceCapsResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct DeviceCapsResp {
    pub hdr: MailboxRespHeader,
    pub caps: [u8; DEVICE_CAPS_SIZE],
}

impl Default for DeviceCapsResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            caps: [0u8; DEVICE_CAPS_SIZE],
        }
    }
}

impl Response for DeviceCapsResp {}

#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum LogType {
    DebugLog = 0,
    AttestationLog = 1,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLogReq {
    pub hdr: MailboxReqHeader,
}
impl Request for GetLogReq {
    const ID: CommandId = CommandId::MC_GET_LOG;
    type Resp = GetLogResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetLogResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_RESP_DATA_SIZE], // variable length
}
impl McuResponseVarSize for GetLogResp {}

impl Default for GetLogResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_RESP_DATA_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ClearLogReq {
    pub hdr: MailboxReqHeader,
}
impl Request for ClearLogReq {
    const ID: CommandId = CommandId::MC_CLEAR_LOG;
    type Resp = ClearLogResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ClearLogResp(MailboxRespHeader);
impl Response for ClearLogResp {}

pub trait McuRequestVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn as_bytes_partial(&self) -> McuMboxResult<&[u8]>;
    fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]>;
}

// Macro to implement McuRequestVarSize for tuple wrappers
macro_rules! impl_mcu_request_varsize {
    ($wrapper:ty, $inner:ty) => {
        impl McuRequestVarSize for $wrapper {
            fn as_bytes_partial(&self) -> McuMboxResult<&[u8]> {
                self.0
                    .as_bytes_partial()
                    .map_err(|_| McuMboxError::MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE)
            }
            fn as_bytes_partial_mut(&mut self) -> McuMboxResult<&mut [u8]> {
                self.0
                    .as_bytes_partial_mut()
                    .map_err(|_| McuMboxError::MCU_MBOX_REQUEST_DATA_LEN_TOO_LARGE)
            }
        }
    };
}

// ---- FIPS Self-Test Passthrough ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsSelfTestStartReq(pub MailboxReqHeader);
impl Request for McuFipsSelfTestStartReq {
    const ID: CommandId = CommandId::MC_FIPS_SELF_TEST_START;
    type Resp = McuFipsSelfTestStartResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsSelfTestStartResp(pub MailboxRespHeader);
impl Response for McuFipsSelfTestStartResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsSelfTestGetResultsReq(pub MailboxReqHeader);
impl Request for McuFipsSelfTestGetResultsReq {
    const ID: CommandId = CommandId::MC_FIPS_SELF_TEST_GET_RESULTS;
    type Resp = McuFipsSelfTestGetResultsResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsSelfTestGetResultsResp(pub MailboxRespHeader);
impl Response for McuFipsSelfTestGetResultsResp {}

// ---- Periodic FIPS Self-Test ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsPeriodicEnableReq {
    pub header: MailboxReqHeader,
    /// 0 = disable, 1 = enable periodic FIPS self-test
    pub enable: u32,
}
impl Request for McuFipsPeriodicEnableReq {
    const ID: CommandId = CommandId::MC_FIPS_PERIODIC_ENABLE;
    type Resp = McuFipsPeriodicEnableResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsPeriodicEnableResp(pub MailboxRespHeader);
impl Response for McuFipsPeriodicEnableResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsPeriodicStatusReq(pub MailboxReqHeader);
impl Request for McuFipsPeriodicStatusReq {
    const ID: CommandId = CommandId::MC_FIPS_PERIODIC_STATUS;
    type Resp = McuFipsPeriodicStatusResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFipsPeriodicStatusResp {
    pub header: MailboxRespHeader,
    /// 0 = disabled, 1 = enabled
    pub enabled: u32,
    /// Number of iterations completed
    pub iterations: u32,
    /// Last result: 0 = not run yet, 1 = pass, 2 = fail
    pub last_result: u32,
}
impl Response for McuFipsPeriodicStatusResp {}

// Create a wrapper for ShaInitReq. MCU mailbox sha init request is the same format of CmShaInitReq
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuShaInitReq(pub CmShaInitReq);

impl Request for McuShaInitReq {
    const ID: CommandId = CommandId::MC_SHA_INIT;
    type Resp = McuShaInitResp;
}
impl_mcu_request_varsize!(McuShaInitReq, CmShaInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuShaInitResp(pub CmShaInitResp);
impl Response for McuShaInitResp {}

// Add ShaUpdateReq and ShaFinalReq similar to McuShaInitReq if needed in the future
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaUpdateReq(pub CmShaUpdateReq);
impl Request for McuShaUpdateReq {
    const ID: CommandId = CommandId::MC_SHA_UPDATE;
    type Resp = McuShaInitResp; // Same response as ShaInit
}
impl_mcu_request_varsize!(McuShaUpdateReq, CmShaUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaFinalReq(pub CmShaFinalReq);
impl Request for McuShaFinalReq {
    const ID: CommandId = CommandId::MC_SHA_FINAL;
    type Resp = McuShaFinalResp;
}
impl_mcu_request_varsize!(McuShaFinalReq, CmShaFinalReq);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct McuShaFinalResp(pub CmShaFinalResp);
impl_mcu_response_varsize!(McuShaFinalResp, CmShaFinalResp);

// ---- HMAC wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHmacReq(pub CmHmacReq);
impl Request for McuHmacReq {
    const ID: CommandId = CommandId::MC_HMAC;
    type Resp = McuHmacResp;
}
impl_mcu_request_varsize!(McuHmacReq, CmHmacReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHmacResp(pub CmHmacResp);
impl_mcu_response_varsize!(McuHmacResp, CmHmacResp);

// ---- HMAC KDF Counter wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHmacKdfCounterReq(pub CmHmacKdfCounterReq);
impl Request for McuHmacKdfCounterReq {
    const ID: CommandId = CommandId::MC_HMAC_KDF_COUNTER;
    type Resp = McuHmacKdfCounterResp;
}
impl_mcu_request_varsize!(McuHmacKdfCounterReq, CmHmacKdfCounterReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHmacKdfCounterResp(pub CmHmacKdfCounterResp);
impl Response for McuHmacKdfCounterResp {}

// ---- HKDF Extract wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHkdfExtractReq(pub CmHkdfExtractReq);
impl Request for McuHkdfExtractReq {
    const ID: CommandId = CommandId::MC_HKDF_EXTRACT;
    type Resp = McuHkdfExtractResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHkdfExtractResp(pub CmHkdfExtractResp);
impl Response for McuHkdfExtractResp {}

// ---- HKDF Expand wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHkdfExpandReq(pub CmHkdfExpandReq);
impl Request for McuHkdfExpandReq {
    const ID: CommandId = CommandId::MC_HKDF_EXPAND;
    type Resp = McuHkdfExpandResp;
}
impl_mcu_request_varsize!(McuHkdfExpandReq, CmHkdfExpandReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuHkdfExpandResp(pub CmHkdfExpandResp);
impl Response for McuHkdfExpandResp {}

// ---- AES Encrypt/Decrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptInitReq(pub CmAesEncryptInitReq);
impl Request for McuAesEncryptInitReq {
    const ID: CommandId = CommandId::MC_AES_ENCRYPT_INIT;
    type Resp = McuAesEncryptInitResp;
}
impl_mcu_request_varsize!(McuAesEncryptInitReq, CmAesEncryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptInitResp(pub CmAesEncryptInitResp);
impl Response for McuAesEncryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptUpdateReq(pub CmAesEncryptUpdateReq);
impl Request for McuAesEncryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_ENCRYPT_UPDATE;
    type Resp = McuAesEncryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesEncryptUpdateReq, CmAesEncryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesEncryptUpdateResp(pub CmAesResp);
impl_mcu_response_varsize!(McuAesEncryptUpdateResp, CmAesResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptInitReq(pub CmAesDecryptInitReq);
impl Request for McuAesDecryptInitReq {
    const ID: CommandId = CommandId::MC_AES_DECRYPT_INIT;
    type Resp = McuAesDecryptInitResp;
}
impl_mcu_request_varsize!(McuAesDecryptInitReq, CmAesDecryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptInitResp(pub CmAesEncryptInitResp); // Reuse encrypt init resp if needed
impl Response for McuAesDecryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptUpdateReq(pub CmAesDecryptUpdateReq);
impl Request for McuAesDecryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_DECRYPT_UPDATE;
    type Resp = McuAesDecryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesDecryptUpdateReq, CmAesDecryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesDecryptUpdateResp(pub CmAesResp); // Reuse encrypt update resp if needed
impl_mcu_response_varsize!(McuAesDecryptUpdateResp, CmAesResp);

// ---- AES-GCM Encrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptInitReq(pub CmAesGcmEncryptInitReq);
impl Request for McuAesGcmEncryptInitReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_INIT;
    type Resp = McuAesGcmEncryptInitResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptInitReq, CmAesGcmEncryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptInitResp(pub CmAesGcmEncryptInitResp);
impl Response for McuAesGcmEncryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptUpdateReq(pub CmAesGcmEncryptUpdateReq);
impl Request for McuAesGcmEncryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_UPDATE;
    type Resp = McuAesGcmEncryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptUpdateResp(pub CmAesGcmEncryptUpdateResp);
impl_mcu_response_varsize!(McuAesGcmEncryptUpdateResp, CmAesGcmEncryptUpdateResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptFinalReq(pub CmAesGcmEncryptFinalReq);
impl Request for McuAesGcmEncryptFinalReq {
    const ID: CommandId = CommandId::MC_AES_GCM_ENCRYPT_FINAL;
    type Resp = McuAesGcmEncryptFinalResp;
}
impl_mcu_request_varsize!(McuAesGcmEncryptFinalReq, CmAesGcmEncryptFinalReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmEncryptFinalResp(pub CmAesGcmEncryptFinalResp);
impl_mcu_response_varsize!(McuAesGcmEncryptFinalResp, CmAesGcmEncryptFinalResp);

// ---- AES-GCM Decrypt wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptInitReq(pub CmAesGcmDecryptInitReq);
impl Request for McuAesGcmDecryptInitReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_INIT;
    type Resp = McuAesGcmDecryptInitResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptInitReq, CmAesGcmDecryptInitReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptInitResp(pub CmAesGcmDecryptInitResp);
impl Response for McuAesGcmDecryptInitResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptUpdateReq(pub CmAesGcmDecryptUpdateReq);
impl Request for McuAesGcmDecryptUpdateReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_UPDATE;
    type Resp = McuAesGcmDecryptUpdateResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptUpdateResp(pub CmAesGcmDecryptUpdateResp);
impl_mcu_response_varsize!(McuAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateResp);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptFinalReq(pub CmAesGcmDecryptFinalReq);
impl Request for McuAesGcmDecryptFinalReq {
    const ID: CommandId = CommandId::MC_AES_GCM_DECRYPT_FINAL;
    type Resp = McuAesGcmDecryptFinalResp;
}
impl_mcu_request_varsize!(McuAesGcmDecryptFinalReq, CmAesGcmDecryptFinalReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuAesGcmDecryptFinalResp(pub CmAesGcmDecryptFinalResp);
impl_mcu_response_varsize!(McuAesGcmDecryptFinalResp, CmAesGcmDecryptFinalResp);

// ---- MCU wrappers for Import, RandomStir, RandomGenerate ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmImportReq(pub CmImportReq);
impl Request for McuCmImportReq {
    const ID: CommandId = CommandId::MC_IMPORT;
    type Resp = McuCmImportResp;
}
impl_mcu_request_varsize!(McuCmImportReq, CmImportReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmImportResp(pub CmImportResp);
impl Response for McuCmImportResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmDeleteReq(pub CmDeleteReq);
impl Request for McuCmDeleteReq {
    const ID: CommandId = CommandId::MC_DELETE;
    type Resp = McuCmDeleteResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmStatusReq(pub MailboxReqHeader);
impl Request for McuCmStatusReq {
    const ID: CommandId = CommandId::MC_CM_STATUS;
    type Resp = McuCmStatusResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmStatusResp(pub CmStatusResp);
impl Response for McuCmStatusResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuCmDeleteResp(pub MailboxRespHeader);
impl Response for McuCmDeleteResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomStirReq(pub CmRandomStirReq);
impl Request for McuRandomStirReq {
    const ID: CommandId = CommandId::MC_RANDOM_STIR;
    type Resp = McuRandomStirResp;
}
impl_mcu_request_varsize!(McuRandomStirReq, CmRandomStirReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomStirResp(pub MailboxRespHeader);
impl Response for McuRandomStirResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomGenerateReq(pub CmRandomGenerateReq);
impl Request for McuRandomGenerateReq {
    const ID: CommandId = CommandId::MC_RANDOM_GENERATE;
    type Resp = McuRandomGenerateResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuRandomGenerateResp(pub CmRandomGenerateResp);
impl_mcu_response_varsize!(McuRandomGenerateResp, CmRandomGenerateResp);

// ---- ECDH wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdhGenerateReq(pub CmEcdhGenerateReq);
impl Request for McuEcdhGenerateReq {
    const ID: CommandId = CommandId::MC_ECDH_GENERATE;
    type Resp = McuEcdhGenerateResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdhGenerateResp(pub CmEcdhGenerateResp);
impl Response for McuEcdhGenerateResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdhFinishReq(pub CmEcdhFinishReq);
impl Request for McuEcdhFinishReq {
    const ID: CommandId = CommandId::MC_ECDH_FINISH;
    type Resp = McuEcdhFinishResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdhFinishResp(pub CmEcdhFinishResp);
impl Response for McuEcdhFinishResp {}

// ---- ECDSA CMK wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkPublicKeyReq(pub CmEcdsaPublicKeyReq);
impl Request for McuEcdsaCmkPublicKeyReq {
    const ID: CommandId = CommandId::MC_ECDSA_CMK_PUBLIC_KEY;
    type Resp = McuEcdsaCmkPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkPublicKeyResp(pub CmEcdsaPublicKeyResp);
impl Response for McuEcdsaCmkPublicKeyResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkSignReq(pub CmEcdsaSignReq);
impl Request for McuEcdsaCmkSignReq {
    const ID: CommandId = CommandId::MC_ECDSA_CMK_SIGN;
    type Resp = McuEcdsaCmkSignResp;
}
impl_mcu_request_varsize!(McuEcdsaCmkSignReq, CmEcdsaSignReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkSignResp(pub CmEcdsaSignResp);
impl Response for McuEcdsaCmkSignResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkVerifyReq(pub CmEcdsaVerifyReq);
impl Request for McuEcdsaCmkVerifyReq {
    const ID: CommandId = CommandId::MC_ECDSA_CMK_VERIFY;
    type Resp = McuEcdsaCmkVerifyResp;
}
impl_mcu_request_varsize!(McuEcdsaCmkVerifyReq, CmEcdsaVerifyReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsaCmkVerifyResp(pub MailboxRespHeader);
impl Response for McuEcdsaCmkVerifyResp {}

// ---- Raw signature verification passthroughs ----
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsa384SigVerifyReq(pub EcdsaVerifyReq);
impl Request for McuEcdsa384SigVerifyReq {
    const ID: CommandId = CommandId::MC_ECDSA384_SIG_VERIFY;
    type Resp = McuEcdsa384SigVerifyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuEcdsa384SigVerifyResp(pub MailboxRespHeader);
impl Response for McuEcdsa384SigVerifyResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuLmsSigVerifyReq(pub LmsVerifyReq);
impl Request for McuLmsSigVerifyReq {
    const ID: CommandId = CommandId::MC_LMS_SIG_VERIFY;
    type Resp = McuLmsSigVerifyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuLmsSigVerifyResp(pub MailboxRespHeader);
impl Response for McuLmsSigVerifyResp {}

// ---- MLDSA CMK wrappers ----
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkPublicKeyReq(pub CmMldsaPublicKeyReq);
impl Request for McuMldsaCmkPublicKeyReq {
    const ID: CommandId = CommandId::MC_MLDSA_CMK_PUBLIC_KEY;
    type Resp = McuMldsaCmkPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkPublicKeyResp(pub CmMldsaPublicKeyResp);
impl Response for McuMldsaCmkPublicKeyResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkSignReq(pub CmMldsaSignReq);
impl Request for McuMldsaCmkSignReq {
    const ID: CommandId = CommandId::MC_MLDSA_CMK_SIGN;
    type Resp = McuMldsaCmkSignResp;
}
impl_mcu_request_varsize!(McuMldsaCmkSignReq, CmMldsaSignReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkSignResp(pub CmMldsaSignResp);
impl Response for McuMldsaCmkSignResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkVerifyReq(pub CmMldsaVerifyReq);
impl Request for McuMldsaCmkVerifyReq {
    const ID: CommandId = CommandId::MC_MLDSA_CMK_VERIFY;
    type Resp = McuMldsaCmkVerifyResp;
}
impl_mcu_request_varsize!(McuMldsaCmkVerifyReq, CmMldsaVerifyReq);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuMldsaCmkVerifyResp(pub MailboxRespHeader);
impl Response for McuMldsaCmkVerifyResp {}

// ---- Debug Unlock ----

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuProdDebugUnlockReqReq(pub ProductionAuthDebugUnlockReq);
impl Request for McuProdDebugUnlockReqReq {
    const ID: CommandId = CommandId::MC_PROD_DEBUG_UNLOCK_REQ;
    type Resp = McuProdDebugUnlockReqResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuProdDebugUnlockReqResp(pub ProductionAuthDebugUnlockChallenge);
impl Response for McuProdDebugUnlockReqResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuProdDebugUnlockTokenReq {
    pub hdr: MailboxReqHeader,
    pub token: ProductionAuthDebugUnlockToken,
}
impl Request for McuProdDebugUnlockTokenReq {
    const ID: CommandId = CommandId::MC_PROD_DEBUG_UNLOCK_TOKEN;
    type Resp = McuProdDebugUnlockTokenResp;
}

impl Default for McuProdDebugUnlockTokenReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            token: ProductionAuthDebugUnlockToken::new_zeroed(),
        }
    }
}

impl McuProdDebugUnlockTokenReq {
    /// Populate the Caliptra command checksum carried inside the token.
    pub fn populate_caliptra_chksum(&mut self) -> McuMboxResult<()> {
        let token_bytes = self.token.as_bytes();
        let token_body = token_bytes
            .get(size_of::<MailboxReqHeader>()..)
            .ok_or(McuMboxError::MCU_RUNTIME_INSUFFICIENT_MEMORY)?;
        self.token.hdr.chksum = calc_checksum(
            CaliptraCommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN.into(),
            token_body,
        );
        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuProdDebugUnlockTokenResp(pub MailboxRespHeader);
impl Response for McuProdDebugUnlockTokenResp {}

// ---- In-Field Fuse Programming (IFP) ----

/// Maximum size of fuse data in bytes for read/write operations.
/// This should accommodate the largest fuse entry (e.g., 768-bit IDevID cert = 96 bytes).
pub const MAX_FUSE_DATA_SIZE: usize = 128;

/// MC_FUSE_READ request: Read fuse values from a partition entry.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseReadReq {
    pub hdr: MailboxReqHeader,
    /// Partition number to read from
    pub partition: u32,
    /// Entry index within the partition
    pub entry: u32,
}
impl Request for FuseReadReq {
    const ID: CommandId = CommandId::MC_FUSE_READ;
    type Resp = FuseReadResp;
}

/// MC_FUSE_READ response: Returns fuse data with length in bits.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseReadResp {
    pub hdr: MailboxRespHeaderVarSize,
    /// Number of valid bits in the data field
    pub length_bits: u32,
    /// Fuse data (variable length, up to MAX_FUSE_DATA_SIZE bytes)
    pub data: [u8; MAX_FUSE_DATA_SIZE],
}
impl McuResponseVarSize for FuseReadResp {}

impl Default for FuseReadResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            length_bits: 0,
            data: [0u8; MAX_FUSE_DATA_SIZE],
        }
    }
}

/// MC_FUSE_WRITE request: Write fuse values to a partition entry.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct FuseWriteReq {
    pub hdr: MailboxReqHeader,
    /// Word address
    pub word_addr: u32,
    /// Data to write
    pub data: u32,
    /// Bit-Mask to only write specified bits
    pub mask: u32,
}

impl Request for FuseWriteReq {
    const ID: CommandId = CommandId::MC_FUSE_WRITE;
    type Resp = FuseWriteResp;
}

/// MC_FUSE_WRITE response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseWriteResp {
    pub hdr: MailboxRespHeader,
}
impl Response for FuseWriteResp {}

/// MC_FUSE_LOCK_PARTITION request: Lock a partition to prevent further writes.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseLockPartitionReq {
    pub hdr: MailboxReqHeader,
    /// Partition number to lock
    pub partition: u32,
}
impl Request for FuseLockPartitionReq {
    const ID: CommandId = CommandId::MC_FUSE_LOCK_PARTITION;
    type Resp = FuseLockPartitionResp;
}

/// MC_FUSE_LOCK_PARTITION response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseLockPartitionResp {
    pub hdr: MailboxRespHeader,
}
impl Response for FuseLockPartitionResp {}

/// Width, in bytes, of the authorized-command challenge nonce.
///
/// Single source of truth for the nonce size — every authorized-command site
/// (challenge response, signer, device verifier, transports, tests) references
/// this constant instead of a hard-coded `48`.
pub const AUTH_CMD_NONCE_LEN: usize = 48;

/// MC_GET_AUTH_CMD_CHALLENGE request: Get a challenge nonce to prove freshness in auth commands
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetAuthCmdChallengeReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub reserved: u32,
}
impl Request for GetAuthCmdChallengeReq {
    const ID: CommandId = CommandId::MC_GET_AUTH_CMD_CHALLENGE;
    type Resp = GetAuthCmdChallengeResp;
}

/// MC_GET_AUTH_CMD_CHALLENGE response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetAuthCmdChallengeResp {
    pub hdr: MailboxRespHeader,
    pub reserved: u32,
    /// Freshness challenge (widened 32 -> 48 to match the SHA-384/SHA-512 nonce).
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}
// Hand-written `Default`: `[u8; AUTH_CMD_NONCE_LEN]` does not implement `Default` via derive.
impl Default for GetAuthCmdChallengeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            reserved: 0,
            challenge: [0u8; AUTH_CMD_NONCE_LEN],
        }
    }
}
impl Response for GetAuthCmdChallengeResp {}

/// MC_FUSE_INCREASE_CALIPTRA_MIN_SVN request: Increases the Caliptra min bootable SVN
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseIncreaseCaliptraMinSvnReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub svn: u32,
}
impl Request for FuseIncreaseCaliptraMinSvnReq {
    const ID: CommandId = CommandId::MC_FUSE_INCREASE_CALIPTRA_MIN_SVN;
    type Resp = FuseIncreaseCaliptraMinSvnResp;
}

/// MC_FUSE_INCREASE_CALIPTRA_MIN_SVN response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseIncreaseCaliptraMinSvnResp {
    pub hdr: MailboxRespHeader,
}
impl Response for FuseIncreaseCaliptraMinSvnResp {}

/// MC_FE_PROG request: Program field entropy.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct McuFeProgReq {
    pub hdr: MailboxReqHeader,
    pub partition: u32,
}
impl Request for McuFeProgReq {
    const ID: CommandId = CommandId::MC_FE_PROG;
    type Resp = FuseWriteResp; // Reuse FuseWriteResp as it only contains header
}

/// MC_FUSE_REVOKE_VENDOR_PUB_KEY request: Revoke a vendor firmware verification key.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseRevokeVendorPubKeyReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub vendor_pk_hash_slot: u32,
    pub key_type: u32,
    pub key_index: u32,
}
impl Request for FuseRevokeVendorPubKeyReq {
    const ID: CommandId = CommandId::MC_FUSE_REVOKE_VENDOR_PUB_KEY;
    type Resp = FuseRevokeVendorPubKeyResp;
}

/// MC_FUSE_LOCK_PARTITION response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseRevokeVendorPubKeyResp {
    pub hdr: MailboxRespHeader,
}
impl Response for FuseRevokeVendorPubKeyResp {}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RevokeVendorPubKeyType {
    Ecdsa384,
    Lms,
    Mldsa87,
}

impl TryFrom<u32> for RevokeVendorPubKeyType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ecdsa384),
            1 => Ok(Self::Lms),
            2 => Ok(Self::Mldsa87),
            _ => Err(()),
        }
    }
}

impl From<RevokeVendorPubKeyType> for u32 {
    fn from(value: RevokeVendorPubKeyType) -> Self {
        value as u32
    }
}

/// MC_FUSE_REVOKE_VENDOR_PK_HASH request: Request revokation of a vendor PK hash.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseRevokeVendorPkHashReq {
    pub hdr: MailboxReqHeader,
    pub reserved: u32,
    pub vendor_pk_hash_slot: u32,
}
impl Request for FuseRevokeVendorPkHashReq {
    const ID: CommandId = CommandId::MC_FUSE_REVOKE_VENDOR_PK_HASH;
    type Resp = FuseRevokeVendorPubKeyResp;
}

/// MC_FUSE_REVOKE_VENDOR_PK_HASH response: Indicates success or failure.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct FuseRevokeVendorPkHashResp {
    pub hdr: MailboxRespHeader,
}
impl Response for FuseRevokeVendorPkHashResp {}

// ============================================================================
// MC_EXPORT_ATTESTED_CSR Command (0x4D45_4143 - "MEAC")
// ============================================================================

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ExportAttestedCsrReq {
    pub hdr: MailboxReqHeader,
    /// Device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
    pub device_key_id: u32,
    /// Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; 32],
}
impl Request for ExportAttestedCsrReq {
    const ID: CommandId = CommandId::MC_EXPORT_ATTESTED_CSR;
    type Resp = ExportAttestedCsrResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct ExportAttestedCsrResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_RESP_DATA_SIZE],
}
impl Default for ExportAttestedCsrResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_RESP_DATA_SIZE],
        }
    }
}
impl McuResponseVarSize for ExportAttestedCsrResp {}

// ============================================================================
// MC_GET_ATTESTATION Command (0x4D47_4154 - "MGAT")
// ============================================================================

/// MC_GET_ATTESTATION request: retrieve signed attestation evidence.
///
/// `evidence_format` selects among the formats the responder was built with;
/// `0` queries the supported-format bitmap instead of returning evidence. The
/// format, algorithm, and entity values match [`caliptra_mcu_common_commands`]'s
/// `EvidenceFormat` / `AsymAlgo` / `PkiEntitySlot`.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetAttestationReq {
    pub hdr: MailboxReqHeader,
    /// Evidence format (0=query supported formats, 1=OCP EAT, 2=PCR Quote)
    pub evidence_format: u32,
    /// Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    pub algorithm: u32,
    /// PKI entity whose hierarchy signs (0=Vendor, 1=Owner). The
    /// `GET_ATTESTATION` analogue of the SPDM `GET_MEASUREMENTS` SlotID.
    pub pki_entity_slot: u32,
    /// 32-byte nonce for freshness
    pub nonce: [u8; 32],
}
impl Request for GetAttestationReq {
    const ID: CommandId = CommandId::MC_GET_ATTESTATION;
    type Resp = GetAttestationResp;
}

/// Bytes of `MC_GET_ATTESTATION` response data that precede the evidence.
///
/// The response body is `[evidence_format:u32][evidence...]`, and
/// `MailboxRespHeaderVarSize::data_len` covers both, so a generic var-size
/// reader yields the whole body and the command-specific parser splits off this
/// prefix.
pub const GET_ATTESTATION_RESP_PREFIX_LEN: usize = 4;

/// Maximum `MC_GET_ATTESTATION` response data: the echoed format plus evidence.
///
/// Larger than [`MAX_RESP_DATA_SIZE`] because attestation evidence can exceed
/// 4 KiB: an ML-DSA-87 PCR quote is 6388 bytes. Rounded up to 8 KiB for
/// headroom.
///
/// This bounds the *decode* type only. The responder never allocates this
/// struct: it sizes its response buffer from
/// `CaliptraCmdHandler::MAX_ATTESTATION_EVIDENCE_LEN`, which is derived from
/// the evidence generators the build actually enables, and frames the response
/// in place.
pub const MAX_ATTESTATION_RESP_DATA_SIZE: usize = 8 * 1024;

/// MC_GET_ATTESTATION response: `[evidence_format:u32][evidence...]`.
///
/// Deliberately absent from [`McuMailboxResp`]: that enum sizes every command's
/// response allocation by its largest variant, so including an
/// attestation-sized array here would enlarge the buffer for every command.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct GetAttestationResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_ATTESTATION_RESP_DATA_SIZE], // variable length
}
impl Default for GetAttestationResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_ATTESTATION_RESP_DATA_SIZE],
        }
    }
}
impl McuResponseVarSize for GetAttestationResp {}

/// MC_PROVISION_VENDOR_PK_HASH request: Provision a new vendor PK hash
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct ProvisionVendorPkHashReq {
    pub hdr: MailboxReqHeader,
    /// The vendor PK hash slot to use
    pub slot: u32,
    /// New vendor PK hash
    pub hash: [u8; OTP_CPTRA_CORE_VENDOR_PK_HASH_0.byte_size],
}
impl Request for ProvisionVendorPkHashReq {
    const ID: CommandId = CommandId::MC_PROVISION_VENDOR_PK_HASH;

    type Resp = ProvisionVendorPkHashResp;
}

/// MC_PROVISION_VENDOR_PK_HASH response: Response for provisioning a new vendor PK hash
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct ProvisionVendorPkHashResp {
    pub hdr: MailboxRespHeader,
}
impl Response for ProvisionVendorPkHashResp {}

/// MC_PROVISION_OWNER_PK_HASH request: Provision the owner public-key hash.
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct ProvisionOwnerPkHashReq {
    pub hdr: MailboxReqHeader,
    pub hash: [u8; OTP_CPTRA_SS_OWNER_PK_HASH.byte_size],
}
impl Request for ProvisionOwnerPkHashReq {
    const ID: CommandId = CommandId::MC_PROVISION_OWNER_PK_HASH;
    type Resp = ProvisionOwnerPkHashResp;
}

/// MC_PROVISION_OWNER_PK_HASH response: Header-only on success.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct ProvisionOwnerPkHashResp {
    pub hdr: MailboxRespHeader,
}
impl Response for ProvisionOwnerPkHashResp {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct HybridSignature {
    pub ecc_sig_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub ecc_sig_s: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub mldsa_sig: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
}

impl Default for HybridSignature {
    fn default() -> Self {
        Self {
            ecc_sig_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            ecc_sig_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
            mldsa_sig: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
        }
    }
}

pub const DOT_KEY_HASH_SIZE: usize = 48;
pub const DOT_ECC_PUBLIC_KEY_COORD_SIZE: usize = 48;
pub const DOT_MLDSA_PUBLIC_KEY_SIZE: usize = 2592;

/// Transport-neutral DOT_LOCK payload.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotLockPayload {
    pub cak: [u8; DOT_KEY_HASH_SIZE],
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
}

impl Default for DotLockPayload {
    fn default() -> Self {
        Self {
            cak: [0; DOT_KEY_HASH_SIZE],
            lak_hash: [0; DOT_KEY_HASH_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotLockReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotLockPayload,
}

impl Default for DotLockReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_LOCK.0,
            payload: DotLockPayload::default(),
        }
    }
}

impl Request for DotLockReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotLockResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotLockResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotLockResp {}

/// Transport-neutral DOT_DISABLE payload.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotDisablePayload {
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
}

impl Default for DotDisablePayload {
    fn default() -> Self {
        Self {
            lak_hash: [0; DOT_KEY_HASH_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotDisableReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotDisablePayload,
}

impl Default for DotDisableReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_DISABLE.0,
            payload: DotDisablePayload::default(),
        }
    }
}

impl Request for DotDisableReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotDisableResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotDisableResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotDisableResp {}

/// Transport-neutral DOT_ROTATE payload.
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotRotatePayload {
    pub min_fuse_count: u32,
    pub cak: [u8; DOT_KEY_HASH_SIZE],
    pub lak_hash: [u8; DOT_KEY_HASH_SIZE],
}

impl Default for DotRotatePayload {
    fn default() -> Self {
        Self {
            min_fuse_count: 0,
            cak: [0; DOT_KEY_HASH_SIZE],
            lak_hash: [0; DOT_KEY_HASH_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotRotateReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotRotatePayload,
}

impl Default for DotRotateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_ROTATE.0,
            payload: DotRotatePayload::default(),
        }
    }
}

impl Request for DotRotateReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotRotateResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotRotateResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotRotateResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotRecoveryReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl Default for DotRecoveryReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_RECOVERY.0,
            blob: [0; DOT_BLOB_SIZE],
        }
    }
}

impl Request for DotRecoveryReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotRecoveryResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotRecoveryResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotRecoveryResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotStatusReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
}

impl Default for DotStatusReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_STATUS.0,
        }
    }
}

impl Request for DotStatusReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotStatusResp;
}

#[repr(C)]
#[derive(
    Debug, Default, Clone, Copy, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq,
)]
pub struct DotStatus {
    pub enabled: u8,
    pub locked: u8,
    pub burned: u16,
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotStatusResp {
    pub hdr: MailboxRespHeader,
    pub status: DotStatus,
}

impl Response for DotStatusResp {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverrideChallengePayload {
    pub recovery_ecc_pub_x: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub recovery_ecc_pub_y: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub recovery_mldsa_pub: [u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
}

impl Default for DotOverrideChallengePayload {
    fn default() -> Self {
        Self {
            recovery_ecc_pub_x: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            recovery_ecc_pub_y: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            recovery_mldsa_pub: [0; DOT_MLDSA_PUBLIC_KEY_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverrideChallengeReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotOverrideChallengePayload,
}

impl Default for DotOverrideChallengeReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_OVERRIDE_CHALLENGE.0,
            payload: DotOverrideChallengePayload::default(),
        }
    }
}

impl Request for DotOverrideChallengeReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotOverrideChallengeResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverrideChallengeResp {
    pub hdr: MailboxRespHeader,
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}

impl Default for DotOverrideChallengeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            challenge: [0; AUTH_CMD_NONCE_LEN],
        }
    }
}

impl Response for DotOverrideChallengeResp {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverridePayload {
    pub recovery_ecc_pub_x: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub recovery_ecc_pub_y: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub recovery_mldsa_pub: [u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    pub signature: HybridSignature,
}

impl Default for DotOverridePayload {
    fn default() -> Self {
        Self {
            recovery_ecc_pub_x: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            recovery_ecc_pub_y: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            recovery_mldsa_pub: [0; DOT_MLDSA_PUBLIC_KEY_SIZE],
            signature: HybridSignature::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverrideReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotOverridePayload,
}

impl Default for DotOverrideReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_OVERRIDE.0,
            payload: DotOverridePayload::default(),
        }
    }
}

impl Request for DotOverrideReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotOverrideResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotOverrideResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotOverrideResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotUnlockChallengeReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
}

impl Default for DotUnlockChallengeReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_UNLOCK_CHALLENGE.0,
        }
    }
}

impl Request for DotUnlockChallengeReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotUnlockChallengeResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotUnlockChallengeResp {
    pub hdr: MailboxRespHeader,
    pub challenge: [u8; AUTH_CMD_NONCE_LEN],
}

impl Default for DotUnlockChallengeResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            challenge: [0; AUTH_CMD_NONCE_LEN],
        }
    }
}

impl Response for DotUnlockChallengeResp {}

#[repr(C)]
#[derive(Debug, Clone, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotUnlockPayload {
    pub lak_ecc_pub_x: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub lak_ecc_pub_y: [u8; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
    pub lak_mldsa_pub: [u8; DOT_MLDSA_PUBLIC_KEY_SIZE],
    pub signature: HybridSignature,
}

impl Default for DotUnlockPayload {
    fn default() -> Self {
        Self {
            lak_ecc_pub_x: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            lak_ecc_pub_y: [0; DOT_ECC_PUBLIC_KEY_COORD_SIZE],
            lak_mldsa_pub: [0; DOT_MLDSA_PUBLIC_KEY_SIZE],
            signature: HybridSignature::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotUnlockReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
    pub payload: DotUnlockPayload,
}

impl Default for DotUnlockReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_DOT_UNLOCK.0,
            payload: DotUnlockPayload::default(),
        }
    }
}

impl Request for DotUnlockReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = DotUnlockResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct DotUnlockResp {
    pub hdr: MailboxRespHeader,
    pub reset_required: u32,
}

impl Response for DotUnlockResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetDotBackupBlobReq {
    pub hdr: MailboxReqHeader,
    pub subcommand: u32,
}

impl Default for GetDotBackupBlobReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            subcommand: CommandId::MC_GET_DOT_BACKUP_BLOB.0,
        }
    }
}

impl Request for GetDotBackupBlobReq {
    const ID: CommandId = CommandId::MC_DEVICE_OWNERSHIP_TRANSFER;
    type Resp = GetDotBackupBlobResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct GetDotBackupBlobResp {
    pub hdr: MailboxRespHeader,
    pub blob: [u8; DOT_BLOB_SIZE],
}

impl Default for GetDotBackupBlobResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            blob: [0; DOT_BLOB_SIZE],
        }
    }
}

impl Response for GetDotBackupBlobResp {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_attestation_wire_layout() {
        assert_eq!(CommandId::MC_GET_ATTESTATION.0, 0x4D47_4154); // "MGAT"
                                                                  // hdr(4) + evidence_format(4) + algorithm(4)
                                                                  // + pki_entity_slot(4) + nonce(32)
        assert_eq!(core::mem::size_of::<GetAttestationReq>(), 48);

        let req = GetAttestationReq {
            hdr: MailboxReqHeader { chksum: 0xABCD },
            evidence_format: 2,
            algorithm: 1,
            pki_entity_slot: 0,
            nonce: [0x5A; 32],
        };
        let parsed = GetAttestationReq::read_from_bytes(req.as_bytes()).unwrap();
        assert_eq!(parsed.hdr.chksum, 0xABCD);
        assert_eq!(parsed.evidence_format, 2);
        assert_eq!(parsed.algorithm, 1);
        assert_eq!(parsed.pki_entity_slot, 0);
        assert_eq!(parsed.nonce, [0x5A; 32]);
    }

    #[test]
    fn get_attestation_resp_is_excluded_from_the_shared_response_union() {
        // The response carries attestation-sized evidence, so folding it into
        // `McuMailboxResp` would enlarge every other command's allocation.
        assert!(
            core::mem::size_of::<GetAttestationResp>() > core::mem::size_of::<McuMailboxResp>()
        );
        assert_eq!(
            core::mem::size_of::<GetAttestationResp>(),
            core::mem::size_of::<MailboxRespHeaderVarSize>() + MAX_ATTESTATION_RESP_DATA_SIZE
        );
    }

    #[test]
    fn test_signature_verify_command_ids_and_layouts() {
        assert_eq!(CommandId::MC_ECDSA384_SIG_VERIFY.0, 0x4D45_4356); // "MECV"
        assert_eq!(CommandId::MC_LMS_SIG_VERIFY.0, 0x4D4C_4D56); // "MLMV"
        assert_eq!(size_of::<McuEcdsa384SigVerifyReq>(), 244);
        assert_eq!(size_of::<McuLmsSigVerifyReq>(), 1720);
        assert_eq!(size_of::<McuEcdsa384SigVerifyResp>(), 8);
        assert_eq!(size_of::<McuLmsSigVerifyResp>(), 8);
        assert_eq!(
            MailboxRespHeader::FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST,
            0x5553_5244
        );
    }

    #[test]
    fn test_fuse_command_ids() {
        // Verify command codes match the spec
        assert_eq!(CommandId::MC_FUSE_READ.0, 0x4946_5052); // "IFPR"
        assert_eq!(CommandId::MC_FUSE_WRITE.0, 0x4946_5057); // "IFPW"
        assert_eq!(CommandId::MC_FUSE_LOCK_PARTITION.0, 0x4946_504B); // "IFPK"
        assert_eq!(CommandId::MC_PROVISION_OWNER_PK_HASH.0, 0x504F_504B); // "POPK"
    }

    #[test]
    fn dot_lock_wire_contract() {
        assert_eq!(CommandId::MC_DEVICE_OWNERSHIP_TRANSFER.0, 0x11);
        assert_eq!(CommandId::MC_DOT_LOCK.0, 0x4D44_4C4B);
        assert_eq!(
            core::mem::size_of::<DotLockReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + core::mem::size_of::<u32>()
                + 2 * DOT_KEY_HASH_SIZE
        );
        assert_eq!(DotLockReq::default().subcommand, CommandId::MC_DOT_LOCK.0);
    }

    #[test]
    fn dot_disable_wire_contract() {
        assert_eq!(CommandId::MC_DOT_DISABLE.0, 0x4D44_4453);
        assert_eq!(
            core::mem::size_of::<DotDisableReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + core::mem::size_of::<u32>()
                + DOT_KEY_HASH_SIZE
        );
        assert_eq!(
            DotDisableReq::default().subcommand,
            CommandId::MC_DOT_DISABLE.0
        );
    }

    #[test]
    fn dot_rotate_wire_contract() {
        assert_eq!(CommandId::MC_DOT_ROTATE.0, 0x4D44_5254);
        assert_eq!(
            core::mem::size_of::<DotRotateReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + 2 * core::mem::size_of::<u32>()
                + 2 * DOT_KEY_HASH_SIZE
        );
        assert_eq!(
            DotRotateReq::default().subcommand,
            CommandId::MC_DOT_ROTATE.0
        );
    }

    #[test]
    fn dot_recovery_wire_contract() {
        assert_eq!(CommandId::MC_DOT_RECOVERY.0, 0x4D44_5243);
        assert_eq!(
            core::mem::size_of::<DotRecoveryReq>(),
            core::mem::size_of::<MailboxReqHeader>() + core::mem::size_of::<u32>() + DOT_BLOB_SIZE
        );
        assert_eq!(
            DotRecoveryReq::default().subcommand,
            CommandId::MC_DOT_RECOVERY.0
        );
    }

    #[test]
    fn dot_status_wire_contract() {
        assert_eq!(CommandId::MC_DOT_STATUS.0, 0x4D44_5354);
        assert_eq!(
            core::mem::size_of::<DotStatusReq>(),
            core::mem::size_of::<MailboxReqHeader>() + core::mem::size_of::<u32>()
        );
        assert_eq!(
            DotStatusReq::default().subcommand,
            CommandId::MC_DOT_STATUS.0
        );
        assert_eq!(
            core::mem::size_of::<DotStatusResp>(),
            core::mem::size_of::<MailboxRespHeader>() + core::mem::size_of::<u32>()
        );
    }

    #[test]
    fn dot_override_challenge_wire_contract() {
        assert_eq!(CommandId::MC_DOT_OVERRIDE_CHALLENGE.0, 0x444F_5457);
        assert_eq!(
            core::mem::size_of::<DotOverrideChallengeReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + core::mem::size_of::<u32>()
                + 2 * DOT_ECC_PUBLIC_KEY_COORD_SIZE
                + DOT_MLDSA_PUBLIC_KEY_SIZE
        );
        assert_eq!(
            DotOverrideChallengeReq::default().subcommand,
            CommandId::MC_DOT_OVERRIDE_CHALLENGE.0
        );
    }

    #[test]
    fn dot_override_wire_contract() {
        assert_eq!(CommandId::MC_DOT_OVERRIDE.0, 0x444F_5458);
        assert_eq!(
            core::mem::size_of::<DotOverrideReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + core::mem::size_of::<u32>()
                + 2 * DOT_ECC_PUBLIC_KEY_COORD_SIZE
                + DOT_MLDSA_PUBLIC_KEY_SIZE
                + core::mem::size_of::<HybridSignature>()
        );
        assert_eq!(
            DotOverrideReq::default().subcommand,
            CommandId::MC_DOT_OVERRIDE.0
        );
    }

    #[test]
    fn dot_unlock_challenge_wire_contract() {
        assert_eq!(CommandId::MC_DOT_UNLOCK_CHALLENGE.0, 0x4D44_5543);
        assert_eq!(
            core::mem::size_of::<DotUnlockChallengeReq>(),
            core::mem::size_of::<MailboxReqHeader>() + core::mem::size_of::<u32>()
        );
        assert_eq!(
            DotUnlockChallengeReq::default().subcommand,
            CommandId::MC_DOT_UNLOCK_CHALLENGE.0
        );
        assert_eq!(
            core::mem::size_of::<DotUnlockChallengeResp>(),
            core::mem::size_of::<MailboxRespHeader>() + AUTH_CMD_NONCE_LEN
        );
    }

    #[test]
    fn dot_unlock_wire_contract() {
        assert_eq!(CommandId::MC_DOT_UNLOCK.0, 0x4D44_554C);
        assert_eq!(
            core::mem::size_of::<DotUnlockReq>(),
            core::mem::size_of::<MailboxReqHeader>()
                + core::mem::size_of::<u32>()
                + 2 * DOT_ECC_PUBLIC_KEY_COORD_SIZE
                + DOT_MLDSA_PUBLIC_KEY_SIZE
                + core::mem::size_of::<HybridSignature>()
        );
        assert_eq!(
            DotUnlockReq::default().subcommand,
            CommandId::MC_DOT_UNLOCK.0
        );
    }

    #[test]
    fn get_dot_backup_blob_wire_contract() {
        assert_eq!(CommandId::MC_GET_DOT_BACKUP_BLOB.0, 0x4D44_4242);
        assert_eq!(
            core::mem::size_of::<GetDotBackupBlobReq>(),
            core::mem::size_of::<MailboxReqHeader>() + core::mem::size_of::<u32>()
        );
        assert_eq!(
            GetDotBackupBlobReq::default().subcommand,
            CommandId::MC_GET_DOT_BACKUP_BLOB.0
        );
        assert_eq!(
            core::mem::size_of::<GetDotBackupBlobResp>(),
            core::mem::size_of::<MailboxRespHeader>() + DOT_BLOB_SIZE
        );
    }

    #[test]
    fn test_fuse_read_req_serialization() {
        let req = FuseReadReq {
            hdr: MailboxReqHeader { chksum: 0x1234 },
            partition: 5,
            entry: 2,
        };

        let bytes = req.as_bytes();
        assert_eq!(bytes.len(), core::mem::size_of::<FuseReadReq>());

        // Verify fields are at expected offsets (little-endian)
        let parsed = FuseReadReq::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.hdr.chksum, 0x1234);
        assert_eq!(parsed.partition, 5);
        assert_eq!(parsed.entry, 2);
    }

    #[test]
    fn test_fuse_read_resp_serialization() {
        let mut resp = FuseReadResp::default();
        resp.hdr.hdr.fips_status = 0;
        resp.hdr.data_len = 8; // 8 bytes of data
        resp.length_bits = 64;
        resp.data[0..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let bytes = resp.as_bytes();
        let parsed = FuseReadResp::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.hdr.hdr.fips_status, 0);
        assert_eq!(parsed.length_bits, 64);
        assert_eq!(
            &parsed.data[0..8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_fuse_lock_partition_req_serialization() {
        let req = FuseLockPartitionReq {
            hdr: MailboxReqHeader { chksum: 0x5678 },
            partition: 7,
        };

        let bytes = req.as_bytes();
        let parsed = FuseLockPartitionReq::read_from_bytes(bytes).unwrap();
        assert_eq!(parsed.hdr.chksum, 0x5678);
        assert_eq!(parsed.partition, 7);
    }

    #[test]
    fn test_provision_owner_pk_hash_req_serialization() {
        let mut req = McuMailboxReq::ProvisionOwnerPkHash(ProvisionOwnerPkHashReq {
            hdr: MailboxReqHeader::default(),
            hash: [0xA5; 48],
        });
        req.populate_chksum().unwrap();

        assert_eq!(req.cmd_code(), CommandId::MC_PROVISION_OWNER_PK_HASH);
        let parsed = ProvisionOwnerPkHashReq::read_from_bytes(req.as_bytes().unwrap()).unwrap();
        assert_ne!(parsed.hdr.chksum, 0);
        assert_eq!(parsed.hash, [0xA5; 48]);
    }

    #[test]
    fn test_fuse_req_checksum() {
        let mut req = McuMailboxReq::FuseRead(FuseReadReq {
            hdr: MailboxReqHeader::default(),
            partition: 1,
            entry: 2,
        });

        // Populate checksum
        req.populate_chksum().unwrap();

        // Verify checksum is non-zero after population
        let bytes = req.as_bytes().unwrap();
        let hdr = MailboxReqHeader::read_from_prefix(bytes).unwrap().0;
        assert_ne!(hdr.chksum, 0);

        // Verify command code
        assert_eq!(req.cmd_code(), CommandId::MC_FUSE_READ);
    }

    #[test]
    fn test_fuse_resp_checksum() {
        let mut resp = McuMailboxResp::FuseWrite(FuseWriteResp {
            hdr: MailboxRespHeader::default(),
        });

        // Populate checksum - for an all-zero payload, checksum is 0
        resp.populate_chksum().unwrap();

        // Verify checksum calculation works (all zeros = zero checksum)
        let bytes = resp.as_bytes().unwrap();
        let hdr = MailboxRespHeader::read_from_prefix(bytes).unwrap().0;
        // Zero checksum is valid for zero payload
        assert_eq!(hdr.chksum, 0);
    }

    #[test]
    fn test_fuse_lock_partition_resp_checksum() {
        let mut resp = McuMailboxResp::FuseLockPartition(FuseLockPartitionResp {
            hdr: MailboxRespHeader::default(),
        });

        resp.populate_chksum().unwrap();

        // Zero checksum is valid for zero payload
        let bytes = resp.as_bytes().unwrap();
        let hdr = MailboxRespHeader::read_from_prefix(bytes).unwrap().0;
        assert_eq!(hdr.chksum, 0);
    }

    #[test]
    fn test_provision_owner_pk_hash_resp_checksum() {
        let mut resp = McuMailboxResp::ProvisionOwnerPkHash(ProvisionOwnerPkHashResp::default());
        resp.populate_chksum().unwrap();

        let bytes = resp.as_bytes().unwrap();
        let hdr = MailboxRespHeader::read_from_prefix(bytes).unwrap().0;
        assert_eq!(hdr.chksum, 0);
    }

    #[test]
    fn test_fuse_read_resp_checksum_with_data() {
        let mut resp = FuseReadResp::default();
        resp.hdr.data_len = 4;
        resp.length_bits = 32;
        resp.data[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut mbox_resp = McuMailboxResp::FuseRead(resp);
        mbox_resp.populate_chksum().unwrap();

        // With non-zero data, checksum should be non-zero
        let bytes = mbox_resp.as_bytes().unwrap();
        let hdr = MailboxRespHeader::read_from_prefix(bytes).unwrap().0;
        assert_ne!(hdr.chksum, 0);

        // Verify checksum can be validated using verify_checksum
        let payload = &bytes[core::mem::size_of::<u32>()..];
        assert!(verify_checksum(hdr.chksum, 0, payload));
    }
}
