// Licensed under the Apache-2.0 license

//! Caliptra mailbox wire definitions needed by MCU mailbox transports.
//!
//! These definitions mirror the pinned `caliptra-api::mailbox` wire layout
//! for the Caliptra cryptographic-manager and debug-unlock commands used by
//! `caliptra-mcu-mbox-common`, without depending on the external
//! `caliptra-api` crate.

use core::mem::size_of;

pub use crate::types::{CmKeyUsage, Cmk, CMK_SIZE as CMK_SIZE_BYTES};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAX_CMB_DATA_SIZE: usize = 4096;
pub const MAILBOX_SIZE: usize = 256 * 1024;
pub const MAX_CM_SHA_INPUT_SIZE: usize = MAILBOX_SIZE - 12;
pub const MAX_CMB_AES_GCM_OUTPUT_SIZE: usize = MAX_CMB_DATA_SIZE + 16;
pub const CMB_SHA_CONTEXT_SIZE: usize = 200;
pub const MAX_RESP_DATA_SIZE: usize = 9216;
pub const _CMB_AES_CONTEXT_SIZE: usize = 128;
pub const CMB_AES_ENCRYPTED_CONTEXT_SIZE: usize = 156;
const _: () = assert!(_CMB_AES_CONTEXT_SIZE + 12 + 16 == CMB_AES_ENCRYPTED_CONTEXT_SIZE);
pub const CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE: usize = 128;
pub const CMB_ECDH_CONTEXT_SIZE: usize = 48;
pub const CMB_ECDH_ENCRYPTED_CONTEXT_SIZE: usize = 76;
const _: () = assert!(CMB_ECDH_CONTEXT_SIZE + 12 + 16 == CMB_ECDH_ENCRYPTED_CONTEXT_SIZE);
pub const CMB_ECDH_EXCHANGE_DATA_MAX_SIZE: usize = 96;
const _: () = assert!(CMB_ECDH_CONTEXT_SIZE * 2 == CMB_ECDH_EXCHANGE_DATA_MAX_SIZE);
pub const CMB_HMAC_MAX_SIZE: usize = 64;
pub const CMK_MAX_KEY_SIZE_BITS: usize = 512;

pub const ECC384_SCALAR_BYTE_SIZE: usize = 48;
pub const SHA512_DIGEST_BYTE_SIZE: usize = 64;
pub const MLDSA87_PUB_KEY_BYTE_SIZE: usize = 2592;
pub const MLDSA87_SIGNATURE_BYTE_SIZE: usize = 4628;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MailboxWireError {
    RequestDataLenTooLarge,
    ResponseDataLenTooLarge,
}

pub type MailboxWireResult<T> = Result<T, MailboxWireError>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const CM_IMPORT: Self = Self(0x434D_494D); // "CMIM"
    pub const CM_DELETE: Self = Self(0x434D_444C); // "CMDL"
    pub const CM_CLEAR: Self = Self(0x434D_434C); // "CMCL"
    pub const CM_STATUS: Self = Self(0x434D_5354); // "CMST"
    pub const CM_SHA_INIT: Self = Self(0x434D_5349); // "CMSI"
    pub const CM_SHA_UPDATE: Self = Self(0x434D_5355); // "CMSU"
    pub const CM_SHA_FINAL: Self = Self(0x434D_5346); // "CMSF"
    pub const CM_RANDOM_GENERATE: Self = Self(0x434D_5247); // "CMRG"
    pub const CM_RANDOM_STIR: Self = Self(0x434D_5253); // "CMRS"
    pub const CM_AES_ENCRYPT_INIT: Self = Self(0x434D_4149); // "CMAI"
    pub const CM_AES_ENCRYPT_UPDATE: Self = Self(0x434D_4155); // "CMAU"
    pub const CM_AES_DECRYPT_INIT: Self = Self(0x434D_414A); // "CMAJ"
    pub const CM_AES_DECRYPT_UPDATE: Self = Self(0x434D_4156); // "CMAV"
    pub const CM_AES_GCM_ENCRYPT_INIT: Self = Self(0x434D_4749); // "CMGI"
    pub const CM_AES_GCM_SPDM_ENCRYPT_INIT: Self = Self(0x434D_5345); // "CMSE"
    pub const CM_AES_GCM_ENCRYPT_UPDATE: Self = Self(0x434D_4755); // "CMGU"
    pub const CM_AES_GCM_ENCRYPT_FINAL: Self = Self(0x434D_4746); // "CMGF"
    pub const CM_AES_GCM_DECRYPT_INIT: Self = Self(0x434D_4449); // "CMDI"
    pub const CM_AES_GCM_SPDM_DECRYPT_INIT: Self = Self(0x434D_5344); // "CMSD"
    pub const CM_AES_GCM_DECRYPT_UPDATE: Self = Self(0x434D_4455); // "CMDU"
    pub const CM_AES_GCM_DECRYPT_FINAL: Self = Self(0x434D_4446); // "CMDF"
    pub const CM_ECDH_GENERATE: Self = Self(0x434D_4547); // "CMEG"
    pub const CM_ECDH_FINISH: Self = Self(0x434D_4546); // "CMEF"
    pub const CM_HMAC: Self = Self(0x434D_484D); // "CMHM"
    pub const CM_HMAC_KDF_COUNTER: Self = Self(0x434D_4B43); // "CMKC"
    pub const CM_HKDF_EXTRACT: Self = Self(0x434D_4B54); // "CMKT"
    pub const CM_HKDF_EXPAND: Self = Self(0x434D_4B50); // "CMKP"
    pub const CM_MLDSA_PUBLIC_KEY: Self = Self(0x434D_4D50); // "CMMP"
    pub const CM_MLDSA_SIGN: Self = Self(0x434D_4D53); // "CMMS"
    pub const CM_MLDSA_VERIFY: Self = Self(0x434D_4D56); // "CMMV"
    pub const CM_ECDSA_PUBLIC_KEY: Self = Self(0x434D_4550); // "CMEP"
    pub const CM_ECDSA_SIGN: Self = Self(0x434D_4553); // "CMES"
    pub const CM_ECDSA_VERIFY: Self = Self(0x434D_4556); // "CMEV"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_REQ: Self = Self(0x5044_5552); // "PDUR"
    pub const PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN: Self = Self(0x5044_5554); // "PDUT"
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

pub trait Request: IntoBytes + FromBytes + Immutable + KnownLayout {
    const ID: CommandId;
    type Resp: Response;
}

pub trait Response: IntoBytes + FromBytes
where
    Self: Sized,
{
    const MIN_SIZE: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct MailboxReqHeader {
    pub chksum: u32,
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Clone)]
pub struct MailboxRespHeader {
    pub chksum: u32,
    pub fips_status: u32,
}

impl MailboxRespHeader {
    pub const FIPS_STATUS_APPROVED: u32 = 0;
    pub const FIPS_STATUS_NON_ZEROIZABLE_KEY: u32 = 0x4241_444B; // "BADK"
    pub const FIPS_STATUS_NOT_APPROVED_USER_SUPPLIED_DIGEST: u32 = 0x5553_5244; // "USRD"
}

impl Default for MailboxRespHeader {
    fn default() -> Self {
        Self {
            chksum: 0,
            fips_status: Self::FIPS_STATUS_APPROVED,
        }
    }
}

impl Response for MailboxRespHeader {}

#[repr(C)]
#[derive(Debug, IntoBytes, Default, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct MailboxRespHeaderVarSize {
    pub hdr: MailboxRespHeader,
    pub data_len: u32,
}

pub trait ResponseVarSize: IntoBytes + FromBytes + Immutable + KnownLayout {
    fn data(&self) -> MailboxWireResult<&[u8]> {
        let (hdr, data) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| MailboxWireError::ResponseDataLenTooLarge)?;
        data.get(..hdr.data_len as usize)
            .ok_or(MailboxWireError::ResponseDataLenTooLarge)
    }

    fn partial_len(&self) -> MailboxWireResult<usize> {
        let (hdr, _) = MailboxRespHeaderVarSize::ref_from_prefix(self.as_bytes())
            .map_err(|_| MailboxWireError::ResponseDataLenTooLarge)?;
        response_partial_len(
            size_of::<MailboxRespHeaderVarSize>(),
            hdr.data_len as usize,
            self.as_bytes().len(),
        )
    }

    fn as_bytes_partial(&self) -> MailboxWireResult<&[u8]> {
        self.as_bytes()
            .get(..self.partial_len()?)
            .ok_or(MailboxWireError::ResponseDataLenTooLarge)
    }

    fn as_bytes_partial_mut(&mut self) -> MailboxWireResult<&mut [u8]> {
        let partial_len = self.partial_len()?;
        self.as_mut_bytes()
            .get_mut(..partial_len)
            .ok_or(MailboxWireError::ResponseDataLenTooLarge)
    }
}

impl<T: ResponseVarSize> Response for T {
    const MIN_SIZE: usize = core::mem::size_of::<MailboxRespHeaderVarSize>();
}

pub fn verify_checksum(checksum: u32, cmd: u32, data: &[u8]) -> bool {
    calc_checksum(cmd, data) == checksum
}

pub fn calc_checksum(cmd: u32, data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as u32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as u32);
    }
    0u32.wrapping_sub(checksum)
}

fn request_partial_len(
    total_len: usize,
    max_data_len: usize,
    data_len: usize,
) -> MailboxWireResult<usize> {
    if data_len > max_data_len {
        return Err(MailboxWireError::RequestDataLenTooLarge);
    }
    total_len
        .checked_sub(max_data_len - data_len)
        .ok_or(MailboxWireError::RequestDataLenTooLarge)
}

fn response_partial_len(
    header_len: usize,
    data_len: usize,
    total_len: usize,
) -> MailboxWireResult<usize> {
    let partial_len = header_len
        .checked_add(data_len)
        .ok_or(MailboxWireError::ResponseDataLenTooLarge)?;
    if partial_len > total_len {
        return Err(MailboxWireError::ResponseDataLenTooLarge);
    }
    Ok(partial_len)
}

fn response_data(bytes: &[u8], header_len: usize, data_len: usize) -> MailboxWireResult<&[u8]> {
    let data = bytes
        .get(header_len..)
        .ok_or(MailboxWireError::ResponseDataLenTooLarge)?;
    data.get(..data_len)
        .ok_or(MailboxWireError::ResponseDataLenTooLarge)
}

macro_rules! impl_request_var_size {
    ($ty:ty, $len_field:ident, $max:expr) => {
        impl $ty {
            pub fn as_bytes_partial(&self) -> MailboxWireResult<&[u8]> {
                let partial_len =
                    request_partial_len(size_of::<Self>(), $max, self.$len_field as usize)?;
                self.as_bytes()
                    .get(..partial_len)
                    .ok_or(MailboxWireError::RequestDataLenTooLarge)
            }

            pub fn as_bytes_partial_mut(&mut self) -> MailboxWireResult<&mut [u8]> {
                let partial_len =
                    request_partial_len(size_of::<Self>(), $max, self.$len_field as usize)?;
                self.as_mut_bytes()
                    .get_mut(..partial_len)
                    .ok_or(MailboxWireError::RequestDataLenTooLarge)
            }
        }
    };
}

macro_rules! impl_response_var_size_with_header {
    ($ty:ty, $hdr:ty, $len_field:ident) => {
        impl ResponseVarSize for $ty {
            fn data(&self) -> MailboxWireResult<&[u8]> {
                response_data(
                    self.as_bytes(),
                    size_of::<$hdr>(),
                    self.hdr.$len_field as usize,
                )
            }

            fn partial_len(&self) -> MailboxWireResult<usize> {
                response_partial_len(
                    size_of::<$hdr>(),
                    self.hdr.$len_field as usize,
                    self.as_bytes().len(),
                )
            }
        }
    };
}

// PRODUCTION_AUTH_DEBUG_UNLOCK_REQ
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq, Default)]
pub struct ProductionAuthDebugUnlockReq {
    pub hdr: MailboxReqHeader,
    pub length: u32,
    pub unlock_level: u8,
    pub reserved: [u8; 3],
}

impl Request for ProductionAuthDebugUnlockReq {
    const ID: CommandId = CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ;
    type Resp = ProductionAuthDebugUnlockChallenge;
}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq, Clone)]
pub struct ProductionAuthDebugUnlockChallenge {
    pub hdr: MailboxRespHeader,
    pub length: u32,
    pub unique_device_identifier: [u8; 32],
    pub challenge: [u8; 48],
}

impl Default for ProductionAuthDebugUnlockChallenge {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            length: 0,
            unique_device_identifier: Default::default(),
            challenge: [0; 48],
        }
    }
}

impl Response for ProductionAuthDebugUnlockChallenge {}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Eq)]
pub struct ProductionAuthDebugUnlockToken {
    pub hdr: MailboxReqHeader,
    pub length: u32,
    pub unique_device_identifier: [u8; 32],
    pub unlock_level: u8,
    pub reserved: [u8; 3],
    pub challenge: [u8; 48],
    pub ecc_public_key: [u32; 24],
    pub mldsa_public_key: [u32; 648],
    pub ecc_signature: [u32; 24],
    pub mldsa_signature: [u32; 1157],
}

impl Default for ProductionAuthDebugUnlockToken {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            length: Default::default(),
            unique_device_identifier: Default::default(),
            unlock_level: Default::default(),
            reserved: Default::default(),
            challenge: [0; 48],
            ecc_public_key: [0; 24],
            mldsa_public_key: [0; 648],
            ecc_signature: [0; 24],
            mldsa_signature: [0; 1157],
        }
    }
}

impl Request for ProductionAuthDebugUnlockToken {
    const ID: CommandId = CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN;
    type Resp = MailboxRespHeader;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmImportReq {
    pub hdr: MailboxReqHeader,
    pub key_usage: u32,
    pub input_size: u32,
    pub input: [u8; Self::MAX_KEY_SIZE],
}

impl Default for CmImportReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            key_usage: 0,
            input_size: 0,
            input: [0u8; Self::MAX_KEY_SIZE],
        }
    }
}

impl CmImportReq {
    pub const MAX_KEY_SIZE: usize = CMK_MAX_KEY_SIZE_BITS / 8;
}

impl_request_var_size!(CmImportReq, input_size, CmImportReq::MAX_KEY_SIZE);

impl Request for CmImportReq {
    const ID: CommandId = CommandId::CM_IMPORT;
    type Resp = CmImportResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmImportResp {
    pub hdr: MailboxRespHeader,
    pub cmk: Cmk,
}

impl Response for CmImportResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmDeleteReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmDeleteReq {
    const ID: CommandId = CommandId::CM_DELETE;
    type Resp = MailboxRespHeader;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmStatusResp {
    pub hdr: MailboxRespHeader,
    pub used_usage_storage: u32,
    pub total_usage_storage: u32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmHashAlgorithm {
    Reserved = 0,
    Sha384 = 1,
    Sha512 = 2,
}

impl From<u32> for CmHashAlgorithm {
    fn from(val: u32) -> Self {
        match val {
            1 => CmHashAlgorithm::Sha384,
            2 => CmHashAlgorithm::Sha512,
            _ => CmHashAlgorithm::Reserved,
        }
    }
}

impl From<CmHashAlgorithm> for u32 {
    fn from(value: CmHashAlgorithm) -> Self {
        match value {
            CmHashAlgorithm::Sha384 => 1,
            CmHashAlgorithm::Sha512 => 2,
            CmHashAlgorithm::Reserved => 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaInitReq {
    pub hdr: MailboxReqHeader,
    pub hash_algorithm: u32,
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            hash_algorithm: 0,
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmShaInitReq, input_size, MAX_CMB_DATA_SIZE);

impl Request for CmShaInitReq {
    const ID: CommandId = CommandId::CM_SHA_INIT;
    type Resp = CmShaInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
}

impl Default for CmShaInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
        }
    }
}

impl Response for CmShaInitResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmShaUpdateReq, input_size, MAX_CMB_DATA_SIZE);

impl Request for CmShaUpdateReq {
    const ID: CommandId = CommandId::CM_SHA_UPDATE;
    type Resp = CmShaInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_SHA_CONTEXT_SIZE],
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmShaFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_SHA_CONTEXT_SIZE],
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmShaFinalReq, input_size, MAX_CMB_DATA_SIZE);

impl Request for CmShaFinalReq {
    const ID: CommandId = CommandId::CM_SHA_FINAL;
    type Resp = CmShaFinalResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmShaFinalResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub hash: [u8; SHA512_DIGEST_BYTE_SIZE],
}

impl Default for CmShaFinalResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            hash: [0u8; SHA512_DIGEST_BYTE_SIZE],
        }
    }
}

impl ResponseVarSize for CmShaFinalResp {}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct CmRandomGenerateReq {
    pub hdr: MailboxReqHeader,
    pub size: u32,
}

impl Request for CmRandomGenerateReq {
    const ID: CommandId = CommandId::CM_RANDOM_GENERATE;
    type Resp = CmRandomGenerateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmRandomGenerateResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub data: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmRandomGenerateResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            data: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl ResponseVarSize for CmRandomGenerateResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmRandomStirReq {
    pub hdr: MailboxReqHeader,
    pub input_size: u32,
    pub input: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmRandomStirReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            input_size: 0,
            input: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmRandomStirReq, input_size, MAX_CMB_DATA_SIZE);

impl Request for CmRandomStirReq {
    const ID: CommandId = CommandId::CM_RANDOM_STIR;
    type Resp = MailboxRespHeader;
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmAesMode {
    Reserved = 0,
    Cbc = 1,
    Ctr = 2,
}

impl From<u32> for CmAesMode {
    fn from(val: u32) -> Self {
        match val {
            1 => CmAesMode::Cbc,
            2 => CmAesMode::Ctr,
            _ => CmAesMode::Reserved,
        }
    }
}

impl From<CmAesMode> for u32 {
    fn from(value: CmAesMode) -> Self {
        match value {
            CmAesMode::Cbc => 1,
            CmAesMode::Ctr => 2,
            CmAesMode::Reserved => 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub mode: u32,
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesEncryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            mode: CmAesMode::Reserved as u32,
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesEncryptInitReq, plaintext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesEncryptInitReq {
    const ID: CommandId = CommandId::CM_AES_ENCRYPT_INIT;
    type Resp = CmAesEncryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitResp {
    pub hdr: CmAesEncryptInitRespHeader,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptInitRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u8; 16],
    pub ciphertext_size: u32,
}

impl Default for CmAesEncryptInitResp {
    fn default() -> Self {
        Self {
            hdr: CmAesEncryptInitRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl Default for CmAesEncryptInitRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u8; 16],
            ciphertext_size: 0,
        }
    }
}

impl_response_var_size_with_header!(
    CmAesEncryptInitResp,
    CmAesEncryptInitRespHeader,
    ciphertext_size
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesEncryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesEncryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesEncryptUpdateReq, plaintext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesEncryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_ENCRYPT_UPDATE;
    type Resp = CmAesResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesDecryptInitReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub mode: u32,
    pub iv: [u8; 16],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesDecryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            mode: CmAesMode::Reserved as u32,
            iv: [0u8; 16],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesDecryptInitReq, ciphertext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesDecryptInitReq {
    const ID: CommandId = CommandId::CM_AES_DECRYPT_INIT;
    type Resp = CmAesResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesDecryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesDecryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesDecryptUpdateReq, ciphertext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesDecryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_DECRYPT_UPDATE;
    type Resp = CmAesResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesResp {
    pub hdr: CmAesRespHeader,
    pub output: [u8; MAX_CMB_DATA_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
    pub output_size: u32,
}

impl Default for CmAesResp {
    fn default() -> Self {
        Self {
            hdr: CmAesRespHeader::default(),
            output: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl Default for CmAesRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_ENCRYPTED_CONTEXT_SIZE],
            output_size: 0,
        }
    }
}

impl_response_var_size_with_header!(CmAesResp, CmAesRespHeader, output_size);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptInitReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub cmk: Cmk,
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            flags: 0,
            cmk: Cmk::default(),
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmEncryptInitReq, aad_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmEncryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_INIT;
    type Resp = CmAesGcmEncryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u8; 12],
}

impl Default for CmAesGcmEncryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u8; 12],
        }
    }
}

impl Response for CmAesGcmEncryptInitResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmEncryptUpdateReq, plaintext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmEncryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_UPDATE;
    type Resp = CmAesGcmEncryptUpdateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateResp {
    pub hdr: CmAesGcmEncryptUpdateRespHeader,
    pub ciphertext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptUpdateRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
}

impl Default for CmAesGcmEncryptUpdateResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmEncryptUpdateRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl Default for CmAesGcmEncryptUpdateRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
        }
    }
}

impl_response_var_size_with_header!(
    CmAesGcmEncryptUpdateResp,
    CmAesGcmEncryptUpdateRespHeader,
    ciphertext_size
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
    pub plaintext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmEncryptFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
            plaintext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmEncryptFinalReq, plaintext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmEncryptFinalReq {
    const ID: CommandId = CommandId::CM_AES_GCM_ENCRYPT_FINAL;
    type Resp = CmAesGcmEncryptFinalResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmEncryptFinalResp {
    pub hdr: CmAesGcmEncryptFinalRespHeader,
    pub ciphertext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmAesGcmEncryptFinalRespHeader {
    pub hdr: MailboxRespHeader,
    pub tag: [u8; 16],
    pub ciphertext_size: u32,
}

impl Default for CmAesGcmEncryptFinalResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmEncryptFinalRespHeader::default(),
            ciphertext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl_response_var_size_with_header!(
    CmAesGcmEncryptFinalResp,
    CmAesGcmEncryptFinalRespHeader,
    ciphertext_size
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptInitReq {
    pub hdr: MailboxReqHeader,
    pub flags: u32,
    pub cmk: Cmk,
    pub iv: [u8; 12],
    pub aad_size: u32,
    pub aad: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptInitReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            flags: 0,
            cmk: Cmk::default(),
            iv: [0u8; 12],
            aad_size: 0,
            aad: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmDecryptInitReq, aad_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmDecryptInitReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_INIT;
    type Resp = CmAesGcmDecryptInitResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptInitResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub iv: [u8; 12],
}

impl Default for CmAesGcmDecryptInitResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            iv: [0u8; 12],
        }
    }
}

impl Response for CmAesGcmDecryptInitResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptUpdateReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmDecryptUpdateReq, ciphertext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmDecryptUpdateReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_UPDATE;
    type Resp = CmAesGcmDecryptUpdateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateResp {
    pub hdr: CmAesGcmDecryptUpdateRespHeader,
    pub plaintext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptUpdateRespHeader {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub plaintext_size: u32,
}

impl Default for CmAesGcmDecryptUpdateResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmDecryptUpdateRespHeader::default(),
            plaintext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl Default for CmAesGcmDecryptUpdateRespHeader {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            plaintext_size: 0,
        }
    }
}

impl_response_var_size_with_header!(
    CmAesGcmDecryptUpdateResp,
    CmAesGcmDecryptUpdateRespHeader,
    plaintext_size
);

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptFinalReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
    pub tag_len: u32,
    pub tag: [u8; 16],
    pub ciphertext_size: u32,
    pub ciphertext: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmAesGcmDecryptFinalReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE],
            tag_len: 0,
            tag: [0u8; 16],
            ciphertext_size: 0,
            ciphertext: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmAesGcmDecryptFinalReq, ciphertext_size, MAX_CMB_DATA_SIZE);

impl Request for CmAesGcmDecryptFinalReq {
    const ID: CommandId = CommandId::CM_AES_GCM_DECRYPT_FINAL;
    type Resp = CmAesGcmDecryptFinalResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmAesGcmDecryptFinalResp {
    pub hdr: CmAesGcmDecryptFinalRespHeader,
    pub plaintext: [u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmAesGcmDecryptFinalRespHeader {
    pub hdr: MailboxRespHeader,
    pub tag_verified: u32,
    pub plaintext_size: u32,
}

impl Default for CmAesGcmDecryptFinalResp {
    fn default() -> Self {
        Self {
            hdr: CmAesGcmDecryptFinalRespHeader::default(),
            plaintext: [0u8; MAX_CMB_AES_GCM_OUTPUT_SIZE],
        }
    }
}

impl_response_var_size_with_header!(
    CmAesGcmDecryptFinalResp,
    CmAesGcmDecryptFinalRespHeader,
    plaintext_size
);

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhGenerateReq {
    pub hdr: MailboxReqHeader,
}

impl Request for CmEcdhGenerateReq {
    const ID: CommandId = CommandId::CM_ECDH_GENERATE;
    type Resp = CmEcdhGenerateResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhGenerateResp {
    pub hdr: MailboxRespHeader,
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for CmEcdhGenerateResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl Response for CmEcdhGenerateResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhFinishReq {
    pub hdr: MailboxReqHeader,
    pub context: [u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
    pub key_usage: u32,
    pub incoming_exchange_data: [u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
}

impl Default for CmEcdhFinishReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            context: [0u8; CMB_ECDH_ENCRYPTED_CONTEXT_SIZE],
            key_usage: 0,
            incoming_exchange_data: [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE],
        }
    }
}

impl Request for CmEcdhFinishReq {
    const ID: CommandId = CommandId::CM_ECDH_FINISH;
    type Resp = CmEcdhFinishResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdhFinishResp {
    pub hdr: MailboxRespHeader,
    pub output: Cmk,
}

impl Response for CmEcdhFinishResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub hash_algorithm: u32,
    pub data_size: u32,
    pub data: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHmacReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            hash_algorithm: 0,
            data_size: 0,
            data: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmHmacReq, data_size, MAX_CMB_DATA_SIZE);

impl Request for CmHmacReq {
    const ID: CommandId = CommandId::CM_HMAC;
    type Resp = CmHmacResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacResp {
    pub hdr: MailboxRespHeaderVarSize,
    pub mac: [u8; CMB_HMAC_MAX_SIZE],
}

impl Default for CmHmacResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeaderVarSize::default(),
            mac: [0u8; CMB_HMAC_MAX_SIZE],
        }
    }
}

impl ResponseVarSize for CmHmacResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacKdfCounterReq {
    pub hdr: MailboxReqHeader,
    pub kin: Cmk,
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub label_size: u32,
    pub label: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHmacKdfCounterReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            kin: Cmk::default(),
            hash_algorithm: 0,
            key_size: 0,
            key_usage: 0,
            label_size: 0,
            label: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmHmacKdfCounterReq, label_size, MAX_CMB_DATA_SIZE);

impl Request for CmHmacKdfCounterReq {
    const ID: CommandId = CommandId::CM_HMAC_KDF_COUNTER;
    type Resp = CmHmacKdfCounterResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHmacKdfCounterResp {
    pub hdr: MailboxRespHeader,
    pub kout: Cmk,
}

impl Response for CmHmacKdfCounterResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmHkdfExtractReq {
    pub hdr: MailboxReqHeader,
    pub hash_algorithm: u32,
    pub salt: Cmk,
    pub ikm: Cmk,
}

impl Request for CmHkdfExtractReq {
    const ID: CommandId = CommandId::CM_HKDF_EXTRACT;
    type Resp = CmHkdfExtractResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExtractResp {
    pub hdr: MailboxRespHeader,
    pub prk: Cmk,
}

impl Response for CmHkdfExtractResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExpandReq {
    pub hdr: MailboxReqHeader,
    pub prk: Cmk,
    pub hash_algorithm: u32,
    pub key_usage: u32,
    pub key_size: u32,
    pub info_size: u32,
    pub info: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmHkdfExpandReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            prk: Cmk::default(),
            hash_algorithm: 0,
            key_size: 0,
            key_usage: 0,
            info_size: 0,
            info: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmHkdfExpandReq, info_size, MAX_CMB_DATA_SIZE);

impl Request for CmHkdfExpandReq {
    const ID: CommandId = CommandId::CM_HKDF_EXPAND;
    type Resp = CmHkdfExpandResp;
}

#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmHkdfExpandResp {
    pub hdr: MailboxRespHeader,
    pub okm: Cmk,
}

impl Response for CmHkdfExpandResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmMldsaPublicKeyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmMldsaPublicKeyReq {
    const ID: CommandId = CommandId::CM_MLDSA_PUBLIC_KEY;
    type Resp = CmMldsaPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaPublicKeyResp {
    pub hdr: MailboxRespHeader,
    pub public_key: [u8; MLDSA87_PUB_KEY_BYTE_SIZE],
}

impl Default for CmMldsaPublicKeyResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            public_key: [0u8; MLDSA87_PUB_KEY_BYTE_SIZE],
        }
    }
}

impl Response for CmMldsaPublicKeyResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaSignReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmMldsaSignReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmMldsaSignReq, message_size, MAX_CMB_DATA_SIZE);

impl Request for CmMldsaSignReq {
    const ID: CommandId = CommandId::CM_MLDSA_SIGN;
    type Resp = CmMldsaSignResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaSignResp {
    pub hdr: MailboxRespHeader,
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
}

impl Default for CmMldsaSignResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
        }
    }
}

impl Response for CmMldsaSignResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmMldsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub signature: [u8; MLDSA87_SIGNATURE_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmMldsaVerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            signature: [0u8; MLDSA87_SIGNATURE_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmMldsaVerifyReq, message_size, MAX_CMB_DATA_SIZE);

impl Request for CmMldsaVerifyReq {
    const ID: CommandId = CommandId::CM_MLDSA_VERIFY;
    type Resp = MailboxRespHeader;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq, Default)]
pub struct CmEcdsaPublicKeyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
}

impl Request for CmEcdsaPublicKeyReq {
    const ID: CommandId = CommandId::CM_ECDSA_PUBLIC_KEY;
    type Resp = CmEcdsaPublicKeyResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaPublicKeyResp {
    pub hdr: MailboxRespHeader,
    pub public_key_x: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub public_key_y: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for CmEcdsaPublicKeyResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            public_key_x: [0u8; ECC384_SCALAR_BYTE_SIZE],
            public_key_y: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl Response for CmEcdsaPublicKeyResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaSignReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmEcdsaSignReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmEcdsaSignReq, message_size, MAX_CMB_DATA_SIZE);

impl Request for CmEcdsaSignReq {
    const ID: CommandId = CommandId::CM_ECDSA_SIGN;
    type Resp = CmEcdsaSignResp;
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaSignResp {
    pub hdr: MailboxRespHeader,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
}

impl Default for CmEcdsaSignResp {
    fn default() -> Self {
        Self {
            hdr: MailboxRespHeader::default(),
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
        }
    }
}

impl Response for CmEcdsaSignResp {}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
pub struct CmEcdsaVerifyReq {
    pub hdr: MailboxReqHeader,
    pub cmk: Cmk,
    pub signature_r: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub signature_s: [u8; ECC384_SCALAR_BYTE_SIZE],
    pub message_size: u32,
    pub message: [u8; MAX_CMB_DATA_SIZE],
}

impl Default for CmEcdsaVerifyReq {
    fn default() -> Self {
        Self {
            hdr: MailboxReqHeader::default(),
            cmk: Cmk::default(),
            signature_r: [0u8; ECC384_SCALAR_BYTE_SIZE],
            signature_s: [0u8; ECC384_SCALAR_BYTE_SIZE],
            message_size: 0,
            message: [0u8; MAX_CMB_DATA_SIZE],
        }
    }
}

impl_request_var_size!(CmEcdsaVerifyReq, message_size, MAX_CMB_DATA_SIZE);

impl Request for CmEcdsaVerifyReq {
    const ID: CommandId = CommandId::CM_ECDSA_VERIFY;
    type Resp = MailboxRespHeader;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_matches_caliptra_api_vector() {
        assert_eq!(calc_checksum(0xe8dc3994, &[0x83, 0xe7, 0x25]), 0xfffffbe0);
        assert!(verify_checksum(0xfffffbe0, 0xe8dc3994, &[0x83, 0xe7, 0x25]));
    }

    #[test]
    fn mailbox_wire_layout_matches_caliptra_api() {
        assert_eq!(size_of::<MailboxReqHeader>(), 4);
        assert_eq!(size_of::<MailboxRespHeader>(), 8);
        assert_eq!(size_of::<MailboxRespHeaderVarSize>(), 12);
        assert_eq!(size_of::<Cmk>(), 128);
        assert_eq!(size_of::<ProductionAuthDebugUnlockReq>(), 12);
        assert_eq!(size_of::<ProductionAuthDebugUnlockChallenge>(), 92);
        assert_eq!(size_of::<ProductionAuthDebugUnlockToken>(), 7504);
        assert_eq!(size_of::<CmImportReq>(), 76);
        assert_eq!(size_of::<CmImportResp>(), 136);
        assert_eq!(size_of::<CmDeleteReq>(), 132);
        assert_eq!(size_of::<CmStatusResp>(), 16);
        assert_eq!(size_of::<CmShaInitReq>(), 4108);
        assert_eq!(size_of::<CmShaUpdateReq>(), 4304);
        assert_eq!(size_of::<CmShaFinalReq>(), 4304);
        assert_eq!(size_of::<CmShaInitResp>(), 208);
        assert_eq!(size_of::<CmShaFinalResp>(), 76);
        assert_eq!(size_of::<CmRandomGenerateReq>(), 8);
        assert_eq!(size_of::<CmRandomGenerateResp>(), 4108);
        assert_eq!(size_of::<CmRandomStirReq>(), 4104);
        assert_eq!(size_of::<CmAesEncryptInitReq>(), 4236);
        assert_eq!(size_of::<CmAesEncryptInitRespHeader>(), 184);
        assert_eq!(size_of::<CmAesEncryptInitResp>(), 4280);
        assert_eq!(size_of::<CmAesRespHeader>(), 168);
        assert_eq!(size_of::<CmAesResp>(), 4264);
        assert_eq!(size_of::<CmAesGcmEncryptInitReq>(), 4236);
        assert_eq!(size_of::<CmAesGcmEncryptInitResp>(), 148);
        assert_eq!(size_of::<CmAesGcmEncryptUpdateRespHeader>(), 140);
        assert_eq!(size_of::<CmAesGcmEncryptUpdateResp>(), 4252);
        assert_eq!(size_of::<CmAesGcmEncryptFinalRespHeader>(), 28);
        assert_eq!(size_of::<CmAesGcmEncryptFinalResp>(), 4140);
        assert_eq!(size_of::<CmAesGcmDecryptFinalReq>(), 4252);
        assert_eq!(size_of::<CmAesGcmDecryptFinalRespHeader>(), 16);
        assert_eq!(size_of::<CmAesGcmDecryptFinalResp>(), 4128);
        assert_eq!(size_of::<CmEcdhGenerateReq>(), 4);
        assert_eq!(size_of::<CmEcdhGenerateResp>(), 180);
        assert_eq!(size_of::<CmEcdhFinishReq>(), 180);
        assert_eq!(size_of::<CmEcdhFinishResp>(), 136);
        assert_eq!(size_of::<CmHmacReq>(), 4236);
        assert_eq!(size_of::<CmHmacResp>(), 76);
        assert_eq!(size_of::<CmHmacKdfCounterReq>(), 4244);
        assert_eq!(size_of::<CmHmacKdfCounterResp>(), 136);
        assert_eq!(size_of::<CmHkdfExtractReq>(), 264);
        assert_eq!(size_of::<CmHkdfExtractResp>(), 136);
        assert_eq!(size_of::<CmHkdfExpandReq>(), 4244);
        assert_eq!(size_of::<CmHkdfExpandResp>(), 136);
        assert_eq!(size_of::<CmMldsaPublicKeyReq>(), 132);
        assert_eq!(size_of::<CmMldsaPublicKeyResp>(), 2600);
        assert_eq!(size_of::<CmMldsaSignReq>(), 4232);
        assert_eq!(size_of::<CmMldsaSignResp>(), 4636);
        assert_eq!(size_of::<CmMldsaVerifyReq>(), 8860);
        assert_eq!(size_of::<CmEcdsaPublicKeyReq>(), 132);
        assert_eq!(size_of::<CmEcdsaPublicKeyResp>(), 104);
        assert_eq!(size_of::<CmEcdsaSignReq>(), 4232);
        assert_eq!(size_of::<CmEcdsaSignResp>(), 104);
        assert_eq!(size_of::<CmEcdsaVerifyReq>(), 4328);
    }

    #[test]
    fn request_partial_len_is_checked() {
        let mut req = CmShaInitReq {
            input_size: 3,
            ..Default::default()
        };
        assert_eq!(
            req.as_bytes_partial().unwrap().len(),
            size_of::<CmShaInitReq>() - MAX_CMB_DATA_SIZE + 3
        );
        assert_eq!(
            req.as_bytes_partial_mut().unwrap().len(),
            size_of::<CmShaInitReq>() - MAX_CMB_DATA_SIZE + 3
        );

        req.input_size = (MAX_CMB_DATA_SIZE + 1) as u32;
        assert_eq!(
            req.as_bytes_partial().unwrap_err(),
            MailboxWireError::RequestDataLenTooLarge
        );
    }

    #[test]
    fn response_partial_len_is_checked() {
        let mut resp = CmAesResp::default();
        resp.hdr.output_size = 4;
        assert_eq!(resp.data().unwrap().len(), 4);
        assert_eq!(
            resp.as_bytes_partial().unwrap().len(),
            size_of::<CmAesRespHeader>() + 4
        );
        assert_eq!(
            resp.as_bytes_partial_mut().unwrap().len(),
            size_of::<CmAesRespHeader>() + 4
        );

        resp.hdr.output_size = (MAX_CMB_DATA_SIZE + 1) as u32;
        assert_eq!(
            resp.as_bytes_partial().unwrap_err(),
            MailboxWireError::ResponseDataLenTooLarge
        );
    }
}
