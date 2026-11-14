// Licensed under the Apache-2.0 license

//! Shared command-authorization wire format and canonical key encoding.

use crate::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_mcu_flash_image::{O_AUTH_KEY_ID, V_AUTH_KEY_ID};
use core::mem::{offset_of, size_of};
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub const COMMAND_AUTHORIZATION_VERSION: u32 = 1;
pub const COMMAND_AUTHORIZATION_UEID_SIZE: usize = 16;
pub const COMMAND_AUTHORIZATION_BLOCK_SIZE: usize = 7484;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationFormatError {
    UnsupportedVersion,
    UnknownAuthority,
    InvalidTarget,
    InvalidSignaturePadding,
}

impl core::fmt::Display for AuthorizationFormatError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "unsupported command-authorization version",
            Self::UnknownAuthority => "unknown command-authorization authority",
            Self::InvalidTarget => "command-authorization UEID does not match this device",
            Self::InvalidSignaturePadding => "nonzero ML-DSA signature padding",
        })
    }
}

impl core::error::Error for AuthorizationFormatError {}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandAuthority {
    VendorOwner = 1,
    Owner = 2,
}

impl CommandAuthority {
    pub const fn key_fw_id(self) -> u32 {
        match self {
            Self::VendorOwner => V_AUTH_KEY_ID,
            Self::Owner => O_AUTH_KEY_ID,
        }
    }

    pub const fn manifest_source(self) -> caliptra_api::mailbox::AuthManifestSource {
        match self {
            Self::VendorOwner => caliptra_api::mailbox::AuthManifestSource::VendorOwner,
            Self::Owner => caliptra_api::mailbox::AuthManifestSource::Owner,
        }
    }
}

impl TryFrom<u32> for CommandAuthority {
    type Error = AuthorizationFormatError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::VendorOwner),
            2 => Ok(Self::Owner),
            _ => Err(AuthorizationFormatError::UnknownAuthority),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandAuthMode {
    ChallengeBound,
    Offline,
}

impl CommandAuthMode {
    /// Decode request intent; live-challenge validation is performed separately.
    pub fn from_nonce(nonce: &[u8; AUTH_CMD_NONCE_LEN]) -> Self {
        if nonce == &[0; AUTH_CMD_NONCE_LEN] {
            Self::Offline
        } else {
            Self::ChallengeBound
        }
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
pub struct AuthorizationMetadata {
    pub version: U32,
    pub authority: U32,
    pub soc_ueid: [u8; COMMAND_AUTHORIZATION_UEID_SIZE],
}

impl AuthorizationMetadata {
    pub const fn new(
        authority: CommandAuthority,
        soc_ueid: [u8; COMMAND_AUTHORIZATION_UEID_SIZE],
    ) -> Self {
        Self {
            version: U32::new(COMMAND_AUTHORIZATION_VERSION),
            authority: U32::new(authority as u32),
            soc_ueid,
        }
    }

    pub fn validate(&self) -> Result<CommandAuthority, AuthorizationFormatError> {
        if self.version.get() != COMMAND_AUTHORIZATION_VERSION {
            return Err(AuthorizationFormatError::UnsupportedVersion);
        }
        CommandAuthority::try_from(self.authority.get())
    }

    pub fn is_fleet(&self) -> bool {
        self.soc_ueid == [0; COMMAND_AUTHORIZATION_UEID_SIZE]
    }

    pub fn validate_target(
        &self,
        local_ueid: &[u8; COMMAND_AUTHORIZATION_UEID_SIZE],
    ) -> Result<(), AuthorizationFormatError> {
        if self.is_fleet() || self.soc_ueid == *local_ueid {
            Ok(())
        } else {
            Err(AuthorizationFormatError::InvalidTarget)
        }
    }
}

impl Default for AuthorizationMetadata {
    fn default() -> Self {
        Self::new(
            CommandAuthority::Owner,
            [0; COMMAND_AUTHORIZATION_UEID_SIZE],
        )
    }
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct AuthorizationBlock {
    pub metadata: AuthorizationMetadata,
    pub nonce: [u8; AUTH_CMD_NONCE_LEN],
    pub ecc_pub_x: [u8; 48],
    pub ecc_pub_y: [u8; 48],
    pub mldsa_pub: [u8; 2592],
    pub signature: HybridSignature,
}

impl AuthorizationBlock {
    pub fn validate_format(&self) -> Result<CommandAuthority, AuthorizationFormatError> {
        let authority = self.metadata.validate()?;
        if self.signature.mldsa_sig.last() != Some(&0) {
            return Err(AuthorizationFormatError::InvalidSignaturePadding);
        }
        Ok(authority)
    }
}

impl Default for AuthorizationBlock {
    fn default() -> Self {
        Self {
            metadata: AuthorizationMetadata::default(),
            nonce: [0; AUTH_CMD_NONCE_LEN],
            ecc_pub_x: [0; 48],
            ecc_pub_y: [0; 48],
            mldsa_pub: [0; 2592],
            signature: HybridSignature::default(),
        }
    }
}

const _: () = assert!(size_of::<AuthorizationMetadata>() == 24);
const _: () = assert!(size_of::<AuthorizationBlock>() == COMMAND_AUTHORIZATION_BLOCK_SIZE);
const _: () = assert!(offset_of!(AuthorizationBlock, nonce) == 24);
const _: () = assert!(offset_of!(AuthorizationBlock, ecc_pub_x) == 72);
const _: () = assert!(offset_of!(AuthorizationBlock, ecc_pub_y) == 120);
const _: () = assert!(offset_of!(AuthorizationBlock, mldsa_pub) == 168);
const _: () = assert!(offset_of!(AuthorizationBlock, signature) == 2760);

/// Encode standard ECC coordinates as Core's little-endian memory of big-endian words.
pub fn ecc_public_key_core_bytes(x: &[u8; 48], y: &[u8; 48]) -> [u8; 96] {
    let mut encoded = [0; 96];
    encoded[..48].copy_from_slice(x);
    encoded[48..].copy_from_slice(y);
    for word in encoded.chunks_exact_mut(4) {
        word.reverse();
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorities_select_fixed_imes_and_manifest_sources() {
        use caliptra_api::mailbox::AuthManifestSource;

        assert_eq!(CommandAuthority::VendorOwner.key_fw_id(), 0x4);
        assert_eq!(CommandAuthority::Owner.key_fw_id(), 0x6);
        assert_eq!(
            CommandAuthority::VendorOwner.manifest_source().flag_bits(),
            AuthManifestSource::VendorOwner.flag_bits()
        );
        assert_eq!(
            CommandAuthority::Owner.manifest_source().flag_bits(),
            AuthManifestSource::Owner.flag_bits()
        );
    }

    #[test]
    fn metadata_has_canonical_little_endian_encoding() {
        let metadata = AuthorizationMetadata::new(CommandAuthority::Owner, [0x5a; 16]);
        assert_eq!(&metadata.as_bytes()[..8], &[1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&metadata.as_bytes()[8..], &[0x5a; 16]);
        assert_eq!(metadata.validate(), Ok(CommandAuthority::Owner));
    }

    #[test]
    fn unknown_versions_and_authorities_are_rejected() {
        let mut metadata = AuthorizationMetadata::default();
        metadata.version = U32::new(0);
        assert_eq!(
            metadata.validate(),
            Err(AuthorizationFormatError::UnsupportedVersion)
        );
        metadata.version = U32::new(COMMAND_AUTHORIZATION_VERSION);
        for value in [0, 3, u32::MAX] {
            metadata.authority = U32::new(value);
            assert_eq!(
                metadata.validate(),
                Err(AuthorizationFormatError::UnknownAuthority)
            );
        }
    }

    #[test]
    fn device_and_fleet_scopes_work_with_both_nonce_modes() {
        let local = [0x42; 16];
        let device = AuthorizationMetadata::new(CommandAuthority::Owner, local);
        let fleet = AuthorizationMetadata::default();
        for (mode, nonce) in [
            (CommandAuthMode::ChallengeBound, [0x73; AUTH_CMD_NONCE_LEN]),
            (CommandAuthMode::Offline, [0; AUTH_CMD_NONCE_LEN]),
        ] {
            assert_eq!(CommandAuthMode::from_nonce(&nonce), mode);
            assert_eq!(device.validate_target(&local), Ok(()));
            assert_eq!(fleet.validate_target(&local), Ok(()));
        }
        assert_eq!(
            device.validate_target(&[0x43; 16]),
            Err(AuthorizationFormatError::InvalidTarget)
        );
    }

    #[test]
    fn request_mode_is_derived_from_all_nonce_bytes() {
        assert_eq!(
            CommandAuthMode::from_nonce(&[0; AUTH_CMD_NONCE_LEN]),
            CommandAuthMode::Offline
        );
        for index in 0..AUTH_CMD_NONCE_LEN {
            let mut nonce = [0; AUTH_CMD_NONCE_LEN];
            nonce[index] = 1;
            assert_eq!(
                CommandAuthMode::from_nonce(&nonce),
                CommandAuthMode::ChallengeBound
            );
        }
    }

    #[test]
    fn authorization_block_has_exact_wire_size_and_rejects_nonzero_padding() {
        let mut block = AuthorizationBlock::default();
        assert_eq!(block.as_bytes().len(), COMMAND_AUTHORIZATION_BLOCK_SIZE);
        assert_eq!(block.validate_format(), Ok(CommandAuthority::Owner));
        *block.signature.mldsa_sig.last_mut().unwrap() = 1;
        assert_eq!(
            block.validate_format(),
            Err(AuthorizationFormatError::InvalidSignaturePadding)
        );
    }

    #[test]
    fn core_ecc_encoding_reverses_bytes_but_not_word_or_coordinate_order() {
        let x = core::array::from_fn(|i| i as u8);
        let y = core::array::from_fn(|i| (i + 48) as u8);
        let encoded = ecc_public_key_core_bytes(&x, &y);
        assert_eq!(&encoded[..8], &[3, 2, 1, 0, 7, 6, 5, 4]);
        assert_eq!(&encoded[44..52], &[47, 46, 45, 44, 51, 50, 49, 48]);
        assert_eq!(&encoded[92..], &[95, 94, 93, 92]);
    }
}
