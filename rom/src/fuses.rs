// Licensed under the Apache-2.0 license

// TODO: remove after we use these
#![allow(dead_code)]
#![allow(unused)]

use caliptra_mcu_error::{McuError, McuResult};
use caliptra_mcu_registers_generated::fuses as generated_fuses;
use caliptra_mcu_romtime::Otp;
use caliptra_mcu_romtime::{Bits, Duplication, FuseLayout, PqcKeyType};
use core::num::NonZero;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Owner public key hash structure.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct OwnerPkHash(pub [u32; 12]);
/// Vendor public key hash structure.
#[derive(Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
pub struct VendorPkHash(pub [u32; 12]);

/// MCU fuses implemented on top of a view of raw fuses.
pub struct McuFuses {
    raw_fuses: &'static dyn RawFuses,
    fuse_layout_policy: McuFuseLayoutPolicy,
}

impl McuFuses {
    pub fn new(
        raw_fuses: &'static dyn RawFuses,
        fuse_layout_policy_override: Option<McuFuseLayoutPolicy>,
    ) -> Self {
        Self {
            raw_fuses,
            fuse_layout_policy: fuse_layout_policy_override.unwrap_or_default(),
        }
    }
}

/// Trait for accessing raw fuse values.
/// Implementors should provide access to the individual fuse values as u32 slices,
/// which will be interpreted by the McuFuses struct to provide the values.
pub trait RawFuses {
    fn anti_rollback_disable(&self) -> u32;
    fn idevid_cert_idevid_attr(&self) -> &[u32];
    fn soc_specific_idevid_certificate(&self) -> Option<&[u32]>;
    fn idevid_manuf_hsm_identifier(&self) -> &[u32];
    fn soc_stepping_id(&self) -> u32;
    fn fmc_key_manifest_svn(&self) -> &[u8];
    fn runtime_svn(&self) -> &[u8];
    fn soc_manifest_svn(&self) -> &[u8];
    fn soc_manifest_max_svn(&self) -> &[u8];
    fn owner_pk_hash(&self) -> Option<OwnerPkHash>;
    fn owner_pqc_key_type(&self) -> &[u8];
    fn owner_pk_hash_valid(&self) -> u32;
    fn vendor_pk_hashes(&self) -> &[VendorPkHash];
    fn pqc_key_types(&self) -> &[u32];
    fn vendor_pk_hash_valid(&self) -> &[u32];
    fn owner_ecc_revocation(&self) -> &[u32];
    fn owner_lms_revocation(&self) -> &[u32];
    fn owner_mldsa_revocation(&self) -> &[u32];
    fn ecc_revocations(&self) -> &[u32];
    fn lms_revocations(&self) -> Option<&[u32]>;
    fn mldsa_revocations(&self) -> Option<&[u32]>;
}

pub struct McuFuseLayoutPolicy {
    anti_rollback_disable: FuseLayout,
    idevid_cert_idevid_attr: FuseLayout,
    soc_specific_idevid_certificate: Option<FuseLayout>,
    idevid_manuf_hsm_identifier: FuseLayout,
    soc_stepping_id: FuseLayout,
    fmc_key_manifest_svn: FuseLayout,
    runtime_svn: FuseLayout,
    soc_manifest_svn: FuseLayout,
    soc_manifest_max_svn: FuseLayout,
    owner_pqc_key_type: FuseLayout,
    owner_pk_hash_valid: FuseLayout,
    pqc_key_types: FuseLayout,
    vendor_pk_hash_valid: FuseLayout,
    owner_ecc_revocation: FuseLayout,
    owner_lms_revocation: FuseLayout,
    owner_mldsa_revocation: FuseLayout,
    ecc_revocations: FuseLayout,
    lms_revocations: FuseLayout,
    mldsa_revocations: FuseLayout,
}

impl Default for McuFuseLayoutPolicy {
    fn default() -> Self {
        Self {
            anti_rollback_disable: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            idevid_cert_idevid_attr: FuseLayout::Single(Bits(NonZero::new(768 * 8).unwrap())),
            soc_specific_idevid_certificate: None,
            idevid_manuf_hsm_identifier: FuseLayout::Single(Bits(NonZero::new(32).unwrap())),
            soc_stepping_id: FuseLayout::Single(Bits(NonZero::new(32).unwrap())),
            fmc_key_manifest_svn: FuseLayout::OneHotLinearOr(
                Bits(NonZero::new(32).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            runtime_svn: FuseLayout::OneHotLinearOr(
                Bits(NonZero::new(128).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            soc_manifest_svn: FuseLayout::OneHotLinearOr(
                Bits(NonZero::new(128).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            soc_manifest_max_svn: FuseLayout::Single(Bits(NonZero::new(128).unwrap())),
            owner_pqc_key_type: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            owner_pk_hash_valid: FuseLayout::Single(Bits(NonZero::new(1).unwrap())),
            pqc_key_types: FuseLayout::Single(Bits(NonZero::new(16).unwrap())),
            vendor_pk_hash_valid: FuseLayout::Single(Bits(NonZero::new(16).unwrap())),
            owner_ecc_revocation: FuseLayout::LinearOr(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            owner_lms_revocation: FuseLayout::LinearOr(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            owner_mldsa_revocation: FuseLayout::LinearOr(
                Bits(NonZero::new(1).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            ecc_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            lms_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
            mldsa_revocations: FuseLayout::WordMajorityVote(
                Bits(NonZero::new(16).unwrap()),
                Duplication(NonZero::new(3).unwrap()),
            ),
        }
    }
}

/// Trait for selecting the vendor public key slot to use.
pub trait VendorKeyPolicy {
    /// Returns the index of the key slot that should be used.
    fn select_key(&self, otp: &Otp) -> McuResult<usize>;
}

/// Default implementation of the vendor key selection policy.
///
/// This policy selects the first key slot that is both marked valid
/// in the VENDOR_PK_HASH_VALID mask and is functional (not fully revoked).
pub struct DefaultVendorKeyPolicy {
    rotate_pk_hash: bool,
}

impl DefaultVendorKeyPolicy {
    pub const fn new(rotate_pk_hash: bool) -> Self {
        Self { rotate_pk_hash }
    }
}

impl Default for DefaultVendorKeyPolicy {
    fn default() -> Self {
        Self::new(false)
    }
}

impl VendorKeyPolicy for DefaultVendorKeyPolicy {
    fn select_key(&self, otp: &Otp) -> McuResult<usize> {
        let valid_mask = otp.read_entry_multi::<1>(generated_fuses::VENDOR_PK_HASH_VALID)?[0];
        let target_slot_count = if self.rotate_pk_hash { 2 } else { 1 };
        let mut slots_found = 0;
        let mut first_functional: Option<usize> = None;

        for i in 0..16 {
            if (valid_mask >> i) & 1 == 1 {
                continue;
            }

            let ecc_revoked = otp.read_vendor_ecc_revocation(i)? & 0xF;
            let pqc_type = otp.read_pqc_key_type(i)?;
            let pqc_revoked = match pqc_type {
                PqcKeyType::MLDSA => otp.read_vendor_mldsa_revocation(i)? & 0xF,
                PqcKeyType::LMS => otp.read_vendor_lms_revocation(i)? & 0xFFFF,
            };

            // A slot is functional if it has at least one unrevoked ECC key AND
            // at least one unrevoked PQC key (LMS or MLDSA).
            // ECC/MLDSA have 4 bits of info, LMS has 16 bits.
            let ecc_functional = ecc_revoked < 0xF;
            let pqc_functional = match pqc_type {
                PqcKeyType::MLDSA => pqc_revoked < 0xF,
                PqcKeyType::LMS => pqc_revoked < 0xFFFF,
            };

            if ecc_functional && pqc_functional {
                slots_found += 1;
                first_functional = Some(i);
                if slots_found == target_slot_count {
                    return Ok(i);
                }
            }
        }

        match first_functional {
            // if the rotation strap is asserted, but we only found one valid PK hash
            // fall back to that one.
            Some(i) => Ok(i),
            None => Err(McuError::ROM_PK_HASH_SELECTION_FAILED),
        }
    }
}
