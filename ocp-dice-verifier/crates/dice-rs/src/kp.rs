// Licensed under the Apache-2.0 license

//! TCG DICE Key Purpose definitions (Extended Key Usage).
//!
//! Reference: TCG DICE Attestation Architecture v1.2, Section 8.2.

use crate::oids::*;
use asn1::ObjectIdentifier;

/// Key Purpose identifiers defined in TCG DICE specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiceKeyPurpose {
    /// Initial Device Identity (IDevID) key purpose.
    IdentityInit,
    /// Local Device Identity (LDevID) key purpose.
    IdentityLoc,
    /// Initial Attestation key purpose.
    AttestInit,
    /// Local Attestation key purpose (Alias / DPE Leaf).
    AttestLoc,
    /// Initial Assertion key purpose.
    AssertInit,
    /// Local Assertion key purpose.
    AssertLoc,
    /// Embedded Certificate Authority (ECA) key purpose.
    Eca,
}

impl DiceKeyPurpose {
    /// Maps an ObjectIdentifier to a known DICE KeyPurpose, if matching.
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        if *oid == OID_TCG_DICE_KP_IDENTITY_INIT {
            Some(Self::IdentityInit)
        } else if *oid == OID_TCG_DICE_KP_IDENTITY_LOC {
            Some(Self::IdentityLoc)
        } else if *oid == OID_TCG_DICE_KP_ATTEST_INIT {
            Some(Self::AttestInit)
        } else if *oid == OID_TCG_DICE_KP_ATTEST_LOC {
            Some(Self::AttestLoc)
        } else if *oid == OID_TCG_DICE_KP_ASSERT_INIT {
            Some(Self::AssertInit)
        } else if *oid == OID_TCG_DICE_KP_ASSERT_LOC {
            Some(Self::AssertLoc)
        } else if *oid == OID_TCG_DICE_KP_ECA {
            Some(Self::Eca)
        } else {
            None
        }
    }

    /// Returns the standard OID corresponding to this DICE KeyPurpose.
    pub fn to_oid(&self) -> ObjectIdentifier {
        match self {
            Self::IdentityInit => OID_TCG_DICE_KP_IDENTITY_INIT,
            Self::IdentityLoc => OID_TCG_DICE_KP_IDENTITY_LOC,
            Self::AttestInit => OID_TCG_DICE_KP_ATTEST_INIT,
            Self::AttestLoc => OID_TCG_DICE_KP_ATTEST_LOC,
            Self::AssertInit => OID_TCG_DICE_KP_ASSERT_INIT,
            Self::AssertLoc => OID_TCG_DICE_KP_ASSERT_LOC,
            Self::Eca => OID_TCG_DICE_KP_ECA,
        }
    }

    /// Returns the exact ASN.1 identifier defined in TCG DICE Attestation Architecture.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IdentityInit => "tcg-dice-kp-identityInit",
            Self::IdentityLoc => "tcg-dice-kp-identityLoc",
            Self::AttestInit => "tcg-dice-kp-attestInit",
            Self::AttestLoc => "tcg-dice-kp-attestLoc",
            Self::AssertInit => "tcg-dice-kp-assertInit",
            Self::AssertLoc => "tcg-dice-kp-assertLoc",
            Self::Eca => "tcg-dice-kp-eca",
        }
    }
}

impl std::fmt::Display for DiceKeyPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
