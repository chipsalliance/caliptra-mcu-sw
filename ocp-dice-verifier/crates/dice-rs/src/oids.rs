// Licensed under the Apache-2.0 license

//! Object Identifiers (OIDs) defined by the TCG DICE specifications.
//!
//! Reference: TCG DICE Attestation Architecture v1.2, Section 8.

use asn1::ObjectIdentifier;

// Base TCG DICE OID arc: { joint-iso-itu-t(2) international-organizations(23) tcg(133) dice(5) }
// 2.23.133.5

/// `tcg-dice-TcbInfo` (`2.23.133.5.4.1`)
///
/// Extension containing a single `DiceTcbInfo` structure.
pub const OID_TCG_DICE_TCB_INFO: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 1);

/// `tcg-dice-Ueid` (`2.23.133.5.4.4`)
///
/// Extension containing a `DiceUeid` structure (Universal Entity Identifier).
pub const OID_TCG_DICE_UEID: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 4);

/// `tcg-dice-MultiTcbInfo` (`2.23.133.5.4.5`)
///
/// Extension containing a `DiceMultiTcbInfo` sequence of `DiceTcbInfo` structures.
pub const OID_TCG_DICE_MULTI_TCB_INFO: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 5);

// TCG DICE Key Purposes (EKU arc: 2.23.133.5.4.100)

/// `tcg-dice-kp-identityInit` (`2.23.133.5.4.100.6`) - Initial Device Identity (IDevID).
pub const OID_TCG_DICE_KP_IDENTITY_INIT: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 6);

/// `tcg-dice-kp-identityLoc` (`2.23.133.5.4.100.7`) - Local Device Identity (LDevID).
pub const OID_TCG_DICE_KP_IDENTITY_LOC: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 7);

/// `tcg-dice-kp-attestInit` (`2.23.133.5.4.100.8`) - Initial Attestation Key.
pub const OID_TCG_DICE_KP_ATTEST_INIT: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 8);

/// `tcg-dice-kp-attestLoc` (`2.23.133.5.4.100.9`) - Local Attestation Key (Alias / DPE Leaf).
pub const OID_TCG_DICE_KP_ATTEST_LOC: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 9);

/// `tcg-dice-kp-assertInit` (`2.23.133.5.4.100.10`) - Initial Assertion Key.
pub const OID_TCG_DICE_KP_ASSERT_INIT: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 10);

/// `tcg-dice-kp-assertLoc` (`2.23.133.5.4.100.11`) - Local Assertion Key.
pub const OID_TCG_DICE_KP_ASSERT_LOC: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 11);

/// `tcg-dice-kp-eca` (`2.23.133.5.4.100.12`) - Embedded Certificate Authority (ECA).
pub const OID_TCG_DICE_KP_ECA: ObjectIdentifier = asn1::oid!(2, 23, 133, 5, 4, 100, 12);
