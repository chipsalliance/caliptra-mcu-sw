// Licensed under the Apache-2.0 license

//! DMTF SPDM Object Identifiers (OIDs).
//!
//! Defined in DMTF DSP0274 (Security Protocol and Data Model Specification).

use asn1::ObjectIdentifier;

/// DMTF base: 1.3.6.1.4.1.412
pub const OID_DMTF: ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 4, 1, 412);

/// DMTF SPDM: 1.3.6.1.4.1.412.274
pub const OID_DMTF_SPDM: ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274);

/// DMTF SPDM Device Info: 1.3.6.1.4.1.412.274.1
/// Used to convey device information (e.g. in Subject Alternative Name otherName).
pub const OID_DMTF_SPDM_DEVICE_INFO: ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 1);

/// DMTF SPDM Hardware Identity: 1.3.6.1.4.1.412.274.2
/// Used to bind a device certificate to immutable hardware identity.
pub const OID_DMTF_SPDM_HARDWARE_IDENTITY: ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 2);

/// DMTF SPDM EKU Responder Auth: 1.3.6.1.4.1.412.274.3
pub const OID_DMTF_SPDM_EKU_RESPONDER_AUTH: ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 3);

/// DMTF SPDM EKU Requester Auth: 1.3.6.1.4.1.412.274.4
pub const OID_DMTF_SPDM_EKU_REQUESTER_AUTH: ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 4);

/// DMTF SPDM Mutable Certificate: 1.3.6.1.4.1.412.274.5
/// Identifies mutable device certificates within the SPDM hierarchy.
pub const OID_DMTF_SPDM_MUTABLE_CERTIFICATE: ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 5);

/// DMTF SPDM Extension: 1.3.6.1.4.1.412.274.6
/// Encapsulates a sequence of SPDM certificate OIDs.
pub const OID_DMTF_SPDM_EXTENSION: ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 4, 1, 412, 274, 6);
