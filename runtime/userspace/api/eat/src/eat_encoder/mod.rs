// Licensed under the Apache-2.0 license
// Re-export all public APIs from the split modules to maintain backward compatibility

#![allow(unused_imports)]

// Import the new modules
mod cbor;
mod concise_evidence;
mod eat;

// Re-export everything from the cbor module
pub use cbor::CborEncoder;

// Re-export only used items from the eat module
pub use eat::{
    CLAIM_KEY_BOOTCOUNT,
    CLAIM_KEY_BOOTSEED,
    CLAIM_KEY_CTI,
    CLAIM_KEY_DBGSTAT,
    CLAIM_KEY_DLOAS,
    CLAIM_KEY_EAT_PROFILE,
    CLAIM_KEY_HWMODEL,
    // Constants
    CLAIM_KEY_ISSUER,
    CLAIM_KEY_MEASUREMENTS,
    CLAIM_KEY_NONCE,
    CLAIM_KEY_OEMID,
    CLAIM_KEY_RIM_LOCATORS,
    CLAIM_KEY_UEID,
    CLAIM_KEY_UPTIME,
    CorimLocatorMap,
    CoseHeaderPair,
    DebugStatus,
    DloaType,
    EatEncoder,
    EatError,
    MeasurementFormat,
    OcpEatClaims,
    PrivateClaim,
    ProtectedHeader,
    cose_headers,
    create_sign1_context,
};

// Re-export only used items from the concise_evidence module
pub use concise_evidence::{
    ClassMap, ConciseEvidence, ConciseEvidenceMap, DigestEntry, EnvironmentMap, EvTriplesMap,
    EvidenceTripleRecord, IntegrityRegisterEntry, IntegrityRegisterIdChoice, MeasurementMap,
    MeasurementValue, TaggedConciseEvidence,
};
