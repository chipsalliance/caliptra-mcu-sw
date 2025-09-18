// Licensed under the Apache-2.0 license
// Re-export all public APIs from the split modules to maintain backward compatibility

#![allow(unused_imports)]

// Import the new modules
mod cbor;
mod eat;
mod concise_evidence;

// Re-export everything from the cbor module
pub use cbor::CborEncoder;

// Re-export only used items from the eat module  
pub use eat::{
    EatEncoder, 
    ProtectedHeader, 
    CoseHeaderPair, 
    cose_headers,
    create_sign1_context,
    MeasurementFormat,
    OcpEatClaims,
    DloaType,
    CorimLocatorMap,
    PrivateClaim,
    DebugStatus,
    EatError,
    // Constants
    CLAIM_KEY_ISSUER,
    CLAIM_KEY_CTI,
    CLAIM_KEY_NONCE,
    CLAIM_KEY_DBGSTAT,
    CLAIM_KEY_EAT_PROFILE,
    CLAIM_KEY_MEASUREMENTS,
    CLAIM_KEY_UEID,
    CLAIM_KEY_OEMID,
    CLAIM_KEY_HWMODEL,
    CLAIM_KEY_UPTIME,
    CLAIM_KEY_BOOTCOUNT,
    CLAIM_KEY_BOOTSEED,
    CLAIM_KEY_DLOAS,
    CLAIM_KEY_RIM_LOCATORS,
};

// Re-export only used items from the concise_evidence module
pub use concise_evidence::{
    DigestEntry, MeasurementValue, MeasurementMap, ClassMap, EnvironmentMap,
    EvidenceTripleRecord, EvTriplesMap, ConciseEvidenceMap, TaggedConciseEvidence, ConciseEvidence,
};