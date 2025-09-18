// Licensed under the Apache-2.0 license
#![no_std]

//! OCP EAT (Entity Attestation Token) encoder library
//! 
//! This library provides a no_std compatible implementation for encoding
//! OCP Profile Entity Attestation Tokens using CBOR and COSE Sign1.
//!
//! # Features
//! 
//! - No standard library dependencies (`no_std` compatible)
//! - Type-safe structured evidence API
//! - CBOR encoding with minimal memory footprint
//! - P-384 ECDSA signature support via COSE Sign1
//! - Compile-time validation of token structure
//!
//! # Usage
//!
//! ```rust,no_run
//! use ocp_eat::{
//!     ConciseEvidenceMap, EnvironmentMap, ClassMap, MeasurementMap, 
//!     MeasurementValue, MeasurementFormat, EvidenceTripleRecord, EvTriplesMap, ConciseEvidence
//! };
//!
//! // Create structured evidence
//! let measurements = [];
//! let evidence_triple = EvidenceTripleRecord {
//!     environment: EnvironmentMap {
//!         class: ClassMap {
//!             class_id: "example-device",
//!             vendor: Some("Example Corp"),
//!             model: Some("Device-v1.0"),
//!         },
//!     },
//!     measurements: &measurements,
//! };
//!
//! // Create a binding for the evidence triple array to avoid temporary value issues
//! let evidence_triple_array = [evidence_triple];
//! let ev_triples_map = EvTriplesMap {
//!     evidence_triples: Some(&evidence_triple_array),
//!     identity_triples: None,
//!     dependency_triples: None,
//!     membership_triples: None,
//!     coswid_triples: None,
//!     attest_key_triples: None,
//! };
//!
//! let evidence_map = ConciseEvidenceMap {
//!     ev_triples: ev_triples_map,
//!     evidence_id: None,
//!     profile: None,
//! };
//!
//! let evidence = ConciseEvidence::Map(evidence_map);
//!
//! // Create measurement format
//! let measurement_format = MeasurementFormat::new(&evidence);
//! ```

pub mod eat_encoder;

// Re-export main types for easier usage
pub use eat_encoder::{
    // Core structures
    ConciseEvidenceMap,
    ConciseEvidence,
    EnvironmentMap,
    ClassMap,
    MeasurementMap,
    MeasurementValue,
    DigestEntry,
    MeasurementFormat,
    OcpEatClaims,
    DloaType,
    CorimLocatorMap,
    PrivateClaim,
    
    // Evidence triple structures
    EvidenceTripleRecord,
    EvTriplesMap,
    
    // COSE structures
    ProtectedHeader,
    CoseHeaderPair,
    
    // Enums and constants
    DebugStatus,
    EatError,
    
    // Encoder
    EatEncoder,
    CborEncoder,
    
    // Constants modules
    cose_headers,
};

// Re-export claim key constants
pub use eat_encoder::{
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