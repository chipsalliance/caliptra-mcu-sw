// Licensed under the Apache-2.0 license

//! OCP EAT claims and COSE signing support.

mod claims;
mod common;
mod sign;

pub(crate) use claims::{concise_evidence_buffer_mut, finish_claims_payload, start_claims_payload};
pub use claims::{
    encode_claims_payload, CONCISE_EVIDENCE_MAX_SIZE, CONCISE_EVIDENCE_MEASUREMENT_COUNT,
    EAT_PAYLOAD_MAX_SIZE, NONCE_LEN,
};
pub(crate) use sign::{cose_sign1_len, SignedEat};
