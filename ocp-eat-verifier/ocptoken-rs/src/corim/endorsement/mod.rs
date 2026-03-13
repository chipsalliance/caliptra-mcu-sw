// Licensed under the Apache-2.0 license

//! Endorsement CoRIM collection and verification.
//!
//! Endorsement CoRIMs use CBOR tag 501 (unsigned CoRIM) as their COSE_Sign1
//! payload. Profile-specific extraction is delegated to sub-modules:
//!
//! - [`safe_sfr`] — OCP SAFE Security Findings Report profile.

pub mod safe_sfr;
pub use safe_sfr::{ConditionEntry, EndorsementEnvironment, SafeFwIdentifier, SafeIssue, SafeSfrEntry};

use std::path::Path;

use crate::cose_verify::{CoseSign1Verifier, CryptoBackend};

use super::{CorimResult, SignedCorim};

/// A verified endorsement CoRIM entry with optional decoded profile data.
pub struct EndorsementCorim {
    /// Source file name.
    pub file_name: String,
    /// CoRIM ID extracted from the payload (key 0).
    pub corim_id: Option<String>,
    /// Extracted OCP SAFE SFR entries from conditional endorsement triples.
    pub sfr_entries: Vec<SafeSfrEntry>,
}

/// A collection of authenticated, verified, and decoded endorsement CoRIMs.
pub struct EndorsementCorims {
    pub entries: Vec<EndorsementCorim>,
}

impl EndorsementCorims {
    /// Decode, authenticate, verify, and extract profile data from all
    /// `.cbor` files in `dir`.
    pub fn decode_and_verify(
        dir: &Path,
        ta_store: &dyn crate::ta_store::TrustAnchorStore,
        verifier: &CoseSign1Verifier<impl CryptoBackend>,
    ) -> CorimResult<Self> {
        let corims = SignedCorim::decode_files(dir, ta_store)?;
        let mut entries = Vec::with_capacity(corims.len());
        for c in &corims {
            c.verify(verifier)?;
            let (corim_id, sfr_entries) = safe_sfr::extract_safe_sfr(c)?;
            entries.push(EndorsementCorim {
                file_name: c.file_name().to_string(),
                corim_id,
                sfr_entries,
            });
        }
        Ok(EndorsementCorims { entries })
    }

    /// Returns `true` if there are no endorsement CoRIM entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over verified endorsement entries.
    pub fn iter(&self) -> impl Iterator<Item = &EndorsementCorim> {
        self.entries.iter()
    }
}
