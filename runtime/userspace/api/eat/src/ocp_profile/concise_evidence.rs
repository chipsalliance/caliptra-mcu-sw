// Licensed under the Apache-2.0 license

// Concise Evidence structures and encoding for RATS CoRIM compliance
use crate::cbor::{CborEncodable, CborEncoder};
use crate::error::EatError;

// CBOR tag for tagged concise evidence
const CBOR_TAG_CONCISE_EVIDENCE: u64 = 571;

// Concise Evidence Map keys (RATS CoRIM)
pub const CE_EV_TRIPLES: i32 = 0;
pub const CE_EVIDENCE_ID: i32 = 1;
pub const CE_PROFILE: i32 = 2;

// Evidence Triples Map keys
pub const CE_EVIDENCE_TRIPLES: i32 = 0;
pub const CE_IDENTITY_TRIPLES: i32 = 1;
pub const CE_DEPENDENCY_TRIPLES: i32 = 2;
pub const CE_MEMBERSHIP_TRIPLES: i32 = 3;
pub const CE_COSWID_TRIPLES: i32 = 4;
pub const CE_ATTEST_KEY_TRIPLES: i32 = 5;

// CoSWID Evidence Map keys
pub const CE_COSWID_TAG_ID: i32 = 0;
pub const CE_COSWID_EVIDENCE: i32 = 1;
pub const CE_AUTHORIZED_BY: i32 = 2;

#[derive(Debug, Clone, Copy)]
pub struct DigestEntry<'a> {
    pub alg_id: i32,     // Algorithm identifier (e.g., SHA-256 = -16)
    pub value: &'a [u8], // Digest value
}

impl CborEncodable for DigestEntry<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?; // [alg_id, value]
        encoder.encode_int(self.alg_id as i64)?;
        encoder.encode_bytes(self.value)?;
        Ok(())
    }
}

// Integrity register identifier choice (uint or text)
#[derive(Debug, Clone, Copy)]
pub enum IntegrityRegisterIdChoice<'a> {
    Uint(u64),
    Text(&'a str),
}

impl CborEncodable for IntegrityRegisterIdChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            IntegrityRegisterIdChoice::Uint(value) => encoder.encode_uint(*value),
            IntegrityRegisterIdChoice::Text(text) => encoder.encode_text(text),
        }
    }
}

// Integrity register entry
#[derive(Debug, Clone, Copy)]
pub struct IntegrityRegisterEntry<'a> {
    pub id: IntegrityRegisterIdChoice<'a>,
    pub digests: &'a [DigestEntry<'a>], // digests-type
}

impl CborEncodable for IntegrityRegisterEntry<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        // Encode the key (register ID)
        self.id.encode(encoder)?;

        // Encode the value (digests array)
        encoder.encode_array_header(self.digests.len() as u64)?;
        for digest in self.digests {
            digest.encode(encoder)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementValue<'a> {
    pub version: Option<&'a str>,
    pub svn: Option<u64>, // Security Version Number
    pub digests: Option<&'a [DigestEntry<'a>]>,
    pub integrity_registers: Option<&'a [IntegrityRegisterEntry<'a>]>, // Map of register ID -> digests
    pub raw_value: Option<&'a [u8]>,
    pub raw_value_mask: Option<&'a [u8]>,
}

impl CborEncodable for MeasurementValue<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 0u64;

        // Count entries
        if self.version.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.svn.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.digests.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.integrity_registers.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.raw_value.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.raw_value_mask.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        encoder.encode_map_header(map_entries)?;

        // Encode entries in deterministic order (sorted by numeric key)
        // Key 0: version
        if let Some(version) = self.version {
            encoder.encode_int(0)?;
            encoder.encode_text(version)?;
        }

        // Key 1: svn
        if let Some(svn) = self.svn {
            encoder.encode_int(1)?;
            encoder.encode_uint(svn)?;
        }

        // Key 2: digests
        if let Some(digests) = self.digests {
            encoder.encode_int(2)?;
            encoder.encode_array_header(digests.len() as u64)?;
            for digest in digests {
                digest.encode(encoder)?;
            }
        }

        // Key 4: raw-value
        if let Some(raw_value) = self.raw_value {
            encoder.encode_int(4)?;
            encoder.encode_bytes(raw_value)?;
        }

        // Key 5: raw-value-mask (deprecated but still supported)
        if let Some(raw_mask) = self.raw_value_mask {
            encoder.encode_int(5)?;
            encoder.encode_bytes(raw_mask)?;
        }

        // Key 14: integrity-registers
        if let Some(registers) = self.integrity_registers {
            encoder.encode_int(14)?;
            // Encode as map: { + integrity-register-id-type-choice => digests-type }
            encoder.encode_map_header(registers.len() as u64)?;
            for register in registers {
                register.encode(encoder)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementMap<'a> {
    pub key: u64, // Measurement key/identifier
    pub mval: MeasurementValue<'a>,
}

impl CborEncodable for MeasurementMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_map_header(2)?; // key and mval

        // Key 0: mkey (measured element type)
        encoder.encode_int(0)?;
        encoder.encode_uint(self.key)?;

        // Key 1: mval (measurement values)
        encoder.encode_int(1)?;
        self.mval.encode(encoder)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClassMap<'a> {
    pub class_id: &'a str,
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
}

impl CborEncodable for ClassMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut entries = 1u64; // class-id is mandatory
        if self.vendor.is_some() {
            entries = entries.saturating_add(1);
        }
        if self.model.is_some() {
            entries = entries.saturating_add(1);
        }

        encoder.encode_map_header(entries)?;

        // Key 0: class-id (mandatory)
        encoder.encode_int(0)?;
        // For now, treat class_id as a text string that should be encoded as tagged OID
        // In a real implementation, you'd parse the OID string and encode it properly
        // Tag 111 is for OID as per CBOR spec
        encoder.encode_tag(111)?;
        encoder.encode_bytes(self.class_id.as_bytes())?;

        // Key 1: vendor (optional)
        if let Some(vendor) = self.vendor {
            encoder.encode_int(1)?;
            encoder.encode_text(vendor)?;
        }

        // Key 2: model (optional)
        if let Some(model) = self.model {
            encoder.encode_int(2)?;
            encoder.encode_text(model)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnvironmentMap<'a> {
    pub class: ClassMap<'a>,
}

impl CborEncodable for EnvironmentMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_map_header(1)?; // Only class for now
        // Key 0: class
        encoder.encode_int(0)?;
        self.class.encode(encoder)?;
        Ok(())
    }
}

// Evidence identifier type choice
#[derive(Debug, Clone, Copy)]
pub enum EvidenceIdTypeChoice<'a> {
    TaggedUuid(&'a [u8]),
}

impl CborEncodable for EvidenceIdTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            EvidenceIdTypeChoice::TaggedUuid(uuid) => {
                // Encode tagged UUID (needs proper tag)
                encoder.encode_bytes(uuid)
            }
        }
    }
}

// Profile type choice
#[derive(Debug, Clone, Copy)]
pub enum ProfileTypeChoice<'a> {
    Uri(&'a str),
    Oid(&'a str),
}

impl CborEncodable for ProfileTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            ProfileTypeChoice::Uri(uri) => encoder.encode_text(uri),
            ProfileTypeChoice::Oid(oid) => {
                encoder.encode_tag(111)?; // OID tag
                encoder.encode_text(oid)
            }
        }
    }
}

// Domain type choice for dependencies and memberships
#[derive(Debug, Clone, Copy)]
pub enum DomainTypeChoice<'a> {
    Uuid(&'a [u8]),
    Uri(&'a str),
}

impl CborEncodable for DomainTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            DomainTypeChoice::Uuid(uuid) => encoder.encode_bytes(uuid),
            DomainTypeChoice::Uri(uri) => encoder.encode_text(uri),
        }
    }
}

// Crypto key type choice for identity and attest key triples
#[derive(Debug, Clone, Copy)]
pub enum CryptoKeyTypeChoice<'a> {
    PublicKey(&'a [u8]),
    KeyId(&'a [u8]),
}

impl CborEncodable for CryptoKeyTypeChoice<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            CryptoKeyTypeChoice::PublicKey(key_bytes) => encoder.encode_bytes(key_bytes),
            CryptoKeyTypeChoice::KeyId(key_id) => encoder.encode_bytes(key_id),
        }
    }
}

// Evidence triple record: [environment-map, [+ measurement-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvidenceTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub measurements: &'a [MeasurementMap<'a>],
}

impl CborEncodable for EvidenceTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Single environment map
        self.environment.encode(encoder)?;

        // Measurements array
        encoder.encode_array_header(self.measurements.len() as u64)?;
        for measurement in self.measurements {
            measurement.encode(encoder)?;
        }

        Ok(())
    }
}

// Identity triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvIdentityTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

impl CborEncodable for EvIdentityTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // Crypto keys array
        encoder.encode_array_header(self.crypto_keys.len() as u64)?;
        for key in self.crypto_keys {
            key.encode(encoder)?;
        }

        Ok(())
    }
}

// Attest key triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvAttestKeyTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

impl CborEncodable for EvAttestKeyTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // Crypto keys array
        encoder.encode_array_header(self.crypto_keys.len() as u64)?;
        for key in self.crypto_keys {
            key.encode(encoder)?;
        }

        Ok(())
    }
}

// Dependency triple record: [domain, [+ domain]]
#[derive(Debug, Clone, Copy)]
pub struct EvDependencyTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub dependencies: &'a [DomainTypeChoice<'a>],
}

impl CborEncodable for EvDependencyTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Domain
        self.domain.encode(encoder)?;

        // Dependencies array
        encoder.encode_array_header(self.dependencies.len() as u64)?;
        for dep in self.dependencies {
            dep.encode(encoder)?;
        }

        Ok(())
    }
}

// Membership triple record: [domain, [+ environment-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvMembershipTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub environments: &'a [EnvironmentMap<'a>],
}

impl CborEncodable for EvMembershipTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Domain
        self.domain.encode(encoder)?;

        // Environments array
        encoder.encode_array_header(self.environments.len() as u64)?;
        for env in self.environments {
            env.encode(encoder)?;
        }

        Ok(())
    }
}

// CoSWID evidence map
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidEvidenceMap<'a> {
    pub coswid_tag_id: Option<&'a [u8]>,
    pub coswid_evidence: &'a [u8],
    pub authorized_by: Option<&'a [&'a CryptoKeyTypeChoice<'a>]>,
}

impl CborEncodable for EvCoswidEvidenceMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 1u64; // coswid_evidence is mandatory
        if self.coswid_tag_id.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.authorized_by.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: coswid-tag-id (optional)
        if let Some(tag_id) = self.coswid_tag_id {
            encoder.encode_int(CE_COSWID_TAG_ID as i64)?;
            encoder.encode_bytes(tag_id)?;
        }

        // Key 1: coswid-evidence (mandatory)
        encoder.encode_int(CE_COSWID_EVIDENCE as i64)?;
        encoder.encode_bytes(self.coswid_evidence)?;

        // Key 2: authorized-by (optional)
        if let Some(authorized_by) = self.authorized_by {
            encoder.encode_int(CE_AUTHORIZED_BY as i64)?;
            encoder.encode_array_header(authorized_by.len() as u64)?;
            for key in authorized_by {
                key.encode(encoder)?;
            }
        }

        Ok(())
    }
}

// CoSWID triple record: [environment-map, [+ ev-coswid-evidence-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub coswid_evidence: &'a [EvCoswidEvidenceMap<'a>],
}

impl CborEncodable for EvCoswidTripleRecord<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        encoder.encode_array_header(2)?;

        // Environment map
        self.environment.encode(encoder)?;

        // CoSWID evidence array
        encoder.encode_array_header(self.coswid_evidence.len() as u64)?;
        for evidence in self.coswid_evidence {
            evidence.encode(encoder)?;
        }

        Ok(())
    }
}

// Evidence triples map
#[derive(Debug, Clone, Copy)]
pub struct EvTriplesMap<'a> {
    pub evidence_triples: Option<&'a [EvidenceTripleRecord<'a>]>, // key 0
    pub identity_triples: Option<&'a [EvIdentityTripleRecord<'a>]>, // key 1
    pub dependency_triples: Option<&'a [EvDependencyTripleRecord<'a>]>, // key 2
    pub membership_triples: Option<&'a [EvMembershipTripleRecord<'a>]>, // key 3
    pub coswid_triples: Option<&'a [EvCoswidTripleRecord<'a>]>,   // key 4
    pub attest_key_triples: Option<&'a [EvAttestKeyTripleRecord<'a>]>, // key 5
}

impl CborEncodable for EvTriplesMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 0u64;
        if self.evidence_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.identity_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.dependency_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.membership_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.coswid_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.attest_key_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: evidence-triples
        if let Some(evidence_triples) = self.evidence_triples {
            encoder.encode_int(CE_EVIDENCE_TRIPLES as i64)?;
            encoder.encode_array_header(evidence_triples.len() as u64)?;
            for triple in evidence_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 1: identity-triples
        if let Some(identity_triples) = self.identity_triples {
            encoder.encode_int(CE_IDENTITY_TRIPLES as i64)?;
            encoder.encode_array_header(identity_triples.len() as u64)?;
            for triple in identity_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 2: dependency-triples
        if let Some(dependency_triples) = self.dependency_triples {
            encoder.encode_int(CE_DEPENDENCY_TRIPLES as i64)?;
            encoder.encode_array_header(dependency_triples.len() as u64)?;
            for triple in dependency_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 3: membership-triples
        if let Some(membership_triples) = self.membership_triples {
            encoder.encode_int(CE_MEMBERSHIP_TRIPLES as i64)?;
            encoder.encode_array_header(membership_triples.len() as u64)?;
            for triple in membership_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 4: coswid-triples
        if let Some(coswid_triples) = self.coswid_triples {
            encoder.encode_int(CE_COSWID_TRIPLES as i64)?;
            encoder.encode_array_header(coswid_triples.len() as u64)?;
            for triple in coswid_triples {
                triple.encode(encoder)?;
            }
        }

        // Key 5: attest-key-triples
        if let Some(attest_key_triples) = self.attest_key_triples {
            encoder.encode_int(CE_ATTEST_KEY_TRIPLES as i64)?;
            encoder.encode_array_header(attest_key_triples.len() as u64)?;
            for triple in attest_key_triples {
                triple.encode(encoder)?;
            }
        }

        Ok(())
    }
}

// Concise evidence map
#[derive(Debug, Clone, Copy)]
pub struct ConciseEvidenceMap<'a> {
    pub ev_triples: EvTriplesMap<'a>, // key 0 (mandatory)
    pub evidence_id: Option<EvidenceIdTypeChoice<'a>>, // key 1
    pub profile: Option<ProfileTypeChoice<'a>>, // key 2
}

impl CborEncodable for ConciseEvidenceMap<'_> {
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        let mut map_entries = 1u64; // ev_triples is mandatory
        if self.evidence_id.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if self.profile.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        encoder.encode_map_header(map_entries)?;

        // Key 0: ev-triples (mandatory)
        encoder.encode_int(CE_EV_TRIPLES as i64)?;
        self.ev_triples.encode(encoder)?;

        // Key 1: evidence-id (optional)
        if let Some(evidence_id) = &self.evidence_id {
            encoder.encode_int(CE_EVIDENCE_ID as i64)?;
            evidence_id.encode(encoder)?;
        }

        // Key 2: profile (optional)
        if let Some(profile) = &self.profile {
            encoder.encode_int(CE_PROFILE as i64)?;
            profile.encode(encoder)?;
        }

        Ok(())
    }
}

// Tagged concise evidence (CBOR tag 571)
#[derive(Debug, Clone, Copy)]
pub struct TaggedConciseEvidence<'a> {
    pub concise_evidence: ConciseEvidenceMap<'a>,
}

// Concise evidence choice
#[derive(Debug, Clone, Copy)]
pub enum ConciseEvidence<'a> {
    Map(ConciseEvidenceMap<'a>),
    Tagged(TaggedConciseEvidence<'a>),
}

impl CborEncodable for ConciseEvidence<'_> {
    /// Encode concise evidence (choice between map and tagged)
    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EatError> {
        match self {
            ConciseEvidence::Map(map) => map.encode(encoder),
            ConciseEvidence::Tagged(tagged) => {
                encoder.encode_tag(CBOR_TAG_CONCISE_EVIDENCE)?;
                tagged.concise_evidence.encode(encoder)
            }
        }
    }
}
