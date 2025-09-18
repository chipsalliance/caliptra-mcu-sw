// Licensed under the Apache-2.0 license

// Concise Evidence structures and encoding for RATS CoRIM compliance
use super::cbor::CborEncoder;
use super::eat::EatError;

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

// Integrity register identifier choice (uint or text)
#[derive(Debug, Clone, Copy)]
pub enum IntegrityRegisterIdChoice<'a> {
    Uint(u64),
    Text(&'a str),
}

// Integrity register entry
#[derive(Debug, Clone, Copy)]
pub struct IntegrityRegisterEntry<'a> {
    pub id: IntegrityRegisterIdChoice<'a>,
    pub digests: &'a [DigestEntry<'a>], // digests-type
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

#[derive(Debug, Clone, Copy)]
pub struct MeasurementMap<'a> {
    pub key: u64, // Measurement key/identifier
    pub mval: MeasurementValue<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct ClassMap<'a> {
    pub class_id: &'a str,
    pub vendor: Option<&'a str>,
    pub model: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct EnvironmentMap<'a> {
    pub class: ClassMap<'a>,
}

// Evidence identifier type choice
#[derive(Debug, Clone, Copy)]
pub enum EvidenceIdTypeChoice<'a> {
    TaggedUuid(&'a [u8]),
}

// Profile type choice
#[derive(Debug, Clone, Copy)]
pub enum ProfileTypeChoice<'a> {
    Uri(&'a str),
    Oid(&'a str),
}

// Domain type choice for dependencies and memberships
#[derive(Debug, Clone, Copy)]
pub enum DomainTypeChoice<'a> {
    Uuid(&'a [u8]),
    Uri(&'a str),
}

// Crypto key type choice for identity and attest key triples
#[derive(Debug, Clone, Copy)]
pub enum CryptoKeyTypeChoice<'a> {
    PublicKey(&'a [u8]),
    KeyId(&'a [u8]),
}

// Evidence triple record: [environment-map, [+ measurement-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvidenceTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub measurements: &'a [MeasurementMap<'a>],
}

// Identity triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvIdentityTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

// Attest key triple record: [environment-map, [+ crypto-key]]
#[derive(Debug, Clone, Copy)]
pub struct EvAttestKeyTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub crypto_keys: &'a [CryptoKeyTypeChoice<'a>],
}

// Dependency triple record: [domain, [+ domain]]
#[derive(Debug, Clone, Copy)]
pub struct EvDependencyTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub dependencies: &'a [DomainTypeChoice<'a>],
}

// Membership triple record: [domain, [+ environment-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvMembershipTripleRecord<'a> {
    pub domain: DomainTypeChoice<'a>,
    pub environments: &'a [EnvironmentMap<'a>],
}

// CoSWID evidence map
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidEvidenceMap<'a> {
    pub coswid_tag_id: Option<&'a [u8]>,
    pub coswid_evidence: &'a [u8],
    pub authorized_by: Option<&'a [&'a CryptoKeyTypeChoice<'a>]>,
}

// CoSWID triple record: [environment-map, [+ ev-coswid-evidence-map]]
#[derive(Debug, Clone, Copy)]
pub struct EvCoswidTripleRecord<'a> {
    pub environment: EnvironmentMap<'a>,
    pub coswid_evidence: &'a [EvCoswidEvidenceMap<'a>],
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

// Concise evidence map
#[derive(Debug, Clone, Copy)]
pub struct ConciseEvidenceMap<'a> {
    pub ev_triples: EvTriplesMap<'a>, // key 0 (mandatory)
    pub evidence_id: Option<EvidenceIdTypeChoice<'a>>, // key 1
    pub profile: Option<ProfileTypeChoice<'a>>, // key 2
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

// Extension methods for CborEncoder to handle concise evidence encoding
impl CborEncoder<'_> {
    // Encode digest entry
    pub fn encode_digest_entry(&mut self, digest: &DigestEntry) -> Result<(), EatError> {
        self.encode_array_header(2)?; // [alg_id, value]
        self.encode_int(digest.alg_id as i64)?;
        self.encode_bytes(digest.value)?;
        Ok(())
    }

    // Encode integrity register identifier choice
    pub fn encode_integrity_register_id(
        &mut self,
        id: &IntegrityRegisterIdChoice,
    ) -> Result<(), EatError> {
        match id {
            IntegrityRegisterIdChoice::Uint(value) => self.encode_uint(*value),
            IntegrityRegisterIdChoice::Text(text) => self.encode_text(text),
        }
    }

    // Encode integrity register entry
    pub fn encode_integrity_register_entry(
        &mut self,
        entry: &IntegrityRegisterEntry,
    ) -> Result<(), EatError> {
        // Encode the key (register ID)
        self.encode_integrity_register_id(&entry.id)?;

        // Encode the value (digests array)
        self.encode_array_header(entry.digests.len() as u64)?;
        for digest in entry.digests {
            self.encode_digest_entry(digest)?;
        }

        Ok(())
    }

    // Encode measurement value
    pub fn encode_measurement_value(&mut self, mval: &MeasurementValue) -> Result<(), EatError> {
        let mut map_entries = 0u64;

        // Count entries
        if mval.version.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if mval.svn.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if mval.digests.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if mval.integrity_registers.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if mval.raw_value.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if mval.raw_value_mask.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        self.encode_map_header(map_entries)?;

        // Encode entries in deterministic order (sorted by numeric key)
        // Key 0: version
        if let Some(version) = mval.version {
            self.encode_int(0)?;
            self.encode_text(version)?;
        }

        // Key 1: svn
        if let Some(svn) = mval.svn {
            self.encode_int(1)?;
            self.encode_uint(svn)?;
        }

        // Key 2: digests
        if let Some(digests) = mval.digests {
            self.encode_int(2)?;
            self.encode_array_header(digests.len() as u64)?;
            for digest in digests {
                self.encode_digest_entry(digest)?;
            }
        }

        // Key 4: raw-value
        if let Some(raw_value) = mval.raw_value {
            self.encode_int(4)?;
            self.encode_bytes(raw_value)?;
        }

        // Key 5: raw-value-mask (deprecated but still supported)
        if let Some(raw_mask) = mval.raw_value_mask {
            self.encode_int(5)?;
            self.encode_bytes(raw_mask)?;
        }

        // Key 14: integrity-registers
        if let Some(registers) = mval.integrity_registers {
            self.encode_int(14)?;
            // Encode as map: { + integrity-register-id-type-choice => digests-type }
            self.encode_map_header(registers.len() as u64)?;
            for register in registers {
                self.encode_integrity_register_entry(register)?;
            }
        }

        Ok(())
    }

    // Encode measurement map
    pub fn encode_measurement_map(&mut self, measurement: &MeasurementMap) -> Result<(), EatError> {
        self.encode_map_header(2)?; // key and mval

        // Key 0: mkey (measured element type)
        self.encode_int(0)?;
        self.encode_uint(measurement.key)?;

        // Key 1: mval (measurement values)
        self.encode_int(1)?;
        self.encode_measurement_value(&measurement.mval)?;

        Ok(())
    }

    // Encode class map
    pub fn encode_class_map(&mut self, class: &ClassMap) -> Result<(), EatError> {
        let mut entries = 1u64; // class-id is mandatory
        if class.vendor.is_some() {
            entries = entries.saturating_add(1);
        }
        if class.model.is_some() {
            entries = entries.saturating_add(1);
        }

        self.encode_map_header(entries)?;

        // Key 0: class-id (mandatory)
        self.encode_int(0)?;
        // For now, treat class_id as a text string that should be encoded as tagged OID
        // In a real implementation, you'd parse the OID string and encode it properly
        // Tag 111 is for OID as per CBOR spec
        self.encode_tag(111)?;
        self.encode_bytes(class.class_id.as_bytes())?;

        // Key 1: vendor (optional)
        if let Some(vendor) = class.vendor {
            self.encode_int(1)?;
            self.encode_text(vendor)?;
        }

        // Key 2: model (optional)
        if let Some(model) = class.model {
            self.encode_int(2)?;
            self.encode_text(model)?;
        }

        Ok(())
    }

    // Encode environment map
    pub fn encode_environment_map(&mut self, env: &EnvironmentMap) -> Result<(), EatError> {
        self.encode_map_header(1)?; // Only class for now
        // Key 0: class
        self.encode_int(0)?;
        self.encode_class_map(&env.class)?;
        Ok(())
    }

    // Encode concise evidence (choice between map and tagged)
    pub fn encode_concise_evidence(&mut self, evidence: &ConciseEvidence) -> Result<(), EatError> {
        match evidence {
            ConciseEvidence::Map(map) => self.encode_concise_evidence_map(map),
            ConciseEvidence::Tagged(tagged) => {
                self.encode_tag(CBOR_TAG_CONCISE_EVIDENCE)?;
                self.encode_concise_evidence_map(&tagged.concise_evidence)
            }
        }
    }

    // Encode concise evidence map
    pub fn encode_concise_evidence_map(
        &mut self,
        evidence: &ConciseEvidenceMap,
    ) -> Result<(), EatError> {
        let mut map_entries = 1u64; // ev_triples is mandatory
        if evidence.evidence_id.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if evidence.profile.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        self.encode_map_header(map_entries)?;

        // Key 0: ev-triples (mandatory)
        self.encode_int(CE_EV_TRIPLES as i64)?;
        self.encode_ev_triples_map(&evidence.ev_triples)?;

        // Key 1: evidence-id (optional)
        if let Some(evidence_id) = &evidence.evidence_id {
            self.encode_int(CE_EVIDENCE_ID as i64)?;
            self.encode_evidence_id_type_choice(evidence_id)?;
        }

        // Key 2: profile (optional)
        if let Some(profile) = &evidence.profile {
            self.encode_int(CE_PROFILE as i64)?;
            self.encode_profile_type_choice(profile)?;
        }

        Ok(())
    }

    // Encode evidence triples map
    pub fn encode_ev_triples_map(&mut self, triples: &EvTriplesMap) -> Result<(), EatError> {
        let mut map_entries = 0u64;
        if triples.evidence_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if triples.identity_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if triples.dependency_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if triples.membership_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if triples.coswid_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if triples.attest_key_triples.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        self.encode_map_header(map_entries)?;

        // Key 0: evidence-triples
        if let Some(evidence_triples) = triples.evidence_triples {
            self.encode_int(CE_EVIDENCE_TRIPLES as i64)?;
            self.encode_array_header(evidence_triples.len() as u64)?;
            for triple in evidence_triples {
                self.encode_evidence_triple_record(triple)?;
            }
        }

        // Key 1: identity-triples
        if let Some(identity_triples) = triples.identity_triples {
            self.encode_int(CE_IDENTITY_TRIPLES as i64)?;
            self.encode_array_header(identity_triples.len() as u64)?;
            for triple in identity_triples {
                self.encode_identity_triple_record(triple)?;
            }
        }

        // Key 2: dependency-triples
        if let Some(dependency_triples) = triples.dependency_triples {
            self.encode_int(CE_DEPENDENCY_TRIPLES as i64)?;
            self.encode_array_header(dependency_triples.len() as u64)?;
            for triple in dependency_triples {
                self.encode_dependency_triple_record(triple)?;
            }
        }

        // Key 3: membership-triples
        if let Some(membership_triples) = triples.membership_triples {
            self.encode_int(CE_MEMBERSHIP_TRIPLES as i64)?;
            self.encode_array_header(membership_triples.len() as u64)?;
            for triple in membership_triples {
                self.encode_membership_triple_record(triple)?;
            }
        }

        // Key 4: coswid-triples
        if let Some(coswid_triples) = triples.coswid_triples {
            self.encode_int(CE_COSWID_TRIPLES as i64)?;
            self.encode_array_header(coswid_triples.len() as u64)?;
            for triple in coswid_triples {
                self.encode_coswid_triple_record(triple)?;
            }
        }

        // Key 5: attest-key-triples
        if let Some(attest_key_triples) = triples.attest_key_triples {
            self.encode_int(CE_ATTEST_KEY_TRIPLES as i64)?;
            self.encode_array_header(attest_key_triples.len() as u64)?;
            for triple in attest_key_triples {
                self.encode_attest_key_triple_record(triple)?;
            }
        }

        Ok(())
    }

    // Encode evidence ID type choice
    pub fn encode_evidence_id_type_choice(
        &mut self,
        id: &EvidenceIdTypeChoice,
    ) -> Result<(), EatError> {
        match id {
            EvidenceIdTypeChoice::TaggedUuid(uuid) => {
                // Encode tagged UUID (needs proper tag)
                self.encode_bytes(uuid)
            }
        }
    }

    // Encode profile type choice
    pub fn encode_profile_type_choice(
        &mut self,
        profile: &ProfileTypeChoice,
    ) -> Result<(), EatError> {
        match profile {
            ProfileTypeChoice::Uri(uri) => self.encode_text(uri),
            ProfileTypeChoice::Oid(oid) => {
                self.encode_tag(111)?; // OID tag
                self.encode_text(oid)
            }
        }
    }

    // Encode domain type choice
    pub fn encode_domain_type_choice(&mut self, domain: &DomainTypeChoice) -> Result<(), EatError> {
        match domain {
            DomainTypeChoice::Uuid(uuid) => self.encode_bytes(uuid),
            DomainTypeChoice::Uri(uri) => self.encode_text(uri),
        }
    }

    // Encode crypto key type choice
    pub fn encode_crypto_key_type_choice(
        &mut self,
        key: &CryptoKeyTypeChoice,
    ) -> Result<(), EatError> {
        match key {
            CryptoKeyTypeChoice::PublicKey(key_bytes) => self.encode_bytes(key_bytes),
            CryptoKeyTypeChoice::KeyId(key_id) => self.encode_bytes(key_id),
        }
    }

    // Encode evidence triple record: [environment-map, [+ measurement-map]]
    pub fn encode_evidence_triple_record(
        &mut self,
        triple: &EvidenceTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Single environment map
        self.encode_environment_map(&triple.environment)?;

        // Measurements array
        self.encode_array_header(triple.measurements.len() as u64)?;
        for measurement in triple.measurements {
            self.encode_measurement_map(measurement)?;
        }

        Ok(())
    }

    // Encode identity triple record: [environment-map, [+ crypto-key]]
    pub fn encode_identity_triple_record(
        &mut self,
        triple: &EvIdentityTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Environment map
        self.encode_environment_map(&triple.environment)?;

        // Crypto keys array
        self.encode_array_header(triple.crypto_keys.len() as u64)?;
        for key in triple.crypto_keys {
            self.encode_crypto_key_type_choice(key)?;
        }

        Ok(())
    }

    // Encode attest key triple record: [environment-map, [+ crypto-key]]
    pub fn encode_attest_key_triple_record(
        &mut self,
        triple: &EvAttestKeyTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Environment map
        self.encode_environment_map(&triple.environment)?;

        // Crypto keys array
        self.encode_array_header(triple.crypto_keys.len() as u64)?;
        for key in triple.crypto_keys {
            self.encode_crypto_key_type_choice(key)?;
        }

        Ok(())
    }

    // Encode dependency triple record: [domain, [+ domain]]
    pub fn encode_dependency_triple_record(
        &mut self,
        triple: &EvDependencyTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Domain
        self.encode_domain_type_choice(&triple.domain)?;

        // Dependencies array
        self.encode_array_header(triple.dependencies.len() as u64)?;
        for dep in triple.dependencies {
            self.encode_domain_type_choice(dep)?;
        }

        Ok(())
    }

    // Encode membership triple record: [domain, [+ environment-map]]
    pub fn encode_membership_triple_record(
        &mut self,
        triple: &EvMembershipTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Domain
        self.encode_domain_type_choice(&triple.domain)?;

        // Environments array
        self.encode_array_header(triple.environments.len() as u64)?;
        for env in triple.environments {
            self.encode_environment_map(env)?;
        }

        Ok(())
    }

    // Encode CoSWID triple record: [environment-map, [+ ev-coswid-evidence-map]]
    pub fn encode_coswid_triple_record(
        &mut self,
        triple: &EvCoswidTripleRecord,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?;

        // Environment map
        self.encode_environment_map(&triple.environment)?;

        // CoSWID evidence array
        self.encode_array_header(triple.coswid_evidence.len() as u64)?;
        for evidence in triple.coswid_evidence {
            self.encode_coswid_evidence_map(evidence)?;
        }

        Ok(())
    }

    // Encode CoSWID evidence map
    pub fn encode_coswid_evidence_map(
        &mut self,
        evidence: &EvCoswidEvidenceMap,
    ) -> Result<(), EatError> {
        let mut map_entries = 1u64; // coswid_evidence is mandatory
        if evidence.coswid_tag_id.is_some() {
            map_entries = map_entries.saturating_add(1);
        }
        if evidence.authorized_by.is_some() {
            map_entries = map_entries.saturating_add(1);
        }

        self.encode_map_header(map_entries)?;

        // Key 0: coswid-tag-id (optional)
        if let Some(tag_id) = evidence.coswid_tag_id {
            self.encode_int(CE_COSWID_TAG_ID as i64)?;
            self.encode_bytes(tag_id)?;
        }

        // Key 1: coswid-evidence (mandatory)
        self.encode_int(CE_COSWID_EVIDENCE as i64)?;
        self.encode_bytes(evidence.coswid_evidence)?;

        // Key 2: authorized-by (optional)
        if let Some(authorized_by) = evidence.authorized_by {
            self.encode_int(CE_AUTHORIZED_BY as i64)?;
            self.encode_array_header(authorized_by.len() as u64)?;
            for key in authorized_by {
                self.encode_crypto_key_type_choice(key)?;
            }
        }

        Ok(())
    }
}
