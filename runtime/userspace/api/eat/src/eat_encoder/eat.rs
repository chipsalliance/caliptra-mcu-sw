// Licensed under the Apache-2.0 license

// EAT (Entity Attestation Token) structures and encoding
use super::cbor::CborEncoder;
use super::concise_evidence::ConciseEvidence;

// Error type for EAT operations
#[derive(Debug, PartialEq)]
pub enum EatError {
    BufferTooSmall,
    InvalidData,
    MissingMandatoryClaim,
    InvalidClaimSize,
    EncodingError,
    InvalidUtf8,
}

// Constants for claim keys (as per OCP Profile spec)
pub const CLAIM_KEY_ISSUER: i32 = 1;
pub const CLAIM_KEY_CTI: i32 = 7;
pub const CLAIM_KEY_NONCE: i32 = 10;
pub const CLAIM_KEY_DBGSTAT: i32 = 263;
pub const CLAIM_KEY_EAT_PROFILE: i32 = 265;
pub const CLAIM_KEY_MEASUREMENTS: i32 = 273;

// Optional claim keys
pub const CLAIM_KEY_UEID: i32 = 256;
pub const CLAIM_KEY_OEMID: i32 = 258;
pub const CLAIM_KEY_HWMODEL: i32 = 259;
pub const CLAIM_KEY_UPTIME: i32 = 261;
pub const CLAIM_KEY_BOOTCOUNT: i32 = 267;
pub const CLAIM_KEY_BOOTSEED: i32 = 268;
pub const CLAIM_KEY_DLOAS: i32 = 269;
pub const CLAIM_KEY_RIM_LOCATORS: i32 = -70001;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DebugStatus {
    Disabled = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct MeasurementFormat<'a> {
    pub content_type: u16,                     // CoAP content format
    pub concise_evidence: ConciseEvidence<'a>, // Structured evidence (required)
}

#[derive(Debug, Clone, Copy)]
pub struct DloaType<'a> {
    pub endorsement_id: &'a str,
    pub locator: &'a str,
    pub platform_label: &'a str,
    pub application_label: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct CorimLocatorMap<'a> {
    pub href: &'a str,
    pub thumbprint: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateClaim<'a> {
    pub key: i32,        // Must be < -65536
    pub value: &'a [u8], // Limited to 100 bytes
}

// OCP Profile EAT Claims using references
#[derive(Debug, Clone, Copy)]
pub struct OcpEatClaims<'a> {
    // Mandatory claims
    pub issuer: &'a str,                           // iss claim (key 1)
    pub cti: &'a [u8],                             // CTI claim for token uniqueness (key 7)
    pub nonce: &'a [u8],                           // Nonce for freshness (key 10)
    pub dbgstat: DebugStatus,                      // Debug status (key 263)
    pub eat_profile: &'a str,                      // EAT Profile OID (key 265)
    pub measurements: &'a [MeasurementFormat<'a>], // Concise evidence (key 273)

    // Optional claims
    pub ueid: Option<&'a [u8]>,            // Unique Entity ID (key 256)
    pub oemid: Option<&'a [u8]>,           // OEM ID (key 258)
    pub hwmodel: Option<&'a [u8]>,         // Hardware model (key 259)
    pub uptime: Option<u64>,               // Uptime in seconds (key 261)
    pub bootcount: Option<u64>,            // Boot count (key 267)
    pub bootseed: Option<&'a [u8]>,        // Boot seed (key 268)
    pub dloas: Option<&'a [DloaType<'a>]>, // DLOA claim (key 269)
    pub rim_locators: Option<&'a [CorimLocatorMap<'a>]>, // RIM locators (key -70001)

    // Private claims (up to 5, keys < -65536)
    pub private_claims: &'a [PrivateClaim<'a>],
}

#[derive(Debug, Clone, Copy)]
pub struct CoseHeaderPair<'a> {
    pub key: i32,
    pub value: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct ProtectedHeader {
    pub alg: i32, // Algorithm identifier
    pub content_type: Option<u16>,
    pub kid: Option<&'static [u8]>, // Key identifier
}

// High-level encoding functions
pub struct EatEncoder;

// Extension methods for CborEncoder to handle EAT-specific encoding
impl CborEncoder<'_> {
    // Encode debug status
    pub fn encode_debug_status(&mut self, status: DebugStatus) -> Result<(), EatError> {
        self.encode_uint(status as u64)
    }

    // Encode measurement format using structured concise evidence
    pub fn encode_measurement_format(
        &mut self,
        format: &MeasurementFormat,
    ) -> Result<(), EatError> {
        self.encode_array_header(2)?; // [content_type, content_format]
        self.encode_uint(format.content_type as u64)?;

        const MAX_EVIDENCE_SIZE: usize = 1024;
        let mut evidence_buffer = [0u8; MAX_EVIDENCE_SIZE];
        let mut evidence_encoder = CborEncoder::new(&mut evidence_buffer);

        // Encode the structured concise evidence
        evidence_encoder.encode_concise_evidence(&format.concise_evidence)?;
        let encoded_len = evidence_encoder.len();

        // Encode the structured concise evidence as a byte string
        let evidence_slice = evidence_buffer
            .get(..encoded_len)
            .ok_or(EatError::BufferTooSmall)?;
        self.encode_bytes(evidence_slice)?;

        Ok(())
    }

    // Encode DLOA type
    pub fn encode_dloa_type(&mut self, dloa: &DloaType) -> Result<(), EatError> {
        // DLOA is encoded as an array [registrar, platform_label, ?application_label]
        let array_len = if dloa.application_label.is_some() {
            3
        } else {
            2
        };
        self.encode_array_header(array_len)?;

        // dloa_registrar: general-uri (text string) - using endorsement_id as registrar
        self.encode_text(dloa.endorsement_id)?;

        // dloa_platform_label: text
        self.encode_text(dloa.platform_label)?;

        // dloa_application_label: text (optional)
        if let Some(app_label) = dloa.application_label {
            self.encode_text(app_label)?;
        }

        Ok(())
    }

    // Encode CoRIM locator map
    pub fn encode_corim_locator(&mut self, locator: &CorimLocatorMap) -> Result<(), EatError> {
        let entries = if locator.thumbprint.is_some() { 2 } else { 1 };
        self.encode_map_header(entries)?;

        // Key 0: href (can be uri or [+ uri])
        self.encode_int(0)?;
        self.encode_text(locator.href)?;

        // Key 1: thumbprint (optional)
        if let Some(thumbprint) = locator.thumbprint {
            self.encode_int(1)?;
            self.encode_bytes(thumbprint)?;
        }

        Ok(())
    }

    // Helper function to count claims in the EAT structure
    fn count_claims(claims: &OcpEatClaims) -> u64 {
        let mut count: u64 = 6; // Mandatory claims: issuer, cti, nonce, dbgstat, eat_profile, measurements

        // Count optional claims
        if claims.ueid.is_some() {
            count = count.saturating_add(1);
        }
        if claims.oemid.is_some() {
            count = count.saturating_add(1);
        }
        if claims.hwmodel.is_some() {
            count = count.saturating_add(1);
        }
        if claims.uptime.is_some() {
            count = count.saturating_add(1);
        }
        if claims.bootcount.is_some() {
            count = count.saturating_add(1);
        }
        if claims.bootseed.is_some() {
            count = count.saturating_add(1);
        }
        if claims.dloas.is_some() {
            count = count.saturating_add(1);
        }
        if claims.rim_locators.is_some() {
            count = count.saturating_add(1);
        }

        // Count private claims (safe cast since len() returns usize which fits in u64)
        count = count.saturating_add(claims.private_claims.len() as u64);

        count
    }

    // Main function to encode OCP EAT claims
    pub fn encode_ocp_eat_claims(&mut self, claims: &OcpEatClaims) -> Result<(), EatError> {
        let claim_count = Self::count_claims(claims);
        self.encode_map_header(claim_count)?;

        // Encode mandatory claims in deterministic order (by claim key)
        // Key 1: issuer
        self.encode_int(CLAIM_KEY_ISSUER as i64)?;
        self.encode_text(claims.issuer)?;

        // Key 7: cti
        self.encode_int(CLAIM_KEY_CTI as i64)?;
        self.encode_bytes(claims.cti)?;

        // Key 10: nonce
        self.encode_int(CLAIM_KEY_NONCE as i64)?;
        self.encode_bytes(claims.nonce)?;

        // Key 263: dbgstat
        self.encode_int(CLAIM_KEY_DBGSTAT as i64)?;
        self.encode_debug_status(claims.dbgstat)?;

        // Key 265: eat_profile
        self.encode_int(CLAIM_KEY_EAT_PROFILE as i64)?;
        // Tag 111 is for OID as per CBOR spec
        self.encode_tag(111)?;
        self.encode_bytes(claims.eat_profile.as_bytes())?;

        // Key 273: measurements
        self.encode_int(CLAIM_KEY_MEASUREMENTS as i64)?;
        self.encode_array_header(claims.measurements.len() as u64)?;
        for measurement in claims.measurements {
            self.encode_measurement_format(measurement)?;
        }

        // Encode optional claims in deterministic order
        if let Some(ueid) = claims.ueid {
            self.encode_int(CLAIM_KEY_UEID as i64)?;
            self.encode_bytes(ueid)?;
        }

        if let Some(oemid) = claims.oemid {
            self.encode_int(CLAIM_KEY_OEMID as i64)?;
            self.encode_bytes(oemid)?;
        }

        if let Some(hwmodel) = claims.hwmodel {
            self.encode_int(CLAIM_KEY_HWMODEL as i64)?;
            self.encode_bytes(hwmodel)?;
        }

        if let Some(uptime) = claims.uptime {
            self.encode_int(CLAIM_KEY_UPTIME as i64)?;
            self.encode_uint(uptime)?;
        }

        if let Some(bootcount) = claims.bootcount {
            self.encode_int(CLAIM_KEY_BOOTCOUNT as i64)?;
            self.encode_uint(bootcount)?;
        }

        if let Some(bootseed) = claims.bootseed {
            self.encode_int(CLAIM_KEY_BOOTSEED as i64)?;
            self.encode_bytes(bootseed)?;
        }

        if let Some(dloas) = claims.dloas {
            self.encode_int(CLAIM_KEY_DLOAS as i64)?;
            self.encode_array_header(dloas.len() as u64)?;
            for dloa in dloas {
                self.encode_dloa_type(dloa)?;
            }
        }

        if let Some(rim_locators) = claims.rim_locators {
            self.encode_int(CLAIM_KEY_RIM_LOCATORS as i64)?;
            self.encode_array_header(rim_locators.len() as u64)?;
            for locator in rim_locators {
                self.encode_corim_locator(locator)?;
            }
        }

        // Encode private claims
        for private_claim in claims.private_claims {
            self.encode_int(private_claim.key as i64)?;
            self.encode_bytes(private_claim.value)?;
        }

        Ok(())
    }

    // Encode COSE protected header
    pub fn encode_protected_header(&mut self, header: &ProtectedHeader) -> Result<(), EatError> {
        let mut entries = 1u64; // alg is mandatory
        if header.content_type.is_some() {
            entries = entries.saturating_add(1);
        }
        if header.kid.is_some() {
            entries = entries.saturating_add(1);
        }

        self.encode_map_header(entries)?;

        // Key 1: alg (algorithm)
        self.encode_int(1)?;
        self.encode_int(header.alg as i64)?;

        // Key 3: content type (optional)
        if let Some(content_type) = header.content_type {
            self.encode_int(3)?;
            self.encode_uint(content_type as u64)?;
        }

        // Key 4: kid (key identifier, optional)
        if let Some(kid) = header.kid {
            self.encode_int(4)?;
            self.encode_bytes(kid)?;
        }

        Ok(())
    }

    // Encode COSE unprotected header
    pub fn encode_unprotected_header(
        &mut self,
        headers: &[CoseHeaderPair],
    ) -> Result<(), EatError> {
        self.encode_map_header(headers.len() as u64)?;

        for header in headers {
            self.encode_int(header.key as i64)?;
            self.encode_bytes(header.value)?;
        }

        Ok(())
    }
}

impl EatEncoder {
    /// Encode complete COSE Sign1 EAT token
    /// Returns the number of bytes written to the buffer
    pub fn encode_cose_sign1_eat(
        buffer: &mut [u8],
        protected_header: &ProtectedHeader,
        unprotected_headers: &[CoseHeaderPair],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<usize, EatError> {
        // Use temporary buffer for protected header
        const MAX_PROTECTED_SIZE: usize = 256;
        let mut protected_buffer = [0u8; MAX_PROTECTED_SIZE];

        // First encode the protected header
        let mut protected_encoder = CborEncoder::new(&mut protected_buffer);
        protected_encoder.encode_protected_header(protected_header)?;
        let protected_len = protected_encoder.len();
        if protected_len > MAX_PROTECTED_SIZE {
            return Err(EatError::BufferTooSmall);
        }

        // Now encode the final structure
        let mut encoder = CborEncoder::new(buffer);

        // Encode the complete COSE_Sign1 structure with tags
        encoder.encode_self_described_cbor()?; // Tag 55799
        encoder.encode_cwt_tag()?; // Tag 61
        encoder.encode_cose_sign1_tag()?; // Tag 18

        // Now encode the COSE_Sign1 array
        encoder.encode_array_header(4)?;

        // Protected header as byte string
        let protected_slice = protected_buffer
            .get(..protected_len)
            .ok_or(EatError::BufferTooSmall)?;
        encoder.encode_bytes(protected_slice)?;

        // Unprotected header as map
        encoder.encode_unprotected_header(unprotected_headers)?;

        // Payload as byte string (use provided pre-encoded payload)
        encoder.encode_bytes(payload)?;

        // Signature as byte string
        encoder.encode_bytes(signature)?;

        Ok(encoder.len())
    }

    /// Validate that claims meet OCP profile requirements
    #[allow(dead_code)]
    pub fn validate_claims(claims: &OcpEatClaims) -> Result<(), EatError> {
        // Check mandatory fields
        if claims.issuer.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        if claims.cti.len() < 8 || claims.cti.len() > 64 {
            return Err(EatError::InvalidClaimSize);
        }

        if claims.nonce.len() < 8 || claims.nonce.len() > 64 {
            return Err(EatError::InvalidClaimSize);
        }

        if claims.eat_profile.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        if claims.measurements.is_empty() {
            return Err(EatError::MissingMandatoryClaim);
        }

        // Validate optional claims size constraints
        if let Some(ueid) = claims.ueid {
            if ueid.len() < 7 || ueid.len() > 33 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(hwmodel) = claims.hwmodel {
            if hwmodel.is_empty() || hwmodel.len() > 32 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        if let Some(bootseed) = claims.bootseed {
            if bootseed.len() < 32 || bootseed.len() > 64 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        // Validate private claims
        for private_claim in claims.private_claims {
            if private_claim.key >= -65536 {
                return Err(EatError::InvalidData);
            }
            if private_claim.value.len() > 100 {
                return Err(EatError::InvalidClaimSize);
            }
        }

        // Validate measurements format - structured evidence is always valid
        // No additional validation needed for structured concise evidence

        Ok(())
    }

    /// Calculate required buffer size for encoding (approximation)
    #[allow(dead_code)]
    pub fn estimate_buffer_size(claims: &OcpEatClaims) -> usize {
        let mut size: usize = 0;

        // Base overhead for CBOR structure
        size = size.saturating_add(100); // Tags, headers, map structures

        // Mandatory claims
        size = size.saturating_add(claims.issuer.len()).saturating_add(10);
        size = size.saturating_add(claims.cti.len()).saturating_add(10);
        size = size.saturating_add(claims.nonce.len()).saturating_add(10);
        size = size
            .saturating_add(claims.eat_profile.len())
            .saturating_add(10);
        size = size.saturating_add(10); // dbgstat

        // Measurements (estimated based on structured evidence)
        for _measurement in claims.measurements {
            size = size.saturating_add(200); // Estimated size for structured concise evidence
        }

        // Optional claims
        if let Some(ueid) = claims.ueid {
            size = size.saturating_add(ueid.len()).saturating_add(10);
        }
        if let Some(oemid) = claims.oemid {
            size = size.saturating_add(oemid.len()).saturating_add(10);
        }
        if let Some(hwmodel) = claims.hwmodel {
            size = size.saturating_add(hwmodel.len()).saturating_add(10);
        }
        if let Some(bootseed) = claims.bootseed {
            size = size.saturating_add(bootseed.len()).saturating_add(10);
        }
        if let Some(dloas) = claims.dloas {
            for dloa in dloas {
                size = size
                    .saturating_add(dloa.endorsement_id.len())
                    .saturating_add(dloa.locator.len())
                    .saturating_add(20);
            }
        }
        if let Some(rim_locators) = claims.rim_locators {
            for locator in rim_locators {
                size = size.saturating_add(locator.href.len()).saturating_add(20);
                if let Some(thumbprint) = locator.thumbprint {
                    size = size.saturating_add(thumbprint.len());
                }
            }
        }

        // Private claims
        for private_claim in claims.private_claims {
            size = size
                .saturating_add(private_claim.value.len())
                .saturating_add(10);
        }

        // Add 20% safety margin using saturating arithmetic
        size.saturating_add(size / 5)
    }
}

// Helper functions for creating common structures
impl<'a> OcpEatClaims<'a> {
    /// Create a new OcpEatClaims with mandatory fields
    pub fn new(
        issuer: &'a str,
        cti: &'a [u8],
        nonce: &'a [u8],
        dbgstat: DebugStatus,
        eat_profile: &'a str,
        measurements: &'a [MeasurementFormat<'a>],
    ) -> Self {
        Self {
            issuer,
            cti,
            nonce,
            dbgstat,
            eat_profile,
            measurements,
            ueid: None,
            oemid: None,
            hwmodel: None,
            uptime: None,
            bootcount: None,
            bootseed: None,
            dloas: None,
            rim_locators: None,
            private_claims: &[],
        }
    }
}

impl<'a> MeasurementFormat<'a> {
    /// Create a new measurement format with structured concise evidence
    pub fn new(concise_evidence: &'a ConciseEvidence<'a>) -> Self {
        Self {
            content_type: 10571, // application/cbor CoAP content format
            concise_evidence: *concise_evidence,
        }
    }
}

impl ProtectedHeader {
    /// Create a new protected header for ES384 (ECDSA with P-384 and SHA-384)
    pub fn new_es384() -> Self {
        Self {
            alg: -51, // ES384 algorithm ID
            content_type: None,
            kid: None,
        }
    }
}

// Constants for common COSE header parameters
pub mod cose_headers {
    pub const X5CHAIN: i32 = 33; // X.509 Certificate Chain
}

// COSE Sign1 signature context creation (as per RFC 8152)
pub fn create_sign1_context(
    buffer: &mut [u8],
    protected_header: &[u8],
    payload: &[u8],
) -> Result<usize, EatError> {
    // Create Sig_structure for COSE_Sign1 as per RFC 8152 Section 4.4
    // Sig_structure = [
    //    "Signature1",   // Context string for COSE_Sign1
    //    protected,      // Protected header (serialized)
    //    external_aad,   // Empty for basic use
    //    payload         // The payload to be signed
    // ]

    let mut encoder = CborEncoder::new(buffer);

    // CBOR encode the Sig_structure array
    encoder.encode_array_header(4)?; // Array of 4 items

    // "Signature1" as text string
    encoder.encode_text("Signature1")?;

    // Protected header as byte string
    encoder.encode_bytes(protected_header)?;

    // External AAD as empty byte string
    encoder.encode_bytes(&[])?;

    // Payload as byte string
    encoder.encode_bytes(payload)?;

    Ok(encoder.len())
}
