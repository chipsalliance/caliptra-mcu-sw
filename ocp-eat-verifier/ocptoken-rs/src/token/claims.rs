// Licensed under the Apache-2.0 license

//! OCP EAT profile claims.
//!
//! Defines the mandatory and optional claims for the OCP EAT profile
//! and provides validation that all mandatory claims are present.

use crate::error::{OcpEatError, OcpEatResult};
use corim_rs::coev::TaggedConciseEvidence;
use coset::cbor::value::Value;
use coset::cwt::{ClaimName, ClaimsSet};

// ── Claim key constants (CBOR map keys) ────────────────────────────

// Mandatory
pub const CLAIM_KEY_NONCE: i64 = 10;
pub const CLAIM_KEY_DEBUG_STATUS: i64 = 263;
pub const CLAIM_KEY_EAT_PROFILE: i64 = 265;
pub const CLAIM_KEY_MEASUREMENTS: i64 = 273;

// Optional
pub const CLAIM_KEY_UEID: i64 = 256;
pub const CLAIM_KEY_SUEID: i64 = 257;
pub const CLAIM_KEY_OEMID: i64 = 258;
pub const CLAIM_KEY_HW_MODEL: i64 = 259;
pub const CLAIM_KEY_UPTIME: i64 = 261;
pub const CLAIM_KEY_BOOT_COUNT: i64 = 267;
pub const CLAIM_KEY_BOOT_SEED: i64 = 268;
pub const CLAIM_KEY_DLOAS: i64 = 269;
pub const CLAIM_KEY_CORIM_LOCATORS: i64 = -70001;

/// OCP EAT profile OID in dotted notation: 1.3.6.1.4.1.42623.1.3
pub const OCP_EAT_PROFILE_OID_STR: &str = "1.3.6.1.4.1.42623.1.3";

/// OCP EAT profile OID as ASN.1 DER TLV bytes.
pub const OCP_EAT_PROFILE_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x4d, 0x1f, 0x01, 0x03,
];

/// OCP EAT profile OID as raw content bytes (without ASN.1 tag+length),
/// matching the CBOR `~oid` (tag 111) encoding.
pub const OCP_EAT_PROFILE_OID_RAW: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x4d, 0x1f, 0x01, 0x03,
];

// ── OCP EAT Claims ────────────────────────────────────────────────

/// Debug status values per RFC 9711 §4.2.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStatus {
    Enabled,
    Disabled,
    DisabledSinceBoot,
    DisabledPermanently,
    DisabledFullyAndPermanently,
}

impl DebugStatus {
    /// Decode from a CBOR integer value.
    pub fn from_cbor(value: &Value) -> OcpEatResult<Self> {
        match value {
            Value::Integer(i) => {
                let v: i128 = (*i).into();
                match v {
                    0 => Ok(DebugStatus::Enabled),
                    1 => Ok(DebugStatus::Disabled),
                    2 => Ok(DebugStatus::DisabledSinceBoot),
                    3 => Ok(DebugStatus::DisabledPermanently),
                    4 => Ok(DebugStatus::DisabledFullyAndPermanently),
                    _ => Err(OcpEatError::InvalidToken("Unknown debug-status value")),
                }
            }
            _ => Err(OcpEatError::InvalidToken("debug-status must be an integer")),
        }
    }
}

impl std::fmt::Display for DebugStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugStatus::Enabled => write!(f, "enabled (0)"),
            DebugStatus::Disabled => write!(f, "disabled (1)"),
            DebugStatus::DisabledSinceBoot => write!(f, "disabled-since-boot (2)"),
            DebugStatus::DisabledPermanently => write!(f, "disabled-permanently (3)"),
            DebugStatus::DisabledFullyAndPermanently => {
                write!(f, "disabled-fully-and-permanently (4)")
            }
        }
    }
}

/// Parsed OCP EAT claims, split into mandatory, optional, and private.
pub struct OcpEatClaims {
    // ── Mandatory ──
    /// Nonce (key 10): bstr .size (8..64)
    pub nonce: Vec<u8>,
    /// Debug status (key 263): dbgstat-type per RFC 9711
    pub debug_status: DebugStatus,
    /// EAT Profile OID (key 265): ~oid 1.3.6.1.4.1.42623.1.3
    pub eat_profile: String,
    /// Measurements (key 273): bstr (CBOR-encoded measurements-type)
    pub measurements: Vec<u8>,

    // ── Optional ──
    /// Issuer (key 1): tstr
    pub issuer: Option<String>,
    /// CWT ID (key 7): bstr .size (8..64)
    pub cwt_id: Option<Vec<u8>>,
    /// UEID (key 256): bstr .size (7..33)
    pub ueid: Option<Vec<u8>>,
    /// SUEID (key 257): bstr .size (7..33)
    pub sueid: Option<Vec<u8>>,
    /// OEM ID (key 258): oemid-type per RFC 9711
    pub oemid: Option<Value>,
    /// Hardware model (key 259): bytes .size (1..32)
    pub hw_model: Option<Vec<u8>>,
    /// Uptime (key 261): uint
    pub uptime: Option<u64>,
    /// Boot count (key 267): uint
    pub boot_count: Option<u64>,
    /// Boot seed (key 268): bstr .size (32..64)
    pub boot_seed: Option<Vec<u8>>,
    /// DLOAs (key 269): [ + dloa-type ]
    pub dloas: Option<Value>,
    /// CoRIM locators (key -70001): [ + corim-locator-map ]
    pub corim_locators: Option<Value>,

    // ── Private claims ──
    /// Remaining claims not covered above.
    pub private_claims: Vec<(ClaimName, Value)>,
}

impl OcpEatClaims {
    /// Parse and validate an `OcpEatClaims` from a `ClaimsSet`.
    ///
    /// Returns an error if any mandatory claim is missing.
    pub fn from_claims_set(cs: ClaimsSet) -> OcpEatResult<Self> {
        let mut nonce: Option<Vec<u8>> = None;
        let mut debug_status: Option<DebugStatus> = None;
        let mut eat_profile: Option<String> = None;
        let mut measurements: Option<Vec<u8>> = None;

        let mut ueid: Option<Vec<u8>> = None;
        let mut sueid: Option<Vec<u8>> = None;
        let mut oemid: Option<Value> = None;
        let mut hw_model: Option<Vec<u8>> = None;
        let mut uptime: Option<u64> = None;
        let mut boot_count: Option<u64> = None;
        let mut boot_seed: Option<Vec<u8>> = None;
        let mut dloas: Option<Value> = None;
        let mut corim_locators: Option<Value> = None;
        let mut private_claims: Vec<(ClaimName, Value)> = Vec::new();

        for (name, value) in cs.rest {
            match &name {
                ClaimName::Assigned(n) => match n.to_i64() {
                    CLAIM_KEY_NONCE => nonce = Some(value_to_bstr(value, "nonce")?),
                    CLAIM_KEY_DEBUG_STATUS => debug_status = Some(DebugStatus::from_cbor(&value)?),
                    CLAIM_KEY_EAT_PROFILE => {
                        let oid_bytes = value_to_oid(value, "eat_profile")?;
                        // Try UTF-8 text first, then dotted notation is already text
                        let oid_str = String::from_utf8(oid_bytes)
                            .map_err(|_| OcpEatError::InvalidToken("eat_profile is not valid UTF-8 or OID"))?;
                        eat_profile = Some(oid_str);
                    }
                    CLAIM_KEY_MEASUREMENTS => {
                        measurements = Some(value_to_measurements(value)?);
                    }
                    CLAIM_KEY_UEID => ueid = Some(value_to_bstr(value, "ueid")?),
                    CLAIM_KEY_SUEID => sueid = Some(value_to_bstr(value, "sueid")?),
                    CLAIM_KEY_OEMID => oemid = Some(value),
                    CLAIM_KEY_HW_MODEL => hw_model = Some(value_to_bstr(value, "hwmodel")?),
                    CLAIM_KEY_UPTIME => uptime = Some(value_to_uint(value, "uptime")?),
                    CLAIM_KEY_BOOT_COUNT => boot_count = Some(value_to_uint(value, "bootcount")?),
                    CLAIM_KEY_BOOT_SEED => boot_seed = Some(value_to_bstr(value, "bootseed")?),
                    CLAIM_KEY_DLOAS => dloas = Some(value),
                    _ => private_claims.push((name, value)),
                },
                ClaimName::PrivateUse(n) => match *n {
                    CLAIM_KEY_CORIM_LOCATORS => corim_locators = Some(value),
                    _ => private_claims.push((name, value)),
                },
                _ => private_claims.push((name, value)),
            }
        }

        // ── Validate mandatory claims ──
        let nonce = nonce.ok_or(OcpEatError::InvalidToken("Missing mandatory claim: nonce (10)"))?;
        let debug_status = debug_status
            .ok_or(OcpEatError::InvalidToken("Missing mandatory claim: dbgstat (263)"))?;
        let eat_profile = eat_profile
            .ok_or(OcpEatError::InvalidToken("Missing mandatory claim: eat_profile (265)"))?;

        // Validate that eat_profile matches the OCP EAT profile OID.
        if eat_profile != OCP_EAT_PROFILE_OID_STR {
            return Err(OcpEatError::InvalidToken(
                "eat_profile does not match OCP EAT profile OID (1.3.6.1.4.1.42623.1.3)",
            ));
        }

        let measurements = measurements
            .ok_or(OcpEatError::InvalidToken("Missing mandatory claim: measurements (273)"))?;

        Ok(OcpEatClaims {
            nonce,
            debug_status,
            eat_profile,
            measurements,
            issuer: cs.issuer,
            cwt_id: cs.cwt_id,
            ueid,
            sueid,
            oemid,
            hw_model,
            uptime,
            boot_count,
            boot_seed,
            dloas,
            corim_locators,
            private_claims,
        })
    }

    /// Decode the measurements bytes as a TaggedConciseEvidence (CBOR tag 571).
    ///
    /// The measurements field is a CBOR array of `[content-type, content-value]`
    /// entries. Each content-value is decoded as a `TaggedConciseEvidence`.
    pub fn decode_measurements(&self) -> OcpEatResult<Vec<DecodedMeasurement>> {
        let value: Value = ciborium::from_reader(self.measurements.as_slice())
            .map_err(|e| OcpEatError::MeasurementsDecode(format!("CBOR parse: {}", e)))?;

        let entries = match value {
            Value::Array(arr) => arr,
            _ => {
                return Err(OcpEatError::MeasurementsDecode(
                    "measurements is not a CBOR array".into(),
                ))
            }
        };

        let mut result = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let pair = match entry {
                Value::Array(a) if a.len() == 2 => a,
                _ => {
                    return Err(OcpEatError::MeasurementsDecode(format!(
                        "entry[{}] is not a 2-element array",
                        i
                    )))
                }
            };

            let content_type = match &pair[0] {
                Value::Integer(n) => {
                    let v: i128 = (*n).into();
                    u64::try_from(v).map_err(|_| {
                        OcpEatError::MeasurementsDecode(format!(
                            "entry[{}] content-type out of range",
                            i
                        ))
                    })?
                }
                _ => {
                    return Err(OcpEatError::MeasurementsDecode(format!(
                        "entry[{}] content-type is not uint",
                        i
                    )))
                }
            };

            let content_bytes = match &pair[1] {
                Value::Bytes(b) => b.as_slice(),
                _ => {
                    return Err(OcpEatError::MeasurementsDecode(format!(
                        "entry[{}] content-value is not bstr",
                        i
                    )))
                }
            };

            let evidence =
                TaggedConciseEvidence::from_cbor(content_bytes).map_err(|e| {
                    OcpEatError::MeasurementsDecode(format!("entry[{}] decode: {}", i, e))
                })?;

            result.push(DecodedMeasurement {
                content_type,
                evidence,
            });
        }

        Ok(result)
    }
}

/// A decoded measurement entry from the measurements array.
pub struct DecodedMeasurement {
    /// CoAP content-type (e.g. 10571 for concise-evidence).
    pub content_type: u64,
    /// The decoded TaggedConciseEvidence (CBOR tag 571).
    pub evidence: TaggedConciseEvidence<'static>,
}

// ── Helpers ────────────────────────────────────────────────────────

/// CBOR tag for OID (RFC 9090).
const CBOR_TAG_OID: u64 = 111;

use coset::iana::EnumI64;

fn value_to_bstr(value: Value, field: &'static str) -> OcpEatResult<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(OcpEatError::InvalidToken(field)),
    }
}

/// Extract OID bytes from a CBOR value that is either:
/// - `Value::Bytes(b)` — unwrapped OID (`~oid`)
/// - `Value::Tag(111, Value::Bytes(b))` — tagged OID (`#6.111(bstr)`)
fn value_to_oid(value: Value, field: &'static str) -> OcpEatResult<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b),
        Value::Tag(CBOR_TAG_OID, inner) => match *inner {
            Value::Bytes(b) => Ok(b),
            _ => Err(OcpEatError::InvalidToken(field)),
        },
        _ => Err(OcpEatError::InvalidToken(field)),
    }
}

fn value_to_uint(value: Value, field: &'static str) -> OcpEatResult<u64> {
    match value {
        Value::Integer(i) => {
            let val: i128 = i.into();
            u64::try_from(val).map_err(|_| OcpEatError::InvalidToken(field))
        }
        _ => Err(OcpEatError::InvalidToken(field)),
    }
}

/// Extract measurements bytes from a CBOR value.
///
/// Per the OCP EAT CDDL, `measurements-type` can be:
///   - `bstr .cbor concise-evidence`  → already a byte string
///   - `concise-evidence` (a CBOR Array) → re-encode to CBOR bytes
fn value_to_measurements(value: Value) -> OcpEatResult<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b),
        Value::Array(_) => {
            let mut buf = Vec::new();
            ciborium::into_writer(&value, &mut buf)
                .map_err(|_| OcpEatError::InvalidToken("measurements: failed to re-encode CBOR array"))?;
            Ok(buf)
        }
        _ => Err(OcpEatError::InvalidToken("measurements must be bstr or array")),
    }
}
