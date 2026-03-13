// Licensed under the Apache-2.0 license

//! OCP SAFE SFR profile extraction from endorsement CoRIM payloads.
//!
//! Walks the raw CBOR payload (tag 501 CoRIM → CoMID → conditional endorsement
//! triples) using `ciborium::Value` to extract Security Findings Report data
//! from the measurement-values-map extension at key `-1`.
//!
//! This bypasses `corim_rs` deserialization which cannot handle the CBOR tag 0
//! (text datetime) format used by the SFR `completion-date` field.

use ciborium::Value;

use crate::corim::{CorimError, CorimResult, SignedCorim};

/// Environment information extracted from a CoMID endorsement triple.
#[derive(Debug, Clone, Default)]
pub struct EndorsementEnvironment {
    /// Class ID (OID, UUID, or opaque bytes) from the class-map.
    pub class_id: Option<String>,
    /// Vendor from the class-map.
    pub vendor: Option<String>,
    /// Model from the class-map.
    pub model: Option<String>,
    /// Layer from the class-map.
    pub layer: Option<i64>,
    /// Index from the class-map.
    pub index: Option<i64>,
    /// Instance identifier (UEID or opaque bytes).
    pub instance: Option<String>,
    /// Group identifier.
    pub group: Option<String>,
}

/// A condition from a conditional-endorsement-triple (environment + measurements).
#[derive(Debug, Clone)]
pub struct ConditionEntry {
    /// Environment from the condition.
    pub environment: EndorsementEnvironment,
    /// Digests from the condition measurements: (algorithm_name, hex_hash).
    pub digests: Vec<(String, String)>,
}

/// An extracted OCP SAFE SFR entry from a conditional endorsement triple.
#[derive(Debug, Clone)]
pub struct SafeSfrEntry {
    /// Conditions that gate this endorsement.
    pub conditions: Vec<ConditionEntry>,
    /// Full environment from the endorsement triple.
    pub environment: EndorsementEnvironment,
    /// Review framework version (SFR key 0).
    pub review_framework_version: Option<String>,
    /// Report version (SFR key 1).
    pub report_version: Option<String>,
    /// Completion date as string (SFR key 2 — may be tag 0 text or tag 1 epoch).
    pub completion_date: Option<String>,
    /// Scope number (SFR key 3).
    pub scope_number: Option<i64>,
    /// Firmware identifiers (SFR key 4).
    pub fw_identifiers: Vec<SafeFwIdentifier>,
    /// Security issues found (SFR key 5).
    pub issues: Vec<SafeIssue>,
}

/// A firmware identifier from the SFR extension.
#[derive(Debug, Clone)]
pub struct SafeFwIdentifier {
    pub fw_version: Option<String>,
    pub repo_tag: Option<String>,
    pub fw_digests: Vec<(String, String)>, // (algorithm, hex hash)
}

/// A security issue from the SFR extension.
#[derive(Debug, Clone)]
pub struct SafeIssue {
    pub title: String,
    pub description: String,
    pub cvss_score: Option<String>,
    pub cvss_vector: Option<String>,
    pub cvss_version: Option<String>,
    pub cwe: Option<String>,
    pub cve: Option<String>,
}

/// Extract SAFE SFR data from a verified SignedCorim's payload using raw
/// CBOR walking (bypasses `corim_rs` deserialization).
pub(crate) fn extract_safe_sfr(
    signed: &SignedCorim,
) -> CorimResult<(Option<String>, Vec<SafeSfrEntry>)> {
    let payload_bytes = signed.decoded_ref().payload().ok_or(CorimError::NoPayload {
        file: signed.file_name().to_string(),
    })?;

    let value: Value = ciborium::from_reader(payload_bytes).map_err(|e| {
        CorimError::PayloadDecode {
            file: signed.file_name().to_string(),
            detail: format!("CBOR parse: {e}"),
        }
    })?;

    // Unwrap tag 501
    let corim_map = match &value {
        Value::Tag(501, inner) => match inner.as_ref() {
            Value::Map(m) => m,
            _ => return Ok((None, Vec::new())),
        },
        Value::Map(m) => m,
        _ => return Ok((None, Vec::new())),
    };

    // Extract CoRIM ID (key 0)
    let corim_id = get_map_text(corim_map, 0);

    // Extract tags array (key 1)
    let tags = match get_map_value(corim_map, 1) {
        Some(Value::Array(arr)) => arr,
        _ => return Ok((corim_id, Vec::new())),
    };

    let mut sfr_entries = Vec::new();

    // Each tag is 506(bstr) — a CoMID
    for tag_val in tags {
        let comid_bytes = match tag_val {
            Value::Tag(506, inner) => match inner.as_ref() {
                Value::Bytes(b) => b,
                _ => continue,
            },
            _ => continue,
        };

        let comid: Value = match ciborium::from_reader(comid_bytes.as_slice()) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let comid_map = match &comid {
            Value::Map(m) => m,
            _ => continue,
        };

        // triples (key 4 in CoMID)
        let triples_map = match get_map_value(comid_map, 4) {
            Some(Value::Map(m)) => m,
            _ => continue,
        };

        // conditional-endorsement-triples (key 10)
        let cond_triples = match get_map_value(triples_map, 10) {
            Some(Value::Array(arr)) => arr,
            _ => continue,
        };

        for cond_triple in cond_triples {
            // Each conditional-endorsement-triple-record is [conditions, endorsements]
            let record = match cond_triple {
                Value::Array(arr) if arr.len() >= 2 => arr,
                _ => continue,
            };

            // Extract conditions (record[0] is an array of [env, [meas, ...]])
            let conditions = extract_conditions(&record[0]);

            let endorsements = match &record[1] {
                Value::Array(arr) => arr,
                _ => continue,
            };

            for endorsed in endorsements {
                // endorsed-triple-record is [environment-map, [measurement-map, ...]]
                let endorsed_arr = match endorsed {
                    Value::Array(arr) if arr.len() >= 2 => arr,
                    _ => continue,
                };

                let env = extract_environment(&endorsed_arr[0]);

                let measurements = match &endorsed_arr[1] {
                    Value::Array(arr) => arr,
                    _ => continue,
                };

                for meas in measurements {
                    // measurement-map: {1: measurement-values-map, ...}
                    let mval_map = match meas {
                        Value::Map(m) => match get_map_value(m, 1) {
                            Some(Value::Map(m2)) => m2,
                            _ => continue,
                        },
                        _ => continue,
                    };

                    // Look for SFR extension at key -1
                    let sfr_val = match get_map_value_neg(mval_map, -1) {
                        Some(Value::Map(m)) => m,
                        _ => continue,
                    };

                    let entry = extract_sfr_map(sfr_val, env.clone(), conditions.clone());
                    sfr_entries.push(entry);
                }
            }
        }
    }

    Ok((corim_id, sfr_entries))
}

// ── CBOR map helpers ────────────────────────────────────────────────────────

/// Get a text value from a CBOR map by integer key.
fn get_map_text(map: &[(Value, Value)], key: i64) -> Option<String> {
    match get_map_value(map, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

/// Get a value from a CBOR map by non-negative integer key.
fn get_map_value(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    for (k, v) in map {
        match k {
            Value::Integer(i) if i128::from(*i) == key as i128 => return Some(v),
            _ => {}
        }
    }
    None
}

/// Get a value from a CBOR map by negative integer key.
fn get_map_value_neg(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    for (k, v) in map {
        match k {
            Value::Integer(i) if i128::from(*i) == key => return Some(v),
            _ => {}
        }
    }
    None
}

// ── Environment extraction ──────────────────────────────────────────────────

/// Extract condition entries from the conditions array of a conditional-endorsement-triple.
fn extract_conditions(val: &Value) -> Vec<ConditionEntry> {
    let conditions_arr = match val {
        Value::Array(arr) => arr,
        _ => return Vec::new(),
    };

    let mut entries = Vec::new();
    for cond in conditions_arr {
        // Each condition is [environment-map, [measurement-map, ...]]
        let cond_arr = match cond {
            Value::Array(arr) if arr.len() >= 2 => arr,
            _ => continue,
        };

        let environment = extract_environment(&cond_arr[0]);

        // Extract digests from measurements
        let mut digests = Vec::new();
        if let Value::Array(measurements) = &cond_arr[1] {
            for meas in measurements {
                let mval_map = match meas {
                    Value::Map(m) => match get_map_value(m, 1) {
                        Some(Value::Map(m2)) => m2,
                        _ => continue,
                    },
                    _ => continue,
                };
                // digests at key 2
                if let Some(Value::Array(digest_arr)) = get_map_value(mval_map, 2) {
                    for d in digest_arr {
                        if let Value::Array(pair) = d {
                            if pair.len() >= 2 {
                                let alg = match &pair[0] {
                                    Value::Integer(i) => hash_alg_name(i128::from(*i)),
                                    _ => continue,
                                };
                                let hash = match &pair[1] {
                                    Value::Bytes(b) => hex::encode(b),
                                    _ => continue,
                                };
                                digests.push((alg, hash));
                            }
                        }
                    }
                }
            }
        }

        entries.push(ConditionEntry {
            environment,
            digests,
        });
    }
    entries
}

/// Extract full environment information from an environment-map CBOR value.
fn extract_environment(env: &Value) -> EndorsementEnvironment {
    let env_map = match env {
        Value::Map(m) => m,
        _ => return EndorsementEnvironment::default(),
    };

    let mut result = EndorsementEnvironment::default();

    // class (key 0)
    if let Some(Value::Map(class_map)) = get_map_value(env_map, 0) {
        // class-id (key 0) — could be OID (tag 111), UUID (tag 37), or bytes
        result.class_id = match get_map_value(class_map, 0) {
            Some(Value::Tag(111, inner)) => match inner.as_ref() {
                Value::Bytes(b) => Some(format!("OID({})", oid_bytes_to_string(b))),
                _ => None,
            },
            Some(Value::Tag(37, inner)) => match inner.as_ref() {
                Value::Bytes(b) if b.len() == 16 => {
                    Some(format_uuid(b))
                }
                _ => None,
            },
            Some(Value::Bytes(b)) => Some(
                std::str::from_utf8(b)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| hex::encode(b)),
            ),
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        result.vendor = get_map_text(class_map, 1);
        result.model = get_map_text(class_map, 2);
        result.layer = match get_map_value(class_map, 3) {
            Some(Value::Integer(i)) => Some(i128::from(*i) as i64),
            _ => None,
        };
        result.index = match get_map_value(class_map, 4) {
            Some(Value::Integer(i)) => Some(i128::from(*i) as i64),
            _ => None,
        };
    }

    // instance (key 1) — UEID bytes or tagged value
    result.instance = match get_map_value(env_map, 1) {
        Some(Value::Bytes(b)) => Some(hex::encode(b)),
        Some(Value::Tag(_, inner)) => match inner.as_ref() {
            Value::Bytes(b) => Some(hex::encode(b)),
            _ => None,
        },
        _ => None,
    };

    // group (key 2)
    result.group = match get_map_value(env_map, 2) {
        Some(Value::Bytes(b)) => Some(hex::encode(b)),
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    };

    result
}

// ── SFR map extraction ─────────────────────────────────────────────────────

/// Extract an SFR map from raw CBOR key-value pairs.
fn extract_sfr_map(
    sfr: &[(Value, Value)],
    environment: EndorsementEnvironment,
    conditions: Vec<ConditionEntry>,
) -> SafeSfrEntry {
    let review_framework_version = get_map_text(sfr, 0);
    let report_version = get_map_text(sfr, 1);

    // completion-date (key 2) — may be tag 0 (text datetime) or tag 1 (epoch)
    let completion_date = match get_map_value(sfr, 2) {
        Some(Value::Tag(0, inner)) => match inner.as_ref() {
            Value::Text(s) => Some(s.clone()),
            _ => None,
        },
        Some(Value::Tag(1, inner)) => match inner.as_ref() {
            Value::Integer(i) => {
                let secs = i128::from(*i);
                Some(format_epoch(secs))
            }
            Value::Float(f) => Some(format_epoch(*f as i128)),
            _ => None,
        },
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    };

    let scope_number = match get_map_value(sfr, 3) {
        Some(Value::Integer(i)) => Some(i128::from(*i) as i64),
        _ => None,
    };

    // fw-identifiers (key 4)
    let fw_identifiers = match get_map_value(sfr, 4) {
        Some(Value::Array(arr)) => arr.iter().filter_map(extract_fw_identifier).collect(),
        _ => Vec::new(),
    };

    // issues (key 5)
    let issues = match get_map_value(sfr, 5) {
        Some(Value::Array(arr)) => arr.iter().filter_map(extract_issue).collect(),
        _ => Vec::new(),
    };

    SafeSfrEntry {
        conditions,
        environment,
        review_framework_version,
        report_version,
        completion_date,
        scope_number,
        fw_identifiers,
        issues,
    }
}

/// Extract a firmware identifier from a CBOR value.
fn extract_fw_identifier(val: &Value) -> Option<SafeFwIdentifier> {
    let m = match val {
        Value::Map(m) => m,
        _ => return None,
    };

    // fw-version (key 0) — version-map {0: version, 1: version-scheme}
    let fw_version = match get_map_value(m, 0) {
        Some(Value::Map(vm)) => get_map_text(vm, 0),
        _ => None,
    };

    // fw-file-digests (key 1) — array of [alg, hash]
    let fw_digests = match get_map_value(m, 1) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|d| {
                let pair = match d {
                    Value::Array(p) if p.len() >= 2 => p,
                    _ => return None,
                };
                let alg = match &pair[0] {
                    Value::Integer(i) => hash_alg_name(i128::from(*i)),
                    _ => return None,
                };
                let hash = match &pair[1] {
                    Value::Bytes(b) => hex::encode(b),
                    _ => return None,
                };
                Some((alg, hash))
            })
            .collect(),
        _ => Vec::new(),
    };

    // repo-tag (key 2)
    let repo_tag = get_map_text(m, 2);

    Some(SafeFwIdentifier {
        fw_version,
        repo_tag,
        fw_digests,
    })
}

/// Extract a security issue from a CBOR value.
fn extract_issue(val: &Value) -> Option<SafeIssue> {
    let m = match val {
        Value::Map(m) => m,
        _ => return None,
    };

    let title = get_map_text(m, 0)?;
    let description = get_map_text(m, 1).unwrap_or_default();

    // assessment (key 2) — CVSS map {0: score, 1: vector, 2: version}
    let (cvss_score, cvss_vector, cvss_version) = match get_map_value(m, 2) {
        Some(Value::Map(cvss)) => (
            get_map_text(cvss, 0),
            get_map_text(cvss, 1),
            get_map_text(cvss, 2),
        ),
        _ => (None, None, None),
    };

    let cwe = get_map_text(m, 3);
    let cve = get_map_text(m, 4);

    Some(SafeIssue {
        title,
        description,
        cvss_score,
        cvss_vector,
        cvss_version,
        cwe,
        cve,
    })
}

// ── Utility ─────────────────────────────────────────────────────────────────

/// Map CBOR hash algorithm IDs to human-readable names.
fn hash_alg_name(alg: i128) -> String {
    match alg {
        -43 => "SHA-384".to_string(),
        -44 => "SHA-512".to_string(),
        1 => "SHA-256".to_string(),
        _ => format!("alg({})", alg),
    }
}

/// Format an epoch timestamp as a human-readable date string.
fn format_epoch(secs: i128) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("epoch({})", secs),
    }
}

/// Decode OID bytes (BER-encoded arc values) into a dotted-decimal string.
fn oid_bytes_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut arcs = Vec::new();
    // First byte encodes the first two arcs
    arcs.push((bytes[0] / 40) as u64);
    arcs.push((bytes[0] % 40) as u64);
    let mut val: u64 = 0;
    for &b in &bytes[1..] {
        val = (val << 7) | (b as u64 & 0x7F);
        if b & 0x80 == 0 {
            arcs.push(val);
            val = 0;
        }
    }
    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

/// Format 16 bytes as a UUID string.
fn format_uuid(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u64::from_be_bytes([0, 0, b[10], b[11], b[12], b[13], b[14], b[15]]),
    )
}
