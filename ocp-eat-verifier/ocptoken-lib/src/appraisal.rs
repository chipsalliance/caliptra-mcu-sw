// Licensed under the Apache-2.0 license

//! Appraisal engine: match evidence triples against CoRIM reference values.
//!
//! Implements a simplified version of the CoRIM-09 §9 Reference Verifier
//! Algorithm:
//!
//! - **Phase 2** (Evidence Augmentation): evidence triples are collected.
//! - **Phase 3** (Reference Values Corroboration): each reference triple is
//!   matched against evidence; corroborated entries are recorded.
//! - **Phase 5** (Verifier Augmentation): the Verifier checks freshness
//!   (nonce) and debug status, augmenting the claims set with Verifier-
//!   authority assertions.
//! - **Phase 6** (Attestation Result): the final pass/fail result is
//!   determined from all preceding phases.

use corim_rs::{ConciseTagTypeChoice, MeasurementMap, ReferenceTripleRecord};

use crate::corim::RefValCorims;
use crate::token::claims::{DebugStatus, OcpEatClaims};

// ── Result types ───────────────────────────────────────────────────

/// Outcome of appraising a single reference triple.
pub struct TripleResult {
    /// Human-readable label for the environment.
    pub env_label: String,
    /// Whether a matching evidence triple was found.
    pub env_matched: bool,
    /// Per-measurement outcomes (populated only when `env_matched`).
    pub measurements: Vec<MeasurementResult>,
}

impl TripleResult {
    pub fn passed(&self) -> bool {
        self.env_matched && self.measurements.iter().all(|m| m.matched)
    }
}

/// Outcome of comparing one reference measurement against the evidence.
pub struct MeasurementResult {
    pub label: String,
    pub matched: bool,
    pub detail: String,
}

// ── Verifier-augmented claims (Phase 5) ────────────────────────────

/// Result of a single verifier precondition check.
pub struct VerifierCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Overall appraisal report.
pub struct AppraisalReport {
    /// Phase 5: Verifier-augmented precondition checks.
    pub verifier_checks: Vec<VerifierCheck>,
    /// Phase 3: Per-reference-triple corroboration results.
    pub results: Vec<TripleResult>,
}

impl AppraisalReport {
    pub fn all_passed(&self) -> bool {
        self.verifier_checks.iter().all(|c| c.passed)
            && !self.results.is_empty()
            && self.results.iter().all(|r| r.passed())
    }
}

// ── Core appraisal logic ───────────────────────────────────────────

/// Run appraisal: for every reference triple in the CoRIM, find the
/// matching evidence triple and compare measurement values.
///
/// `expected_nonce` is the hex-encoded nonce the Verifier sent to the
/// Attester via SPDM GET_MEASUREMENTS.  If `Some`, it is compared
/// against the nonce in the evidence claims (Phase 5 freshness check).
/// If `None`, the freshness check is skipped.
pub fn appraise(
    claims: &OcpEatClaims,
    refval_corims: &RefValCorims,
    expected_nonce: Option<&str>,
) -> Result<AppraisalReport, String> {
    // ── Phase 5: Verifier Augmentation ─────────────────────────────
    let verifier_checks = verify_preconditions(claims, expected_nonce);

    // 1. Collect reference triples from all CoRIM's CoMID tags.
    let ref_triples: Vec<&ReferenceTripleRecord> = refval_corims
        .iter()
        .flat_map(|(_, corim_map)| {
            corim_map.tags.iter().filter_map(|tag| {
                if let ConciseTagTypeChoice::Mid(tagged_comid) = tag {
                    tagged_comid.triples.reference_triples.as_deref()
                } else {
                    None
                }
            })
        })
        .flatten()
        .collect();

    if ref_triples.is_empty() {
        return Err("No reference triples found in CoRIM files".into());
    }

    // 2. Collect evidence triples from decoded measurements.
    let decoded = claims
        .decode_measurements()
        .map_err(|e| format!("Failed to decode measurements: {}", e))?;

    let ev_triples: Vec<&ReferenceTripleRecord> = decoded
        .iter()
        .filter_map(|entry| entry.evidence.ev_triples.evidence_triples.as_deref())
        .flatten()
        .collect();

    // 3. Appraise each reference triple against the evidence.
    let mut results = Vec::with_capacity(ref_triples.len());

    for ref_triple in &ref_triples {
        let env_label = format_env(&ref_triple.ref_env);

        // Find evidence triples whose environment matches the reference.
        let matching_ev: Vec<&&ReferenceTripleRecord> = ev_triples
            .iter()
            .filter(|ev| ref_triple.ref_env.matches(&ev.ref_env))
            .collect();

        if matching_ev.is_empty() {
            results.push(TripleResult {
                env_label,
                env_matched: false,
                measurements: Vec::new(),
            });
            continue;
        }

        // Compare each reference measurement against the matched evidence.
        let measurements = ref_triple
            .ref_claims
            .iter()
            .map(|ref_meas| appraise_measurement(ref_meas, &matching_ev))
            .collect();

        results.push(TripleResult {
            env_label,
            env_matched: true,
            measurements,
        });
    }

    Ok(AppraisalReport {
        verifier_checks,
        results,
    })
}

// ── Phase 5 helpers ────────────────────────────────────────────────

/// Run verifier precondition checks (Phase 5: Verifier Augmentation).
///
/// These are claims generated by the Verifier itself — they do not come
/// from reference values or endorsements.
fn verify_preconditions(claims: &OcpEatClaims, expected_nonce: Option<&str>) -> Vec<VerifierCheck> {
    let mut checks = Vec::new();

    // 1. Freshness: compare the evidence nonce against the expected nonce
    //    that the Verifier sent via SPDM GET_MEASUREMENTS.
    if let Some(expected) = expected_nonce {
        let evidence_nonce_hex = hex::encode(&claims.nonce);
        let nonce_ok = evidence_nonce_hex.eq_ignore_ascii_case(expected);
        checks.push(VerifierCheck {
            name: "Freshness (nonce)".into(),
            passed: nonce_ok,
            detail: if nonce_ok {
                let short = if evidence_nonce_hex.len() > 16 {
                    format!(
                        "{}…{}",
                        &evidence_nonce_hex[..8],
                        &evidence_nonce_hex[evidence_nonce_hex.len() - 8..]
                    )
                } else {
                    evidence_nonce_hex.clone()
                };
                format!("nonce={} — evidence matches expected", short)
            } else {
                format!(
                    "nonce mismatch: expected={}, evidence={}",
                    expected, evidence_nonce_hex
                )
            },
        });
    }

    // 2. Debug status: the evidence MUST NOT indicate debug is enabled.
    let dbg_ok = claims.debug_status != DebugStatus::Enabled;
    checks.push(VerifierCheck {
        name: "Debug status".into(),
        passed: dbg_ok,
        detail: if dbg_ok {
            format!("debug status is {} — acceptable", claims.debug_status)
        } else {
            "debug status is enabled (0) — NOT acceptable".into()
        },
    });

    checks
}

// ── Helpers ────────────────────────────────────────────────────────

/// Compare a single reference measurement against all evidence measurements
/// from the matching evidence triples.
fn appraise_measurement(
    ref_meas: &MeasurementMap,
    matching_ev: &[&&ReferenceTripleRecord],
) -> MeasurementResult {
    let label = format_mkey(ref_meas);

    for ev_triple in matching_ev {
        for ev_meas in &ev_triple.ref_claims {
            // If the reference measurement has a key, only compare with
            // evidence measurements that carry the same key.
            if let Some(ref rk) = ref_meas.mkey {
                match &ev_meas.mkey {
                    Some(ek) if ek == rk => {}
                    _ => continue,
                }
            }

            if ref_meas.mval.matches(&ev_meas.mval) {
                return MeasurementResult {
                    label,
                    matched: true,
                    detail: describe_match(&ref_meas.mval, &ev_meas.mval),
                };
            } else {
                return MeasurementResult {
                    label,
                    matched: false,
                    detail: describe_mismatch(&ref_meas.mval, &ev_meas.mval),
                };
            }
        }
    }

    MeasurementResult {
        label,
        matched: false,
        detail: "no evidence measurement found for this key".into(),
    }
}

/// Produce a human-readable label for a measurement key.
fn format_mkey(meas: &MeasurementMap) -> String {
    match &meas.mkey {
        Some(corim_rs::MeasuredElementTypeChoice::Tstr(s)) => s.to_string(),
        Some(corim_rs::MeasuredElementTypeChoice::UInt(n)) => format!("{}", n),
        Some(other) => format!("{:?}", other),
        None => "(no key)".into(),
    }
}

/// Produce a human-readable label for an environment.
fn format_env(env: &corim_rs::EnvironmentMap) -> String {
    let mut parts = Vec::new();
    if let Some(ref class) = env.class {
        if let Some(ref vendor) = class.vendor {
            parts.push(format!("vendor={}", vendor));
        }
        if let Some(ref model) = class.model {
            parts.push(format!("model={}", model));
        }
        if let Some(ref class_id) = class.class_id {
            if let Some(bytes) = class_id.as_bytes() {
                match std::str::from_utf8(bytes) {
                    Ok(s) => parts.push(format!("class-id=\"{}\"", s)),
                    Err(_) => parts.push(format!("class-id={}", hex::encode(bytes))),
                }
            }
        }
    }
    if parts.is_empty() {
        format!("{:?}", env)
    } else {
        parts.join(", ")
    }
}

/// Describe which fields in the reference matched the evidence.
fn describe_match(
    ref_mval: &corim_rs::MeasurementValuesMap,
    ev_mval: &corim_rs::MeasurementValuesMap,
) -> String {
    let mut matches = Vec::new();

    if let Some(ref ref_digests) = ref_mval.digests {
        if let Some(ref ev_digests) = ev_mval.digests {
            for rd in ref_digests {
                if let Some(ed) = ev_digests
                    .iter()
                    .find(|ed| ed.alg == rd.alg && ed.val == rd.val)
                {
                    let hex_val = hex::encode(&ed.val);
                    let short = if hex_val.len() > 16 {
                        format!("{}…{}", &hex_val[..8], &hex_val[hex_val.len() - 8..])
                    } else {
                        hex_val
                    };
                    matches.push(format!("digest({:?})={}", rd.alg, short));
                }
            }
        }
    }

    if let Some(ref ref_svn) = ref_mval.svn {
        if let Some(ref ev_svn) = ev_mval.svn {
            if ref_svn.matches(ev_svn) {
                matches.push(format!("svn={:?}", ev_svn));
            }
        }
    }

    if let Some(ref ref_ver) = ref_mval.version {
        if let Some(ref ev_ver) = ev_mval.version {
            if ref_ver.matches(ev_ver) {
                matches.push(format!("version={:?}", ev_ver));
            }
        }
    }

    if matches.is_empty() {
        "all specified values match".into()
    } else {
        matches.join("; ")
    }
}

/// Describe which fields in the reference didn't match the evidence.
fn describe_mismatch(
    ref_mval: &corim_rs::MeasurementValuesMap,
    ev_mval: &corim_rs::MeasurementValuesMap,
) -> String {
    let mut mismatches = Vec::new();

    if let Some(ref ref_digests) = ref_mval.digests {
        match &ev_mval.digests {
            Some(ev_digests) => {
                for rd in ref_digests {
                    let found = ev_digests.iter().find(|ed| ed.alg == rd.alg);
                    match found {
                        Some(ed) if ed.val != rd.val => {
                            mismatches.push(format!(
                                "digest({:?}): ref={} ev={}",
                                rd.alg,
                                hex::encode(&rd.val),
                                hex::encode(&ed.val),
                            ));
                        }
                        None => {
                            mismatches
                                .push(format!("digest({:?}): not present in evidence", rd.alg));
                        }
                        _ => {} // matching
                    }
                }
            }
            None => mismatches.push("digests: not present in evidence".into()),
        }
    }

    if let Some(ref ref_svn) = ref_mval.svn {
        match &ev_mval.svn {
            Some(ev_svn) => {
                if !ref_svn.matches(ev_svn) {
                    mismatches.push(format!("svn: ref={:?} ev={:?}", ref_svn, ev_svn));
                }
            }
            None => mismatches.push("svn: not present in evidence".into()),
        }
    }

    if let Some(ref ref_ver) = ref_mval.version {
        match &ev_mval.version {
            Some(ev_ver) => {
                if !ref_ver.matches(ev_ver) {
                    mismatches.push(format!("version: ref={:?} ev={:?}", ref_ver, ev_ver));
                }
            }
            None => mismatches.push("version: not present in evidence".into()),
        }
    }

    if mismatches.is_empty() {
        "unknown mismatch".into()
    } else {
        mismatches.join("; ")
    }
}
