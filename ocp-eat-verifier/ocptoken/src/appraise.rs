// Licensed under the Apache-2.0 license

//! The `appraise` subcommand: authenticate all inputs, decode EAT claims,
//! appraise evidence against CoRIM reference values, run verifier checks,
//! and produce the final attestation result.

use std::env;

use ocptoken::appraisal;
use ocptoken::cose_verify::{CoseSign1Verifier, CryptoBackend};
use ocptoken::ta_store::TrustAnchorStore;

use crate::authenticate::{self, AuthenticateArgs};
use crate::common::SIGNED_REFVAL_CORIM_PATH;
use crate::display::{print_claims, print_corim_payload};

/// Environment variable for the SPDM nonce (hex-encoded).
const SPDM_NONCE: &str = "SPDM_NONCE";

pub(crate) fn run(
    args: &AuthenticateArgs,
    ta_store: &dyn TrustAnchorStore,
    verifier: &CoseSign1Verifier<impl CryptoBackend>,
) {
    // Phase 1: Input Validation & Transformation
    println!("Phase 1: Input Validation & Transformation");
    let result = authenticate::authenticate(args, ta_store, verifier);
    println!("All inputs validated and authenticated.");

    // Phase 2: Evidence Augmentation (decode EAT claims)
    println!("\nPhase 2: Evidence Augmentation (Appraisal Claim Set Initialization)");
    println!("Initializing Appraisal Claims Set with evidence claims...");
    print_claims(result.evidence.claims());

    // Phase 3: Reference Values Corroboration
    println!("\nPhase 3: Reference Values Corroboration");
    let refval_corims = match result.refval_corims {
        Some(ref c) if !c.is_empty() => c,
        _ => {
            eprintln!(
                "No CoRIM reference values loaded (set {} to enable appraisal)",
                SIGNED_REFVAL_CORIM_PATH
            );
            std::process::exit(1);
        }
    };

    println!("Loaded reference values:");
    for (file_name, corim_map) in refval_corims.iter() {
        print_corim_payload(file_name, corim_map);
    }

    println!("\nCorroborating evidence against reference values...");

    let expected_nonce = env::var(SPDM_NONCE).ok();

    let report = match appraisal::appraise(
        result.evidence.claims(),
        refval_corims,
        expected_nonce.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Appraisal error: {}", e);
            std::process::exit(1);
        }
    };

    for triple_result in &report.results {
        let mark = if triple_result.passed() { "PASS" } else { "FAIL" };
        println!("  [{}] {}", mark, triple_result.env_label);
        if !triple_result.env_matched {
            println!("         No matching evidence environment found");
        } else {
            for m in &triple_result.measurements {
                let mark = if m.matched { "PASS" } else { "FAIL" };
                println!("      [{}] {}: {}", mark, m.label, m.detail);
            }
        }
    }

    // Phase 5: Verifier Augmentation
    println!("\nPhase 5: Verifier Augmentation");
    println!("Running Verifier-generated checks (freshness, debug status)...");
    for check in &report.verifier_checks {
        let mark = if check.passed { "PASS" } else { "FAIL" };
        println!("  [{}] {}: {}", mark, check.name, check.detail);
    }

    // Phase 6: Attestation Result
    println!("\nPhase 6: Attestation Result");
    if report.all_passed() {
        println!("ATTESTATION RESULT: PASS — all phases completed successfully.");
    } else {
        println!("ATTESTATION RESULT: FAIL — one or more checks did not pass.");
        std::process::exit(1);
    }
}
