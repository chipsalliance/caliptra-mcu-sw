// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fs};

use ocptoken::corim::RefValCorims;
use ocptoken::cose_verify::{
    extract_signer_key_cert, CoseSign1Verifier, DecodedCoseSign1, OpenSslBackend,
};
use ocptoken::ta_store::FsTrustAnchorStore;
use ocptoken::token::claims::OcpEatClaims;
use ocptoken::token::evidence::{Evidence, OCP_EAT_TAGS};

/// Environment variable for the trust anchor store path.
const TA_STORE_PATH: &str = "TA_STORE_PATH";

/// Environment variable for the signed CoRIM directory path.
const SIGNED_REFVAL_CORIM_PATH: &str = "SIGNED_REFVAL_CORIM_PATH";

/// Environment variable for the expected SPDM nonce (hex-encoded).
const SPDM_NONCE: &str = "SPDM_NONCE";

// ── ANSI color palette for up to 6 distinct target environments ──
const ENV_COLORS: &[&str] = &[
    "\x1b[36m", // cyan
    "\x1b[33m", // yellow
    "\x1b[35m", // magenta
    "\x1b[32m", // green
    "\x1b[34m", // blue
    "\x1b[91m", // bright red
];
const C_RESET: &str = "\x1b[0m";

#[derive(Parser, Debug)]
#[command(
    name = "ocptoken",
    author,
    version,
    about = "Verify an OCP TOKEN COSE_Sign1 token",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Quick structural check: decode the COSE_Sign1 and verify its
    /// signature using the x5chain leaf certificate from the evidence.
    ///
    /// NOTE: This does NOT authenticate the signing certificate against
    /// a Trust Anchor Store, so it only confirms internal consistency
    /// of the token. Use the `authenticate` subcommand for full
    /// end-to-end verification.
    Verify(VerifyArgs),

    /// Authenticate the evidence with the Trust Anchor Store and verify the COSE_Sign1 signature
    Authenticate(AuthenticateArgs),

    /// Authenticate, verify, and appraise evidence against CoRIM reference values
    Appraise(AppraiseArgs),
}

#[derive(Parser, Debug)]
struct AppraiseArgs {
    #[clap(flatten)]
    auth: AuthenticateArgs,

    /// Demo mode: print phase banners and pause between phases
    #[arg(long = "demo", default_value_t = false)]
    demo: bool,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    #[arg(
        short = 'e',
        long = "evidence",
        value_name = "EVIDENCE",
        default_value = "ocp_eat.cbor"
    )]
    evidence: PathBuf,
}

#[derive(Parser, Debug)]
struct AuthenticateArgs {
    #[arg(
        short = 'e',
        long = "evidence",
        value_name = "EVIDENCE",
        default_value = "ocp_eat.cbor"
    )]
    evidence: PathBuf,

    #[arg(
        short = 'c',
        long = "cert-chain",
        value_name = "CERT_CHAIN",
        long_help = "\
Concatenated DER certificate chain blob from the device \
(root-to-leaf order, e.g. from SPDM GET_CERTIFICATE).

The device leaf (last cert in the blob) is dropped and replaced \
with the leaf cert(s) from the x5chain in the evidence unprotected \
header. The resulting chain is validated against the Trust Anchor Store.

Omit this option if the x5chain already contains the full chain."
    )]
    cert_chain: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify(args) => run_verify(&args),
        Commands::Authenticate(args) => run_authenticate(&args),
        Commands::Appraise(args) => run_appraise(&args),
    }
}

/// Print a prominent phase banner.
fn phase_banner(phase: &str, title: &str) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  Phase {}: {}", phase, title);
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
}

/// In demo mode, pause and wait for the user to press Enter.
/// Reads from /dev/tty so it works even when stdout is piped.
fn demo_pause(demo: bool) {
    if !demo {
        return;
    }
    // Open /dev/tty directly so this works regardless of stdin redirection.
    let tty = match fs::OpenOptions::new().read(true).open("/dev/tty") {
        Ok(f) => f,
        Err(_) => return, // Non-interactive environment — skip pause.
    };
    print!("\n  ▶ Press Enter to continue to the next phase...");
    std::io::stdout().flush().ok();
    let mut reader = std::io::BufReader::new(tty);
    let mut buf = String::new();
    std::io::BufRead::read_line(&mut reader, &mut buf).ok();
    println!();
}

/// Verify only: decode the EAT, extract the x5chain leaf, and
/// cryptographically verify the COSE_Sign1 signature.
fn run_verify(args: &VerifyArgs) {
    // 1. Load the binary evidence file
    let encoded = load_evidence(&args.evidence);

    // 2. Decode the COSE_Sign1 with OCP EAT tag wrapping
    let decoded = match DecodedCoseSign1::decode(&encoded, OCP_EAT_TAGS) {
        Ok(d) => {
            println!("Decode successful");
            d
        }
        Err(e) => {
            eprintln!("COSE_Sign1 decode failed: {:?}", e);
            std::process::exit(1);
        }
    };

    // 3. Extract the leaf certificate from x5chain
    let leaf_cert = match extract_signer_key_cert(&decoded) {
        Some(cert) => cert,
        None => {
            eprintln!("No x5chain found in COSE headers");
            std::process::exit(1);
        }
    };

    // 4. Verify the COSE_Sign1 signature
    let verifier = CoseSign1Verifier::new(OpenSslBackend);
    match verifier.verify_ref(&decoded, &leaf_cert) {
        Ok(()) => {
            println!("Signature verification successful");
        }
        Err(e) => {
            eprintln!("Signature verification failed: {:?}", e);
            std::process::exit(1);
        }
    }
}

/// Shared context produced by the authenticate-and-verify pipeline.
/// Both `authenticate` and `appraise` commands build on this.
struct AuthenticatedContext<'a> {
    ev: Evidence<'a>,
    refval_corims: RefValCorims,
}

/// Common pipeline: load TA store, cert chain, evidence; authenticate and
/// verify both the evidence and any signed CoRIM reference values.
fn authenticate_pipeline<'a>(
    args: &AuthenticateArgs,
    ta_store: &'a FsTrustAnchorStore,
) -> AuthenticatedContext<'a> {
    // 1. Load the certificate chain blob (if provided)
    let cert_chain_blob = match &args.cert_chain {
        Some(path) => match fs::read(path) {
            Ok(b) => {
                println!("Loaded evidence:");
                println!(
                    "  - certificate chain: '{}' ({} bytes)",
                    path.display(),
                    b.len()
                );
                b
            }
            Err(e) => {
                eprintln!(
                    "Failed to read certificate chain '{}': {}",
                    path.display(),
                    e
                );
                std::process::exit(1);
            }
        },
        None => Vec::new(),
    };

    // 2. Load the binary evidence file
    let encoded = load_evidence(&args.evidence);

    // 3. Decode the evidence
    let ev = match Evidence::decode(&encoded, ta_store) {
        Ok(ev) => {
            println!("Decode successful");
            ev
        }
        Err(e) => {
            eprintln!("Evidence::decode failed: {:?}", e);
            std::process::exit(1);
        }
    };

    // 4. Authenticate the signing key
    println!("\x1b[38;2;178;34;34mAuthenticating the Evidence...\x1b[0m");
    match ev.authenticate(&cert_chain_blob) {
        Ok(_) => {
            println!(
                "  \x1b[32m✓\x1b[0m Evidence signer certificate chain authentication successful"
            );
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Evidence::authenticate failed: {:?}", e);
            std::process::exit(1);
        }
    }

    // 5. Verify the COSE_Sign1 signature
    let verifier = CoseSign1Verifier::new(OpenSslBackend);
    match ev.verify(&cert_chain_blob, &verifier) {
        Ok(()) => {
            println!("  \x1b[32m✓\x1b[0m Evidence signature verification successful");
        }
        Err(e) => {
            eprintln!("  \x1b[31m✗\x1b[0m Evidence::verify failed: {:?}", e);
            std::process::exit(1);
        }
    }

    // 6. Authenticate and verify signed reference value CoRIM files (if SIGNED_REFVAL_CORIM_PATH is set)
    let refval_corims = if let Ok(corims_path) = env::var(SIGNED_REFVAL_CORIM_PATH) {
        let corims_dir = PathBuf::from(corims_path);
        println!("\n\x1b[36mAuthenticating Signed CoRIMs\x1b[0m ...");
        match RefValCorims::decode_and_verify(&corims_dir, ta_store, &verifier) {
            Ok(rv) => {
                for (name, _) in rv.iter() {
                    println!("  \x1b[32m✓\x1b[0m \x1b[36m{}\x1b[0m: signature verified, signer authenticated", name);
                }
                println!("\x1b[32m✓\x1b[0m All signed CoRIM files verified successfully.");
                rv
            }
            Err(e) => {
                eprintln!("Signed CoRIM processing failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        RefValCorims {
            entries: Vec::new(),
        }
    };

    AuthenticatedContext { ev, refval_corims }
}

/// Load the Trust Anchor Store from the TA_STORE_PATH environment variable.
fn load_ta_store() -> FsTrustAnchorStore {
    let ta_store_path = match env::var(TA_STORE_PATH) {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!(
                "Environment variable {} is not set. \
                 Set it to the path of the trust anchor store directory \
                 (containing roots/ and optionally signing-certs/).",
                TA_STORE_PATH
            );
            std::process::exit(1);
        }
    };

    match FsTrustAnchorStore::load(&ta_store_path) {
        Ok(s) => {
            println!(
                "Loaded trust anchor store from '{}'",
                ta_store_path.display()
            );
            s
        }
        Err(e) => {
            eprintln!(
                "Failed to load trust anchor store '{}': {}",
                ta_store_path.display(),
                e
            );
            std::process::exit(1);
        }
    }
}

/// Authenticate and verify: load the trust anchor store, authenticate
/// the certificate chain, and verify the COSE_Sign1 signature.
fn run_authenticate(args: &AuthenticateArgs) {
    let ta_store = load_ta_store();
    let ctx = authenticate_pipeline(args, &ta_store);

    let env_colors = build_env_color_map(&ctx.refval_corims, ctx.ev.claims());

    // Print the decoded claims and measurements
    eprintln!("\nEvidence authentication and verification successful.");
    eprintln!("Decoded OCP EAT claims:");
    print_claims(ctx.ev.claims(), &env_colors);

    if !ctx.refval_corims.is_empty() {
        println!("\n=== Decoded CoRIM Reference Values ===");
        for (file_name, corim_map) in ctx.refval_corims.iter() {
            print_corim_payload(file_name, corim_map, &env_colors);
        }
        println!("======================================\n");
    }
}

/// Appraise: authenticate and verify, then appraise evidence against
/// CoRIM reference values.
fn run_appraise(args: &AppraiseArgs) {
    let demo = args.demo;

    // ── Phase 1: Input Validation & Transformation ──────────────────
    phase_banner("1", "Input Validation & Transformation");
    let ta_store = load_ta_store();
    let ctx = authenticate_pipeline(&args.auth, &ta_store);
    let env_colors = build_env_color_map(&ctx.refval_corims, ctx.ev.claims());
    println!("All inputs validated and authenticated.");
    demo_pause(demo);

    // ── Phase 2: Evidence Augmentation (Evidence Claimset Initialization) ─────────
    phase_banner(
        "2",
        "Evidence Augmentation (Evidence Claimset Initialization)",
    );
    println!("Initializing Evidence Claim with evidence claims...");
    print_claims(ctx.ev.claims(), &env_colors);
    demo_pause(demo);

    // ── Phase 3: Reference Values Corroboration ─────────────────────
    phase_banner("3", "Reference Values Corroboration");
    if ctx.refval_corims.is_empty() {
        eprintln!(
            "No CoRIM reference values loaded (set {} to enable appraisal)",
            SIGNED_REFVAL_CORIM_PATH
        );
        std::process::exit(1);
    }

    println!("Loaded reference values:");
    for (file_name, corim_map) in ctx.refval_corims.iter() {
        print_corim_payload(file_name, corim_map, &env_colors);
    }

    println!("\nCorroborating evidence against reference values...");

    // Read the expected nonce for Phase 5.
    let expected_nonce = env::var(SPDM_NONCE).ok();

    let report = match ocptoken::appraisal::appraise(
        ctx.ev.claims(),
        &ctx.refval_corims,
        expected_nonce.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Appraisal error: {}", e);
            std::process::exit(1);
        }
    };

    // Display Phase 3 results.
    for result in &report.results {
        let color = env_colors.get(&result.env_label).copied().unwrap_or("");
        if result.passed() {
            println!(
                "  \x1b[32m✓\x1b[0m {}{}{}",
                color, result.env_label, C_RESET
            );
        } else {
            println!(
                "  \x1b[31m✗\x1b[0m {}{}{}",
                color, result.env_label, C_RESET
            );
        }
        if !result.env_matched {
            println!("         No matching evidence environment found");
        } else {
            for m in &result.measurements {
                if m.matched {
                    println!("      \x1b[32m✓\x1b[0m {}: {}", m.label, m.detail);
                } else {
                    println!("      \x1b[31m✗\x1b[0m {}: {}", m.label, m.detail);
                }
            }
        }
    }
    demo_pause(demo);

    // ── Phase 5: Verifier Augmentation ──────────────────────────────
    phase_banner("5", "Verifier Augmentation");
    println!("Running Verifier-generated checks (freshness, debug status)...");
    for check in &report.verifier_checks {
        if check.passed {
            println!("  \x1b[32m✓\x1b[0m {}: {}", check.name, check.detail);
        } else {
            println!("  \x1b[31m✗\x1b[0m {}: {}", check.name, check.detail);
        }
    }
    demo_pause(demo);

    // ── Verdict ─────────────────────────────────────────────────────
    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    if report.all_passed() {
        println!(
            "  ATTESTATION RESULT: \x1b[32m✓ PASS\x1b[0m — all phases completed successfully."
        );
    } else {
        println!("  ATTESTATION RESULT: \x1b[31m✗ FAIL\x1b[0m — one or more checks did not pass.");
    }
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();

    if !report.all_passed() {
        std::process::exit(1);
    }
}

fn load_evidence(path: &PathBuf) -> Vec<u8> {
    match fs::read(path) {
        Ok(b) => {
            println!(
                "  - measurement block: '{}' ({} bytes)",
                path.display(),
                b.len()
            );
            b
        }
        Err(e) => {
            eprintln!("Failed to read evidence file '{}': {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

fn print_claims(claims: &OcpEatClaims, env_colors: &HashMap<String, &str>) {
    println!("\n=== OCP EAT Claims ===");

    // Mandatory
    println!("  [Mandatory]");
    println!("  Nonce:           {}", hex::encode(&claims.nonce));
    println!("  Debug Status:    {}", claims.debug_status);
    println!("  EAT Profile:     {}", claims.eat_profile);
    println!("  Measurements:    {} bytes", claims.measurements.len());

    // Decode and print concise-evidence measurements
    print_measurements(claims, env_colors);

    // Optional
    println!("  [Optional]");
    if let Some(ref iss) = claims.issuer {
        println!("  Issuer:          {}", iss);
    }
    if let Some(ref cti) = claims.cwt_id {
        println!("  CWT ID:          {}", hex::encode(cti));
    }
    if let Some(ref ueid) = claims.ueid {
        println!("  UEID:            {}", hex::encode(ueid));
    }
    if let Some(ref sueid) = claims.sueid {
        println!("  SUEID:           {}", hex::encode(sueid));
    }
    if let Some(ref oemid) = claims.oemid {
        println!("  OEM ID:          {:?}", oemid);
    }
    if let Some(ref hw_model) = claims.hw_model {
        println!("  HW Model:        {}", hex::encode(hw_model));
    }
    if let Some(uptime) = claims.uptime {
        println!("  Uptime:          {}", uptime);
    }
    if let Some(boot_count) = claims.boot_count {
        println!("  Boot Count:      {}", boot_count);
    }
    if let Some(ref boot_seed) = claims.boot_seed {
        println!("  Boot Seed:       {}", hex::encode(boot_seed));
    }
    if let Some(ref dloas) = claims.dloas {
        println!("  DLOAs:           {:?}", dloas);
    }
    if let Some(ref locs) = claims.corim_locators {
        println!("  CoRIM Locators:  {:?}", locs);
    }

    if !claims.private_claims.is_empty() {
        println!("  [Private]");
        for (name, value) in &claims.private_claims {
            println!("  {:?}: {:?}", name, value);
        }
    }

    println!("======================\n");
}

fn format_unix_timestamp(secs: i128) -> String {
    use chrono::DateTime;
    match DateTime::from_timestamp(secs as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{}(unknown)", secs),
    }
}

/// Produce a display label for an environment (vendor, model, class-id).
fn env_label(env: &corim_rs::EnvironmentMap) -> String {
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

/// Build a deterministic color map from environment labels.
/// Collects unique labels from reference triples first, then evidence triples,
/// assigning a distinct color to each.
fn build_env_color_map(
    refval_corims: &ocptoken::corim::RefValCorims,
    claims: &OcpEatClaims,
) -> HashMap<String, &'static str> {
    let mut map = HashMap::new();
    let mut idx = 0usize;

    // Collect from reference triples (CoRIM).
    for (_name, corim_map) in refval_corims.iter() {
        for tag in &corim_map.tags {
            if let corim_rs::ConciseTagTypeChoice::Mid(tagged_comid) = tag {
                let comid = &tagged_comid.0 .0;
                if let Some(ref ref_triples) = comid.triples.reference_triples {
                    for triple in ref_triples {
                        let label = env_label(&triple.ref_env);
                        if !map.contains_key(&label) {
                            map.insert(label, ENV_COLORS[idx % ENV_COLORS.len()]);
                            idx += 1;
                        }
                    }
                }
            }
        }
    }

    // Collect from evidence triples.
    if let Ok(entries) = claims.decode_measurements() {
        for entry in &entries {
            if let Some(ref triples) = entry.evidence.ev_triples.evidence_triples {
                for triple in triples {
                    let label = env_label(&triple.ref_env);
                    if !map.contains_key(&label) {
                        map.insert(label, ENV_COLORS[idx % ENV_COLORS.len()]);
                        idx += 1;
                    }
                }
            }
        }
    }

    map
}

fn print_corim_payload(
    file_name: &str,
    corim_map: &corim_rs::CorimMap,
    env_colors: &HashMap<String, &str>,
) {
    println!("  File: {}", file_name);
    println!("  CoRIM ID: {:?}", corim_map.id);
    if let Some(ref profile) = corim_map.profile {
        println!("  Profile:  {:?}", profile);
    }
    if let Some(ref validity) = corim_map.rim_validity {
        let not_after_secs = validity.not_after.as_i128();
        let not_after_str = format_unix_timestamp(not_after_secs);
        if let Some(ref not_before) = validity.not_before {
            let not_before_secs = not_before.as_i128();
            let not_before_str = format_unix_timestamp(not_before_secs);
            println!("  Validity: {} to {}", not_before_str, not_after_str);
        } else {
            println!("  Validity: until {}", not_after_str);
        }
    }
    if let Some(ref entities) = corim_map.entities {
        println!("  Entities ({}):", entities.len());
        for (i, entity) in entities.iter().enumerate() {
            println!("    [{}] {:?}", i, entity);
        }
    }
    println!("  Tags ({}):", corim_map.tags.len());
    for (i, tag) in corim_map.tags.iter().enumerate() {
        match tag {
            corim_rs::ConciseTagTypeChoice::Mid(tagged_comid) => {
                let comid = &tagged_comid.0 .0;
                println!("    [{}] CoMID: tag-id={:?}", i, comid.tag_identity.tag_id);
                print_comid_triples(&comid.triples, env_colors);
            }
            corim_rs::ConciseTagTypeChoice::Ev(tagged_coev) => {
                println!("    [{}] CoEV (concise-evidence)", i);
                let coev = &tagged_coev.0 .0;
                if let Some(ref triples) = coev.ev_triples.evidence_triples {
                    println!("      Evidence Triples ({}):", triples.len());
                    for (j, triple) in triples.iter().enumerate() {
                        println!("        [{}] Environment:", j);
                        let color = env_colors
                            .get(&env_label(&triple.ref_env))
                            .copied()
                            .unwrap_or("");
                        print_environment(&triple.ref_env, color);
                        println!("            Measurements ({}):", triple.ref_claims.len());
                        for (k, meas) in triple.ref_claims.iter().enumerate() {
                            print_measurement(k, meas);
                        }
                    }
                }
            }
            _ => {
                println!("    [{}] {:?}", i, tag);
            }
        }
    }
}

fn print_comid_triples(triples: &corim_rs::TriplesMap, env_colors: &HashMap<String, &str>) {
    if let Some(ref ref_triples) = triples.reference_triples {
        println!("      Reference Triples ({}):", ref_triples.len());
        for (i, triple) in ref_triples.iter().enumerate() {
            let color = env_colors
                .get(&env_label(&triple.ref_env))
                .copied()
                .unwrap_or("");
            println!("        [{}] Environment:", i);
            print_environment(&triple.ref_env, color);
            println!("            Measurements ({}):", triple.ref_claims.len());
            for (j, meas) in triple.ref_claims.iter().enumerate() {
                print_measurement(j, meas);
            }
        }
    }
    if let Some(ref end_triples) = triples.endorsed_triples {
        println!("      Endorsed Triples ({}):", end_triples.len());
        for (i, triple) in end_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
    if let Some(ref id_triples) = triples.identity_triples {
        println!("      Identity Triples ({}):", id_triples.len());
        for (i, triple) in id_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
    if let Some(ref ak_triples) = triples.attest_key_triples {
        println!("      Attest Key Triples ({}):", ak_triples.len());
        for (i, triple) in ak_triples.iter().enumerate() {
            println!("        [{}] {:?}", i, triple);
        }
    }
}

fn print_measurements(claims: &OcpEatClaims, env_colors: &HashMap<String, &str>) {
    let entries = match claims.decode_measurements() {
        Ok(e) => e,
        Err(e) => {
            println!("    (failed to decode measurements: {})", e);
            return;
        }
    };

    for (idx, entry) in entries.iter().enumerate() {
        println!(
            "    [{}] Content-Type: {} (concise-evidence)",
            idx, entry.content_type
        );
        let coev = &entry.evidence;

        // Evidence ID
        if let Some(ref eid) = coev.evidence_id {
            println!("        Evidence ID:     {:?}", eid);
        }

        // Profile
        if let Some(ref profile) = coev.profile {
            println!("        Profile:         {:?}", profile);
        }

        // Evidence triples
        if let Some(ref triples) = coev.ev_triples.evidence_triples {
            println!("        Evidence Triples ({}):", triples.len());
            for (i, triple) in triples.iter().enumerate() {
                let color = env_colors
                    .get(&env_label(&triple.ref_env))
                    .copied()
                    .unwrap_or("");
                println!("          [{}] Environment:", i);
                print_environment(&triple.ref_env, color);
                println!("              Measurements ({}):", triple.ref_claims.len());
                for (j, meas) in triple.ref_claims.iter().enumerate() {
                    print_measurement(j, meas);
                }
            }
        }

        // Identity triples
        if let Some(ref triples) = coev.ev_triples.identity_triples {
            println!("        Identity Triples ({}):", triples.len());
            for (i, triple) in triples.iter().enumerate() {
                println!("          [{}] {:?}", i, triple);
            }
        }

        // Dependency triples
        if let Some(ref triples) = coev.ev_triples.dependency_triples {
            println!("        Dependency Triples ({}):", triples.len());
            for (i, triple) in triples.iter().enumerate() {
                println!("          [{}] {:?}", i, triple);
            }
        }

        // Membership triples
        if let Some(ref triples) = coev.ev_triples.membership_triples {
            println!("        Membership Triples ({}):", triples.len());
            for (i, triple) in triples.iter().enumerate() {
                println!("          [{}] {:?}", i, triple);
            }
        }
    }
}

fn print_environment(env: &corim_rs::EnvironmentMap, color: &str) {
    if let Some(ref class) = env.class {
        if let Some(ref class_id) = class.class_id {
            if let Some(bytes) = class_id.as_bytes() {
                match std::str::from_utf8(bytes) {
                    Ok(s) => println!("                {}Class ID:  \"{}\"{}", color, s, C_RESET),
                    Err(_) => println!(
                        "                {}Class ID:  {:?}{}",
                        color, class_id, C_RESET
                    ),
                }
            } else {
                println!(
                    "                {}Class ID:  {:?}{}",
                    color, class_id, C_RESET
                );
            }
        }
        if let Some(ref vendor) = class.vendor {
            println!("                {}Vendor:    {}{}", color, vendor, C_RESET);
        }
        if let Some(ref model) = class.model {
            println!("                {}Model:     {}{}", color, model, C_RESET);
        }
        if let Some(ref layer) = class.layer {
            println!("                {}Layer:     {}{}", color, layer, C_RESET);
        }
        if let Some(ref index) = class.index {
            println!("                {}Index:     {}{}", color, index, C_RESET);
        }
    }
    if let Some(ref instance) = env.instance {
        println!(
            "                {}Instance:  {:?}{}",
            color, instance, C_RESET
        );
    }
    if let Some(ref group) = env.group {
        println!("                {}Group:     {:?}{}", color, group, C_RESET);
    }
}

fn print_measurement(idx: usize, meas: &corim_rs::MeasurementMap) {
    if let Some(ref mkey) = meas.mkey {
        println!("                [{}] Key:  {:?}", idx, mkey);
    } else {
        println!("                [{}]", idx);
    }
    let mval = &meas.mval;
    if let Some(ref ver) = mval.version {
        println!("                    Version:  {:?}", ver);
    }
    if let Some(ref svn) = mval.svn {
        println!("                    SVN:      {:?}", svn);
    }
    if let Some(ref digests) = mval.digests {
        println!("                    Digests:");
        for d in digests.iter() {
            println!("                      {:?}: {}", d.alg, hex::encode(&d.val));
        }
    }
    if let Some(ref flags) = mval.flags {
        println!("                    Flags:    {:?}", flags);
    }
    if let Some(ref raw) = mval.raw {
        println!("                    Raw:      {:?}", raw);
    }
}
