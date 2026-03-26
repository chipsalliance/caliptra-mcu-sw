// Licensed under the Apache-2.0 license

//! The `authenticate` subcommand: load the trust anchor store,
//! authenticate the certificate chain, verify the COSE_Sign1 signature,
//! and optionally authenticate signed reference-value CoRIMs.

use clap::Parser;
use std::path::PathBuf;
use std::{env, fs};

use ocptoken::corim::RefValCorims;
use ocptoken::cose_verify::{CoseSign1Verifier, CryptoBackend};
use ocptoken::ta_store::TrustAnchorStore;
use ocptoken::token::evidence::Evidence;

use crate::common::load_evidence;
use crate::display::print_corim_payload;

/// Environment variable for the signed reference-value CoRIM directory path.
const SIGNED_REFVAL_CORIM_PATH: &str = "SIGNED_REFVAL_CORIM_PATH";

#[derive(Parser, Debug)]
pub(crate) struct AuthenticateArgs {
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

/// Load, decode, authenticate, and verify the evidence.
/// Returns the verified `Evidence` and the certificate chain blob.
/// Exits the process on failure.
fn authenticate_evidence<'a>(
    args: &AuthenticateArgs,
    ta_store: &'a dyn TrustAnchorStore,
    verifier: &CoseSign1Verifier<impl CryptoBackend>,
) -> (Evidence<'a>, Vec<u8>) {
    // Load the certificate chain blob (if provided)
    let cert_chain_blob = match &args.cert_chain {
        Some(path) => match fs::read(path) {
            Ok(b) => {
                println!(
                    "Loaded certificate chain '{}' ({} bytes)",
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

    // Load the binary evidence file
    let encoded = load_evidence(&args.evidence);

    // Decode the evidence
    let evidence = match Evidence::decode(&encoded, ta_store) {
        Ok(ev) => {
            println!("Evidence decoded successfully.");
            ev
        }
        Err(e) => {
            eprintln!("Evidence::decode failed: {:?}", e);
            std::process::exit(1);
        }
    };

    // Authenticate the signing key
    println!("Authenticating the Evidence...");
    match evidence.authenticate(&cert_chain_blob) {
        Ok(_) => {
            println!("  Evidence signer certificate chain authentication successful");
        }
        Err(e) => {
            eprintln!("  Evidence::authenticate failed: {:?}", e);
            std::process::exit(1);
        }
    }

    // Verify the COSE_Sign1 signature
    match evidence.verify(&cert_chain_blob, verifier) {
        Ok(()) => {
            println!("  Evidence signature verification successful");
        }
        Err(e) => {
            eprintln!("  Evidence::verify failed: {:?}", e);
            std::process::exit(1);
        }
    }

    (evidence, cert_chain_blob)
}

/// Authenticate and verify signed reference-value CoRIM files from
/// the SIGNED_REFVAL_CORIM_PATH environment variable directory.
/// Returns `None` if the environment variable is not set.
/// Exits the process on failure.
fn authenticate_refval_corims(
    ta_store: &dyn TrustAnchorStore,
    verifier: &CoseSign1Verifier<impl CryptoBackend>,
) -> Option<RefValCorims> {
    let corims_path = match env::var(SIGNED_REFVAL_CORIM_PATH) {
        Ok(p) => p,
        Err(_) => return None,
    };

    let corims_dir = PathBuf::from(corims_path);
    println!("\nAuthenticating Signed CoRIMs ...");
    match RefValCorims::decode_and_verify(&corims_dir, ta_store, verifier) {
        Ok(refval_corims) => {
            for (name, _) in refval_corims.iter() {
                println!("  {}: signer authenticated, signature verified", name);
            }
            println!("All signed CoRIM files verified successfully.");
            Some(refval_corims)
        }
        Err(e) => {
            eprintln!("Signed CoRIM processing failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Result of a full authentication pipeline.
pub(crate) struct AuthenticateResult<'a> {
    pub evidence: Evidence<'a>,
    pub cert_chain_blob: Vec<u8>,
    pub refval_corims: Option<RefValCorims>,
}

/// Run the full authentication pipeline: authenticate evidence and
/// optionally authenticate signed reference-value CoRIMs.
///
/// Returns the authenticated evidence and decoded CoRIM payloads for
/// downstream use (e.g. appraisal).  Exits the process on failure.
pub(crate) fn authenticate<'a>(
    args: &AuthenticateArgs,
    ta_store: &'a dyn TrustAnchorStore,
    verifier: &CoseSign1Verifier<impl CryptoBackend>,
) -> AuthenticateResult<'a> {
    let (evidence, cert_chain_blob) = authenticate_evidence(args, ta_store, verifier);
    let refval_corims = authenticate_refval_corims(ta_store, verifier);
    AuthenticateResult {
        evidence,
        cert_chain_blob,
        refval_corims,
    }
}

/// Authenticate and verify all inputs: load the trust anchor store, authenticate
/// the certificate chain, verify the COSE_Sign1 signature, and optionally
/// authenticate signed reference-value CoRIMs.
pub(crate) fn run(
    args: &AuthenticateArgs,
    ta_store: &dyn TrustAnchorStore,
    verifier: &CoseSign1Verifier<impl CryptoBackend>,
) {
    let result = authenticate(args, ta_store, verifier);

    if let Some(ref refval_corims) = result.refval_corims {
        if !refval_corims.is_empty() {
            println!("\n=== Decoded CoRIM Reference Values ===");
            for (file_name, corim_map) in refval_corims.iter() {
                print_corim_payload(file_name, corim_map);
            }
            println!("======================================\n");
        }
    }

    println!("\nAll verifier inputs authenticated and verified successfully.");
}
