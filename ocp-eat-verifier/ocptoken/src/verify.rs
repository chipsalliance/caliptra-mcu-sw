// Licensed under the Apache-2.0 license

//! The `verify` subcommand: decode the EAT, extract the x5chain leaf,
//! and cryptographically verify the COSE_Sign1 signature.

use clap::Parser;
use std::path::PathBuf;

use ocptoken::cose_verify::{CoseSign1Verifier, CryptoBackend, DecodedCoseSign1};
use ocptoken::token::evidence::OCP_EAT_TAGS;

use crate::common::{extract_x5chain_leaf, load_evidence};

#[derive(Parser, Debug)]
pub(crate) struct VerifyArgs {
    #[arg(
        short = 'e',
        long = "evidence",
        value_name = "EVIDENCE",
        default_value = "ocp_eat.cbor"
    )]
    evidence: PathBuf,
}

/// Verify only: decode the EAT, extract the x5chain leaf, and
/// cryptographically verify the COSE_Sign1 signature.
pub(crate) fn run(args: &VerifyArgs, verifier: &CoseSign1Verifier<impl CryptoBackend>) {
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

    // 3. Extract the leaf certificate from x5chain (label 33)
    let leaf_cert = match extract_x5chain_leaf(decoded.unprotected_header()) {
        Ok(cert) => cert,
        Err(msg) => {
            eprintln!("Failed to extract x5chain leaf: {}", msg);
            std::process::exit(1);
        }
    };

    // 4. Verify the COSE_Sign1 signature
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
