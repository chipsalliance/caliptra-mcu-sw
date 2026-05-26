// Licensed under the Apache-2.0 license

//! The `verify` subcommand: decode the EAT, extract the signing key
//! (from x5chain or cert-chain for kid-based tokens), and
//! cryptographically verify the COSE_Sign1 signature.

use clap::Parser;
use std::path::PathBuf;

use ocptoken::cose_verify::{CoseSign1Verifier, CryptoBackend, DecodedCoseSign1};
use ocptoken::token::evidence::OCP_EAT_TAGS;

use crate::common::{extract_signing_leaf, load_evidence};

#[derive(Parser, Debug)]
pub(crate) struct VerifyArgs {
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

Required for kid-based tokens where the signing certificate \
is not embedded in the token via x5chain."
    )]
    cert_chain: Option<PathBuf>,
}

/// Verify only: decode the EAT, extract the signing key, and
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

    // 3. Load optional cert chain
    let cert_chain_blob = args.cert_chain.as_ref().map(|path| {
        match std::fs::read(path) {
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
        }
    });

    // 4. Extract the leaf certificate (x5chain or cert-chain for kid)
    let leaf_cert = match extract_signing_leaf(&decoded, cert_chain_blob.as_deref()) {
        Ok(cert) => cert,
        Err(msg) => {
            eprintln!("Failed to extract signing leaf: {}", msg);
            std::process::exit(1);
        }
    };

    // 5. Verify the COSE_Sign1 signature
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
