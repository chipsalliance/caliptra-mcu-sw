// Licensed under the Apache-2.0 license

//! The `authenticate` subcommand: load the trust anchor store,
//! authenticate the certificate chain, and verify the COSE_Sign1 signature.

use clap::Parser;
use std::path::PathBuf;
use std::{env, fs};

use ocptoken::cose_verify::{CoseSign1Verifier, OpenSslBackend};
use ocptoken::ta_store::FsTrustAnchorStore;
use ocptoken::token::evidence::Evidence;

use crate::common::load_evidence;

/// Environment variable for the trust anchor store path.
const TA_STORE_PATH_ENV: &str = "OCP_TA_STORE_PATH";

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

/// Authenticate and verify: load the trust anchor store, authenticate
/// the certificate chain, and verify the COSE_Sign1 signature.
pub(crate) fn run(args: &AuthenticateArgs) {
    // 1. Load the Trust Anchor Store from OCP_TA_STORE_PATH
    let ta_store_path = match env::var(TA_STORE_PATH_ENV) {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!(
                "Environment variable {} is not set. \
                 Set it to the path of the trust anchor store directory \
                 (containing roots/ and optionally endorsement-certs/).",
                TA_STORE_PATH_ENV
            );
            std::process::exit(1);
        }
    };

    let ta_store = match FsTrustAnchorStore::load(&ta_store_path) {
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
    };

    // 2. Load the certificate chain blob (if provided)
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

    // 3. Load the binary evidence file
    let encoded = load_evidence(&args.evidence);

    // 4. Decode the evidence
    let ev = match Evidence::decode(&encoded, &ta_store) {
        Ok(ev) => {
            println!("Decode successful");
            ev
        }
        Err(e) => {
            eprintln!("Evidence::decode failed: {:?}", e);
            std::process::exit(1);
        }
    };

    // 5. Authenticate the signing key
    match ev.authenticate(&cert_chain_blob) {
        Ok(_) => {
            println!("Certificate chain authentication successful");
        }
        Err(e) => {
            eprintln!("Evidence::authenticate failed: {:?}", e);
            std::process::exit(1);
        }
    }

    // 6. Verify the COSE_Sign1 signature
    let verifier = CoseSign1Verifier::new(OpenSslBackend);
    match ev.verify(&cert_chain_blob, &verifier) {
        Ok(()) => {
            println!("Signature verification successful");
        }
        Err(e) => {
            eprintln!("Evidence::verify failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
