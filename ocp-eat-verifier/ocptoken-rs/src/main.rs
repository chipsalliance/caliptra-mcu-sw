// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use coset::cbor::value::Value;
use coset::Label;
use std::path::PathBuf;
use std::{env, fs};

use ocptoken::cose_verify::{CoseSign1Verifier, DecodedCoseSign1, OpenSslBackend};
use ocptoken::ta_store::FsTrustAnchorStore;
use ocptoken::token::evidence::{Evidence, OCP_EAT_TAGS};

/// Environment variable for the trust anchor store path.
const TA_STORE_PATH_ENV: &str = "OCP_TA_STORE_PATH";

/// COSE header label for x5chain (RFC 9360).
const COSE_HDR_PARAM_X5CHAIN: i64 = 33;

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
    /// Cryptographically verify the COSE_Sign1 signature using the
    /// x5chain leaf certificate from the evidence
    Verify(VerifyArgs),

    /// Authenticate the evidence with the Trust Anchor Store and verify the COSE_Sign1 signature
    Authenticate(AuthenticateArgs),
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
    }
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

    // 3. Extract the leaf certificate from x5chain (label 33)
    let leaf_cert = match extract_x5chain_leaf(decoded.unprotected_header()) {
        Ok(cert) => cert,
        Err(msg) => {
            eprintln!("Failed to extract x5chain leaf: {}", msg);
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

/// Authenticate and verify: load the trust anchor store, authenticate
/// the certificate chain, and verify the COSE_Sign1 signature.
fn run_authenticate(args: &AuthenticateArgs) {
    // 1. Load the Trust Anchor Store from OCP_TA_STORE_PATH
    let ta_store_path = match env::var(TA_STORE_PATH_ENV) {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            eprintln!(
                "Environment variable {} is not set. \
                 Set it to the path of the trust anchor store directory \
                 (containing roots/ and optionally signing-certs/).",
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

fn load_evidence(path: &PathBuf) -> Vec<u8> {
    match fs::read(path) {
        Ok(b) => {
            println!(
                "Loaded evidence file '{}' ({} bytes)",
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

/// Extract the leaf (first) certificate from x5chain (label 33) in
/// a COSE unprotected header.
fn extract_x5chain_leaf(header: &coset::Header) -> Result<Vec<u8>, &'static str> {
    let value = header
        .rest
        .iter()
        .find_map(|(l, v)| {
            if *l == Label::Int(COSE_HDR_PARAM_X5CHAIN) {
                Some(v)
            } else {
                None
            }
        })
        .ok_or("Missing x5chain (label 33) in unprotected header")?;

    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        Value::Array(arr) => arr
            .first()
            .and_then(|v| match v {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or("x5chain array contains no valid certificate"),
        _ => Err("x5chain (label 33) has unexpected CBOR type"),
    }
}
