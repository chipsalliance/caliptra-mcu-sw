// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use ocptoken::token::evidence::Evidence;

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
    /// Cryptographically verify the supplied OCP token using the EAT attestation key
    Verify(VerifyArgs),
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Cryptographically verify the supplied OCP token using the EAT attestation key"
)]
struct VerifyArgs {
    #[arg(
        short = 'e',
        long = "evidence",
        value_name = "EVIDENCE",
        default_value = "ocp_eat.cbor"
    )]
    evidence: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify(args) => run_verify(&args),
    }
}

fn run_verify(args: &VerifyArgs) {
    // 1. Load the binary file
    let encoded = match fs::read(&args.evidence) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "Failed to read evidence file '{}': {}",
                args.evidence.display(),
                e
            );
            std::process::exit(1);
        }
    };

    println!(
        "Loaded evidence file '{}' ({} bytes)",
        args.evidence.display(),
        encoded.len()
    );

    // 2. Decode the evidence
    let ev = match Evidence::decode(&encoded) {
        Ok(ev) => {
            println!("Decode successful");
            ev
        }
        Err(e) => {
            eprintln!("Evidence::decode failed: {:?}", e);

            // Optional debug dump
            let prefix_len = encoded.len().min(32);
            eprintln!(
                "First {} bytes of input: {:02x?}",
                prefix_len,
                &encoded[..prefix_len]
            );

            std::process::exit(1);
        }
    };

    // 3. Cryptographically verify
    match ev.verify() {
        Ok(()) => {
            println!("Signature verification successful");
        }
        Err(e) => {
            eprintln!("Evidence::verify failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
