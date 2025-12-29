// Licensed under the Apache-2.0 license

use clap::Parser;
use std::fs;
use std::path::PathBuf;

use ocptoken::token::evidence::Evidence;

#[derive(Parser, Debug)]
#[command(
    name = "ocptoken",
    author,
    version,
    about = "Decode and verify an OCP TOKEN COSE_Sign1 token"
)]
struct Cli {
    /// Path to CBOR-encoded evidence
    #[arg(short = 'e', long = "evidence", value_name = "FILE")]
    evidence: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    // 1. Load the binary file
    let encoded = match fs::read(&cli.evidence) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "Failed to read evidence file '{}': {}",
                cli.evidence.display(),
                e
            );
            std::process::exit(1);
        }
    };

    println!(
        "Loaded evidence file '{}' ({} bytes)",
        cli.evidence.display(),
        encoded.len()
    );

    // 2. Decode the evidence
    match Evidence::decode(&encoded) {
        Ok(_ev) => {
            println!("success decoded");
        }
        Err(e) => {
            eprintln!("Evidence::decode failed: {:?}", e);

            // Optional: show first few bytes to help debugging
            let prefix_len = encoded.len().min(32);
            eprintln!(
                "First {} bytes of input: {:02x?}",
                prefix_len,
                &encoded[..prefix_len]
            );

            std::process::exit(1);
        }
    }
}
