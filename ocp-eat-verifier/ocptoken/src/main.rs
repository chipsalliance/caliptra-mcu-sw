// Licensed under the Apache-2.0 license

mod authenticate;
mod common;
mod verify;

use clap::{Parser, Subcommand};

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
    Verify(verify::VerifyArgs),

    /// Authenticate the evidence with the Trust Anchor Store and verify the COSE_Sign1 signature
    Authenticate(authenticate::AuthenticateArgs),
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify(args) => verify::run(&args),
        Commands::Authenticate(args) => authenticate::run(&args),
    }
}
