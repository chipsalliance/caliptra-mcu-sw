// Licensed under the Apache-2.0 license

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;

mod build;
mod clean;
mod test;

#[derive(Parser)]
#[command(
    name = "xtask",
    version,
    about = "Command-line toolkit for caliptra-util-host library",
    long_about = "A comprehensive toolkit for building, testing, and maintaining the caliptra-util-host library and its components."
)]
struct Xtask {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the caliptra-util-host library and its components
    Build {
        /// Build in release mode
        #[arg(short, long)]
        release: bool,
        /// Build specific package(s)
        #[arg(short, long)]
        package: Vec<String>,
        /// Build all workspace packages
        #[arg(long)]
        all: bool,
    },

    /// Run tests for the caliptra-util-host library
    Test {
        /// Run tests in release mode
        #[arg(short, long)]
        release: bool,
        /// Run specific test package(s)
        #[arg(short, long)]
        package: Vec<String>,
        /// Run all workspace tests
        #[arg(long)]
        all: bool,
        /// Run Rust integration tests only
        #[arg(long)]
        rust_only: bool,
        /// Run C binding tests only
        #[arg(long)]
        c_only: bool,
    },

    /// Clean build artifacts
    Clean {
        /// Clean target directory
        #[arg(long)]
        target: bool,
        /// Clean C test artifacts
        #[arg(long)]
        c_tests: bool,
        /// Clean all artifacts
        #[arg(long)]
        all: bool,
    },

    /// Format code
    Fmt {
        /// Check formatting without applying changes
        #[arg(long)]
        check: bool,
    },

    /// Run clippy lints
    Clippy {
        /// Fix issues automatically where possible
        #[arg(long)]
        fix: bool,
        /// Fail on warnings
        #[arg(long)]
        deny_warnings: bool,
    },

    /// Generate C bindings
    Cbindings {
        /// Force regeneration even if up-to-date
        #[arg(short, long)]
        force: bool,
    },

    /// Run comprehensive checks (build, test, format, clippy)
    Check {
        /// Skip time-consuming tests
        #[arg(long)]
        quick: bool,
    },

    /// Run pre-check-in checks (format, clippy, build)
    Precheckin,

    /// Run the mailbox server
    Server {
        /// Server address to bind to
        #[arg(short, long, default_value = "127.0.0.1:62222")]
        address: String,
        /// Path to TOML configuration file with device parameters
        #[arg(short, long)]
        config: Option<String>,
        /// Build in release mode before running
        #[arg(short, long)]
        release: bool,
    },

    /// Run the mailbox client validator
    Validator {
        /// Server address to connect to
        #[arg(short, long, default_value = "127.0.0.1:62222")]
        server: String,
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Path to TOML configuration file with test parameters
        #[arg(short, long)]
        config: Option<String>,
        /// Build in release mode before running
        #[arg(short, long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let args = Xtask::parse();

    println!("xtask caliptra-util-host toolkit");

    match args.command {
        Commands::Build {
            release,
            package,
            all,
        } => build::run(release, package, all),
        Commands::Test {
            release,
            package,
            all,
            rust_only,
            c_only,
        } => test::run(release, package, all, rust_only, c_only),
        Commands::Clean {
            target,
            c_tests,
            all,
        } => clean::run(target, c_tests, all),
        Commands::Fmt { check } => run_fmt(check),
        Commands::Clippy { fix, deny_warnings } => run_clippy(fix, deny_warnings),
        Commands::Cbindings { force } => run_cbindings(force),
        Commands::Check { quick } => run_check(quick),
        Commands::Precheckin => run_precheckin(),
        Commands::Server {
            address,
            config,
            release,
        } => run_server(address, config, release),
        Commands::Validator {
            server,
            verbose,
            config,
            release,
        } => run_validator(server, verbose, config, release),
    }
}

pub fn run_command(name: &str, cmd: &mut Command) -> Result<()> {
    println!("Running: {}", name);

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute command: {}", name))?;

    if status.success() {
        println!("✓ {}", name);
        Ok(())
    } else {
        anyhow::bail!("Command failed: {}", name);
    }
}

pub fn run_command_with_output(name: &str, cmd: &mut Command) -> Result<String> {
    println!("Running: {}", name);

    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute command: {}", name))?;

    if output.status.success() {
        println!("✓ {}", name);
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("✗ {}", name);
        println!("{}", stderr);
        anyhow::bail!("Command failed: {}", name);
    }
}

fn run_fmt(check: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("fmt");

    if check {
        cmd.arg("--check");
    }

    run_command("cargo fmt", &mut cmd)
}

fn run_clippy(fix: bool, deny_warnings: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["clippy", "--workspace", "--all-targets", "--all-features"]);

    if fix {
        cmd.arg("--fix");
    }

    if deny_warnings {
        cmd.args(["--", "-D", "warnings"]);
    }

    run_command("cargo clippy", &mut cmd)
}

fn run_cbindings(force: bool) -> Result<()> {
    println!("Generating C bindings");

    let cbinding_dir = PathBuf::from("cbinding");
    if !cbinding_dir.exists() {
        anyhow::bail!("C binding directory not found: {}", cbinding_dir.display());
    }

    let header_path = cbinding_dir.join("include/caliptra_util_host.h");

    // Check if regeneration is needed
    if !force && header_path.exists() {
        let cargo_toml = cbinding_dir.join("Cargo.toml");
        let cargo_time = std::fs::metadata(&cargo_toml)?.modified()?;
        let header_time = std::fs::metadata(&header_path)?.modified()?;

        if header_time > cargo_time {
            println!("✓ C bindings are up-to-date");
            return Ok(());
        }
    }

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "caliptra-util-host-cbinding"]);

    run_command("cargo build cbinding", &mut cmd)?;

    println!("✓ Generated C bindings at {}", header_path.display());

    Ok(())
}

fn run_check(quick: bool) -> Result<()> {
    println!("Starting comprehensive check");

    // Format check
    run_fmt(true)?;

    // Clippy check
    run_clippy(false, true)?;

    // Build check
    build::run(false, vec![], true)?;

    // Test check
    if quick {
        println!("ℹ Skipping tests (quick mode)");
    } else {
        test::run(false, vec![], true, false, false)?;
    }

    println!("✓ All checks passed!");
    Ok(())
}

fn run_precheckin() -> Result<()> {
    println!("Starting pre-check-in checks");

    // Format check
    run_fmt(true)?;

    // Clippy check with denied warnings
    run_clippy(false, true)?;

    // Build check
    build::run(false, vec![], true)?;

    println!("✓ Pre-check-in passed!");
    Ok(())
}

fn run_server(address: String, config: Option<String>, release: bool) -> Result<()> {
    println!("Starting Mailbox server on {}", address);

    // Build the server first
    println!("ℹ Building mailbox server...");
    let mut build_cmd = Command::new("cargo");
    build_cmd.args(["build", "-p", "caliptra-mailbox-server"]);

    if release {
        build_cmd.arg("--release");
    }

    run_command("cargo build server", &mut build_cmd)?;

    // Run the server
    let target_dir = if release { "release" } else { "debug" };
    let mut cmd = Command::new(format!(
        "../target/caliptra-util-host/{}/caliptra-mailbox-server",
        target_dir
    ));
    cmd.args(["--server", &address]);

    if let Some(config_path) = config {
        // Make config path absolute or relative to current working directory (caliptra-util-host)
        let full_config_path = if config_path.starts_with('/') {
            config_path
        } else {
            std::env::current_dir()
                .unwrap()
                .join(&config_path)
                .to_string_lossy()
                .to_string()
        };
        cmd.args(["--config", &full_config_path]);
    }

    println!("✓ Server starting on {} (Press Ctrl+C to stop)", address);

    let status = cmd
        .status()
        .with_context(|| "Failed to start mailbox server")?;

    if !status.success() {
        anyhow::bail!("Server exited with error");
    }

    Ok(())
}

fn run_validator(
    server: String,
    verbose: bool,
    config: Option<String>,
    release: bool,
) -> Result<()> {
    println!("Starting Mailbox validator (connecting to {})", server);

    // Build the validator first
    println!("ℹ Building mailbox validator...");
    let mut build_cmd = Command::new("cargo");
    build_cmd.args(["build", "-p", "caliptra-mailbox-client"]);

    if release {
        build_cmd.arg("--release");
    }

    run_command("cargo build validator", &mut build_cmd)?;

    // Run the validator
    let target_dir = if release { "release" } else { "debug" };
    let mut cmd = Command::new(format!(
        "../target/caliptra-util-host/{}/validator",
        target_dir
    ));
    cmd.args(["--server", &server]);

    if verbose {
        cmd.arg("--verbose");
    }

    if let Some(config_path) = config {
        // Make config path absolute or relative to current working directory (caliptra-util-host)
        let full_config_path = if config_path.starts_with('/') {
            config_path
        } else {
            std::env::current_dir()
                .unwrap()
                .join(&config_path)
                .to_string_lossy()
                .to_string()
        };
        cmd.args(["--config", &full_config_path]);
    }

    run_command("mailbox validator", &mut cmd)
}
