// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::collections::HashSet;
use std::fs;
use std::process::{Command, Stdio};

pub(crate) fn docs() -> Result<()> {
    check_mdbook()?;
    check_mermaid()?;
    println!("Running: mdbook");
    let dir = PROJECT_ROOT.join("docs");
    let dest_dir = PROJECT_ROOT.join("target/book");
    let mut args = vec!["clippy", "--workspace"];
    args.extend(["--", "-D", "warnings", "--no-deps"]);
    let status = Command::new("mdbook")
        .current_dir(&*dir)
        .args(["build", "--dest-dir", dest_dir.to_str().unwrap()])
        .status()?;

    if !status.success() {
        bail!("mdbook failed");
    }
    println!(
        "Docs built successfully: view at {}/book/index.html",
        dest_dir.display()
    );
    Ok(())
}

fn check_mdbook() -> Result<()> {
    let status = Command::new("mdbook")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok() {
        return Ok(());
    }
    println!("mdbook not found; installing...");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["install", "mdbook"])
        .status()?;
    if !status.success() {
        bail!("mdbook installation failed");
    }
    Ok(())
}

fn check_mermaid() -> Result<()> {
    let status = Command::new("mdbook-mermaid")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok() {
        return Ok(());
    }
    println!("mdbook-mermaid not found; installing...");
    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args(["install", "mdbook-mermaid"])
        .status()?;
    if !status.success() {
        bail!("mdbook-mermaid installation failed");
    }
    Ok(())
}

fn is_mdbook_installed() -> bool {
    Command::new("mdbook")
        .args(["--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Extract markdown links from SUMMARY.md (patterns like `](./file.md)` or `](file.md)`)
fn extract_linked_files(content: &str) -> HashSet<String> {
    let mut linked = HashSet::new();
    for line in content.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find("](") {
            rest = &rest[idx + 2..];
            if let Some(end) = rest.find(')') {
                let link = &rest[..end];
                let link = link.strip_prefix("./").unwrap_or(link);
                if link.ends_with(".md") && !link.contains('/') {
                    linked.insert(link.to_string());
                }
                rest = &rest[end + 1..];
            }
        }
    }
    linked
}

/// Extract included files from markdown (patterns like `{{#include file.md}}`)
fn extract_included_files(content: &str) -> HashSet<String> {
    let mut included = HashSet::new();
    for line in content.lines() {
        let mut rest = line;
        while let Some(start) = rest.find("{{#include ") {
            rest = &rest[start + 11..];
            if let Some(end) = rest.find("}}") {
                let file = rest[..end].trim();
                if file.ends_with(".md") && !file.contains('/') {
                    included.insert(file.to_string());
                }
                rest = &rest[end + 2..];
            }
        }
    }
    included
}

/// Check that all markdown documents in docs/src are linked to SUMMARY.md
/// either directly or via an include in another linked document.
/// We also chekc if the docs build if mdbook is installed locally.
pub(crate) fn check_docs() -> Result<()> {
    println!("Checking that all docs are linked in SUMMARY.md...");
    let docs_src = PROJECT_ROOT.join("docs/src");
    let summary_path = docs_src.join("SUMMARY.md");

    // Read SUMMARY.md content
    let summary_content = fs::read_to_string(&summary_path)?;

    // Collect all .md files in docs/src (excluding SUMMARY.md itself)
    let mut all_md_files: HashSet<String> = HashSet::new();
    for entry in fs::read_dir(&docs_src)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "md" {
                    if let Some(name) = path.file_name() {
                        let name = name.to_string_lossy().to_string();
                        if name != "SUMMARY.md" {
                            all_md_files.insert(name);
                        }
                    }
                }
            }
        }
    }

    // Find files linked in SUMMARY.md
    let linked_files = extract_linked_files(&summary_content);

    // Find files included in any markdown file
    let mut included_files: HashSet<String> = HashSet::new();
    for entry in fs::read_dir(&docs_src)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "md") {
            let content = fs::read_to_string(&path)?;
            included_files.extend(extract_included_files(&content));
        }
    }

    // Check that all files are either linked in SUMMARY.md or included somewhere
    let mut missing: Vec<String> = Vec::new();
    for file in &all_md_files {
        if !linked_files.contains(file) && !included_files.contains(file) {
            missing.push(file.clone());
        }
    }

    if !missing.is_empty() {
        missing.sort();
        bail!(
            "The following markdown files are not linked in SUMMARY.md or included in another document:\n  {}",
            missing.join("\n  ")
        );
    }

    println!("All docs are properly linked.");

    // If mdbook is installed, also check that the docs compile
    if is_mdbook_installed() {
        println!("Running: mdbook build (check only)");
        let dir = PROJECT_ROOT.join("docs");
        let dest_dir = PROJECT_ROOT.join("target/book-check");
        let status = Command::new("mdbook")
            .current_dir(&dir)
            .args(["build", "--dest-dir", dest_dir.to_str().unwrap()])
            .status()?;

        if !status.success() {
            bail!("mdbook build failed");
        }
        println!("mdbook build succeeded.");
    } else {
        println!("mdbook not installed; skipping build check.");
    }

    Ok(())
}
