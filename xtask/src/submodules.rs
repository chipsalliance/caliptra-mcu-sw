// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use caliptra_mcu_builder::PROJECT_ROOT;
use std::process::Command;

pub(crate) fn check() -> Result<()> {
    println!("Checking git submodules");

    let gitmodules_path = PROJECT_ROOT.join(".gitmodules");
    if !gitmodules_path.exists() {
        return Ok(());
    }

    let output = Command::new("git")
        .current_dir(&*PROJECT_ROOT)
        .args(["submodule", "status", "--recursive"])
        .output();

    let output = match output {
        Ok(out) => out,
        Err(e) => {
            bail!("Failed to execute `git submodule status`: {e}");
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`git submodule status --recursive` failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let uninitialized = parse_uninitialized_submodules(&stdout);

    if !uninitialized.is_empty() {
        eprintln!("Error: The following git submodules are not checked out:");
        for path in &uninitialized {
            eprintln!("  - {path}");
        }
        eprintln!("Please run `git submodule update --init --recursive` to check out submodules.");
        bail!("Git submodules are not checked out. Run `git submodule update --init --recursive` to fix.");
    }

    Ok(())
}

/// Parses the output of `git submodule status` and returns paths of uninitialized submodules (lines starting with '-').
pub(crate) fn parse_uninitialized_submodules(output: &str) -> Vec<String> {
    let mut uninitialized = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('-') {
            // Format is: -<sha> <path>[ (<describe>)]
            let rest = trimmed.strip_prefix('-').unwrap_or(trimmed).trim();
            let mut parts = rest.split_whitespace();
            // Skip the SHA hash
            parts.next();
            if let Some(path) = parts.next() {
                uninitialized.push(path.to_string());
            }
        }
    }
    uninitialized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uninitialized_submodules() {
        let output = "\
-b5718a0f7fe7936b5082a8dfc23add896755af3a hw/caliptra-ss
 c9d45534ab46b447861eba2ac8be2cf435a16763 hw/caliptra-ss/third_party/caliptra-rtl (v2.0.4)
+c6eacc84c4466348950d7a6a449efb913596795c hw/caliptra-ss/third_party/caliptra-rtl/submodules/adams-bridge (v1.0.3)
-db4a6f341145e05a5b7002a21d1cd5cc31147f35 hw/caliptra-ss/third_party/i3c-core
";
        let uninit = parse_uninitialized_submodules(output);
        assert_eq!(
            uninit,
            vec![
                "hw/caliptra-ss".to_string(),
                "hw/caliptra-ss/third_party/i3c-core".to_string(),
            ]
        );
    }

    #[test]
    fn test_parse_all_initialized() {
        let output = "\
 b5718a0f7fe7936b5082a8dfc23add896755af3a hw/caliptra-ss (css-v2.0.2)
 c9d45534ab46b447861eba2ac8be2cf435a16763 hw/caliptra-ss/third_party/caliptra-rtl (v2.0.4)
";
        let uninit = parse_uninitialized_submodules(output);
        assert!(uninit.is_empty());
    }

    #[test]
    fn test_parse_empty() {
        let uninit = parse_uninitialized_submodules("");
        assert!(uninit.is_empty());
    }
}
