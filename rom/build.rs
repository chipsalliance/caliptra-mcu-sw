// Licensed under the Apache-2.0 license

use std::{path::Path, process::Command};

fn main() {
    let revision = caliptra_mcu_hw_revision::HardwareRevision::from_env()
        .unwrap_or_else(|error| panic!("{error}"));
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let versions = root.join("core/versions.toml");
    println!("cargo:rerun-if-changed={}", versions.display());
    let versions: toml::Table = std::fs::read_to_string(versions)
        .expect("Cannot read core/versions.toml")
        .parse()
        .expect("Invalid core/versions.toml");
    let expected = versions["versions"][revision.as_str()]
        .as_str()
        .expect("Missing Caliptra software pin");
    let core = root.join("core/caliptra-sw");
    assert!(
        core.join(".git").exists(),
        "Initialize core/caliptra-sw first"
    );
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&core)
            .args(args)
            .output()
            .expect("Cannot run git for core/caliptra-sw");
        assert!(
            output.status.success(),
            "Cannot inspect core/caliptra-sw: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("Invalid Git output")
            .trim()
            .to_owned()
    };
    for path in ["HEAD", "refs", "packed-refs"] {
        println!(
            "cargo:rerun-if-changed={}",
            core.join(git(&["rev-parse", "--git-path", path])).display()
        );
    }
    let actual = git(&["rev-parse", "HEAD"]);
    assert_eq!(
        actual, expected,
        "CALIPTRA_HW_REV={revision} requires the matching Caliptra software pin. \
         Run cargo xtask switch-version {revision} before building ROM."
    );
    revision.emit_build_configuration();
}
