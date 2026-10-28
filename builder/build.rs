// Licensed under the Apache-2.0 license

use std::{path::Path, process::Command};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/caliptra-sw");
    assert!(
        root.join(".git").exists(),
        "Initialize core/caliptra-sw with git submodule update --init --recursive"
    );
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&root)
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
    for name in ["HEAD", "refs", "packed-refs"] {
        let path = root.join(git(&["rev-parse", "--git-path", name]));
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed={}", root.join(".git").display());
    println!(
        "cargo:rustc-env=CALIPTRA_SW_REVISION={}",
        git(&["rev-parse", "HEAD"])
    );
}
