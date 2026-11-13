// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use caliptra_mcu_builder::PROJECT_ROOT;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Deserialize)]
struct Versions {
    versions: BTreeMap<String, String>,
}

const LOCKFILES: [(&str, &str); 2] = [
    ("Cargo.lock", "workspace.lock"),
    ("caliptra-util-host/Cargo.lock", "util-host.lock"),
];

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run git in {}", root.display()))?;
    if !output.status.success() {
        bail!(
            "git {} in {} failed: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn checkout(core: &Path, reference: &str) -> Result<()> {
    // Retired nested submodules otherwise remain as untracked repositories
    // when the selected hardware pin removes them.
    git(core, &["submodule", "deinit", "--all"])?;
    git(core, &["checkout", "--detach", reference])?;
    // Fetches must not visit deinitialized worktrees; update initializes each level.
    git(
        core,
        &[
            "-c",
            "fetch.recurseSubmodules=false",
            "submodule",
            "update",
            "--init",
            "--recursive",
        ],
    )?;
    Ok(())
}

fn check_lockfiles(root: &Path) -> Result<()> {
    for workspace in [root.to_path_buf(), root.join("caliptra-util-host")] {
        if !workspace.join("Cargo.lock").is_file() {
            bail!(
                "Missing reviewed lockfile: {}",
                workspace.join("Cargo.lock").display()
            );
        }
        let status = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(&workspace)
            .args(["metadata", "--locked", "--format-version", "1"])
            .stdout(Stdio::null())
            .status()
            .with_context(|| {
                format!(
                    "Cannot run Cargo metadata validation in {}; install Cargo or set CARGO to its executable",
                    workspace.display()
                )
            })?;
        if !status.success() {
            bail!(
                "The selected source is incompatible with {}. Review the dependency graph \
                 and lockfile snapshots before changing core/versions.toml.",
                workspace.join("Cargo.lock").display()
            );
        }
    }
    Ok(())
}

pub(crate) fn switch_version(version: &str) -> Result<()> {
    switch_at(&PROJECT_ROOT, version)
}

fn switch_at(root: &Path, version: &str) -> Result<()> {
    let config: Versions =
        toml::from_str(&std::fs::read_to_string(root.join("core/versions.toml"))?)?;
    let revision = config
        .versions
        .get(version)
        .with_context(|| format!("Unknown Caliptra software version {version:?}"))?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Version {version:?} must pin a full 40-digit Git commit, not a branch or tag");
    }
    let core = root.join("core/caliptra-sw");
    if !core.join(".git").exists() {
        bail!("Initialize core/caliptra-sw with git submodule update --init --recursive first");
    }
    let lock_path = root.join(git(
        root,
        &["rev-parse", "--git-path", "caliptra-sw-switch.lock"],
    )?);
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.try_lock()
        .context("Another switch-version operation is running")?;

    let changes = git(
        &core,
        &[
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
    )?;
    if !changes.is_empty() {
        bail!(
            "Refusing to switch a dirty core/caliptra-sw checkout (including nested \
             submodules and untracked files). Save your changes first:\n{changes}"
        );
    }
    let previous = git(&core, &["rev-parse", "HEAD"])?;
    let active_version = config.versions.iter()
        .find_map(|(name, sha)| (sha == &previous).then_some(name))
        .context("Current core commit has no recorded version; save your active lockfiles and select a recorded core commit before switching")?;
    let mut lockfiles = Vec::new();
    for (path, snapshot) in LOCKFILES {
        let path = root.join(path);
        let original = std::fs::read(&path)?;
        let active = root.join("core/locks").join(active_version).join(snapshot);
        if original
            != std::fs::read(&active)
                .with_context(|| format!("Cannot read reviewed snapshot {}", active.display()))?
        {
            bail!(
                "Refusing to overwrite modified {}. Save or review your changes against {} first.",
                path.display(),
                active.display()
            );
        }
        let selected = root.join("core/locks").join(version).join(snapshot);
        let selected = std::fs::read(&selected)
            .with_context(|| format!("Cannot read reviewed snapshot {}", selected.display()))?;
        lockfiles.push((path, original, selected));
    }
    let symbolic = Command::new("git")
        .current_dir(&core)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()?;
    let restore = match symbolic.status.code() {
        Some(0) => String::from_utf8(symbolic.stdout)?.trim().to_owned(),
        Some(1) => previous.clone(),
        _ => bail!(
            "Cannot inspect the current Caliptra branch: {}",
            String::from_utf8_lossy(&symbolic.stderr)
        ),
    };
    let present = Command::new("git")
        .current_dir(&core)
        .args(["cat-file", "-e", &format!("{revision}^{{commit}}")])
        .output()?;
    if !present.status.success() {
        // Initialize only the selected commit's submodules after checkout.
        git(
            &core,
            &["fetch", "--no-recurse-submodules", "origin", revision],
        )?;
    }

    println!("Switching core/caliptra-sw to {version} ({revision})");
    let result = (|| {
        checkout(&core, revision)?;
        for (path, _, selected) in &lockfiles {
            std::fs::write(path, selected)?;
        }
        check_lockfiles(root)?;
        for (path, _, selected) in &lockfiles {
            if std::fs::read(path)? != *selected {
                bail!(
                    "Cargo changed reviewed lockfile {} during validation",
                    path.display()
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for (path, original, _) in &lockfiles {
            if let Err(restore) = std::fs::write(path, original) {
                failures.push(format!("Cannot restore {}: {restore}", path.display()));
            }
        }
        // Restore the original branch as well as its commit if it was not detached.
        let rollback = checkout(&core, &restore).and_then(|()| git(&core, &["checkout", &restore]));
        if let Err(rollback) = rollback {
            failures.push(format!("Cannot restore core checkout: {rollback:#}"));
        }
        if !failures.is_empty() {
            bail!(
                "Switch failed: {error:#}\nRollback also failed:\n{}\n\
                 Inspect core/caliptra-sw and both lockfiles before building; the original commit was {previous}.",
                failures.join("\n")
            );
        }
        return Err(error.context(format!(
            "Restored the original Caliptra checkout ({previous})"
        )));
    }
    println!(
        "Caliptra software selected: {version} ({revision}). \
         CALIPTRA_HW_REV is unchanged; run subsequent builds with the intended hardware selector."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        directory: TempDir,
        stable: String,
        latest: String,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let core = root.join("core/caliptra-sw");
            let nested = root.join("nested-source");
            std::fs::create_dir_all(&core).unwrap();
            std::fs::create_dir_all(&nested).unwrap();
            git(root, &["init"]).unwrap();
            git(&core, &["init"]).unwrap();
            git(&nested, &["init"]).unwrap();
            std::fs::write(nested.join("input"), "original\n").unwrap();
            commit(&nested);
            git(
                &core,
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "add",
                    nested.to_str().unwrap(),
                    "nested",
                ],
            )
            .unwrap();
            std::fs::write(
                core.join("Cargo.toml"),
                "[workspace]\n[package]\nname='switch-core'\nversion='0.1.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
            ).unwrap();
            std::fs::write(core.join("lib.rs"), "pub const VERSION: u8 = 1;\n").unwrap();
            commit(&core);
            let stable = git(&core, &["rev-parse", "HEAD"]).unwrap();
            git(
                &core,
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "add",
                    nested.to_str().unwrap(),
                    "latest-only",
                ],
            )
            .unwrap();
            std::fs::write(core.join("lib.rs"), "pub const VERSION: u8 = 2;\n").unwrap();
            let manifest = std::fs::read_to_string(core.join("Cargo.toml")).unwrap();
            std::fs::write(core.join("Cargo.toml"), manifest.replace("0.1.0", "0.2.0")).unwrap();
            commit(&core);
            let latest = git(&core, &["rev-parse", "HEAD"]).unwrap();
            std::fs::write(
                root.join("core/versions.toml"),
                format!("[versions]\n'2.1'='{stable}'\nlatest='{latest}'\n"),
            )
            .unwrap();
            for (workspace, name, dependency) in [
                (root.to_path_buf(), "switch-root", "core/caliptra-sw"),
                (
                    root.join("caliptra-util-host"),
                    "switch-host",
                    "../core/caliptra-sw",
                ),
            ] {
                std::fs::create_dir_all(&workspace).unwrap();
                std::fs::write(
                    workspace.join("Cargo.toml"),
                    format!(
                        "[workspace]\nexclude=['core/caliptra-sw','caliptra-util-host']\n\
                         [package]\nname='{name}'\nversion='0.1.0'\nedition='2021'\n\
                         [lib]\npath='lib.rs'\n[dependencies]\nswitch-core={{path='{dependency}'}}\n"
                    ),
                ).unwrap();
                std::fs::write(workspace.join("lib.rs"), "").unwrap();
            }
            let branch = git(&core, &["symbolic-ref", "--short", "HEAD"]).unwrap();
            for (version, reference) in [("2.1", stable.as_str()), ("latest", branch.as_str())] {
                checkout(&core, reference).unwrap();
                git(&core, &["checkout", reference]).unwrap();
                let snapshots = root.join("core/locks").join(version);
                std::fs::create_dir_all(&snapshots).unwrap();
                for (path, snapshot) in LOCKFILES {
                    let path = root.join(path);
                    assert!(Command::new(env!("CARGO"))
                        .current_dir(path.parent().unwrap())
                        .args(["generate-lockfile", "--offline"])
                        .status()
                        .unwrap()
                        .success());
                    std::fs::copy(&path, snapshots.join(snapshot)).unwrap();
                }
            }
            Self {
                directory,
                stable,
                latest,
            }
        }

        fn root(&self) -> &Path {
            self.directory.path()
        }

        fn core(&self) -> std::path::PathBuf {
            self.root().join("core/caliptra-sw")
        }
    }

    fn commit(root: &Path) {
        git(root, &["add", "-A"]).unwrap();
        git(
            root,
            &[
                "-c",
                "user.name=Switch test",
                "-c",
                "user.email=switch@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "fixture",
            ],
        )
        .unwrap();
    }

    #[test]
    fn switches_both_pins_and_selects_their_reviewed_lockfiles() {
        let fixture = Fixture::new();
        for (version, sha) in [
            ("2.1", &fixture.stable),
            ("latest", &fixture.latest),
            ("2.1", &fixture.stable),
        ] {
            switch_at(fixture.root(), version).unwrap();
            assert_eq!(git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(), *sha);
            assert!(git(&fixture.core(), &["status", "--porcelain"])
                .unwrap()
                .is_empty());
            for (path, snapshot) in LOCKFILES {
                assert_eq!(
                    std::fs::read(fixture.root().join(path)).unwrap(),
                    std::fs::read(
                        fixture
                            .root()
                            .join("core/locks")
                            .join(version)
                            .join(snapshot)
                    )
                    .unwrap()
                );
            }
        }
    }

    #[test]
    fn fetches_missing_nested_pin_without_fetching_deinitialized_descendants() {
        let fixture = Fixture::new();
        let core = fixture.core();
        let nested = fixture.root().join("nested-source");
        let descendant = fixture.root().join("descendant-source");
        std::fs::create_dir(&descendant).unwrap();
        git(&descendant, &["init"]).unwrap();
        std::fs::write(descendant.join("input"), "descendant\n").unwrap();
        commit(&descendant);
        git(
            &nested,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "--depth=1",
                &format!("file://{}", descendant.display()),
                "descendant",
            ],
        )
        .unwrap();
        git(
            &nested,
            &[
                "config",
                "-f",
                ".gitmodules",
                "submodule.descendant.shallow",
                "true",
            ],
        )
        .unwrap();
        commit(&nested);
        let stable = git(&nested, &["rev-parse", "HEAD"]).unwrap();
        std::fs::write(descendant.join("input"), "latest descendant\n").unwrap();
        commit(&descendant);
        let latest_descendant = git(&descendant, &["rev-parse", "HEAD"]).unwrap();
        git(
            &nested.join("descendant"),
            &[
                "fetch",
                "--no-recurse-submodules",
                "origin",
                &latest_descendant,
            ],
        )
        .unwrap();
        git(
            &nested.join("descendant"),
            &["checkout", &latest_descendant],
        )
        .unwrap();
        std::fs::write(nested.join("input"), "latest\n").unwrap();
        commit(&nested);
        git(
            &core,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "--depth=1",
                &format!("file://{}", nested.display()),
                "shallow",
            ],
        )
        .unwrap();
        git(
            &core,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "update",
                "--init",
                "--recursive",
            ],
        )
        .unwrap();
        let shallow = core.join("shallow");
        git(&shallow, &["config", "protocol.file.allow", "always"]).unwrap();
        git(
            &shallow.join("descendant"),
            &["config", "protocol.file.allow", "always"],
        )
        .unwrap();
        git(&shallow, &["config", "fetch.recurseSubmodules", "true"]).unwrap();
        assert!(git(&shallow, &["cat-file", "-e", &stable]).is_err());
        commit(&core);
        let latest = git(&core, &["rev-parse", "HEAD"]).unwrap();
        git(
            &core,
            &[
                "update-index",
                "--cacheinfo",
                &format!("160000,{stable},shallow"),
            ],
        )
        .unwrap();
        git(
            &core,
            &[
                "-c",
                "user.name=Switch test",
                "-c",
                "user.email=switch@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-m",
                "pin older nested commit",
            ],
        )
        .unwrap();
        let selected = git(&core, &["rev-parse", "HEAD"]).unwrap();
        git(&core, &["checkout", &latest]).unwrap();

        checkout(&core, &selected).unwrap();

        assert_eq!(git(&shallow, &["rev-parse", "HEAD"]).unwrap(), stable);
        assert_eq!(
            std::fs::read_to_string(shallow.join("descendant/input")).unwrap(),
            "descendant\n"
        );
        assert!(git(&core, &["status", "--porcelain"]).unwrap().is_empty());
    }

    #[test]
    fn fetches_missing_pin_without_fetching_unselected_submodule_history() {
        let fixture = Fixture::new();
        let remote = fixture.root().join("remote");
        git(
            fixture.root(),
            &[
                "clone",
                "--no-hardlinks",
                "--no-recurse-submodules",
                fixture.core().to_str().unwrap(),
                remote.to_str().unwrap(),
            ],
        )
        .unwrap();
        let nested = git(&fixture.core(), &["rev-parse", "HEAD:nested"]).unwrap();
        for reference in ["1111111111111111111111111111111111111111", &nested] {
            git(
                &remote,
                &[
                    "update-index",
                    "--cacheinfo",
                    &format!("160000,{reference},nested"),
                ],
            )
            .unwrap();
            git(
                &remote,
                &[
                    "-c",
                    "user.name=Switch test",
                    "-c",
                    "user.email=switch@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "change nested reference",
                ],
            )
            .unwrap();
        }
        let target = git(&remote, &["rev-parse", "HEAD"]).unwrap();
        git(
            &fixture.core(),
            &["remote", "add", "origin", remote.to_str().unwrap()],
        )
        .unwrap();
        git(
            &fixture.core(),
            &["config", "protocol.file.allow", "always"],
        )
        .unwrap();
        git(
            &fixture.core(),
            &["config", "fetch.recurseSubmodules", "true"],
        )
        .unwrap();
        switch_at(fixture.root(), "2.1").unwrap();
        std::fs::write(
            fixture.root().join("core/versions.toml"),
            format!(
                "[versions]\n'2.1'='{}'\nlatest='{target}'\n",
                fixture.stable
            ),
        )
        .unwrap();
        switch_at(fixture.root(), "latest").unwrap();
        assert_eq!(
            git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
            target
        );
        assert!(git(&fixture.core(), &["status", "--porcelain"])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rejects_dirty_and_untracked_source_without_touching_it() {
        for file in ["lib.rs", "untracked"] {
            let fixture = Fixture::new();
            std::fs::write(fixture.core().join(file), "local edit\n").unwrap();
            let error = switch_at(fixture.root(), "2.1").unwrap_err().to_string();
            assert!(error.contains("dirty"), "{error}");
            assert_eq!(
                git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
                fixture.latest
            );
            assert_eq!(
                std::fs::read_to_string(fixture.core().join(file)).unwrap(),
                "local edit\n"
            );
        }
    }

    #[test]
    fn rejects_dirty_nested_submodules_even_when_configured_to_ignore_them() {
        let fixture = Fixture::new();
        git(
            &fixture.core(),
            &["config", "submodule.nested.ignore", "all"],
        )
        .unwrap();
        std::fs::write(fixture.core().join("nested/input"), "local edit\n").unwrap();
        let error = switch_at(fixture.root(), "2.1").unwrap_err().to_string();
        assert!(error.contains("dirty"), "{error}");
        assert_eq!(
            git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
            fixture.latest
        );
        assert_eq!(
            std::fs::read_to_string(fixture.core().join("nested/input")).unwrap(),
            "local edit\n"
        );
    }

    #[test]
    fn rejects_unknown_versions_and_floating_refs() {
        let fixture = Fixture::new();
        assert!(switch_at(fixture.root(), "2.2")
            .unwrap_err()
            .to_string()
            .contains("Unknown"));
        std::fs::write(
            fixture.root().join("core/versions.toml"),
            "[versions]\nlatest='main'\n",
        )
        .unwrap();
        assert!(switch_at(fixture.root(), "latest")
            .unwrap_err()
            .to_string()
            .contains("40-digit"));
        assert_eq!(
            git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
            fixture.latest
        );
    }

    #[test]
    fn rolls_back_source_and_branch_when_lock_validation_fails() {
        let fixture = Fixture::new();
        let branch = git(&fixture.core(), &["symbolic-ref", "--short", "HEAD"]).unwrap();
        let lock = std::fs::read(fixture.root().join("Cargo.lock")).unwrap();
        let host_lock =
            std::fs::read(fixture.root().join("caliptra-util-host/Cargo.lock")).unwrap();
        std::fs::write(
            fixture.root().join("core/locks/2.1/util-host.lock"),
            "invalid lockfile\n",
        )
        .unwrap();
        let error = switch_at(fixture.root(), "2.1").unwrap_err();
        assert!(format!("{error:#}").contains("Restored"), "{error:#}");
        assert_eq!(
            git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
            fixture.latest
        );
        assert_eq!(
            git(&fixture.core(), &["symbolic-ref", "--short", "HEAD"]).unwrap(),
            branch
        );
        assert_eq!(
            std::fs::read(fixture.root().join("Cargo.lock")).unwrap(),
            lock
        );
        assert_eq!(
            std::fs::read(fixture.root().join("caliptra-util-host/Cargo.lock")).unwrap(),
            host_lock
        );
    }

    #[test]
    fn refuses_to_overwrite_edited_active_lockfiles() {
        for (path, _) in LOCKFILES {
            let fixture = Fixture::new();
            let original = std::fs::read(fixture.root().join(path)).unwrap();
            let mut modified = original.clone();
            modified.extend_from_slice(b"\n# Local dependency work\n");
            std::fs::write(fixture.root().join(path), &modified).unwrap();
            let error = switch_at(fixture.root(), "2.1").unwrap_err();
            assert!(
                format!("{error:#}").contains("Refusing to overwrite modified"),
                "{error:#}"
            );
            assert_eq!(
                git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
                fixture.latest
            );
            assert_eq!(std::fs::read(fixture.root().join(path)).unwrap(), modified);
        }
    }

    #[test]
    fn serializes_switch_operations() {
        let fixture = Fixture::new();
        let path = fixture.root().join(
            git(
                fixture.root(),
                &["rev-parse", "--git-path", "caliptra-sw-switch.lock"],
            )
            .unwrap(),
        );
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        lock.try_lock().unwrap();
        let error = switch_at(fixture.root(), "2.1").unwrap_err();
        assert!(
            format!("{error:#}").contains("Another switch-version"),
            "{error:#}"
        );
        assert_eq!(
            git(&fixture.core(), &["rev-parse", "HEAD"]).unwrap(),
            fixture.latest
        );
    }
}
