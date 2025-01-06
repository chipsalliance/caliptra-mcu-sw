// Licensed under the Apache-2.0 license

use crate::{DynError, PROJECT_ROOT};
use std::path::{Path, PathBuf};
use toml::Table;

const IGNORE_DIRS: [&str; 1] = ["libtock"];

pub(crate) fn check() -> Result<(), DynError> {
    let cargo_tomls = find_cargo_tomls(&PROJECT_ROOT)?;
    let mut okay = true;
    for toml_path in cargo_tomls.iter() {
        let data = std::fs::read_to_string(toml_path)?;
        let value = data.parse::<Table>()?;
        if !value.contains_key("dependencies") {
            continue;
        }
        println!("Checking dependencies in {}", toml_path.display());
        let deps = value
            .get("dependencies")
            .unwrap()
            .as_table()
            .expect("Dependencies should be a table");
        for (k, v) in deps.iter() {
            let dep_okay = if v.is_table() {
                let vtable = v.as_table().unwrap();
                if !vtable.contains_key("workspace") {
                    false
                } else {
                    vtable.get("workspace").unwrap().as_bool().unwrap_or(false)
                }
            } else {
                false
            };
            if !dep_okay {
                okay = false;
                println!(
                    "  dependency {} should be {}.workspace = true but was {} = {}",
                    k, k, k, v
                );
            }
        }
    }
    if okay {
        Ok(())
    } else {
        Err("Dependency check failed".into())
    }
}

pub(crate) fn find_cargo_tomls(dir: &Path) -> Result<Vec<PathBuf>, DynError> {
    let mut result = vec![];
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry
            .path()
            .components()
            .any(|c| IGNORE_DIRS.contains(&c.as_os_str().to_str().unwrap()))
        {
            continue;
        }
        if entry.file_name() == "Cargo.toml" {
            result.push(entry.into_path());
        }
    }
    result.sort();
    Ok(result)
}
