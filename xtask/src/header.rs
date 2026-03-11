// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use mcu_builder::PROJECT_ROOT;
use std::{
    fs::File,
    io::{BufRead, BufReader, Error, ErrorKind},
    path::{Path, PathBuf},
};
use walkdir::DirEntry;

const REQUIRED_TEXT: &str = "Licensed under the Apache-2.0 license";
const EXTENSIONS: &[&str] = &[
    "rs", "h", "c", "cpp", "cc", "toml", "sh", "py", "ld", "go", "yml", "yaml", "S", "s",
];
const IGNORED_PATHS: &[&str] = &[
    ".github/dependabot.yml",
    "builder/src/tbf.rs",
    "emulator/app/src/dis.rs",
    "hw/model/src/xi3c/controller.rs",
];
const IGNORED_DIRS: &[&str] = &[
    ".git",
    "caliptra-rtl",
    "caliptra-ss",
    "compliance-test",
    "i3c-core",
    "libtock",
    "lwip",
    "out",
    "target",
];

pub(crate) fn fix() -> Result<()> {
    println!("Running: license header fix");

    let files = find_files(&PROJECT_ROOT, EXTENSIONS, false).unwrap();
    let mut failed = false;
    for file in files.iter() {
        if check_file(file).is_err() {
            println!("Fixing header in {}", remove_root(file));
            fix_file(file).unwrap();
        }
        if let Err(e) = check_file(file) {
            println!("{e}");
            failed = true;
        }
    }
    if failed {
        bail!("License header fix failed; please fix the above files manually.");
    }
    Ok(())
}

pub(crate) fn check() -> Result<()> {
    println!("Running: license header check");
    let files = find_files(&PROJECT_ROOT, EXTENSIONS, false).unwrap();
    let mut failed = false;
    for file in files.iter() {
        if let Err(e) = check_file(file) {
            println!("{e}");
            failed = true;
        }
    }
    if failed {
        bail!("Some files failed to have the correct license header; to fix, run \"cargo xtask header-fix\" from the repo root");
    }
    Ok(())
}

fn remove_root(path: &Path) -> String {
    let root = PROJECT_ROOT.to_str().unwrap().to_owned() + "/";
    let path = path.to_str().unwrap_or_default();
    path.strip_prefix(&root).unwrap_or(path).into()
}

fn add_path_walkdir_error(path: &Path) -> impl Fn(walkdir::Error) -> Error + Copy + '_ {
    move |e: walkdir::Error| {
        let path = remove_root(path);
        match e.io_error() {
            Some(e) => Error::new(e.kind(), format!("{path:?}: {e}")),
            None => Error::new(ErrorKind::Other, format!("{path:?}: {e}")),
        }
    }
}

fn add_path(path: &Path) -> impl Fn(Error) -> Error + Copy + '_ {
    move |e: Error| {
        let path = remove_root(path);
        Error::new(e.kind(), format!("{path:?}: {e}"))
    }
}

fn check_file_contents(path: &Path, contents: impl BufRead) -> Result<(), Error> {
    const N: usize = 3;
    let wrap_err = add_path(path);

    for line in contents.lines().take(N) {
        if line.map_err(wrap_err)?.contains(REQUIRED_TEXT) {
            return Ok(());
        }
    }
    let path = remove_root(path);
    Err(Error::new(
        ErrorKind::Other,
        format!("File {path:?} doesn't contain {REQUIRED_TEXT:?} in the first {N} lines"),
    ))
}

fn check_file(path: &Path) -> Result<(), Error> {
    let wrap_err = add_path(path);
    check_file_contents(path, BufReader::new(File::open(path).map_err(wrap_err)?))
}

fn fix_file(path: &Path) -> Result<(), Error> {
    let wrap_err = add_path(path);

    let mut contents = Vec::from(match path.extension().and_then(|s| s.to_str()) {
        Some("rs" | "h" | "c" | "cpp" | "cc" | "go") => format!("// {REQUIRED_TEXT}\n"),
        Some("toml" | "sh" | "py" | "yaml" | "yml") => format!("# {REQUIRED_TEXT}\n"),
        Some("ld" | "s" | "S") => format!("/* {REQUIRED_TEXT} */\n"),
        other => {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!("Unknown extension {other:?}"),
            ))
        }
    });
    let mut prev_contents = std::fs::read(path).map_err(wrap_err)?;
    if prev_contents.first() != Some(&b'\n') {
        contents.push(b'\n');
    }
    contents.append(&mut prev_contents);
    std::fs::write(path, contents)?;
    Ok(())
}

fn allow(file: &DirEntry) -> bool {
    let file_path = remove_root(file.path());
    if IGNORED_PATHS.contains(&file_path.as_str()) {
        return false;
    }
    let file_type = file.file_type();
    if file_type.is_dir() {
        if let Some(file_name) = file.file_name().to_str() {
            if IGNORED_DIRS.contains(&file_name) {
                return false;
            }
        }
    }
    true
}

pub(crate) fn find_files(
    dir: &Path,
    extensions: &[&str],
    ignore_none: bool,
) -> Result<Vec<PathBuf>, Error> {
    let mut result = vec![];
    let wrap_err = add_path_walkdir_error(dir);
    let walker = walkdir::WalkDir::new(dir).into_iter();
    for file in walker.filter_entry(|f| ignore_none || allow(f)) {
        let file = file.map_err(wrap_err)?;
        let file_path = &file.path();
        let file_type = file.file_type();
        if let Some(Some(extension)) = file.path().extension().map(|s| s.to_str()) {
            if file_type.is_file() && extensions.contains(&extension) {
                result.push(file_path.into());
            }
        }
    }
    result.sort();
    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::header::*;

    #[test]
    fn test_check_success() {
        check_file_contents(
            Path::new("foo/bar.rs"),
            "# Licensed under the Apache-2.0 license".as_bytes(),
        )
        .unwrap();
        check_file_contents(
            Path::new("foo/bar.rs"),
            "/*\n * Licensed under the Apache-2.0 license\n */".as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn test_check_failures() {
        assert_eq!(
            check_file_contents(Path::new("foo/bar.rs"), "int main()\n {\n // foobar\n".as_bytes()).unwrap_err().to_string(),
             "File \"foo/bar.rs\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines");

        assert_eq!(
            check_file_contents(Path::new("bar/foo.sh"), "".as_bytes()).unwrap_err().to_string(),
             "File \"bar/foo.sh\" doesn't contain \"Licensed under the Apache-2.0 license\" in the first 3 lines");

        let err = check_file_contents(Path::new("some/invalid_utf8_file"), [0x80].as_slice())
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("some/invalid_utf8_file"));
    }
}
