// Licensed under the Apache-2.0 license

use crate::string_arena::StringArena;
use core::panic;
use same_file::is_same_file;
use std::{cell::RefCell, path::Path};

#[cfg(test)]
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    path::PathBuf,
};

pub trait FileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str>;
}

#[derive(Default)]
pub struct FsFileSource {
    arena: StringArena,
    patches: RefCell<Vec<(String, String, String)>>,
}

fn trim_lines(s: &str) -> String {
    s.lines().map(|l| l.trim()).collect::<Vec<_>>().join("\n")
}

impl FsFileSource {
    pub fn new() -> Self {
        FsFileSource {
            arena: StringArena::new(),
            patches: RefCell::new(Vec::new()),
        }
    }

    pub fn add_patch(&self, path: &Path, from: &str, to: &str) {
        self.patches.borrow_mut().push((
            path.display().to_string(),
            trim_lines(from),
            trim_lines(to),
        ));
    }
}

impl FileSource for FsFileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str> {
        let mut contents = trim_lines(&std::fs::read_to_string(path)?);
        for (patch_path, from, to) in self.patches.borrow().iter() {
            if is_same_file(path, patch_path).unwrap_or_default() {
                if !contents.contains(from) {
                    panic!("Patch {:?} not found in file: {}", from, path.display());
                }
                let before = contents.clone();
                contents = contents.replace(from, to);
                if before == contents {
                    panic!("Patch {:?} did not change file: {}", from, path.display());
                }
            }
        }
        Ok(self.arena.add(contents))
    }
}

#[cfg(test)]
pub struct MemFileSource {
    arena: crate::string_arena::StringArena,
    map: HashMap<PathBuf, String>,
}
#[cfg(test)]
impl MemFileSource {
    #[allow(unused)]
    pub fn from_entries(entries: &[(PathBuf, String)]) -> Self {
        Self {
            arena: StringArena::new(),
            map: entries.iter().cloned().collect(),
        }
    }
}
#[cfg(test)]
impl FileSource for MemFileSource {
    fn read_to_string(&self, path: &Path) -> std::io::Result<&str> {
        Ok(self.arena.add(
            self.map
                .get(path)
                .ok_or(Error::new(ErrorKind::NotFound, path.to_string_lossy()))?
                .clone(),
        ))
    }
}
