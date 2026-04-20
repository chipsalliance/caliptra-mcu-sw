// Licensed under the Apache-2.0 license

use anyhow::Context;
use bit_vec::BitVec;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hasher;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const MCU_COVERAGE_PATH: &str = "MCU_COVERAGE_PATH";

pub struct CoverageMap {
    pub map: HashMap<u64, BitVec>,
}

impl CoverageMap {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        let mut map = HashMap::<u64, BitVec>::default();
        for path in paths {
            if let Some((tag, bv)) = get_entry_from_path(&path) {
                match map.entry(tag) {
                    Entry::Vacant(e) => {
                        e.insert(bv);
                    }
                    Entry::Occupied(mut e) => {
                        e.get_mut().or(&bv);
                    }
                }
            }
        }
        Self { map }
    }
}

fn get_entry_from_path(path: &PathBuf) -> Option<(u64, BitVec)> {
    let filename = path.file_name().and_then(|val| val.to_str())?;
    let prefix = filename
        .split('-')
        .nth(1)
        .and_then(|val| val.strip_suffix(".bitvec"))?;
    let tag: u64 = prefix.parse().ok()?;
    let bitmap = read_bitvec_from_file(path).ok()?;
    Some((tag, bitmap))
}

pub fn dump_coverage_to_file(
    coverage_path: &str,
    tag: u64,
    bitmap: &BitVec,
) -> std::io::Result<()> {
    let mut filename = format!("CovData{}", hex::encode(rand::random::<[u8; 16]>()));
    filename.push('-');
    filename.push_str(&tag.to_string());
    filename.push_str(".bitvec");

    let path = std::path::Path::new(coverage_path).join(filename);

    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &bitmap)?;
    writer.flush()?;
    Ok(())
}

pub fn get_bitvec_paths(dir: &str) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let paths = std::fs::read_dir(dir)?
        .filter_map(|res| res.ok())
        .map(|dir_entry| dir_entry.path())
        .filter_map(|path| {
            if path.extension().is_some_and(|ext| ext == "bitvec") {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    Ok(paths)
}

pub fn read_bitvec_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<BitVec, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let coverage = serde_json::from_reader(reader)?;
    Ok(coverage)
}

pub fn get_tag_from_image(image: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::hash::Hash::hash_slice(image, &mut hasher);
    hasher.finish()
}

/// Collect all instruction PCs from an ELF's .text section.
pub fn collect_instr_pcs_from_elf(elf_bytes: &[u8]) -> anyhow::Result<(u32, Vec<u32>)> {
    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes)
        .with_context(|| "Failed to parse ELF file")?;

    let section = elf_file
        .section_header_by_name(".text")
        .with_context(|| "Failed to find .text section")?
        .with_context(|| ".text section not found")?;

    let data = elf_file
        .section_data(&section)
        .with_context(|| "Failed to read .text section")?
        .0;

    let load_addr = section.sh_addr as u32;
    let mut index = 0_usize;
    let mut instr_pcs = Vec::<u32>::new();

    while index < data.len() {
        let instruction = u16::from_le_bytes([data[index], data[index + 1]]);
        match instruction & 0b11 {
            0..=2 => {
                index += 2;
            }
            _ => {
                index += 4;
            }
        }
        instr_pcs.push(load_addr + index as u32);
    }
    Ok((load_addr, instr_pcs))
}

/// List functions that have zero coverage.
pub fn uncovered_functions(
    base_addr: usize,
    elf_bytes: &[u8],
    bitmap: &BitVec,
) -> anyhow::Result<Vec<String>> {
    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes)
        .with_context(|| "Failed to parse ELF file")?;

    let (symtab, strtab) = elf_file
        .symbol_table()
        .with_context(|| "Failed to read symbol table")?
        .with_context(|| "No symbol table found")?;

    let mut uncovered = Vec::new();

    for sym in symtab.iter() {
        // STT_FUNC = 2
        if sym.st_symtype() != 2 || sym.st_size == 0 {
            continue;
        }
        let name = strtab.get(sym.st_name as usize).unwrap_or("???");

        let start = sym.st_value as usize;
        let end = start + sym.st_size as usize;

        let any_hit = (start..end).any(|pc| {
            let offset = pc.wrapping_sub(base_addr);
            offset < bitmap.len() && bitmap.get(offset).unwrap_or(false)
        });

        if !any_hit {
            uncovered.push(format!(
                "not covered: (NAME:{})  (start:0x{:x}) (size:{})",
                name, start, sym.st_size
            ));
        }
    }

    Ok(uncovered)
}

pub fn coverage_from_bitmap(base_addr: usize, coverage: &BitVec, instr_pcs: &[u32]) -> (i32, i32) {
    let mut hit = 0;
    for pc in instr_pcs {
        let offset = (*pc as usize).wrapping_sub(base_addr);
        if offset < coverage.len() && coverage[offset] {
            hit += 1;
        }
    }
    (hit, instr_pcs.len() as i32)
}
