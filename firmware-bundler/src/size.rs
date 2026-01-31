// Licensed under the Apache-2.0 license

//! A module to analyze the size of a binary.

use anyhow::{anyhow, Result};
use elf::{endian::AnyEndian, ElfBytes};

use crate::build::{BuildOutput, BuiltBinary};

trait BinarySymbols {
    const INSTRUCTION_START_SYMBOL: &str;
    const INSTRUCTION_END_SYMBOL: &str;
    const DATA_START_SYMBOL: &str;
    const DATA_END_SYMBOL: &str;
}

struct KernelSymbols {}

impl BinarySymbols for KernelSymbols {
    const INSTRUCTION_START_SYMBOL: &str = "_textstart";
    const INSTRUCTION_END_SYMBOL: &str = "_textend";
    const DATA_START_SYMBOL: &str = "_ssram";
    const DATA_END_SYMBOL: &str = "_kernel_ram_done";
}

struct ApplicationSymbols {}

impl BinarySymbols for ApplicationSymbols {
    const INSTRUCTION_START_SYMBOL: &str = "FLASH_START";
    const INSTRUCTION_END_SYMBOL: &str = "_flash_end";
    const DATA_START_SYMBOL: &str = "_sram_origin";
    const DATA_END_SYMBOL: &str = "_sram_end";
}

/// A utility structure containing the parsed results of an Elf.
#[derive(Debug, Default, Clone)]
struct FoundSymbols {
    instruction_start: Option<u64>,
    instruction_end: Option<u64>,
    data_start: Option<u64>,
    data_end: Option<u64>,
}

/// The size of a binary.
#[derive(Debug, Clone)]
pub struct BinarySize {
    pub name: String,
    pub instructions: u64,
    pub data: u64,
}

/// The output from doing a sizing pass.
#[derive(Debug, Clone)]
pub struct SizeOutput {
    pub kernel: BinarySize,
    pub apps: Vec<BinarySize>,
}

/// Determine the sizes of the runtime applications. This could fail if the required symbols are not
/// located within the elf.
pub fn sizes(build: &BuildOutput) -> Result<SizeOutput> {
    let kernel = binary_size::<KernelSymbols>(&build.kernel.0)?;

    let apps = build
        .apps
        .iter()
        .map(|app| binary_size::<ApplicationSymbols>(&app.binary))
        .collect::<Result<Vec<_>>>()?;

    Ok(SizeOutput { kernel, apps })
}

/// Determine the instruction and data sizes of an application.
fn binary_size<B: BinarySymbols>(build: &BuiltBinary) -> Result<BinarySize> {
    let elf_bytes = std::fs::read(&build.elf)?;
    let elf_file = ElfBytes::<AnyEndian>::minimal_parse(&elf_bytes)?;

    let mut found_symbols = FoundSymbols::default();
    let (symbols, strings) = elf_file
        .symbol_table()?
        .ok_or_else(|| anyhow!("Elf {} does not contain symbol table", build.elf.display()))?;
    symbols.iter().for_each(|symbol| {
        let name = strings.get(symbol.st_name as usize);

        match name {
            Ok(n) if n == B::INSTRUCTION_START_SYMBOL => {
                found_symbols.instruction_start = Some(symbol.st_value)
            }
            Ok(n) if n == B::INSTRUCTION_END_SYMBOL => {
                found_symbols.instruction_end = Some(symbol.st_value)
            }
            Ok(n) if n == B::DATA_START_SYMBOL => found_symbols.data_start = Some(symbol.st_value),
            Ok(n) if n == B::DATA_END_SYMBOL => found_symbols.data_end = Some(symbol.st_value),
            _ => { /* no op */ }
        }
    });

    let instruction_start = found_symbols.instruction_start.ok_or_else(|| {
        anyhow!(
            "Instruction start symbol ({}) not defined for {}",
            B::INSTRUCTION_START_SYMBOL,
            &build.name
        )
    })?;
    let instruction_end = found_symbols.instruction_end.ok_or_else(|| {
        anyhow!(
            "Instruction end symbol ({}) not defined for {}",
            B::INSTRUCTION_END_SYMBOL,
            &build.name
        )
    })?;
    let data_start = found_symbols.data_start.ok_or_else(|| {
        anyhow!(
            "Data start symbol ({}) not defined for {}",
            B::DATA_START_SYMBOL,
            &build.name
        )
    })?;
    let data_end = found_symbols.data_end.ok_or_else(|| {
        anyhow!(
            "Data end symbol ({}) not defined for {}",
            B::DATA_END_SYMBOL,
            &build.name
        )
    })?;

    Ok(BinarySize {
        name: build.name.clone(),
        instructions: instruction_end - instruction_start,
        data: data_end - data_start,
    })
}
