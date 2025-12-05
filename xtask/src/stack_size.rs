// Licensed under the Apache-2.0 license

use anyhow::Result;
use object::{Object, ObjectSymbol, SymbolKind};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub(crate) fn analyze_stack_size(elf_path: &PathBuf) -> Result<()> {
    // 2. Read the ELF file
    let data = fs::read(elf_path)?;
    let obj = object::File::parse(&data[..])?;

    // 3. Build address-to-name map from symbol table
    let mut addr_to_name: HashMap<u64, String> = HashMap::new();
    for symbol in obj.symbols() {
        if symbol.kind() == SymbolKind::Text {
            if let Ok(name) = symbol.name() {
                addr_to_name.insert(symbol.address(), name.to_string());
            }
        }
    }

    // 4. Parse .stack_sizes section
    let stack_sizes = stack_sizes::analyze_executable(&data)?;

    // 5. Combine and output results
    let mut results: Vec<(String, u64)> = stack_sizes
        .defined
        .iter()
        .map(|(address, function)| {
            let name = addr_to_name
                .get(address)
                .cloned()
                .unwrap_or_else(|| format!("0x{:x}", address));

            // Demangle the function name
            let demangled = rustc_demangle::demangle(&name).to_string();

            (demangled, function.size())
        })
        .collect();

    // Sort by stack size (ascending)
    results.sort_by(|a, b| a.1.cmp(&b.1));

    // Print results
    println!("{:<60} {:>10}", "Function", "Stack (bytes)");
    println!("{}", "-".repeat(72));
    for (name, size) in &results {
        println!("{:<60} {:>10}", name, size);
    }

    Ok(())
}
