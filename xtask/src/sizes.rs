// Licensed under the Apache-2.0 license

//! `cargo xtask sizes` — report binary sizes vs. budgets.
//!
//! Builds the curated set of ROM variants from
//! `caliptra_mcu_builder::features::ROM_VARIANTS`, reads each ELF,
//! extracts the `.text` section size, and prints a table with the
//! available budget and percent used.
//!
//! Future work can add runtime kernel + userspace apps to the same
//! report.

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_builder::features::RomVariant;
use caliptra_mcu_builder::{rom_build, rom_size_for_platform, CaliptraBuildArgs, PROJECT_ROOT};
use std::path::PathBuf;

/// Output format for the size report.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Table,
    Csv,
}

/// Size of the SHA-384 ROM digest that `append_rom_digest` writes into
/// the tail of every ROM binary. Must match `DIGEST_SIZE` in
/// `builder/src/rom.rs`.
const ROM_DIGEST_SIZE: usize = 48;

/// One row in the report — currently always a ROM, but the schema is
/// already shaped so we can mix in runtime/app rows later.
struct Row {
    /// Human-readable variant name shown in the table.
    name: String,
    /// Total `.text` section size in bytes.
    text_bytes: u64,
    /// Maximum allowed size in bytes (after the digest carve-out).
    budget_bytes: u64,
}

/// Locate the ELF artifact for a built ROM variant. Mirrors the
/// naming convention in `caliptra_mcu_builder::rom_build`.
fn rom_elf_path(variant: &RomVariant) -> PathBuf {
    let platform = variant.platform.unwrap_or("emulator");
    // The bundler/cargo build leaves the bare ELF (no `.bin`) at the
    // canonical `mcu-rom-<platform>` name, regardless of the
    // feature-suffixed `.bin` output produced by `rom_build`.
    PROJECT_ROOT
        .join("target")
        .join(caliptra_mcu_builder::TARGET)
        .join("release")
        .join(format!("mcu-rom-{platform}"))
}

/// Extract the size of the `.text` section from a riscv32imc ELF.
fn text_section_size(elf_path: &PathBuf) -> Result<u64> {
    let bytes =
        std::fs::read(elf_path).with_context(|| format!("reading ELF {}", elf_path.display()))?;
    let elf = elf::ElfBytes::<elf::endian::LittleEndian>::minimal_parse(&bytes)
        .with_context(|| format!("parsing ELF {}", elf_path.display()))?;
    let (sections, strings) = elf
        .section_headers_with_strtab()
        .with_context(|| format!("reading section headers from {}", elf_path.display()))?;
    let sections =
        sections.ok_or_else(|| anyhow!("no section headers in {}", elf_path.display()))?;
    let strings =
        strings.ok_or_else(|| anyhow!("no section name string table in {}", elf_path.display()))?;

    for shdr in sections.iter() {
        let name = strings
            .get(shdr.sh_name as usize)
            .map_err(|e| anyhow!("section name parse: {e}"))?;
        if name == ".text" {
            return Ok(shdr.sh_size);
        }
    }
    bail!("no .text section in {}", elf_path.display())
}

/// Build all variants in the supplied list and collect their sizes into
/// rows.
fn collect_rows(variants: &[RomVariant]) -> Result<Vec<Row>> {
    let mut rows = Vec::with_capacity(variants.len());
    for variant in variants {
        let display = variant.display();
        println!("Building {display}...");
        rom_build(&CaliptraBuildArgs {
            platform: variant.platform,
            features: variant.features,
            ..Default::default()
        })
        .with_context(|| format!("building ROM variant {display}"))?;

        let elf = rom_elf_path(variant);
        let text = text_section_size(&elf)?;
        let rom_size = rom_size_for_platform(variant.platform.unwrap_or("emulator")) as u64;
        let budget = rom_size
            .checked_sub(ROM_DIGEST_SIZE as u64)
            .ok_or_else(|| anyhow!("rom_size {rom_size} < digest size"))?;

        rows.push(Row {
            name: display,
            text_bytes: text,
            budget_bytes: budget,
        });
    }
    Ok(rows)
}

/// Render a list of rows as a Unicode box-drawing table.
fn render_table(rows: &[Row]) -> String {
    // Column headers and the rendered values.
    let header = ["Variant", ".text (B)", "Budget (B)", "Used", "Headroom (B)"];
    let rendered: Vec<[String; 5]> = rows
        .iter()
        .map(|r| {
            let used_pct = (r.text_bytes as f64 / r.budget_bytes as f64) * 100.0;
            let headroom = r.budget_bytes as i64 - r.text_bytes as i64;
            [
                r.name.clone(),
                format!("{}", r.text_bytes),
                format!("{}", r.budget_bytes),
                format!("{used_pct:.1}%"),
                format!("{headroom}"),
            ]
        })
        .collect();

    // Column widths = max of header + all cells in that column.
    let mut widths = [0usize; 5];
    for (i, h) in header.iter().enumerate() {
        widths[i] = h.len();
    }
    for cells in &rendered {
        for (i, c) in cells.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    let mut out = String::new();
    let push_sep = |out: &mut String, l: char, m: char, r: char, fill: char| {
        out.push(l);
        for (i, w) in widths.iter().enumerate() {
            for _ in 0..(w + 2) {
                out.push(fill);
            }
            out.push(if i + 1 == widths.len() { r } else { m });
        }
        out.push('\n');
    };
    let push_row = |out: &mut String, cells: &[String; 5], left_align_first: bool| {
        out.push('│');
        for (i, c) in cells.iter().enumerate() {
            let pad = widths[i] - c.chars().count();
            if i == 0 && left_align_first {
                out.push(' ');
                out.push_str(c);
                for _ in 0..pad {
                    out.push(' ');
                }
                out.push(' ');
            } else {
                out.push(' ');
                for _ in 0..pad {
                    out.push(' ');
                }
                out.push_str(c);
                out.push(' ');
            }
            out.push('│');
        }
        out.push('\n');
    };

    push_sep(&mut out, '┌', '┬', '┐', '─');
    let header_cells: [String; 5] = header.map(|s| s.to_string());
    push_row(&mut out, &header_cells, true);
    push_sep(&mut out, '├', '┼', '┤', '─');
    for cells in &rendered {
        push_row(&mut out, cells, true);
    }
    push_sep(&mut out, '└', '┴', '┘', '─');
    out
}

/// Render a list of rows as RFC 4180-style CSV.
fn render_csv(rows: &[Row]) -> String {
    let mut out = String::from("variant,text_bytes,budget_bytes,used_percent,headroom_bytes\n");
    for r in rows {
        let used_pct = (r.text_bytes as f64 / r.budget_bytes as f64) * 100.0;
        let headroom = r.budget_bytes as i64 - r.text_bytes as i64;
        // Quote the variant name in case it contains a comma or quote.
        let escaped = r.name.replace('"', "\"\"");
        out.push_str(&format!(
            "\"{escaped}\",{},{},{:.2},{}\n",
            r.text_bytes, r.budget_bytes, used_pct, headroom
        ));
    }
    out
}

pub(crate) fn run(format: Format, variants: &[RomVariant]) -> Result<()> {
    let rows = collect_rows(variants)?;
    let output = match format {
        Format::Table => render_table(&rows),
        Format::Csv => render_csv(&rows),
    };
    print!("{output}");
    Ok(())
}
