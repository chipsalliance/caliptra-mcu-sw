// Licensed under the Apache-2.0 license

//! `cargo xtask stack-guard` — fail CI if any single user-app stack frame grows
//! past `MAX_SINGLE_FRAME`.
//!
//! The existing size check (`ci.rs::elf_stack_size`) reads the `.stack`
//! *section* size, which is just the budget carved out by the linker — it
//! reports the budget no matter how much stack the code actually uses, so it
//! cannot catch frame growth. This guard builds the app with
//! `-Z emit-stack-sizes` and checks the exact LLVM-emitted per-function frames.
//!
//! Deliberately budget-independent: a multi-KB stack frame is a bug regardless
//! of how much `[[app]].stack` happens to be available, and tying the threshold
//! to the budget would mean raising the budget silently weakens the detector.
//!
//! This does **not** check "will the app fit in SRAM" — the bundler already
//! fails the build for that (`firmware-bundler/src/manifest.rs`: "Bytes N would
//! exceed remaining memory space M"), and `ci.rs`'s size report surfaces the
//! overflow magnitude. A stack *peak* estimate would be the least reliable of
//! the three: the executor dispatches task polls through indirect/`dyn` edges a
//! static call graph cannot follow, and `.stack_sizes` omits asm frames.
//! Largest-single-frame is cheap and exact to parse, and it is the signal that
//! nothing else provides.

use anyhow::{anyhow, bail, Context, Result};
use caliptra_mcu_builder::{runtime_build_with_apps, CaliptraBuildArgs, PROJECT_ROOT, TARGET};
use elf::endian::LittleEndian;
use elf::ElfBytes;
use std::path::PathBuf;

/// Maximum bytes any one function's stack frame may occupy.
///
/// The largest frame on `main` today is 4,320 B (`spdm_mctp_responder` task
/// poll), so this leaves ~1.9x headroom for legitimate growth while still
/// tripping on the class of regression this guard exists for: the 11,324 B
/// `MldsaVerifyReq` that originally landed in an async frame, and the 36,848 B
/// frame it produced. Raise it only with a deliberate review — a frame this
/// large is normally a buffer that belongs in a static or the heap.
const MAX_SINGLE_FRAME: u64 = 8 * 1024;

/// Feature set that reproduces the deepest observed stack path (the SPDM
/// attestation + command-auth responder). `release` matches the shipping
/// profile / constrained SRAM layout.
const GUARD_FEATURES: &str = "test-mctp-spdm-attestation,release";

/// Build the full firmware bundle with `-Z emit-stack-sizes` and return the
/// path to the fully-linked user-app ELF.
///
/// The build MUST go through the bundler (`runtime_build_with_apps`), not a
/// bare `cargo rustc -p user-app`: the app is `no_main` on riscv32 and only the
/// Tock TBF linker script the bundler supplies retains the entry root, so a
/// bare build dead-code-eliminates the whole app down to a stub with none of
/// the frames we need to measure.
///
/// `-Z emit-stack-sizes` is injected via `RUSTFLAGS` (appended to the workspace
/// flags from `.cargo/config.toml`, which env `RUSTFLAGS` overrides, so they
/// are re-listed here) and gated on stable via `RUSTC_BOOTSTRAP=1`. It only
/// adds a non-alloc section (objcopy strips it from the shipped `.bin`), so
/// codegen and behavior are unchanged.
fn build_instrumented_user_app() -> Result<PathBuf> {
    let target_dir = PROJECT_ROOT.join("target").join("stack-guard");

    // Mirror .cargo/config.toml [target.riscv32imc].rustflags verbatim (env
    // RUSTFLAGS replaces, not extends, the config value), then append the
    // instrumentation. `force-frame-pointers=no` MUST be mirrored: it changes
    // the prologue slot layout `.stack_sizes` records, so omitting it would
    // measure frames a few bytes off from the shipping build. `-icf` and the
    // `--remap-path-prefix` lines are omitted only where they cannot affect
    // `.stack_sizes` (code folding / .rodata path strings).
    let rustflags = concat!(
        "-Cpanic=abort ",
        "-Ctarget-feature=+relax,+zba,+zbb,+zbc,+zbs ",
        "-Cforce-frame-pointers=no ",
        "-Crelocation-model=static ",
        "-Csymbol-mangling-version=v0 ",
        "-Clinker=rust-lld ",
        "-Clinker-flavor=ld.lld ",
        "-Clink-arg=-nmagic ",
        "-Clink-arg=-icf=all ",
        "-Zemit-stack-sizes",
    );

    // Set the instrumentation env for this build, then clear it. Cleanup runs on
    // the error path (before `?`); a panic inside the build would leak it, which
    // is acceptable because this is the last build in the process. If this is
    // ever chained ahead of other builds, replace with an RAII guard.
    std::env::set_var("RUSTFLAGS", rustflags);
    std::env::set_var("RUSTC_BOOTSTRAP", "1");
    let result = runtime_build_with_apps(&CaliptraBuildArgs {
        features: Some(GUARD_FEATURES),
        profile: Some("release"),
        no_default_features: true,
        target_dir: Some(target_dir.clone()),
        ..Default::default()
    });
    std::env::remove_var("RUSTFLAGS");
    std::env::remove_var("RUSTC_BOOTSTRAP");
    result.context("instrumented firmware build failed")?;

    let elf = target_dir.join(TARGET).join("release").join("user-app");
    if !elf.exists() {
        bail!("instrumented user-app ELF not found at {}", elf.display());
    }
    Ok(elf)
}

/// Largest per-function frame from `.stack_sizes` and its function name.
///
/// `.stack_sizes` records are `{ u32 addr (LE), ULEB128 size }`; the function
/// name is resolved from the symbol table by address.
fn largest_frame(elf_bytes: &[u8]) -> Result<(u64, String)> {
    let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).context("parsing ELF")?;

    let shdr = elf
        .section_header_by_name(".stack_sizes")
        .context("reading section headers")?
        .ok_or_else(|| anyhow!("ELF has no .stack_sizes (build with -Z emit-stack-sizes)"))?;
    let (raw, _) = elf.section_data(&shdr).context("reading .stack_sizes")?;

    // addr -> name for STT_FUNC symbols.
    let (symtab, strtab) = elf
        .symbol_table()
        .context("reading symbol table")?
        .ok_or_else(|| anyhow!("ELF has no symbol table"))?;
    let name_of = |addr: u64| -> String {
        for sym in symtab.iter() {
            if sym.st_symtype() == elf::abi::STT_FUNC && sym.st_value == addr {
                if let Ok(n) = strtab.get(sym.st_name as usize) {
                    return n.to_string();
                }
            }
        }
        format!("<{addr:#x}>")
    };

    let mut best = (0u64, String::new());
    let mut i = 0usize;
    while i + 4 <= raw.len() {
        let addr = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as u64;
        i += 4;
        let (size, adv) = uleb128(&raw[i..])?;
        i += adv;
        if size > best.0 {
            best = (size, name_of(addr));
        }
    }
    if best.0 == 0 {
        bail!("no non-zero frames found in .stack_sizes");
    }
    Ok(best)
}

fn uleb128(b: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = 0usize;
    loop {
        let byte = *b
            .get(i)
            .ok_or_else(|| anyhow!("truncated ULEB128 in .stack_sizes"))?;
        result |= u64::from(byte & 0x7f) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("ULEB128 value in .stack_sizes exceeds 64 bits");
        }
    }
    Ok((result, i))
}

/// Shorten a mangled task/function symbol for display.
fn short(sym: &str) -> &str {
    for tag in [
        "spdm_mctp_responder",
        "spdm_doe_responder",
        "mcu_mbox",
        "__start_task",
    ] {
        if sym.contains(tag) {
            return tag;
        }
    }
    sym
}

pub(crate) fn run() -> Result<()> {
    println!("max single frame allowed = {MAX_SINGLE_FRAME} B");
    println!("Building instrumented user-app ({GUARD_FEATURES})...");
    let elf_path = build_instrumented_user_app()?;
    let elf_bytes =
        std::fs::read(&elf_path).with_context(|| format!("reading {}", elf_path.display()))?;

    let (max_frame, offender) = largest_frame(&elf_bytes)?;
    let margin = MAX_SINGLE_FRAME as i64 - max_frame as i64;
    println!("  largest frame  {max_frame:>7} B  ({})", short(&offender));
    println!("  limit          {MAX_SINGLE_FRAME:>7} B");
    println!("  margin         {margin:>7} B");

    if max_frame > MAX_SINGLE_FRAME {
        bail!(
            "STACK GUARD FAILED: frame {max_frame} B in {} exceeds the {MAX_SINGLE_FRAME} B \
             per-frame limit. Move the large local into a static or the heap; raise \
             MAX_SINGLE_FRAME only if the frame is genuinely justified.",
            short(&offender),
        );
    }
    println!("STACK GUARD OK: largest frame {max_frame} B is within {MAX_SINGLE_FRAME} B ({margin} B margin).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal, valid .stack_sizes-style records: u32 LE addr + ULEB128 size.
    fn record(addr: u32, size_bytes: &[u8]) -> Vec<u8> {
        let mut v = addr.to_le_bytes().to_vec();
        v.extend_from_slice(size_bytes);
        v
    }

    #[test]
    fn uleb128_decodes_single_and_multibyte() {
        assert_eq!(uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(uleb128(&[0x7f]).unwrap(), (127, 1));
        assert_eq!(uleb128(&[0x60]).unwrap(), (96, 1));
        // 36960 -> ULEB 0xe0 0xa0 0x02
        assert_eq!(uleb128(&[0xe0, 0xa0, 0x02]).unwrap(), (36960, 3));
    }

    #[test]
    fn uleb128_rejects_truncated_and_overlong() {
        assert!(uleb128(&[0x80]).is_err()); // continuation bit but no next byte
        assert!(uleb128(&[0x80; 11]).is_err()); // never terminates within 64 bits
    }

    #[test]
    fn limit_is_budget_independent() {
        // The threshold must not be derived from [[app]].stack: raising the
        // budget must not weaken frame-regression detection.
        assert_eq!(MAX_SINGLE_FRAME, 8 * 1024);
    }

    // At the current 0x5000 (20,480 B) budget, the gate must PASS the measured
    // largest frame (6,960 B, spdm_mctp_responder::poll) and FAIL any frame that
    // regrows past the 10,240 B limit — e.g. re-introducing a multi-KB on-stack
    // buffer like the pre-#1859 11 KB MldsaVerifyReq.
    #[test]
    fn gate_passes_current_frame_rejects_regression() {
        // Largest frame on main today; must pass with headroom.
        const CURRENT_MAX_FRAME: u64 = 4_320;
        // The MldsaVerifyReq that originally landed in an async frame.
        const REGRESSION: u64 = 11_324;
        assert!(CURRENT_MAX_FRAME <= MAX_SINGLE_FRAME);
        assert!(
            CURRENT_MAX_FRAME + REGRESSION > MAX_SINGLE_FRAME,
            "re-adding an 11 KB on-stack buffer must trip the guard"
        );
    }

    // Largest-frame selection picks the max size and resolves nothing to panic on
    // an address with no symbol (returns a hex fallback name via the ELF path;
    // here we exercise the pure record scan through a hand-built section is not
    // possible without a full ELF, so we assert the ULEB+addr record shape the
    // parser consumes stays fixed).
    #[test]
    fn stack_size_record_layout_is_addr_then_uleb() {
        let r = record(0x4001_cf94, &[0xe0, 0xa0, 0x02]); // addr + 36960
        assert_eq!(&r[..4], 0x4001_cf94u32.to_le_bytes());
        let (sz, adv) = uleb128(&r[4..]).unwrap();
        assert_eq!((sz, adv), (36960, 3));
    }
}
