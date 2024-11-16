// Licensed under the Apache-2.0 license

//! Build the Runtime Tock kernel image for VeeR RISC-V.

// Based on the tock board Makefile.common.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use crate::apps_build::apps_build_flat_tbf;
use crate::{DynError, PROJECT_ROOT, TARGET};
use std::path::PathBuf;
use std::process::Command;

const RUNTIME_START: usize = 0x4000_0000;
const INTERRUPT_TABLE_SIZE: usize = 128;
const ICCM_SIZE: usize = 256 * 1024;
const RAM_START: usize = 0x5000_0000;
const RAM_SIZE: usize = 128 * 1024;
const BSS_SIZE: usize = 5000; // this is approximate. Increase it is there are "sram" errors when linking

pub fn target_binary(name: &str) -> PathBuf {
    PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(name)
}

// Set additional flags to produce binary from .elf.
//
// - `--strip-sections`: Prevents enormous binaries when SRAM is below flash.
// - `--strip-all`: Remove non-allocated sections outside segments.
//   `.gnu.warning*` and `.ARM.attribute` sections are not removed.
// - `--remove-section .apps`: Prevents the .apps section from being included in
//   the base kernel binary file. This section is a placeholder for optionally
//   including application binaries, and only needs to exist in the .elf. By
//   removing it, we prevent the kernel binary from overwriting applications.
pub const OBJCOPY_FLAGS: &str = "--strip-sections --strip-all";

fn find_file(dir: &str, name: &str) -> Option<PathBuf> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_name() == name {
            return Some(entry.path().to_path_buf());
        }
    }
    None
}

pub fn objcopy() -> Result<String, DynError> {
    std::env::var("OBJCOPY").map(Ok).unwrap_or_else(|_| {
        // We need to get the full path to llvm-objcopy, if it is installed.
        if let Some(llvm_size) = find_file(&sysroot()?, "llvm-objcopy") {
            Ok(llvm_size.to_str().unwrap().to_string())
        } else {
            Err("Could not find llvm-objcopy; perhaps you need to run `rustup component add llvm-tools` or set the OBJCOPY environment variable to where to find objcopy".into())
        }
    })
}

fn sysroot() -> Result<String, DynError> {
    let tock_dir = &PROJECT_ROOT.join("runtime");
    let sysroot = String::from_utf8(
        Command::new("cargo")
            .args(["rustc", "--", "--print", "sysroot"])
            .current_dir(tock_dir)
            .output()?
            .stdout,
    )?
    .trim()
    .to_string();
    if sysroot.is_empty() {
        Err("Failed to get sysroot")?;
    }
    Ok(sysroot)
}

fn runtime_build_no_apps(apps_offset: usize) -> Result<(), DynError> {
    let tock_dir = &PROJECT_ROOT.join("runtime");
    let sysroot = sysroot()?;
    let ld_file_path = tock_dir.join("layout.ld");

    let runtime_size = apps_offset - RUNTIME_START - INTERRUPT_TABLE_SIZE;
    let apps_size = ICCM_SIZE - runtime_size - INTERRUPT_TABLE_SIZE;

    std::fs::write(
        &ld_file_path,
        format!(
            "/* Licensed under the Apache-2.0 license. */

        /* Based on the Tock board layouts, which are: */
        /* Licensed under the Apache License, Version 2.0 or the MIT License. */
        /* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
        /* Copyright Tock Contributors 2023.                                  */

        MEMORY
        {{
          rom (rx)  : ORIGIN = 0x{:x}, LENGTH = 0x{:x}
          prog (rx) : ORIGIN = 0x{:x}, LENGTH = 0x{:x}
          ram (rwx) : ORIGIN = 0x{:x}, LENGTH = 0x{:x}
        }}

        INCLUDE runtime/kernel_layout.ld
        ",
            RUNTIME_START + INTERRUPT_TABLE_SIZE,
            runtime_size,
            apps_offset,
            apps_size,
            RAM_START,
            RAM_SIZE,
        ),
    )?;

    // RUSTC_FLAGS allows boards to define board-specific options.
    // This will hopefully move into Cargo.toml (or Cargo.toml.local) eventually.
    //
    // - `-Tlayout.ld`: Use the linker script `layout.ld` all boards must provide.
    // - `linker=rust-lld`: Tell rustc to use the LLVM linker. This avoids needing
    //   GCC as a dependency to build the kernel.
    // - `linker-flavor=ld.lld`: Use the LLVM lld executable with the `-flavor gnu`
    //   flag.
    // - `relocation-model=static`: See https://github.com/tock/tock/pull/2853
    // - `-nmagic`: lld by default uses a default page size to align program
    //   sections. Tock expects that program sections are set back-to-back. `-nmagic`
    //   instructs the linker to not page-align sections.
    // - `-icf=all`: Identical Code Folding (ICF) set to all. This tells the linker
    //   to be more aggressive about removing duplicate code. The default is `safe`,
    //   and the downside to `all` is that different functions in the code can end up
    //   with the same address in the binary. However, it can save a fair bit of code
    //   size.
    // - `-C symbol-mangling-version=v0`: Opt-in to Rust v0 symbol mangling scheme.
    //   See https://github.com/rust-lang/rust/issues/60705 and
    //   https://github.com/tock/tock/issues/3529.
    let rustc_flags = [
        format!("-C link-arg=-T{}", ld_file_path.display()).as_str(),
        "-C linker=rust-lld",
        "-C linker-flavor=ld.lld",
        "-C relocation-model=static",
        "-C link-arg=-nmagic", // don't page align sections, link against static libs
        "-C link-arg=-icf=all", // identical code folding
        "-C symbol-mangling-version=v0",
        // RISC-V-specific flags.
        "-C force-frame-pointers=no",
        //   Ensure relocations generated is eligible for linker relaxation.
        //   This provide huge space savings.
        "-C target-feature=+relax",
    ]
    .join(" ");

    // RUSTC_FLAGS_TOCK by default extends RUSTC_FLAGS with options that are global
    // to all Tock boards.
    //
    // We use `remap-path-prefix` to remove user-specific filepath strings for error
    // reporting from appearing in the generated binary. The first line is used for
    // remapping the tock directory, and the second line is for remapping paths to
    // the source code of the core library, which end up in the binary as a result of
    // our use of `-Zbuild-std=core`.
    let rustc_flags_tock = [
        rustc_flags,
        format!(
            "--remap-path-prefix={}/runtime=",
            PROJECT_ROOT.to_str().unwrap()
        ),
        format!(
            "--remap-path-prefix={}/lib/rustlib/src/rust/library/core=/core/",
            sysroot
        ),
    ]
    .join(" ");

    // The following flags should only be passed to the board's binary crate, but
    // not to any of its dependencies (the kernel, capsules, chips, etc.). The
    // dependencies wouldn't use it, but because the link path is different for each
    // board, Cargo wouldn't be able to cache builds of the dependencies.
    //
    // Indeed, as far as Cargo is concerned, building the kernel with
    // `-C link-arg=-L/tock/boards/imix` is different than building the kernel with
    // `-C link-arg=-L/tock/boards/hail`, so Cargo would have to rebuild the kernel
    // for each board instead of caching it per board (even if in reality the same
    // kernel is built because the link-arg isn't used by the kernel).
    //
    // Ultimately, this should move to the Cargo.toml, for example when
    // https://github.com/rust-lang/cargo/pull/7811 is merged into Cargo.
    //
    // The difference between `RUSTC_FLAGS_TOCK` and `RUSTC_FLAGS_FOR_BIN` is that
    // the former is forwarded to all the dependencies (being passed to cargo via
    // the `RUSTFLAGS` environment variable), whereas the latter is only applied to
    // the final binary crate (being passed as parameter to `cargo rustc`).
    let rustc_flags_for_bin = format!("-C link-arg=-L{}/runtime", sysroot);

    // Validate that rustup is new enough.
    let minimum_rustup_version = semver::Version::parse("1.23.0").unwrap();
    let rustup_version = semver::Version::parse(
        String::from_utf8(Command::new("rustup").arg("--version").output()?.stdout)?
            .split(" ")
            .nth(1)
            .unwrap_or(""),
    )?;
    if rustup_version < minimum_rustup_version {
        println!("WARNING: Required tool `rustup` is out-of-date. Attempting to update.");
        if !Command::new("rustup").arg("update").status()?.success() {
            Err("Failed to update rustup. Please update manually with `rustup update`.")?;
        }
    }

    // Verify that various required Rust components are installed. All of these steps
    // only have to be done once per Rust version, but will take some time when
    // compiling for the first time.
    if !String::from_utf8(
        Command::new("rustup")
            .args(["target", "list", "--installed"])
            .output()?
            .stdout,
    )?
    .split('\n')
    .any(|line| line.contains(TARGET))
    {
        println!("WARNING: Request to compile for a missing TARGET, will install in 5s");
        std::thread::sleep(std::time::Duration::from_secs(5));
        if !Command::new("rustup")
            .arg("target")
            .arg("add")
            .arg(TARGET)
            .status()?
            .success()
        {
            Err(format!("Failed to install target {}", TARGET))?;
        }
    }

    let objcopy = objcopy()?;
    // we delete the .attributes because we don't use host tools for development, and it causes padding
    let objcopy_flags_kernel = format!(
        "{} --remove-section .apps --remove-section .attributes",
        OBJCOPY_FLAGS
    );

    // Add flags since we are compiling on nightly.
    //
    // - `-Z build-std=core,compiler_builtins`: Build the std library from source
    //   using our optimization settings. This leads to significantly smaller binary
    //   sizes, and makes debugging easier since debug information for the core
    //   library is included in the resulting .elf file. See
    //   https://github.com/tock/tock/pull/2847 for more details.
    // - `optimize_for_size`: Sets a feature flag in the core library that aims to
    //   produce smaller implementations for certain algorithms. See
    //   https://github.com/rust-lang/rust/pull/125011 for more details.
    let cargo_flags_tock = [
        "--verbose".into(),
        format!("--target={}", TARGET),
        format!("--package {}", "runtime"),
        "-Z build-std=core,compiler_builtins".into(),
        "-Z build-std-features=core/optimize_for_size".into(),
    ]
    .join(" ");

    let mut cmd = Command::new("cargo");
    let cmd = cmd
        .arg("rustc")
        .args(cargo_flags_tock.split(' '))
        .arg("--bin")
        .arg("runtime")
        .arg("--release")
        .arg("--")
        .args(rustc_flags_for_bin.split(' '))
        .env("RUSTFLAGS", rustc_flags_tock)
        .current_dir(tock_dir);

    println!("Executing {:?}", cmd);
    if !cmd.status()?.success() {
        Err("cargo rustc failed to build runtime")?;
    }

    let mut cmd = Command::new(&objcopy);
    let cmd = cmd
        .arg("--output-target=binary")
        .args(objcopy_flags_kernel.split(' '))
        .arg(target_binary("runtime"))
        .arg(target_binary("runtime.bin"));

    println!("Executing {:?}", cmd);
    if !cmd.status()?.success() {
        Err("objcopy failed to build runtime")?;
    }

    Ok(())
}

pub fn runtime_build_with_apps() -> Result<(), DynError> {
    let mut app_offset = RUNTIME_START;
    let runtime_bin = target_binary("runtime.bin");

    // build once to get the size of the runtime binary without apps
    runtime_build_no_apps(RUNTIME_START + 0x2_0000)?;

    let runtime_bin_size = std::fs::metadata(&runtime_bin)?.len() as usize;
    app_offset += runtime_bin_size;
    let runtime_end_offset = app_offset;
    app_offset += BSS_SIZE; // it's not clear why this is necessary as the BSS should be part of .sram, but the linker fails without this
    app_offset = app_offset.next_multiple_of(4096); // align to 4096 bytes. Needed for rust-lld
    let padding = app_offset - runtime_end_offset - INTERRUPT_TABLE_SIZE;

    // now re-link and place the apps after the runtime binary
    runtime_build_no_apps(app_offset)?;

    let mut bin = std::fs::read(&runtime_bin)?;
    let kernel_size = bin.len();
    println!("Kernel binary built: {} bytes", kernel_size);

    // now build the apps starting at the correct offset
    let apps_bin = apps_build_flat_tbf(app_offset)?;
    println!("Apps built: {} bytes", apps_bin.len());
    bin.extend_from_slice(vec![0; padding].as_slice());
    bin.extend_from_slice(&apps_bin);
    std::fs::write(&runtime_bin, &bin)?;

    println!("Kernel binary size: {} bytes", kernel_size);
    println!("Total runtime binary: {} bytes", bin.len());
    println!("Runtime binary is available at {:?}", &runtime_bin);

    Ok(())
}
