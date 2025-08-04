// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::{target_dir, PROJECT_ROOT};
use std::process::Command;

const CBINDING_DIR: &str = "emulator/cbinding";

/// Get the static library name with the correct extension for the target platform
fn get_lib_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "emulator_cbinding.lib"
    } else {
        "libemulator_cbinding.a"
    }
}

/// Build the Rust static library for the emulator C binding
pub(crate) fn build_lib(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!(
        "Building Rust static library and generating C header ({})...",
        build_type
    );

    let mut args = vec!["build", "-p", "emulator-cbinding"];
    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build Rust static library");
    }

    // Check if the header file was generated
    let header_path = PROJECT_ROOT.join(CBINDING_DIR).join("emulator_cbinding.h");
    if !header_path.exists() {
        anyhow::bail!(
            "Header file was not generated at expected location: {:?}",
            header_path
        );
    }

    println!("Rust static library built successfully");
    println!("Header file generated successfully at {:?}", header_path);
    Ok(())
}

/// Build the C emulator binary
pub(crate) fn build_emulator(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!("Building C emulator binary ({})...", build_type);

    // First ensure the library and header are built
    build_lib(release)?;

    let cbinding_dir = PROJECT_ROOT.join(CBINDING_DIR);
    let target_build_dir = target_dir().join(build_type);
    let lib_dir = target_build_dir.to_str().unwrap();

    println!("Linking C emulator with library directory: {}", lib_dir);

    // First compile the CFI stubs
    let cfi_stubs_status = Command::new("gcc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-O2",
            "-c",
            "cfi_stubs.c",
            "-o",
            "cfi_stubs.o",
        ])
        .current_dir(&cbinding_dir)
        .status()?;

    if !cfi_stubs_status.success() {
        anyhow::bail!("Failed to compile CFI stubs");
    }

    println!("CFI stubs compiled successfully");

    // Now link the main emulator with stubs
    let status = Command::new("gcc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-O2",
            "-I.",
            "-o",
            "emulator",
            "emulator.c",
            "cfi_stubs.o", // Include the compiled stubs
            "-L",
            lib_dir,
            "-lemulator_cbinding",
            "-lpthread",
            "-ldl",
            "-lm",
            "-lrt", // POSIX real-time extensions (for mq_*, timer_*, aio_* functions)
        ])
        .current_dir(&cbinding_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build C emulator binary");
    }

    let emulator_path = cbinding_dir.join("emulator");
    if !emulator_path.exists() {
        anyhow::bail!(
            "Emulator binary was not created at expected location: {:?}",
            emulator_path
        );
    }

    // Create target directory for organized artifacts
    let target_cbinding_dir = target_build_dir.join("emulator_cbinding");
    std::fs::create_dir_all(&target_cbinding_dir)?;

    // Move all artifacts to target directory
    let lib_name = get_lib_name();
    let lib_src = target_build_dir.join(lib_name);
    let lib_dst = target_cbinding_dir.join(lib_name);
    if lib_src.exists() {
        std::fs::rename(&lib_src, &lib_dst)?;
    }

    let header_src = PROJECT_ROOT.join(CBINDING_DIR).join("emulator_cbinding.h");
    let header_dst = target_cbinding_dir.join("emulator_cbinding.h");
    if header_src.exists() {
        std::fs::copy(&header_src, &header_dst)?;
    }

    let emulator_dst = target_cbinding_dir.join("emulator");
    if emulator_path.exists() {
        std::fs::rename(&emulator_path, &emulator_dst)?;
    }

    let cfi_stubs_src = cbinding_dir.join("cfi_stubs.o");
    let cfi_stubs_dst = target_cbinding_dir.join("cfi_stubs.o");
    if cfi_stubs_src.exists() {
        std::fs::rename(&cfi_stubs_src, &cfi_stubs_dst)?;
    }

    println!("C emulator binary built successfully");
    println!("All artifacts organized in {:?}", target_cbinding_dir);
    println!("  - {}", lib_name);
    println!("  - emulator_cbinding.h");
    println!("  - emulator");
    println!("  - cfi_stubs.o");
    Ok(())
}

/// Clean build artifacts
pub(crate) fn clean(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!("Cleaning build artifacts ({})...", build_type);

    // Clean organized artifacts from target directory
    let target_build_dir = target_dir().join(build_type);
    let target_cbinding_dir = target_build_dir.join("emulator_cbinding");
    if target_cbinding_dir.exists() {
        std::fs::remove_dir_all(&target_cbinding_dir)?;
        println!("Removed organized artifacts directory");
    }

    // Clean C artifacts from original locations (in case they weren't moved)
    let cbinding_dir = PROJECT_ROOT.join(CBINDING_DIR);
    let emulator_binary = cbinding_dir.join("emulator");
    let header_file = cbinding_dir.join("emulator_cbinding.h");
    let cfi_stubs_obj = cbinding_dir.join("cfi_stubs.o");

    if emulator_binary.exists() {
        std::fs::remove_file(&emulator_binary)?;
        println!("Removed emulator binary");
    }

    if header_file.exists() {
        std::fs::remove_file(&header_file)?;
        println!("Removed header file");
    }

    if cfi_stubs_obj.exists() {
        std::fs::remove_file(&cfi_stubs_obj)?;
        println!("Removed CFI stubs object file");
    }

    // Clean specific Rust artifacts for emulator-cbinding only
    let mut args = vec!["clean", "-p", "emulator-cbinding"];
    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .current_dir(&*PROJECT_ROOT)
        .status()?;

    if !status.success() {
        eprintln!("Warning: Failed to clean emulator-cbinding Rust artifacts");
        return Ok(());
    }

    println!("Build artifacts cleaned successfully");
    Ok(())
}

/// Build everything (library, header, and emulator binary)
pub(crate) fn build_all(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!(
        "Building emulator C binding (library, header, and binary) in {} mode...",
        build_type
    );
    build_emulator(release)?;
    println!("All emulator C binding components built successfully");
    Ok(())
}
