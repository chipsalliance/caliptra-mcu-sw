// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::PROJECT_ROOT;
use std::{path::PathBuf, process::Command};

const CBINDING_DIR: &str = "emulator/cbinding";

/// Build the Rust static library for the emulator C binding
pub(crate) fn build_lib(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!("Building Rust static library and generating C header ({})...", build_type);
    
    let mut args = vec!["build", "-p", "emulator-cbinding"];
    if release {
        args.push("--release");
    }
    
    let output = Command::new("cargo")
        .args(&args)
        .current_dir(&*PROJECT_ROOT)
        .output()?;
    
    // Print stdout and stderr for debug purposes
    if !output.stdout.is_empty() {
        println!("cargo stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        println!("cargo stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }
    
    if !output.status.success() {
        anyhow::bail!("Failed to build Rust static library");
    }
    
    // Check if the header file was generated
    let header_path = PathBuf::from(CBINDING_DIR).join("emulator_cbinding.h");
    if !header_path.exists() {
        anyhow::bail!("Header file was not generated at expected location: {:?}", header_path);
    }
    
    println!("✓ Rust static library built successfully");
    println!("✓ Header file generated successfully at {:?}", header_path);
    Ok(())
}

/// Build the C emulator binary
pub(crate) fn build_emulator(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!("Building C emulator binary ({})...", build_type);
    
    // First ensure the library and header are built
    build_lib(release)?;
    
    let cbinding_dir = PathBuf::from(CBINDING_DIR);
    let lib_dir = if release { "../../target/release" } else { "../../target/debug" };
    
    println!("Linking C emulator with library directory: {}", lib_dir);
    
    // First compile the CFI stubs
    let cfi_stubs_output = Command::new("gcc")
        .args(&[
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
        .output()?;
    
    if !cfi_stubs_output.status.success() {
        if !cfi_stubs_output.stderr.is_empty() {
            println!("gcc cfi_stubs stderr:\n{}", String::from_utf8_lossy(&cfi_stubs_output.stderr));
        }
        anyhow::bail!("Failed to compile CFI stubs");
    }
    
    println!("✓ CFI stubs compiled successfully");
    
    // Now link the main emulator with stubs
    let output = Command::new("gcc")
        .args(&[
            "-std=c11",
            "-Wall", 
            "-Wextra",
            "-O2",
            "-I.",
            "-o", "emulator",
            "emulator.c",
            "cfi_stubs.o",  // Include the compiled stubs
            "-L", lib_dir,
            "-lemulator_cbinding",
            "-lpthread",
            "-ldl", 
            "-lm",
            "-lrt",  // POSIX real-time extensions (for mq_*, timer_*, aio_* functions)
        ])
        .current_dir(&cbinding_dir)
        .output()?;
    
    // Print stdout and stderr for debug purposes
    if !output.stdout.is_empty() {
        println!("gcc stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        println!("gcc stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }
    
    if !output.status.success() {
        anyhow::bail!("Failed to build C emulator binary");
    }
    
    let emulator_path = cbinding_dir.join("emulator");
    if !emulator_path.exists() {
        anyhow::bail!("Emulator binary was not created at expected location: {:?}", emulator_path);
    }
    
    println!("✓ C emulator binary built successfully at {:?}", emulator_path);
    Ok(())
}

/// Clean build artifacts
pub(crate) fn clean() -> Result<()> {
    println!("Cleaning build artifacts...");
    
    // Clean C artifacts
    let cbinding_dir = PathBuf::from(CBINDING_DIR);
    let emulator_binary = cbinding_dir.join("emulator");
    let header_file = cbinding_dir.join("emulator_cbinding.h");
    let cfi_stubs_obj = cbinding_dir.join("cfi_stubs.o");
    
    if emulator_binary.exists() {
        std::fs::remove_file(&emulator_binary)?;
        println!("✓ Removed emulator binary");
    }
    
    if header_file.exists() {
        std::fs::remove_file(&header_file)?;
        println!("✓ Removed header file");
    }
    
    if cfi_stubs_obj.exists() {
        std::fs::remove_file(&cfi_stubs_obj)?;
        println!("✓ Removed CFI stubs object file");
    }
    
    // Clean specific Rust artifacts for emulator-cbinding only
    let status = Command::new("cargo")
        .args(&["clean", "-p", "emulator-cbinding"])
        .current_dir(&*PROJECT_ROOT)
        .status()?;
    
    if !status.success() {
        eprintln!("Warning: Failed to clean emulator-cbinding Rust artifacts");
    } else {
        println!("✓ Cleaned emulator-cbinding Rust artifacts");
    }
    
    println!("✓ Build artifacts cleaned successfully");
    Ok(())
}

/// Build everything (library, header, and emulator binary)
pub(crate) fn build_all(release: bool) -> Result<()> {
    let build_type = if release { "release" } else { "debug" };
    println!("Building emulator C binding (library, header, and binary) in {} mode...", build_type);
    build_emulator(release)?;
    println!("✓ All emulator C binding components built successfully");
    Ok(())
}
