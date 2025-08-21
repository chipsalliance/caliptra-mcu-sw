// Licensed under the Apache-2.0 license

use anyhow::Result;
use mcu_builder::{target_dir, PROJECT_ROOT};
use std::process::Command;

const CBINDING_DIR: &str = "emulator/cbinding";

/// Helper function to manage environment variables for cc crate
fn with_cc_env<F, R>(release: bool, f: F) -> R 
where
    F: FnOnce() -> R,
{
    // Save existing environment variables
    let original_opt_level = std::env::var("OPT_LEVEL").ok();
    let original_target = std::env::var("TARGET").ok();
    let original_host = std::env::var("HOST").ok();

    // Set required environment variables for cc crate when used outside build script
    if original_opt_level.is_none() {
        std::env::set_var("OPT_LEVEL", if release { "3" } else { "0" });
    }
    if original_target.is_none() {
        std::env::set_var(
            "TARGET",
            if cfg!(target_os = "windows") {
                "x86_64-pc-windows-msvc"
            } else {
                "x86_64-unknown-linux-gnu"
            }
        );
    }
    if original_host.is_none() {
        std::env::set_var(
            "HOST",
            if cfg!(target_os = "windows") {
                "x86_64-pc-windows-msvc"
            } else {
                "x86_64-unknown-linux-gnu"
            }
        );
    }

    // Execute the closure
    let result = f();

    // Restore original environment variables
    match original_opt_level {
        Some(val) => std::env::set_var("OPT_LEVEL", val),
        None => std::env::remove_var("OPT_LEVEL"),
    }
    match original_target {
        Some(val) => std::env::set_var("TARGET", val),
        None => std::env::remove_var("TARGET"),
    }
    match original_host {
        Some(val) => std::env::set_var("HOST", val),
        None => std::env::remove_var("HOST"),
    }

    result
}

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

    // First compile the CFI stubs using cc crate for cross-platform compatibility
    let tool = with_cc_env(release, || {
        let cc_build = cc::Build::new();
        cc_build.get_compiler()
    });

    let cfi_stubs_obj = if cfg!(windows) {
        cbinding_dir.join("cfi_stubs.obj")
    } else {
        cbinding_dir.join("cfi_stubs.o")
    };

    let mut cmd = tool.to_command();

    // Use platform-specific compiler flags
    #[cfg(windows)]
    {
        cmd.arg("/std:c11")
            .arg(if release { "/O2" } else { "/Od" })
            .arg("/c")
            .arg("cfi_stubs.c")
            .arg("/Fo")
            .arg(&cfi_stubs_obj);
    }

    #[cfg(not(windows))]
    {
        cmd.args(["-std=c11", "-Wall", "-Wextra"])
            .arg(if release { "-O2" } else { "-O0" })
            .arg("-c")
            .arg("cfi_stubs.c")
            .arg("-o")
            .arg(&cfi_stubs_obj);
    }

    cmd.current_dir(&cbinding_dir);

    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("Failed to compile CFI stubs");
    }

    println!("CFI stubs compiled successfully");

    // Now link the main emulator with stubs using cc for cross-platform compatibility
    let tool = with_cc_env(release, || {
        let cc_build = cc::Build::new();
        cc_build.get_compiler()
    });

    let mut cmd = tool.to_command();

    // Use platform-specific compiler and linker flags
    #[cfg(windows)]
    {
        let emulator_exe = cbinding_dir.join("emulator.exe");
        let lib_path = target_build_dir.join("emulator_cbinding.lib");
        cmd.arg("/std:c11")
            .arg(if release { "/O2" } else { "/Od" })
            .arg("emulator.c")
            .arg("cfi_stubs.obj") // MSVC uses .obj extension
            .arg(format!("/Fe:{}", emulator_exe.display()))
            .arg(&lib_path) // Use full path to library
            .arg("ws2_32.lib")
            .arg("userenv.lib")
            .arg("bcrypt.lib")
            .arg("ntdll.lib") // For NtReadFile, NtWriteFile, etc.
            .arg("user32.lib") // For GetForegroundWindow, MessageBoxW, etc.
            .arg("advapi32.lib") // For CryptAcquireContextW, RegisterEventSourceW, etc.
            .arg("crypt32.lib") // For CertCloseStore, CertFindCertificateInStore, etc.
            .arg("kernel32.lib") // General Windows kernel functions
            .arg("ole32.lib") // Additional Windows system functions
            .arg("shell32.lib"); // Additional Windows shell functions
    }

    #[cfg(not(windows))]
    {
        cmd.args(["-std=c11", "-Wall", "-Wextra"])
            .arg(if release { "-O2" } else { "-O0" })
            .arg("-I.")
            .arg("-o")
            .arg("emulator")
            .arg("emulator.c")
            .arg("cfi_stubs.o")
            .arg("-L")
            .arg(lib_dir)
            .arg("-lemulator_cbinding")
            .args(["-lpthread", "-ldl", "-lm", "-lrt"]);
    }

    cmd.current_dir(&cbinding_dir);

    let status = cmd.status()?;

    if !status.success() {
        anyhow::bail!("Failed to build C emulator binary");
    }

    let emulator_path = if cfg!(windows) {
        cbinding_dir.join("emulator.exe")
    } else {
        cbinding_dir.join("emulator")
    };

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

    let emulator_dst = if cfg!(windows) {
        target_cbinding_dir.join("emulator.exe")
    } else {
        target_cbinding_dir.join("emulator")
    };

    if emulator_path.exists() {
        std::fs::rename(&emulator_path, &emulator_dst)?;
    }

    let cfi_stubs_src = if cfg!(windows) {
        cbinding_dir.join("cfi_stubs.obj")
    } else {
        cbinding_dir.join("cfi_stubs.o")
    };

    let cfi_stubs_dst = if cfg!(windows) {
        target_cbinding_dir.join("cfi_stubs.obj")
    } else {
        target_cbinding_dir.join("cfi_stubs.o")
    };

    if cfi_stubs_src.exists() {
        std::fs::rename(&cfi_stubs_src, &cfi_stubs_dst)?;
    }

    println!("C emulator binary built successfully");
    println!("All artifacts organized in {:?}", target_cbinding_dir);
    println!("  - {}", lib_name);
    println!("  - emulator_cbinding.h");
    if cfg!(windows) {
        println!("  - emulator.exe");
        println!("  - cfi_stubs.obj");
    } else {
        println!("  - emulator");
        println!("  - cfi_stubs.o");
    }
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
    let emulator_binary = if cfg!(windows) {
        cbinding_dir.join("emulator.exe")
    } else {
        cbinding_dir.join("emulator")
    };
    let header_file = cbinding_dir.join("emulator_cbinding.h");
    let cfi_stubs_obj = if cfg!(windows) {
        cbinding_dir.join("cfi_stubs.obj")
    } else {
        cbinding_dir.join("cfi_stubs.o")
    };

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
