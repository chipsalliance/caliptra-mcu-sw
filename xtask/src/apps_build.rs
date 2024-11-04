// Licensed under the Apache-2.0 license

use crate::{DynError, PROJECT_ROOT, TARGET};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

pub fn apps_build() -> Result<(), DynError> {
    let _ = app_build("pldm-app", 0x4002_0000)?;
    Ok(())
}

fn app_build(app_name: &str, offset: usize) -> Result<usize, DynError> {
    let mut file = NamedTempFile::new()?;

    writeln!(
        file,
        "
TBF_HEADER_SIZE = 0x60;
FLASH_START = 0x{:x};
FLASH_LENGTH = 0x10000;
RAM_START = 0x50000000;
RAM_LENGTH = 0x10000;
INCLUDE runtime/app_layout.ld",
        offset
    )?;
    file.flush()?;
    let layout_ld = file.path().to_str().unwrap();

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", format!("-C link-arg=-T{}", layout_ld))
        .env("LIBTOCK_LINKER_FLASH", format!("0x{:x}", offset))
        .env("LIBTOCK_LINKER_FLASH_LENGTH", "128K")
        .env("LIBTOCK_LINKER_RAM", "0x50000000")
        .env("LIBTOCK_LINKER_RAM_LENGTH", "128K")
        .args(["b", "-p", app_name, "--release", "--target", TARGET])
        .status()?;
    if !status.success() {
        Err("build ROM binary failed")?;
    }
    let output = PROJECT_ROOT
        .join("target")
        .join(TARGET)
        .join("release")
        .join(app_name);
    let metadata = std::fs::metadata(output)?;
    Ok(metadata.len() as usize)
}
