// Licensed under the Apache-2.0 license

use crate::runtime_build::{objcopy, target_binary, OBJCOPY_FLAGS, RUSTFLAGS_COMMON};
use crate::tbf::TbfHeader;
use crate::{DynError, PROJECT_ROOT, TARGET};
use std::process::Command;

pub const APPS: &[App] = &[App {
    name: "pldm-app",
    permissions: vec![],
    minimum_ram: 16384,
}];

pub struct App {
    pub name: &'static str,
    pub permissions: Vec<(u32, u32)>, // pairs of (driver, command). All console and alarm commands are allowed by default.
    pub minimum_ram: u32,
}

pub const BASE_PERMISSIONS: &[(u32, u32)] = &[
    (0, 0), // Alarm
    (0, 1),
    (0, 2),
    (0, 3),
    (0, 4),
    (0, 5),
    (0, 6),
    (1, 0), // Console
    (1, 1),
    (1, 2),
    (1, 3),
];

// creates a single flat binary with all the apps built with TBF headers
pub fn apps_build_flat_tbf(start: usize) -> Result<Vec<u8>, DynError> {
    let mut bin = vec![];
    let mut offset = start;
    for app in APPS.iter() {
        let app_bin = app_build_tbf(app, offset)?;
        bin.extend_from_slice(&app_bin);
        offset += app_bin.len();
    }
    Ok(bin)
}

// creates a flat binary of the app with the TBF header
fn app_build_tbf(app: &App, start: usize) -> Result<Vec<u8>, DynError> {
    // start the TBF header
    let mut tbf = TbfHeader::new();
    let mut permissions = BASE_PERMISSIONS.to_vec();
    permissions.extend_from_slice(&app.permissions);
    tbf.create(
        app.minimum_ram,
        0,
        app.name.to_owned(),
        None,
        None,
        permissions,
        (None, None, None),
        Some((2, 0)),
        false,
    );
    tbf.set_binary_end_offset(0); // temporary just to get the size of the header
    let tbf_header_size = tbf.generate()?.get_ref().len();

    app_build(app.name, start, tbf_header_size)?;
    let objcopy = objcopy()?;

    let app_bin = target_binary(&format!("{}.bin", app.name));

    let mut app_cmd = Command::new(&objcopy);
    let app_cmd = app_cmd
        .arg("--output-target=binary")
        .args(OBJCOPY_FLAGS.split(' '))
        .arg(target_binary(app.name))
        .arg(&app_bin);
    println!("Executing {:?}", &app_cmd);
    if !app_cmd.status()?.success() {
        Err("objcopy failed to build app")?;
    }

    // read the flat binary
    let b = std::fs::read(&app_bin)?;

    tbf.set_total_size(b.len() as u32);
    tbf.set_init_fn_offset(0x20);
    tbf.set_binary_end_offset(b.len() as u32);
    let tbf = tbf.generate()?;

    // concatenate the TBF header and the binary
    let mut bin = vec![];
    bin.extend_from_slice(&tbf.into_inner());
    bin.extend_from_slice(&b);
    Ok(bin)
}

// creates an ELF of the app
fn app_build(app_name: &str, offset: usize, tbf_header_size: usize) -> Result<(), DynError> {
    let layout_ld = &PROJECT_ROOT.join("runtime").join("apps").join("layout.ld");

    // TODO: do we need to fix the RAM start and length?
    std::fs::write(
        layout_ld,
        format!(
            "
/* Licensed under the Apache-2.0 license */
TBF_HEADER_SIZE = 0x{:x};
FLASH_START = 0x{:x};
FLASH_LENGTH = 0x10000;
RAM_START = 0x50000000;
RAM_LENGTH = 0x10000;
INCLUDE runtime/apps/app_layout.ld",
            tbf_header_size, offset,
        ),
    )?;

    let ld_flag = format!("-C link-arg=-T{}", layout_ld.display());
    let mut rustc_flags = Vec::from(RUSTFLAGS_COMMON);
    rustc_flags.push(ld_flag.as_str());
    let rustc_flags = rustc_flags.join(" ");

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .env("RUSTFLAGS", rustc_flags)
        .env("LIBTOCK_LINKER_FLASH", format!("0x{:x}", offset))
        .env("LIBTOCK_LINKER_FLASH_LENGTH", "128K")
        .env("LIBTOCK_LINKER_RAM", "0x50000000")
        .env("LIBTOCK_LINKER_RAM_LENGTH", "128K")
        .args(["b", "-p", app_name, "--release", "--target", TARGET])
        .status()?;
    if !status.success() {
        Err("build ROM ELF failed")?;
    }
    Ok(())
}
