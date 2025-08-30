// Licensed under the Apache-2.0 license

use crate::tbf::TbfHeader;
use crate::{objcopy, target_binary, OBJCOPY_FLAGS};
use crate::{PROJECT_ROOT, TARGET};
use anyhow::{bail, Result};
use std::process::Command;

pub const APPS: &[App] = &[
    App {
        // Make sure this is the first app in the list
        name: "example-app",
        permissions: vec![],
        minimum_ram: 48 * 1024,
    },
    App {
        name: "user-app",
        permissions: vec![],
        minimum_ram: 108 * 1024,
    },
];

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
    (8, 0), // Low-level debug
    (8, 1), // Low-level debug
    (8, 2), // Low-level debug
    (8, 3), // Low-level debug
];

// Generates a single flat binary containing the apps built with their TBF headers.
// If `example_app` is true, only the example app is included; otherwise, all other apps are included.
pub fn apps_build_flat_tbf(
    start: usize,
    ram_start: usize,
    features: &[&str],
    example_app: bool,
) -> Result<Vec<u8>> {
    let mut bin = vec![];
    let mut offset = start;
    let mut ram_start = ram_start;
    for app in APPS.iter() {
        if app.name == "example-app" && !example_app {
            continue;
        }
        println!("Building TBF for app {}", app.name);
        let app_bin = app_build_tbf(app, offset, ram_start, app.minimum_ram as usize, features)?;
        bin.extend_from_slice(&app_bin);
        offset += app_bin.len();
        ram_start += app.minimum_ram as usize;

        if app.name == "example-app" && example_app {
            // example app is always the first app
            // and we do not want to build any more apps after it
            // so we can just break out of the loop
            break;
        }
    }
    // align to 4-byte boundary for PMP
    while bin.len() % 4 != 0 {
        bin.push(0);
    }
    Ok(bin)
}

// creates a flat binary of the app with the TBF header
fn app_build_tbf(
    app: &App,
    start: usize,
    ram_start: usize,
    ram_length: usize,
    features: &[&str],
) -> Result<Vec<u8>> {
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

    app_build(
        app.name,
        start,
        ram_start,
        ram_length,
        tbf_header_size,
        features,
    )?;
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
        bail!("objcopy failed to build app");
    }

    // read the flat binary
    let mut b = std::fs::read(&app_bin)?;

    while b.len() % 4 != 0 {
        b.push(0);
    }

    let total_size = b.len() + tbf_header_size;

    tbf.set_total_size(total_size as u32);
    tbf.set_init_fn_offset(0x20);
    tbf.set_binary_end_offset(total_size as u32);
    let tbf = tbf.generate()?;

    // concatenate the TBF header and the binary
    let mut bin = vec![];
    bin.extend_from_slice(&tbf.into_inner());
    bin.extend_from_slice(&b);
    Ok(bin)
}

// creates an ELF of the app
fn app_build(
    app_name: &str,
    offset: usize,
    ram_start: usize,
    ram_length: usize,
    tbf_header_size: usize,
    features: &[&str],
) -> Result<()> {
    let app_ld_filename = format!("{}-layout.ld", app_name);
    let layout_ld = &PROJECT_ROOT
        .join("platforms")
        .join("emulator")
        .join("runtime")
        .join("userspace")
        .join("apps")
        .join(app_ld_filename);

    // TODO: do we need to fix the RAM start and length?
    std::fs::write(
        layout_ld,
        format!(
            "
/* Licensed under the Apache-2.0 license */
TBF_HEADER_SIZE = 0x{:x};
FLASH_START = 0x{:x};
FLASH_LENGTH = 0x49000;
RAM_START = 0x{:x};
RAM_LENGTH = 0x{:x};
INCLUDE platforms/emulator/runtime/userspace/apps/app_layout.ld",
            tbf_header_size, offset, ram_start, ram_length,
        ),
    )?;

    let ld_flag = format!("-C link-arg=-T{}", layout_ld.display());

    let features_str = if features.is_empty() {
        "".to_string()
    } else {
        features.join(",")
    };

    let status = Command::new("cargo")
        .current_dir(&*PROJECT_ROOT)
        .args([
            "rustc",
            "-p",
            app_name,
            "--release",
            "--features",
            &features_str,
            "--target",
            TARGET,
            "--",
        ])
        .args(ld_flag.split(' '))
        .status()?;
    if !status.success() {
        bail!("build ROM ELF failed");
    }
    println!(
        "App {} built for location {:x}, RAM start {:x}",
        app_name, offset, ram_start
    );
    Ok(())
}
