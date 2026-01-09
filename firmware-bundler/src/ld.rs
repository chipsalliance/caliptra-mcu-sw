// Licensed under the Apache-2.0 license

//! A module for handling the generation of linker scripts for a set of applications based on a
//! manifest file.  This includes allocating memory from the RAM, ITCM, and ROM spaces to be
//! associated with individual applications.

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};

use crate::{
    args::Common,
    manifest::{Binary, Manifest, Memory},
    utils,
};

// To keep the ld file generation simple, a layout is defined for each type of application, and then
// when a build runs it is configured by the individual Memory offsets and sizes for a specific
// platform and budget.  These constants define where the layout files exist within the
// linker-script directory as well as the default contents for those files.
//
// Vendors can choose to override the default layouts via cli arguments if they so choose.
const BASE_ROM_LD_FILE: &str = "rom-layout.ld";
const BASE_KERNEL_LD_FILE: &str = "kernel-layout.ld";
const BASE_APP_LD_FILE: &str = "app-layout.ld";
const BASE_ROM_LD_CONTENTS: &str = include_str!("../data/default-rom-layout.ld");
const BASE_KERNEL_LD_CONTENTS: &str = include_str!("../data/default-kernel-layout.ld");
const BASE_APP_LD_CONTENTS: &str = include_str!("../data/default-app-layout.ld");

/// A pairing of application name to the linker script it should be built with.
#[derive(Debug, Clone)]
// TODO: Remove this when the Bundle step is implemented.
#[allow(dead_code)]
pub struct AppLinkerScript {
    name: String,
    linker_script: PathBuf,
}

/// The build definition for a collection of applications.  The ROM and Runtime are both fully
/// specified with their linker files.  This is the output of the generation step.
#[derive(Debug, Clone)]
// TODO: Remove this when the Bundle step is implemented.
#[allow(dead_code)]
pub struct BuildDefinition {
    rom: Option<AppLinkerScript>,
    kernel: AppLinkerScript,
    apps: Vec<AppLinkerScript>,
}

/// Generate the collection of linker files required to build the set of applications specified in
/// the manifest.  If successful the linker files will exist in disk space, and the build definition
/// will contain the application names paired with the linker script which they should be built
/// with.
///
/// This could fail for a number of reasons, most likely for an incorrectly configured manifest
/// including the case where the manifest describes an application profile which cannot fit on
/// the Platform.  This could also fail if unable to write the linker files to the hard drive.
pub fn generate(manifest: Manifest, common: Common) -> Result<BuildDefinition> {
    LdGeneration::new(&manifest, common)?.run()
}

/// A helper struct containing the context required to do a linker script generation.
struct LdGeneration<'a> {
    manifest: &'a Manifest,
    linker_dir: PathBuf,
}

impl<'a> LdGeneration<'a> {
    /// Create a new LdGeneration.  This will also output the base linker scripts to the target
    /// directory.
    fn new(manifest: &'a Manifest, common: Common) -> Result<Self> {
        // Linker files should exist in the target directory for the platform tuple.  Put them in
        // a unique directory to prevent collisions and simplify inspection for debugging.  If
        // the workspace has not been specified attempt to determine it algorithmically.
        let linker_dir = match common.workspace_dir {
            Some(wd) => wd.join("target"),
            None => utils::find_target_directory()?,
        }
        .join(&manifest.platform.tuple)
        .join("linker-scripts");

        // Create all parent directories up to the output directory.
        let _ = std::fs::create_dir_all(&linker_dir);

        // Go through each layout file.  If the user specified a file to use, copy it into the
        // output linker directory, otherwise copy out the default contents.
        let rom_ld_file = linker_dir.join(BASE_ROM_LD_FILE);
        match common.rom_ld_base {
            Some(user_base) => std::fs::copy(user_base, rom_ld_file).map(|_| ())?,
            None => std::fs::write(rom_ld_file, BASE_ROM_LD_CONTENTS)?,
        };

        let kernel_ld_file = linker_dir.join(BASE_KERNEL_LD_FILE);
        match common.kernel_ld_base {
            Some(user_base) => std::fs::copy(user_base, kernel_ld_file).map(|_| ())?,
            None => std::fs::write(kernel_ld_file, BASE_KERNEL_LD_CONTENTS)?,
        };

        let app_ld_file = linker_dir.join(BASE_APP_LD_FILE);
        match common.app_ld_base {
            Some(user_base) => std::fs::copy(user_base, app_ld_file).map(|_| ())?,
            None => std::fs::write(app_ld_file, BASE_APP_LD_CONTENTS)?,
        };

        Ok(LdGeneration {
            manifest,
            linker_dir,
        })
    }

    /// Execute an Ld Generation pass.  This includes allocting memory from the various spaces to
    /// accomadate the application.  Utilizing this allocated memory generate respective linker
    /// files which can be used to build a complete application.
    fn run(&self) -> Result<BuildDefinition> {
        let binary_context =
            |name: &str| format!("Linker generation failed for application {name} with error:");

        // First generate the ROM linker script if an application is specified.
        let rom_def = self
            .manifest
            .rom
            .as_ref()
            .map(|binary| -> Result<AppLinkerScript> {
                let mut rom_tracker = self.manifest.platform.rom.clone();
                // The ROM will have sole access to RAM since it runs before any runtime
                // applications.  Therfore use a separate copy of the ram tracker from the runtime,
                // since the ROM can use the whole thing.
                let mut ram_tracker = self.manifest.platform.ram.clone();

                let instructions = self
                    .get_mem_block(
                        binary.exec_mem.size,
                        binary.exec_mem.alignment,
                        &mut rom_tracker,
                    )
                    .with_context(|| binary_context(&binary.name))?;
                let data = self
                    .get_mem_block(binary.ram, binary.ram_alignment, &mut ram_tracker)
                    .with_context(|| binary_context(&binary.name))?;
                let content = self
                    .rom_linker_content(binary, instructions, data)
                    .with_context(|| binary_context(&binary.name))?;
                let path = self.create_ld_file(binary, &content)?;
                Ok(AppLinkerScript {
                    name: binary.name.clone(),
                    linker_script: path,
                })
            })
            .transpose()?;

        // Now get trackers for runtime instruction and data memory.
        let mut itcm_tracker = self.manifest.platform.itcm.clone();
        let mut ram_tracker = self.manifest.platform.ram.clone();

        // The kernel should be the first element in both ITCM and RAM, therefore allocate it.  Wait
        // before creating the LD file, as application alignment can effect the value of some LD
        // variables.
        let kernel = &self.manifest.kernel;
        let instructions = self
            .get_mem_block(
                kernel.exec_mem.size,
                kernel.exec_mem.alignment,
                &mut itcm_tracker,
            )
            .with_context(|| binary_context(&kernel.name))?;
        let data = self
            .get_mem_block(kernel.ram, kernel.ram_alignment, &mut ram_tracker)
            .with_context(|| binary_context(&kernel.name))?;

        // Now iterate through each application and allocate its ITCM and RAM requirements.
        let mut first_app_instructions = None;
        let mut app_defs = Vec::new();
        for binary in &self.manifest.apps {
            let instructions = self
                .get_mem_block(
                    binary.exec_mem.size,
                    binary.exec_mem.alignment,
                    &mut itcm_tracker,
                )
                .with_context(|| binary_context(&binary.name))?;
            let data = self
                .get_mem_block(binary.ram, binary.ram_alignment, &mut ram_tracker)
                .with_context(|| binary_context(&binary.name))?;

            if first_app_instructions.is_none() {
                first_app_instructions = Some(instructions.clone());
            }

            let content = self
                .app_linker_content(binary, instructions, data)
                .with_context(|| binary_context(&binary.name))?;
            let path = self.create_ld_file(binary, &content)?;
            app_defs.push(AppLinkerScript {
                name: binary.name.clone(),
                linker_script: path,
            });
        }

        // Finally generate the linker file for the kernel.
        let content = self
            .kernel_linker_content(kernel, instructions, first_app_instructions, data)
            .with_context(|| binary_context(&kernel.name))?;
        let path = self.create_ld_file(kernel, &content)?;
        let kernel_def = AppLinkerScript {
            name: kernel.name.clone(),
            linker_script: path,
        };

        Ok(BuildDefinition {
            rom: rom_def,
            kernel: kernel_def,
            apps: app_defs,
        })
    }

    /// A small utility for allocating a memory block from a tracker.
    ///
    /// This will return an error if unable to satisfy the request.
    fn get_mem_block(
        &self,
        size: u64,
        binary_alignment: Option<u64>,
        tracker: &mut Memory,
    ) -> Result<Memory> {
        // Determine alignment for the block.
        let alignment =
            binary_alignment.unwrap_or_else(|| self.manifest.platform.default_alignment());

        // If the tracker currently doeesn't match the alignment, consume the number of bytes
        // required to reach that alignment.
        if tracker.offset % alignment != 0 {
            tracker.consume(alignment - (tracker.offset % alignment))?;
        }

        // Finally allocate the requested amount of memory from the tracker and return the allocated
        // block.
        tracker.consume(size)
    }

    /// Output a linker file for the application.
    fn create_ld_file(&self, binary: &Binary, content: &str) -> Result<PathBuf> {
        let output_file = self.linker_dir.join(format!("{}.ld", binary.name));

        std::fs::write(&output_file, content)?;

        Ok(output_file)
    }

    fn rom_linker_content(
        &self,
        binary: &Binary,
        instructions: Memory,
        data: Memory,
    ) -> Result<String> {
        const ROM_LD_TEMPLATE: &str = r#"
ROM_START = $ROM_START;
ROM_LENGTH = $ROM_LENGTH;
RAM_START = $RAM_START;
RAM_LENGTH = $RAM_LENGTH;
STACK_SIZE = $STACK_SIZE;
ESTACK_SIZE = $ESTACK_SIZE;
INCLUDE $BASE_LD_CONTENTS
"#;

        let base_ld_file = self.linker_dir.join(BASE_ROM_LD_FILE);

        let mut sub_map = HashMap::new();
        sub_map.insert("ROM_START", format!("{:#x}", instructions.offset));
        sub_map.insert("ROM_LENGTH", format!("{:#x}", instructions.size));
        sub_map.insert("RAM_START", format!("{:#x}", data.offset));
        sub_map.insert("RAM_LENGTH", format!("{:#x}", data.size));
        sub_map.insert("STACK_SIZE", format!("{:#x}", binary.stack()));
        sub_map.insert("ESTACK_SIZE", format!("{:#x}", binary.exception_stack));
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );

        subst::substitute(ROM_LD_TEMPLATE, &sub_map).map_err(|e| e.into())
    }

    fn kernel_linker_content(
        &self,
        binary: &Binary,
        instructions: Memory,
        first_app_instructions: Option<Memory>,
        data: Memory,
    ) -> Result<String> {
        const KERNEL_LD_TEMPLATE: &str = r#"
/* Licensed under the Apache-2.0 license. */

/* Based on the Tock board layouts, which are: */
/* Licensed under the Apache License, Version 2.0 or the MIT License. */
/* SPDX-License-Identifier: Apache-2.0 OR MIT                         */
/* Copyright Tock Contributors 2023.                                  */

MEMORY
{
    rom (rx)  : ORIGIN = $KERNEL_START, LENGTH = $KERNEL_LENGTH
    prog (rx) : ORIGIN = $APPS_START, LENGTH = $APPS_LENGTH
    ram (rwx) : ORIGIN = $DATA_RAM_START, LENGTH = $DATA_RAM_LENGTH
    flash (r) : ORIGIN = 0x0, LENGTH = 0x0
}

$PAGE_SIZE

INCLUDE $BASE_LD_CONTENTS
"#;
        let base_ld_file = self.linker_dir.join(BASE_KERNEL_LD_FILE);

        let mut sub_map = HashMap::new();
        sub_map.insert("KERNEL_START", format!("{:#x}", instructions.offset));
        sub_map.insert("KERNEL_LENGTH", format!("{:#x}", instructions.size));

        // The APP Memory region is defined as the region of ITCM utilized by the applications.
        // Utilize the offset of the first app instructions block to determine when it begins, and
        // then assign the rest of the ITCM to the APP memory space.
        //
        // If no APPs are specified in the manifest than it is not used anyway so just use 0s.
        let (apps_start, apps_length) = match first_app_instructions {
            Some(fai) => (
                fai.offset,
                self.manifest.platform.itcm.offset + self.manifest.platform.itcm.size - fai.offset,
            ),
            None => (0, 0),
        };
        sub_map.insert("APPS_START", format!("{apps_start:#x}",));
        sub_map.insert("APPS_LENGTH", format!("{apps_length:#x}",));

        sub_map.insert("DATA_RAM_START", format!("{:#x}", data.offset));
        sub_map.insert("DATA_RAM_LENGTH", format!("{:#x}", data.size));
        sub_map.insert("STACK_SIZE", format!("{:#x}", binary.stack()));
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );
        let page_size = self
            .manifest
            .platform
            .page_size
            .map(|pg| format!("PAGE_SIZE = {}", pg))
            .unwrap_or_default();
        sub_map.insert("PAGE_SIZE", page_size);

        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );

        subst::substitute(KERNEL_LD_TEMPLATE, &sub_map).map_err(|e| e.into())
    }

    fn app_linker_content(
        &self,
        binary: &Binary,
        instructions: Memory,
        data: Memory,
    ) -> Result<String> {
        // Note: In the future determine the size of the TBF header based on input.  For now assume
        // an 0x84 size.
        const APP_LD_TEMPLATE: &str = r#"
TBF_HEADER_SIZE = 0x84;
FLASH_START = $FLASH_START;
FLASH_LENGTH = $FLASH_LENGTH;
RAM_START = $RAM_START;
RAM_LENGTH = $RAM_LENGTH;
STACK_SIZE = $STACK_SIZE;
INCLUDE $BASE_LD_CONTENTS
"#;

        let base_ld_file = self.linker_dir.join(BASE_APP_LD_FILE);

        let mut sub_map = HashMap::new();
        sub_map.insert("FLASH_START", format!("{:#x}", instructions.offset));
        sub_map.insert("FLASH_LENGTH", format!("{:#x}", instructions.size));
        sub_map.insert("RAM_START", format!("{:#x}", data.offset));
        sub_map.insert("RAM_LENGTH", format!("{:#x}", data.size));
        sub_map.insert("STACK_SIZE", format!("{:#x}", binary.stack()));
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );

        subst::substitute(APP_LD_TEMPLATE, &sub_map).map_err(|e| e.into())
    }
}
