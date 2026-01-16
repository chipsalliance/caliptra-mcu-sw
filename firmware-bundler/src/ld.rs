// Licensed under the Apache-2.0 license

//! A module for handling the generation of linker scripts for a set of applications based on a
//! manifest file.  This includes allocating memory from the RAM, ITCM, and ROM spaces to be
//! associated with individual applications.

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};

use crate::{
    args::{Common, LdArgs},
    manifest::{Binary, Manifest, Memory},
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
pub struct AppLinkerScript {
    pub name: String,
    pub linker_script: PathBuf,
}

/// The build definition for a collection of applications.  The ROM and Runtime are both fully
/// specified with their linker files.  This is the output of the generation step.
#[derive(Debug, Clone)]
pub struct BuildDefinition {
    pub rom: Option<AppLinkerScript>,
    pub kernel: AppLinkerScript,
    pub apps: Vec<AppLinkerScript>,
}

/// Generate the collection of linker files required to build the set of applications specified in
/// the manifest.  If successful the linker files will exist in disk space, and the build definition
/// will contain the application names paired with the linker script which they should be built
/// with.
///
/// This could fail for a number of reasons, most likely for an incorrectly configured manifest
/// including the case where the manifest describes an application profile which cannot fit on
/// the Platform.  This could also fail if unable to write the linker files to the hard drive.
pub fn generate(manifest: &Manifest, common: &Common, ld: &LdArgs) -> Result<BuildDefinition> {
    LdGeneration::new(manifest, common, ld)?.run()
}

/// A helper struct containing the context required to do a linker script generation.
struct LdGeneration<'a> {
    manifest: &'a Manifest,
    linker_dir: PathBuf,
}

impl<'a> LdGeneration<'a> {
    /// Create a new LdGeneration.  This will also output the base linker scripts to the target
    /// directory.
    fn new(manifest: &'a Manifest, common: &Common, ld: &LdArgs) -> Result<Self> {
        // Linker files should exist in the target directory for the platform tuple.  Put them in
        // a unique directory to prevent collisions and simplify inspection for debugging.  If
        // the workspace has not been specified attempt to determine it algorithmically.
        let linker_dir = common
            .workspace_dir()?
            .join(&manifest.platform.tuple)
            .join("linker-scripts");

        // Create all parent directories up to the output directory.
        let _ = std::fs::create_dir_all(&linker_dir);

        // Go through each layout file.  If the user specified a file to use, copy it into the
        // output linker directory, otherwise copy out the default contents.
        let rom_ld_file = linker_dir.join(BASE_ROM_LD_FILE);
        match &ld.rom_ld_base {
            Some(user_base) => std::fs::copy(user_base, rom_ld_file).map(|_| ())?,
            None => std::fs::write(rom_ld_file, BASE_ROM_LD_CONTENTS)?,
        };

        let kernel_ld_file = linker_dir.join(BASE_KERNEL_LD_FILE);
        match &ld.kernel_ld_base {
            Some(user_base) => std::fs::copy(user_base, kernel_ld_file).map(|_| ())?,
            None => std::fs::write(kernel_ld_file, BASE_KERNEL_LD_CONTENTS)?,
        };

        let app_ld_file = linker_dir.join(BASE_APP_LD_FILE);
        match &ld.app_ld_base {
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
        let binary_context = |name: &str, stage: &str| {
            format!("Linker generation failed for application {name} at stage {stage} with error:")
        };

        // First generate the ROM linker script if an application is specified.
        let rom_def = self
            .manifest
            .rom
            .as_ref()
            .map(|binary| -> Result<AppLinkerScript> {
                let mut rom_tracker = self.manifest.platform.rom.clone();
                let mut dccm_tracker = self.manifest.platform.dccm().clone();

                let instructions = self
                    .get_mem_block(
                        binary.exec_mem.size,
                        binary.exec_mem.alignment,
                        &mut rom_tracker,
                    )
                    .with_context(|| binary_context(&binary.name, "instruction allocation"))?;
                let data = self
                    .get_mem_block(binary.ram, binary.ram_alignment, &mut dccm_tracker)
                    .with_context(|| binary_context(&binary.name, "data allocation"))?;
                let content = self
                    .rom_linker_content(binary, instructions, data)
                    .with_context(|| binary_context(&binary.name, "context generation"))?;
                let path = self.output_ld_file(binary, &content)?;
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
            .with_context(|| binary_context(&kernel.name, "instruction allocation"))?;
        let data = self
            .get_mem_block(kernel.ram, kernel.ram_alignment, &mut ram_tracker)
            .with_context(|| binary_context(&kernel.name, "data allocation"))?;

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
                .with_context(|| binary_context(&binary.name, "instruction allocation"))?;
            let data = self
                .get_mem_block(binary.ram, binary.ram_alignment, &mut ram_tracker)
                .with_context(|| binary_context(&binary.name, "data allocation"))?;

            if first_app_instructions.is_none() {
                first_app_instructions = Some(instructions.clone());
            }

            let content = self
                .app_linker_content(binary, instructions, data)
                .with_context(|| binary_context(&binary.name, "context generation"))?;
            let path = self.output_ld_file(binary, &content)?;
            app_defs.push(AppLinkerScript {
                name: binary.name.clone(),
                linker_script: path,
            });
        }

        // Finally generate the linker file for the kernel.
        let content = self
            .kernel_linker_content(kernel, instructions, first_app_instructions, data)
            .with_context(|| binary_context(&kernel.name, "context generation"))?;
        let path = self.output_ld_file(kernel, &content)?;
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
    fn output_ld_file(&self, binary: &Binary, content: &str) -> Result<PathBuf> {
        // Determine if a linker file has been previously generated.
        // First read through the linker-script directory
        let maybe_previous_file = std::fs::read_dir(&self.linker_dir)?
            .find(|f| {
                f.as_ref()
                    .map(|f| {
                        // Then check if each entry has a name which starts with the same name as
                        // this linker file.  If so return it as the previous file.
                        f.file_name()
                            .to_str()
                            .map(|n| n.starts_with(&binary.name))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            })
            .transpose()?;

        // To keep incremental builds fast, only output the linker contents if they differ from the
        // previously existing file.
        if let Some(previous_file) = maybe_previous_file {
            let previous_file = previous_file.path();
            // If the contents match exactly, just use the previous file, and perhaps the cached
            // build.
            if std::fs::read_to_string(&previous_file)
                .map(|prev| prev == content)
                .unwrap_or(false)
            {
                return Ok(previous_file);
            } else {
                // If they are different clean up the old file to avoid confusing multiple entries
                // within the linker-script directory.
                std::fs::remove_file(previous_file)?;
            }
        }

        // Finally output the linker script file if we need to.  Use a unique UUID with each linker
        // script generated.  This allows the `rustc` compiler to recognize when different scripts
        // are used, and thus trigger a new build when memory space allocations change.
        //
        // If this is not done, compilation can diverge from the actual status of the Manifest toml
        // until `cargo clean` is executed which can be quite confusing.
        let output_file =
            self.linker_dir
                .join(format!("{}-{}.ld", binary.name, uuid::Uuid::new_v4()));
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
    dccm (rw) : ORIGIN = $DCCM_OFFSET, LENGTH = $DCCM_LENGTH
    flash (r) : ORIGIN = $FLASH_OFFSET, LENGTH = $FLASH_LENGTH
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

        let dccm = self.manifest.platform.dccm();
        sub_map.insert("DCCM_OFFSET", format!("{:#x}", dccm.offset));
        sub_map.insert("DCCM_LENGTH", format!("{:#x}", dccm.size));

        let flash = self.manifest.platform.flash();
        sub_map.insert("FLASH_OFFSET", format!("{:#x}", flash.offset));
        sub_map.insert("FLASH_LENGTH", format!("{:#x}", flash.size));

        sub_map.insert("STACK_SIZE", format!("{:#x}", binary.stack()));
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );
        let page_size = self
            .manifest
            .platform
            .page_size
            .map(|pg| format!("PAGE_SIZE = {};", pg))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Platform;
    use tempfile::TempDir;

    /// Create a platform with configurable memory sizes.
    /// All memory regions start at offset 0x0, 0x10000, and 0x20000 respectively.
    fn test_platform(rom_size: u64, itcm_size: u64, ram_size: u64, dccm_size: u64) -> Platform {
        Platform {
            tuple: "riscv32imc-unknown-none-elf".to_string(),
            default_alignment: Some(8),
            page_size: Some(256),
            rom: Memory {
                offset: 0x0,
                size: rom_size,
            },
            itcm: Memory {
                offset: 0x10000,
                size: itcm_size,
            },
            ram: Memory {
                offset: 0x20000,
                size: ram_size,
            },
            dccm: Some(Memory {
                offset: 0x30000,
                size: dccm_size,
            }),
            flash: None,
        }
    }

    /// Create a binary with specified resource requirements.
    fn test_binary(name: &str, exec_size: u64, ram_size: u64) -> Binary {
        Binary::new_for_test(name, exec_size, ram_size, None, 0)
    }

    /// Create a Common args struct pointing to a temp directory.
    fn test_common(temp_dir: &TempDir) -> Common {
        Common::new_for_test(temp_dir.path().to_path_buf())
    }

    /// Create an LdArgs struct with default values.
    fn test_ld_args() -> LdArgs {
        LdArgs {
            rom_ld_base: None,
            kernel_ld_base: None,
            app_ld_base: None,
        }
    }

    /// Build a complete manifest from components.
    fn test_manifest(
        platform: Platform,
        rom: Option<Binary>,
        kernel: Binary,
        apps: Vec<Binary>,
    ) -> Manifest {
        Manifest {
            platform,
            rom,
            kernel,
            apps,
        }
    }

    // ==================== Happy Path Tests ====================

    #[test]
    fn kernel_only_fits() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert!(build_def.rom.is_none());
        assert_eq!(build_def.kernel.name, "kernel");
        assert!(build_def.apps.is_empty());
    }

    #[test]
    fn rom_and_kernel_fit() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x1000, 0x1000),
            Some(test_binary("rom", 0x100, 0x100)),
            test_binary("kernel", 0x100, 0x100),
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert!(build_def.rom.is_some());
        assert_eq!(build_def.rom.as_ref().unwrap().name, "rom");
        assert_eq!(build_def.kernel.name, "kernel");
        assert!(build_def.apps.is_empty());
    }

    #[test]
    fn kernel_and_single_app_fit() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![test_binary("app1", 0x100, 0x100)],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert!(build_def.rom.is_none());
        assert_eq!(build_def.kernel.name, "kernel");
        assert_eq!(build_def.apps.len(), 1);
        assert_eq!(build_def.apps[0].name, "app1");
    }

    #[test]
    fn kernel_and_multiple_apps_fit() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x2000, 0x2000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![
                test_binary("app1", 0x100, 0x100),
                test_binary("app2", 0x100, 0x100),
                test_binary("app3", 0x100, 0x100),
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert_eq!(build_def.apps.len(), 3);
        assert_eq!(build_def.apps[0].name, "app1");
        assert_eq!(build_def.apps[1].name, "app2");
        assert_eq!(build_def.apps[2].name, "app3");
    }

    #[test]
    fn full_manifest_rom_kernel_apps_fit() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x2000, 0x2000, 0x1000),
            Some(test_binary("rom", 0x200, 0x200)),
            test_binary("kernel", 0x200, 0x200),
            vec![
                test_binary("app1", 0x100, 0x100),
                test_binary("app2", 0x100, 0x100),
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert!(build_def.rom.is_some());
        assert_eq!(build_def.rom.as_ref().unwrap().name, "rom");
        assert_eq!(build_def.kernel.name, "kernel");
        assert_eq!(build_def.apps.len(), 2);
    }

    #[test]
    fn exact_fit_consumes_all_resources() {
        let temp = TempDir::new().unwrap();
        // Platform with exactly enough space for kernel + 1 app
        // ITCM: 0x200 total, kernel 0x100, app 0x100
        // RAM: 0x200 total, kernel 0x100, app 0x100
        let manifest = test_manifest(
            test_platform(0x1000, 0x200, 0x200, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![test_binary("app1", 0x100, 0x100)],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();
        assert_eq!(build_def.kernel.name, "kernel");
        assert_eq!(build_def.apps.len(), 1);
    }

    #[test]
    fn linker_scripts_created_on_disk() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x1000, 0x1000),
            Some(test_binary("my_rom", 0x100, 0x100)),
            test_binary("my_kernel", 0x100, 0x100),
            vec![test_binary("my_app", 0x100, 0x100)],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_ok());

        let build_def = result.unwrap();

        // Verify linker script files exist on disk
        assert!(build_def.rom.as_ref().unwrap().linker_script.exists());
        assert!(build_def.kernel.linker_script.exists());
        assert!(build_def.apps[0].linker_script.exists());

        // Verify base layout files also exist
        let linker_dir = temp
            .path()
            .join("target/riscv32imc-unknown-none-elf/linker-scripts");
        assert!(linker_dir.join("rom-layout.ld").exists());
        assert!(linker_dir.join("kernel-layout.ld").exists());
        assert!(linker_dir.join("app-layout.ld").exists());
    }

    // ==================== Failure Cases ====================

    #[test]
    fn kernel_exceeds_itcm() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x100, 0x1000, 0x1000), // Small ITCM
            None,
            test_binary("kernel", 0x200, 0x100), // Kernel exec_mem > ITCM
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn kernel_exceeds_ram() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x100, 0x1000), // Small RAM
            None,
            test_binary("kernel", 0x100, 0x200), // Kernel RAM > platform RAM
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn rom_exceeds_rom_memory() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x100, 0x1000, 0x1000, 0x1000), // Small ROM
            Some(test_binary("rom", 0x200, 0x100)),       // ROM exec_mem > platform ROM
            test_binary("kernel", 0x100, 0x100),
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn rom_exceeds_ram() {
        let temp = TempDir::new().unwrap();
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x100, 0x100), // Small RAM and DCCM
            Some(test_binary("rom", 0x100, 0x200)),      // ROM RAM > platform DCCM
            test_binary("kernel", 0x100, 0x100),
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn single_app_exceeds_remaining_itcm() {
        let temp = TempDir::new().unwrap();
        // ITCM: 0x200 total, kernel takes 0x100, only 0x100 left for app
        let manifest = test_manifest(
            test_platform(0x1000, 0x200, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![test_binary("app1", 0x200, 0x100)], // App needs 0x200, only 0x100 available
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn single_app_exceeds_remaining_ram() {
        let temp = TempDir::new().unwrap();
        // RAM: 0x200 total, kernel takes 0x100, only 0x100 left for app
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x200, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![test_binary("app1", 0x100, 0x200)], // App needs 0x200 RAM, only 0x100 available
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn multiple_apps_exceed_itcm_cumulatively() {
        let temp = TempDir::new().unwrap();
        // ITCM: 0x300 total, kernel takes 0x100, leaves 0x200 for apps
        // Three apps each need 0x100, totaling 0x300 - exceeds available 0x200
        let manifest = test_manifest(
            test_platform(0x1000, 0x300, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![
                test_binary("app1", 0x100, 0x50),
                test_binary("app2", 0x100, 0x50),
                test_binary("app3", 0x100, 0x50), // This one should fail
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn multiple_apps_exceed_ram_cumulatively() {
        let temp = TempDir::new().unwrap();
        // RAM: 0x300 total, kernel takes 0x100, leaves 0x200 for apps
        // Three apps each need 0x100 RAM, totaling 0x300 - exceeds available 0x200
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x300, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![
                test_binary("app1", 0x50, 0x100),
                test_binary("app2", 0x50, 0x100),
                test_binary("app3", 0x50, 0x100), // This one should fail
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn last_app_causes_itcm_overflow() {
        let temp = TempDir::new().unwrap();
        // ITCM: 0x280 total, kernel takes 0x100, leaves 0x180 for apps
        // First two apps fit (0x80 each = 0x100), third app (0x100) overflows
        let manifest = test_manifest(
            test_platform(0x1000, 0x280, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![
                test_binary("app1", 0x80, 0x50),
                test_binary("app2", 0x80, 0x50),
                test_binary("app3", 0x100, 0x50), // Needs 0x100, only 0x80 left
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn last_app_causes_ram_overflow() {
        let temp = TempDir::new().unwrap();
        // RAM: 0x280 total, kernel takes 0x100, leaves 0x180 for apps
        // First two apps fit (0x80 each = 0x100), third app (0x100) overflows
        let manifest = test_manifest(
            test_platform(0x1000, 0x1000, 0x280, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![
                test_binary("app1", 0x50, 0x80),
                test_binary("app2", 0x50, 0x80),
                test_binary("app3", 0x50, 0x100), // Needs 0x100 RAM, only 0x80 left
            ],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }

    #[test]
    fn zero_size_memory_regions_fail() {
        let temp = TempDir::new().unwrap();
        // ITCM has zero size - kernel cannot fit
        let manifest = test_manifest(
            test_platform(0x1000, 0x0, 0x1000, 0x1000),
            None,
            test_binary("kernel", 0x100, 0x100),
            vec![],
        );
        let result = generate(&manifest, &test_common(&temp), &test_ld_args());
        assert!(result.is_err());
    }
}
