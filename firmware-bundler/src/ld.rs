// Licensed under the Apache-2.0 license

//! A module for handling the generation of linker scripts for a set of applications based on a
//! manifest file.  This includes allocating memory from the RAM, ITCM, and ROM spaces to be
//! associated with individual applications.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tbf_header::TbfHeader;

use crate::{
    args::{Common, LdArgs},
    manifest::{Binary, Manifest, Memory, RuntimeMemory},
    tbf::create_tbf_header,
    TOCK_ALIGNMENT,
};

// To keep the ld file generation simple, a layout is defined for each type of application, and then
// when a build runs it is configured by the individual Memory offsets and sizes for a specific
// platform and budget.  These constants define where the layout files exist within the
// linker-script directory as well as the default contents for those files.
//
// Vendors can choose to override the default layouts via cli arguments if they so choose.
const BASE_ROM_LD_PREFIX: &str = "bundler-rom-layout";
const BASE_KERNEL_LD_PREFIX: &str = "bundler-kernel-layout";
const BASE_APP_LD_PREFIX: &str = "bundler-app-layout";
const BASE_ROM_LD_CONTENTS: &str = include_str!("../data/default-rom-layout.ld");
const BASE_KERNEL_LD_CONTENTS: &str = include_str!("../data/default-kernel-layout.ld");
const BASE_APP_LD_CONTENTS: &str = include_str!("../data/default-app-layout.ld");

/// A pairing of application name to the linker script it should be built with.
#[derive(Debug, Clone)]
pub struct LinkerScript {
    pub name: String,
    pub linker_script: PathBuf,
}

/// A TockOS application.
#[derive(Debug, Clone)]
pub struct App {
    pub linker: LinkerScript,
    pub header: TbfHeader,
    pub instruction_block: Memory,
}

/// The build definition for a collection of applications.  The ROM and Runtime are both fully
/// specified with their linker files.  This is the output of the generation step.
#[derive(Debug, Clone)]
pub struct BuildDefinition {
    pub rom: Option<LinkerScript>,
    pub kernel: (LinkerScript, Memory),
    pub apps: Vec<App>,
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

/// Generate a collection of linker files where every application is given the entirety of the
/// device's memory for both instructions and data.  While the resulting applications cannot be
/// deployed to the device (as their memory overlaps), it can be used to determine the size of
/// each binary as part of a two-pass build process.
///
/// Since the ROM application always has complete access to its memory hierarchy, skip generating an
/// ld file for it, since it would not be interesting for a sizing pass.
///
/// This could fail if an application exceeds the memory bounds of the entire device, or a hard
/// drive operation fails.
pub fn generate_maximal_link_scripts(
    manifest: &Manifest,
    common: &Common,
    ld: &LdArgs,
) -> Result<BuildDefinition> {
    LdGeneration::new(manifest, common, ld)?.maximal()
}

/// A helper struct containing the context required to do a linker script generation.
struct LdGeneration<'a> {
    manifest: &'a Manifest,
    linker_dir: PathBuf,
    base_rom: PathBuf,
    base_kernel: PathBuf,
    base_app: PathBuf,
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
        let rom_contents = match &ld.rom_ld_base {
            Some(user_base) => &String::from_utf8(std::fs::read(user_base)?)?,
            None => BASE_ROM_LD_CONTENTS,
        };
        let base_rom = content_aware_write(BASE_ROM_LD_PREFIX, rom_contents, &linker_dir)?;

        let kernel_contents = match &ld.kernel_ld_base {
            Some(user_base) => &String::from_utf8(std::fs::read(user_base)?)?,
            None => BASE_KERNEL_LD_CONTENTS,
        };
        let base_kernel = content_aware_write(BASE_KERNEL_LD_PREFIX, kernel_contents, &linker_dir)?;

        let app_contents = match &ld.app_ld_base {
            Some(user_base) => &String::from_utf8(std::fs::read(user_base)?)?,
            None => BASE_APP_LD_CONTENTS,
        };
        let base_app = content_aware_write(BASE_APP_LD_PREFIX, app_contents, &linker_dir)?;

        Ok(LdGeneration {
            manifest,
            linker_dir,
            base_rom,
            base_kernel,
            base_app,
        })
    }

    /// Generate the maximal linker scripts for each application.
    fn maximal(&self) -> Result<BuildDefinition> {
        let binary_context = |name: &str, stage: &str| {
            format!("Linker generation failed for application {name} at stage {stage} with error:")
        };

        // Skip generating a ROM linker script.  The ROM always has full access to its memory space,
        // and is thus not interesting for generating a maximal script for sizing purposes.

        // Determine the maximal size of itcm/dtcm for the application.
        let (itcm, dtcm) = match self.manifest.platform.runtime_memory.clone() {
            RuntimeMemory::Sram(mut mem) => {
                // If in SRAM mode, split the memory in approximately half for instructions and
                // data.  They cannot be the same, as it causes allocations to overlap and fail to
                // compile.
                //
                // Note: The in half split is arbitrary.  This may have to be adjusted if real world
                // applications are found not to compile with this split, but can fit in the SRAM.
                let split = (mem.size / 2).next_multiple_of(TOCK_ALIGNMENT);
                let instructions = mem.consume(split)?;
                (instructions, mem)
            }
            RuntimeMemory::Tcm { itcm, dtcm } => (itcm, dtcm),
        };

        // Iterate through each application providing it with the entirety of ITCM and DTCM space.
        let mut app_defs = Vec::new();
        for binary in &self.manifest.apps {
            // This is a sizing build, so the header values don't matter.
            let header = create_tbf_header(binary)?;

            let content = self
                .app_linker_content(binary, &header, itcm.clone(), dtcm.clone())
                .with_context(|| binary_context(&binary.name, "context generation"))?;
            let path = self.output_ld_file(binary, &content)?;
            app_defs.push(App {
                linker: LinkerScript {
                    name: binary.name.clone(),
                    linker_script: path,
                },
                header,
                instruction_block: itcm.clone(),
            });
        }

        // Then generate a kernel linker file with the entirety of ITCM and DTCM space.
        let kernel = &self.manifest.kernel;
        let content = self
            .kernel_linker_content(itcm.clone(), None, dtcm.clone(), itcm.clone(), dtcm.clone())
            .with_context(|| binary_context(&kernel.name, "context generation"))?;
        let path = self.output_ld_file(kernel, &content)?;
        let kernel_def = LinkerScript {
            name: kernel.name.clone(),
            linker_script: path,
        };

        Ok(BuildDefinition {
            rom: None,
            kernel: (kernel_def, itcm.clone()),
            apps: app_defs,
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
            .map(|binary| -> Result<LinkerScript> {
                let mut rom_tracker = self.manifest.platform.rom.clone();
                let mut dccm_tracker = self.manifest.platform.dccm().clone();

                let exec_mem = binary.exec_mem()?;
                let instructions = self
                    .get_mem_block(exec_mem.size, exec_mem.alignment, &mut rom_tracker)
                    .with_context(|| binary_context(&binary.name, "instruction allocation"))?;
                let data_mem = binary.data_mem()?;
                let data = self
                    .get_mem_block(data_mem.size, data_mem.alignment, &mut dccm_tracker)
                    .with_context(|| binary_context(&binary.name, "data allocation"))?;
                let content = self
                    .rom_linker_content(binary, instructions, data)
                    .with_context(|| binary_context(&binary.name, "context generation"))?;
                let path = self.output_ld_file(binary, &content)?;
                Ok(LinkerScript {
                    name: binary.name.clone(),
                    linker_script: path,
                })
            })
            .transpose()?;

        let kernel = &self.manifest.kernel;
        let kernel_exec_mem = kernel.exec_mem()?;

        // Now get trackers for runtime instruction and data memory.
        let (mut itcm_tracker, mut dtcm_tracker) =
            match self.manifest.platform.runtime_memory.clone() {
                RuntimeMemory::Sram(mut mem) => {
                    // Determine the amount of space required within SRAM for the instructions.  It is
                    // equal to the kernel imem plus each apps imem, with padding for Tock alignment.
                    let mut split = kernel_exec_mem.size.next_multiple_of(TOCK_ALIGNMENT);
                    for app in &self.manifest.apps {
                        split += app.exec_mem()?.size.next_multiple_of(TOCK_ALIGNMENT);
                    }

                    let instructions = mem.consume(split)?;
                    (instructions, mem)
                }
                RuntimeMemory::Tcm { itcm, dtcm } => (itcm, dtcm),
            };
        let initial_itcm = itcm_tracker.clone();
        let initial_dtcm = dtcm_tracker.clone();

        // The kernel should be the first element in both ITCM and RAM, therefore allocate it.  Wait
        // before creating the LD file, as application alignment can effect the value of some LD
        // variables.
        let instructions = self
            .get_mem_block(
                kernel_exec_mem.size,
                kernel_exec_mem.alignment,
                &mut itcm_tracker,
            )
            .with_context(|| binary_context(&kernel.name, "instruction allocation"))?;
        let kernel_data_mem = kernel.data_mem()?;
        let data = self
            .get_mem_block(
                kernel_data_mem.size,
                kernel_data_mem.alignment,
                &mut dtcm_tracker,
            )
            .with_context(|| binary_context(&kernel.name, "data allocation"))?;

        // Now iterate through each application and allocate its ITCM and RAM requirements.
        let mut first_app_instructions = None;
        let mut app_defs = Vec::new();
        for binary in &self.manifest.apps {
            let header = create_tbf_header(binary)?;

            let exec_mem = binary.exec_mem()?;
            let instructions = self
                .get_mem_block(exec_mem.size, exec_mem.alignment, &mut itcm_tracker)
                .with_context(|| binary_context(&binary.name, "instruction allocation"))?;
            let data_mem = binary.data_mem()?;
            let data = self
                .get_mem_block(data_mem.size, data_mem.alignment, &mut dtcm_tracker)
                .with_context(|| binary_context(&binary.name, "data allocation"))?;

            if first_app_instructions.is_none() {
                first_app_instructions = Some(instructions.clone());
            }

            let content = self
                .app_linker_content(binary, &header, instructions.clone(), data)
                .with_context(|| binary_context(&binary.name, "context generation"))?;
            let path = self.output_ld_file(binary, &content)?;
            app_defs.push(App {
                linker: LinkerScript {
                    name: binary.name.clone(),
                    linker_script: path,
                },
                header,
                instruction_block: instructions,
            });
        }

        // Finally generate the linker file for the kernel.
        let content = self
            .kernel_linker_content(
                instructions.clone(),
                first_app_instructions,
                data,
                initial_itcm,
                initial_dtcm,
            )
            .with_context(|| binary_context(&kernel.name, "context generation"))?;
        let path = self.output_ld_file(kernel, &content)?;
        let kernel_def = LinkerScript {
            name: kernel.name.clone(),
            linker_script: path,
        };

        Ok(BuildDefinition {
            rom: rom_def,
            kernel: (kernel_def, instructions),
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
        content_aware_write(&binary.name, content, &self.linker_dir)
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

        let base_ld_file = self.linker_dir.join(&self.base_rom);

        let mut sub_map = HashMap::new();
        sub_map.insert("ROM_START", format!("{:#x}", instructions.offset));
        sub_map.insert("ROM_LENGTH", format!("{:#x}", instructions.size));
        sub_map.insert("RAM_START", format!("{:#x}", data.offset));
        sub_map.insert("RAM_LENGTH", format!("{:#x}", data.size));
        // If the stack isn't specified we are in a sizing build, and it doesnt matter.  Therefore
        // default to 0.
        sub_map.insert(
            "STACK_SIZE",
            format!("{:#x}", binary.stack().unwrap_or_default()),
        );
        sub_map.insert("ESTACK_SIZE", format!("{:#x}", binary.exception_stack));
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );

        subst::substitute(ROM_LD_TEMPLATE, &sub_map).map_err(|e| e.into())
    }

    fn kernel_linker_content(
        &self,
        instructions: Memory,
        first_app_instructions: Option<Memory>,
        kernel_data: Memory,
        itcm: Memory,
        dtcm: Memory,
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
    app_ram(rwx) : ORIGIN = $APP_RAM_START, LENGTH = $APP_RAM_LENGTH
    dccm (rw) : ORIGIN = $DCCM_OFFSET, LENGTH = $DCCM_LENGTH
    flash (r) : ORIGIN = $FLASH_OFFSET, LENGTH = $FLASH_LENGTH
}

$PAGE_SIZE

INCLUDE $BASE_LD_CONTENTS
"#;
        let base_ld_file = self.linker_dir.join(&self.base_kernel);

        let mut sub_map = HashMap::new();
        sub_map.insert("KERNEL_START", format!("{:#x}", instructions.offset));
        sub_map.insert("KERNEL_LENGTH", format!("{:#x}", instructions.size));

        // The APP Memory region is defined as the region of ITCM utilized by the applications.
        // Utilize the offset of the first app instructions block to determine when it begins, and
        // then assign the rest of the ITCM to the APP memory space.
        //
        // If no APPs are specified in the manifest than it is not used anyway so just use 0s.
        let (apps_start, apps_length) = match first_app_instructions {
            Some(fai) => (fai.offset, itcm.offset + itcm.size - fai.offset),
            None => (0, 0),
        };
        sub_map.insert("APPS_START", format!("{apps_start:#x}",));
        sub_map.insert("APPS_LENGTH", format!("{apps_length:#x}",));

        sub_map.insert("DATA_RAM_START", format!("{:#x}", kernel_data.offset));
        sub_map.insert("DATA_RAM_LENGTH", format!("{:#x}", dtcm.size));

        let app_offset = kernel_data.offset + kernel_data.size;
        let app_length = dtcm.size - kernel_data.size;
        sub_map.insert("APP_RAM_START", format!("{:#x}", app_offset));
        sub_map.insert("APP_RAM_LENGTH", format!("{:#x}", app_length));

        let dccm = self.manifest.platform.dccm();
        sub_map.insert("DCCM_OFFSET", format!("{:#x}", dccm.offset));
        sub_map.insert("DCCM_LENGTH", format!("{:#x}", dccm.size));

        let flash = self.manifest.platform.flash();
        sub_map.insert("FLASH_OFFSET", format!("{:#x}", flash.offset));
        sub_map.insert("FLASH_LENGTH", format!("{:#x}", flash.size));

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
        header: &TbfHeader,
        instructions: Memory,
        data: Memory,
    ) -> Result<String> {
        // Note: In the future determine the size of the TBF header based on input.  For now assume
        // an 0x84 size.
        const APP_LD_TEMPLATE: &str = r#"
TBF_HEADER_SIZE = $TBF_HEADER_LENGTH;
FLASH_START = $FLASH_START;
FLASH_LENGTH = $FLASH_LENGTH;
RAM_START = $RAM_START;
RAM_LENGTH = $RAM_LENGTH;
STACK_SIZE = $STACK_SIZE;
INCLUDE $BASE_LD_CONTENTS
"#;

        let base_ld_file = self.linker_dir.join(&self.base_app);
        let header_length = header.generate()?.get_ref().len();

        let mut sub_map = HashMap::new();
        sub_map.insert("TBF_HEADER_LENGTH", format!("{:#x}", header_length));
        sub_map.insert("FLASH_START", format!("{:#x}", instructions.offset));
        sub_map.insert("FLASH_LENGTH", format!("{:#x}", instructions.size));
        sub_map.insert("RAM_START", format!("{:#x}", data.offset));
        sub_map.insert("RAM_LENGTH", format!("{:#x}", data.size));
        // If the stack isn't specified we are in a sizing build, and it doesnt matter.  Therefore
        // default to 0.
        sub_map.insert(
            "STACK_SIZE",
            format!("{:#x}", binary.stack().unwrap_or_default()),
        );
        sub_map.insert(
            "BASE_LD_CONTENTS",
            base_ld_file.to_string_lossy().to_string(),
        );

        subst::substitute(APP_LD_TEMPLATE, &sub_map).map_err(|e| e.into())
    }
}

/// Output a linker file for the application.
fn content_aware_write(prefix: &str, content: &str, linker_dir: &Path) -> Result<PathBuf> {
    // Determine if a previous file matching this prefix has already been generated.
    // First read through the linker-script directory
    let maybe_previous_file = std::fs::read_dir(linker_dir)?
        .find(|f| {
            f.as_ref()
                .map(|f| {
                    // Then check if each entry has a name which starts with the same name as
                    // this linker file.  If so return it as the previous file.
                    f.file_name()
                        .to_str()
                        .map(|n| n.starts_with(prefix))
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
    let output_file = linker_dir.join(format!("{}-{}.ld", prefix, uuid::Uuid::new_v4()));
    std::fs::write(&output_file, content)?;
    Ok(output_file)
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
            name: "test".to_string(),
            tuple: "riscv32imc-unknown-none-elf".to_string(),
            dynamic_sizing: Some(false),
            default_alignment: Some(8),
            page_size: Some(256),
            rom: Memory {
                offset: 0x0,
                size: rom_size,
            },
            runtime_memory: RuntimeMemory::Tcm {
                itcm: Memory {
                    offset: 0x10000,
                    size: itcm_size,
                },
                dtcm: Memory {
                    offset: 0x20000,
                    size: ram_size,
                },
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
        assert_eq!(build_def.kernel.0.name, "kernel");
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
        assert_eq!(build_def.kernel.0.name, "kernel");
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
        assert_eq!(build_def.kernel.0.name, "kernel");
        assert_eq!(build_def.apps.len(), 1);
        assert_eq!(build_def.apps[0].linker.name, "app1");
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
        assert_eq!(build_def.apps[0].linker.name, "app1");
        assert_eq!(build_def.apps[1].linker.name, "app2");
        assert_eq!(build_def.apps[2].linker.name, "app3");
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
        assert_eq!(build_def.kernel.0.name, "kernel");
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
        assert_eq!(build_def.kernel.0.name, "kernel");
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
        assert!(build_def.kernel.0.linker_script.exists());
        assert!(build_def.apps[0].linker.linker_script.exists());

        // Verify base layout files also exist (with UUID suffixes)
        let linker_dir = temp
            .path()
            .join("target/riscv32imc-unknown-none-elf/linker-scripts");
        let has_file_with_prefix = |prefix: &str| {
            std::fs::read_dir(&linker_dir)
                .map(|entries| {
                    entries.filter_map(|e| e.ok()).any(|e| {
                        e.file_name()
                            .to_str()
                            .map(|n| n.starts_with(prefix) && n.ends_with(".ld"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        };
        assert!(has_file_with_prefix("bundler-rom-layout"));
        assert!(has_file_with_prefix("bundler-kernel-layout"));
        assert!(has_file_with_prefix("bundler-app-layout"));
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
