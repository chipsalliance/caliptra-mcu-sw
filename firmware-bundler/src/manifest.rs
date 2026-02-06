// Licensed under the Apache-2.0 license

//! The manifest required for bundling a set of applications for a particular platform.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

/// The configuration for this distribution.  It includes both the platform and binaries to be
/// deployed, as well as any relevent information required for compilation and composition of the
/// binaries.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// A description of the platform to deploy applications to.
    pub platform: Platform,

    /// The rom binary to build.  This will be assumed as the first running code, and will have
    /// sole access to the ROM memory, and assumed to have full access to the RAM memory.
    pub rom: Option<Binary>,

    /// The tock kernel application.  This will be placed at the beginning of ITCM.
    pub kernel: Binary,

    /// The set of userspace apps which should be deployed to the given platform.  The ordering of
    /// binaries indicates the order applications should be allocated memory from the space
    /// remaining after the kernel allocation.
    #[serde(rename = "app")]
    pub apps: Vec<Binary>,
}

impl Manifest {
    /// Verify that a manifest matches the semantic patterns exceeding the syntax requirements of
    /// parsing.
    pub fn validate(&self) -> Result<()> {
        const APP_RAM_ALIGNMENT: u64 = 4096;

        let dynamic_sizing = self.platform.dynamic_sizing();

        if let Some(rom) = &self.rom {
            rom.validate(dynamic_sizing)?;

            if self.platform.dccm.is_none() {
                bail!("ROM Applications require DCCM to be defined");
            }
        }

        let dtcm = match &self.platform.runtime_memory {
            RuntimeMemory::Sram(s) => s.clone(),
            RuntimeMemory::Tcm { itcm: _itcm, dtcm } => dtcm.clone(),
        };

        if (dtcm.offset % APP_RAM_ALIGNMENT) != 0 {
            bail!(
                "Start of kernel RAM ({}) is not aligned with App memory offset requirement ({})",
                dtcm.offset,
                APP_RAM_ALIGNMENT
            );
        }

        if let Some(data_mem) = &self.kernel.data_mem {
            if (data_mem.size % APP_RAM_ALIGNMENT) != 0 {
                bail!(
                    "Kernel RAM size ({}) is not aligned with App memory offset requirement ({})",
                    data_mem.size,
                    APP_RAM_ALIGNMENT
                );
            }
        }

        self.kernel.validate(dynamic_sizing)?;
        for app in &self.apps {
            app.validate(dynamic_sizing)?;
        }

        Ok(())
    }
}

/// A description of how the runtime memory space is physically instantiated.  There can be either
/// an SRAM architecture where ITCM and DTCM are combined, or a TCM (Tightly Couple Memory)
/// architecture where they are split.
///
/// To configure a Platform with explicit splits between Instructions and Data, even when physically
/// backed by a single SRAM use the `TCM` option with the SRAM split as desired between instructions
/// and data.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub enum RuntimeMemory {
    /// A singular memory block is used for both Instructions and Data.
    #[serde(rename = "sram")]
    Sram(Memory),

    /// The memory space is split for instructions and data.  This can either be a physical or
    /// logical constraint.
    #[serde(rename = "tcm")]
    Tcm {
        /// The instruction memory for runtime applications.
        itcm: Memory,
        /// The RAM/Data memory for both the ROM and runtime applications.  It is assumed that the ROM
        /// and Runtime applications will not be executed at the same time, and thus can reused between
        /// the two.
        dtcm: Memory,
    },
}

/// A description of the platform to deploy applications to.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    /// The name of this platform.  This may be used the bundle artifact name, if not specified on
    /// the command line.
    pub name: String,

    /// The rustc target tuple this platform should be built with.
    pub tuple: String,

    /// Instead of utilizing budgets for applications specified within the Manifest, dynamically
    /// allocate memory for runtime binaries based on their actual sizes.  This requires a two pass
    /// build process, the first to determine the size of the binaries, and the second to build the
    /// binaries with an appropriate linker file matching their allocations.
    ///
    /// If this option is specified the `exec_mem` and `data_mem` sections must not be specified.
    /// The `stack` section must be specified for each application, as it will not be able to fall
    /// back to the `data_mem` specification.
    pub dynamic_sizing: Option<bool>,

    /// The alignment all binaries should use by default.  If not specified, this will be assume to
    /// be 8 bytes.
    pub default_alignment: Option<u64>,

    /// The page size to specify for the tock kernel linker script.  If this is not defined, the
    /// base linker page size is used.
    pub page_size: Option<u64>,

    /// The instruction location for ROM applications.
    pub rom: Memory,

    /// The memory runtime application should use.
    pub runtime_memory: RuntimeMemory,

    /// Data memory, outside of the RAM used by the application.  This is used for the
    /// _pic_vector_table on VeeR chips.  Defaults to a size and offset of 0 if not defined.
    pub dccm: Option<Memory>,

    /// Location of flash memory.  This can be used for persistent storage, e.g. logs.  Defaults to
    /// a size and offset of 0 if not defined.
    pub flash: Option<Memory>,
}

impl Platform {
    /// Retrieve the value of dynamic resizing.  If not specified it is false.
    pub fn dynamic_sizing(&self) -> bool {
        self.dynamic_sizing.unwrap_or_default()
    }

    /// Retrieve the default alignment of the platform.  If not specified in the toml file, it is 8
    /// bytes.
    pub fn default_alignment(&self) -> u64 {
        self.default_alignment.unwrap_or(8)
    }

    /// Retrieve the dccm memory layout.  If not specified it is empty.
    pub fn dccm(&self) -> Memory {
        self.dccm.clone().unwrap_or(Memory { offset: 0, size: 0 })
    }

    /// Retrieve the dccm memory layout.  If not specified it is empty.
    pub fn flash(&self) -> Memory {
        self.flash.clone().unwrap_or(Memory { offset: 0, size: 0 })
    }
}

/// A specification for a Memory block within a platform.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// The offset in the memory space which this block starts at, in bytes.
    pub offset: u64,

    /// The size of this memory block, in bytes.
    pub size: u64,
}

impl Memory {
    /// Consume the given number of bytes from the memory block.  This will both update the current
    /// memory blocks offset and size to account for the allocated chunk, as well as return a new
    /// Memory block with the consumed segment.
    pub fn consume(&mut self, bytes: u64) -> Result<Memory> {
        if bytes <= self.size {
            let new_block = Memory {
                offset: self.offset,
                size: bytes,
            };
            self.offset += bytes;
            self.size -= bytes;

            Ok(new_block)
        } else {
            bail!(
                "Bytes {bytes} would exceed remaining memory space {}",
                self.size
            )
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct AllocationRequest {
    pub size: u64,
    pub alignment: Option<u64>,
}

/// A specification for an individual binary to deploy on the Platform.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Binary {
    /// The name of the binary.
    pub name: String,

    /// The amount of instruction memory to request allocation for this binary.  Whether this will
    /// be from ROM or ITCM will depend on the field this binary populates.
    pub exec_mem: Option<AllocationRequest>,

    /// The amount of RAM the code should be able to allocate for uses like the data, bss, stack,
    /// grant, and other arbitrary code blocks.
    pub data_mem: Option<AllocationRequest>,

    /// The amount of stack the application should have.  This memory will exist in the ram segment
    /// and thus must be equal to or smaller, than that value.
    ///
    /// Default: Equivalent to `ram`.
    stack: Option<u64>,

    /// A separate stack allocation to be utilized during exception handling.  This memory will
    /// exist in the ram segment.
    ///
    /// Default: 0
    #[serde(default)]
    pub exception_stack: u64,
}

impl Binary {
    /// Retrieve the exec memory for the binary.  If not defined an error is returned.
    pub fn exec_mem(&self) -> Result<AllocationRequest> {
        // Note: The application should have already verified the exec memory is specified prior to
        // its utilization, so the error case should not be triggered.
        self.exec_mem
            .clone()
            .ok_or_else(|| anyhow!("Binary {} doesn't have exec mem", self.name))
    }

    /// Retrieve the data memory for the binary.  If not defined an error is returned.
    pub fn data_mem(&self) -> Result<AllocationRequest> {
        // Note: The application should have already verified the data memory is specified prior to
        // its utilization, so the error case should not be triggered.
        self.data_mem
            .clone()
            .ok_or_else(|| anyhow!("Binary {} doesn't have data mem", self.name))
    }

    /// Retrieve the stack field of the `Binary` structure.  If not defined the default is
    /// equivalent to the specified RAM value.
    pub fn stack(&self) -> Result<u64> {
        match &self.stack {
            Some(s) => Ok(*s),
            None => self.data_mem().map(|d| d.size),
        }
    }

    /// Verify that a `Binary` matches its semantic requirements.
    ///
    /// This could fail if the binary is misconfigured for any of the following reasons:
    ///     * The stack/estack exceed the RAM specification.
    ///     * The exec or data memory are incorrectly populated in regard to dynamic sizing.
    pub fn validate(&self, dynamic_sizing: bool) -> Result<()> {
        if dynamic_sizing {
            if self.exec_mem.is_some() {
                bail!(
                    "Binary {} has exec mem specified and is using dynamic sizing",
                    self.name
                );
            }

            if self.data_mem.is_some() {
                bail!(
                    "Binary {} has data mem specified and is using dynamic sizing",
                    self.name
                );
            }

            if self.stack.is_none() {
                bail!(
                    "Binary {} has no stack specified and is using dyanmic sizing",
                    self.name
                );
            }
        } else {
            if self.exec_mem.is_none() {
                bail!(
                    "Binary {} does not have exec mem specified and is not using dynamic sizing",
                    self.name
                );
            }

            if self.data_mem.is_none() {
                bail!(
                    "Binary {} does not have data mem specified and is not using dynamic sizing",
                    self.name
                );
            }
        }

        // If the data mem is specified, verify the stack and exception stack can fit within it.
        if let Some(data_mem) = &self.data_mem {
            let stack = self.stack()?;
            if stack + self.exception_stack > data_mem.size {
                bail!(
                "Binary {} ram ({:#x}) is exceeded by stack ({:#x}) and exception stack ({:#x})",
                self.name,
                data_mem.size,
                stack,
                self.exception_stack
            );
            }
        }

        Ok(())
    }

    /// Create a new Binary for testing purposes.
    #[cfg(test)]
    pub fn new_for_test(
        name: &str,
        exec_size: u64,
        ram: u64,
        stack: Option<u64>,
        exception_stack: u64,
    ) -> Self {
        Binary {
            name: name.to_string(),
            exec_mem: Some(AllocationRequest {
                size: exec_size,
                alignment: None,
            }),
            data_mem: Some(AllocationRequest {
                size: ram,
                alignment: None,
            }),
            stack,
            exception_stack,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AllocationRequest, Binary, Memory};

    #[test]
    fn memory_consume_with_room() {
        let mut test_mem = Memory {
            size: 0x10,
            offset: 0x00,
        };

        let block = test_mem.consume(8).unwrap();
        assert_eq!(block.offset, 0);
        assert_eq!(block.size, 8);

        assert_eq!(test_mem.offset, 8);
        assert_eq!(test_mem.size, 8);
    }

    #[test]
    fn memory_consume_without_room() {
        let mut test_mem = Memory {
            size: 0x10,
            offset: 0x00,
        };

        assert!(test_mem.consume(0x20).is_err());
    }

    // ==================== Binary::validate() Tests ====================

    #[test]
    fn binary_validate_default_stack_within_ram() {
        // When stack is None, it defaults to ram. With exception_stack = 0,
        // stack() + exception_stack == ram, which should pass.
        let binary = Binary::new_for_test("test", 0x100, 0x200, None, 0);
        assert!(binary.validate(false,).is_ok());
    }

    #[test]
    fn binary_validate_explicit_stack_within_ram() {
        // Explicit stack (0x80) + exception_stack (0x40) = 0xC0 < ram (0x200)
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x80), 0x40);
        assert!(binary.validate(false,).is_ok());
    }

    #[test]
    fn binary_validate_stack_exceeds_ram() {
        // Explicit stack (0x300) > ram (0x200), should fail
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x300), 0);
        assert!(binary.validate(false,).is_err());
    }

    #[test]
    fn binary_validate_exception_stack_causes_overflow() {
        // stack (0x100) fits, but stack + exception_stack (0x100 + 0x150 = 0x250) > ram (0x200)
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x100), 0x150);
        assert!(binary.validate(false,).is_err());
    }

    #[test]
    fn binary_validate_exact_fit() {
        // stack (0x100) + exception_stack (0x100) == ram (0x200), should pass
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x100), 0x100);
        assert!(binary.validate(false,).is_ok());
    }

    #[test]
    fn binary_validate_dynamic_sizing_rejects_exec_mem() {
        // With dynamic_sizing=true, exec_mem must not be specified
        let binary = Binary::new_for_test("test", 0x100, 0x200, None, 0);
        let result = binary.validate(true);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exec mem specified"));
    }

    #[test]
    fn binary_validate_static_sizing_requires_exec_mem() {
        // With dynamic_sizing=false, exec_mem must be specified
        let binary = Binary {
            name: "test".to_string(),
            exec_mem: None,
            data_mem: Some(AllocationRequest {
                size: 0x200,
                alignment: None,
            }),
            stack: None,
            exception_stack: 0,
        };
        let result = binary.validate(false);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not have exec mem"));
    }

    #[test]
    fn binary_validate_dynamic_sizing_rejects_data_mem() {
        // With dynamic_sizing=true, data_mem must not be specified
        let binary = Binary {
            name: "test".to_string(),
            exec_mem: None,
            data_mem: Some(AllocationRequest {
                size: 0x200,
                alignment: None,
            }),
            stack: None,
            exception_stack: 0,
        };
        let result = binary.validate(true);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("data mem specified"));
    }

    #[test]
    fn binary_validate_static_sizing_requires_data_mem() {
        // With dynamic_sizing=false, data_mem must be specified
        let binary = Binary {
            name: "test".to_string(),
            exec_mem: Some(AllocationRequest {
                size: 0x100,
                alignment: None,
            }),
            data_mem: None,
            stack: None,
            exception_stack: 0,
        };
        let result = binary.validate(false);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not have data mem"));
    }

    #[test]
    fn binary_validate_dynamic_sizing_requires_stack() {
        // With dynamic_sizing=true, stack must be explicitly specified
        let binary = Binary {
            name: "test".to_string(),
            exec_mem: None,
            data_mem: None,
            stack: None,
            exception_stack: 0,
        };
        let result = binary.validate(true);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no stack specified"));
    }
}
