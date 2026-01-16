// Licensed under the Apache-2.0 license

//! The manifest required for bundling a set of applications for a particular platform.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The configuration for this distribution.  It includes both the platform and binaries to be
/// deployed, as well as any relevent information required for compilation and composition of the
/// binaries.
#[derive(Deserialize, Debug, Clone)]
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
        if let Some(rom) = &self.rom {
            rom.validate()?;
        }
        self.kernel.validate()?;
        for app in &self.apps {
            app.validate()?;
        }

        Ok(())
    }
}

/// A description of the platform to deploy applications to.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Platform {
    /// The rustc target tuple this platform should be built with.
    pub tuple: String,

    /// The alignment all binaries should use by default.  If not specified, this will be assume to
    /// be 8 bytes.
    pub default_alignment: Option<u64>,

    /// The page size to specify for the tock kernel linker script.  If this is not defined, the
    /// base linker page size is used.
    pub page_size: Option<u64>,

    /// The instruction location for ROM applications.
    pub rom: Memory,

    /// The instruction memory for runtime applications.
    pub itcm: Memory,

    /// The RAM/Data memory for both the ROM and runtime applications.  It is assumed that the ROM
    /// and Runtime applications will not be executed at the same time, and thus can reused between
    /// the two.
    pub ram: Memory,
}

impl Platform {
    /// Retrieve the default alignment of the platform.  If not specified in the toml file, it is 8
    /// bytes.
    pub fn default_alignment(&self) -> u64 {
        self.default_alignment.unwrap_or(8)
    }
}

/// A specification for a Memory block within a platform.
#[derive(Serialize, Deserialize, Debug, Clone)]
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
pub struct AllocationRequest {
    pub size: u64,
    pub alignment: Option<u64>,
}

/// A specification for an individual binary to deploy on the Platform.
#[derive(Deserialize, Debug, Clone)]
pub struct Binary {
    /// The name of the binary.
    pub name: String,

    /// The amount of instruction memory to request allocation for this binary.  Whether this will
    /// be from ROM or ITCM will depend on the field this binary populates.
    pub exec_mem: AllocationRequest,

    /// The amount of RAM the code should be able to allocate for uses like the data, bss, stack,
    /// grant, and other arbitrary code blocks.
    pub ram: u64,

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

    /// The alignment in bytes the ram offset should match.  The previous offset in memory space
    /// will be padded, and left unused, until this alignment is matched.  Defaults to platform's
    /// alignment if not defined.
    pub ram_alignment: Option<u64>,
}

impl Binary {
    /// Retrieve the stack field of the `Binary` structure.  If not defined the default is
    /// equivalent to the specified RAM value.
    pub fn stack(&self) -> u64 {
        self.stack.unwrap_or(self.ram)
    }

    /// Verify that a `Binary` matches its semantic requirements.
    ///
    /// This could fail if the binary is misconfigured for any of the following reasons:
    ///     * The stack/estack exceed the RAM specification.
    pub fn validate(&self) -> Result<()> {
        if self.stack() + self.exception_stack > self.ram {
            bail!(
                "Binary {} ram ({:#x}) is exceeded by stack ({:#x}) and exception stack ({:#x})",
                self.name,
                self.ram,
                self.stack(),
                self.exception_stack
            );
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
            exec_mem: AllocationRequest {
                size: exec_size,
                alignment: None,
            },
            ram,
            stack,
            exception_stack,
            ram_alignment: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Binary, Memory};

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
        assert!(binary.validate().is_ok());
    }

    #[test]
    fn binary_validate_explicit_stack_within_ram() {
        // Explicit stack (0x80) + exception_stack (0x40) = 0xC0 < ram (0x200)
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x80), 0x40);
        assert!(binary.validate().is_ok());
    }

    #[test]
    fn binary_validate_stack_exceeds_ram() {
        // Explicit stack (0x300) > ram (0x200), should fail
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x300), 0);
        assert!(binary.validate().is_err());
    }

    #[test]
    fn binary_validate_exception_stack_causes_overflow() {
        // stack (0x100) fits, but stack + exception_stack (0x100 + 0x150 = 0x250) > ram (0x200)
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x100), 0x150);
        assert!(binary.validate().is_err());
    }

    #[test]
    fn binary_validate_exact_fit() {
        // stack (0x100) + exception_stack (0x100) == ram (0x200), should pass
        let binary = Binary::new_for_test("test", 0x100, 0x200, Some(0x100), 0x100);
        assert!(binary.validate().is_ok());
    }
}
