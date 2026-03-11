// Licensed under the Apache-2.0 license

//! Output types and code generation for tock-registers.
//!
//! This module contains the data structures that represent the generated output
//! ([`GeneratedAddrMap`], [`GeneratedRegister`], etc.) and the logic to convert
//! them into Rust code compatible with the tock-registers crate.
//!
//! ## Code Generation Flow
//!
//! ```text
//! World (parsed RDL) → GeneratedAddrMap → Rust code string
//!                      ├── GeneratedRegisterType[]  → register_bitfields! macro
//!                      ├── GeneratedRegister[]      → register_structs! macro
//!                      └── GeneratedMemory[]        → const PTR declarations
//! ```
//!
//! ## Generated Code Structure
//!
//! For an addrmap named "MyDevice", the generated code looks like:
//!
//! ```text
//! pub const MY_DEVICE_ADDR: u32 = 0x1000_0000;
//!
//! pub mod bits {
//!     use tock_registers::register_bitfields;
//!     register_bitfields! { u32,
//!         pub StatusReg [ ... ],
//!         pub ControlReg [ ... ],
//!     }
//! }
//!
//! pub mod regs {
//!     use tock_registers::register_structs;
//!     register_structs! {
//!         pub MyDevice {
//!             (0x0 => pub status: ReadOnly<u32, bits::StatusReg::Register>),
//!             (0x4 => pub control: ReadWrite<u32, bits::ControlReg::Register>),
//!             (0x8 => @END),
//!         }
//!     }
//! }
//! ```

use crate::util::{camel_case, hex_const, snake_case};
use std::fmt::Write;

//=============================================================================
// Generated Types
//=============================================================================

/// A generated bit field within a register.
#[derive(Clone, Debug)]
pub struct GeneratedField {
    /// Field name.
    pub name: String,
    /// Bit offset within the register.
    pub offset: usize,
    /// Width in bits.
    pub width: usize,
    /// Optional description for doc comments.
    pub description: Option<String>,
    /// Enum values for this field, if any.
    pub enum_values: Vec<(String, u64)>,
}

/// A generated register type with its fields.
///
/// Register types define the bitfield layout and are referenced by
/// register instances.
#[derive(Clone, Debug)]
pub struct GeneratedRegisterType {
    /// Type name (used in CamelCase for the bitfield definition).
    pub name: String,
    /// Register width in bits (8, 16, 32, or 64).
    pub width: u8,
    /// Fields within this register type.
    pub fields: Vec<GeneratedField>,
}

/// A generated register instance.
///
/// Register instances are placed at specific offsets within an addrmap
/// and reference a register type for their bitfield layout.
#[derive(Clone, Debug)]
pub struct GeneratedRegister {
    /// Instance name.
    pub name: String,
    /// Byte offset from addrmap base.
    pub offset: usize,
    /// Name of the register type (for bitfield reference).
    pub type_name: Option<String>,
    /// Whether software can read this register.
    pub can_read: bool,
    /// Whether software can write this register.
    pub can_write: bool,
    /// For array registers, the total number of elements.
    pub array_size: Option<usize>,
    /// Register width in bits (8, 16, 32, or 64).
    pub width: u8,
}

/// A generated memory region (SRAM, tables, etc.).
#[derive(Clone, Debug)]
pub struct GeneratedMemory {
    /// Memory region name.
    pub name: String,
    /// Byte offset from addrmap base.
    pub offset: usize,
    /// Total size in bytes.
    pub size_bytes: usize,
    /// Optional description.
    pub description: Option<String>,
}

/// The complete output for a single addrmap.
///
/// This struct collects all the information needed to generate Rust code
/// for an address map, including register types, instances, and memory regions.
#[derive(Clone, Debug, Default)]
pub struct GeneratedAddrMap {
    /// Addrmap name (used for struct and module names).
    pub name: String,
    /// Base address of this addrmap.
    pub base_address: usize,
    /// Register type definitions (for bitfields).
    pub register_types: Vec<GeneratedRegisterType>,
    /// Register instances.
    pub registers: Vec<GeneratedRegister>,
    /// Memory regions.
    pub memories: Vec<GeneratedMemory>,
}

//=============================================================================
// Code Generation
//=============================================================================

impl GeneratedAddrMap {
    /// Generate the complete Rust code for this addrmap.
    ///
    /// # Arguments
    ///
    /// * `crate_prefix` - Prefix for type references (e.g., "crate::my_module::")
    ///
    /// # Returns
    ///
    /// A string containing valid Rust code using tock-registers macros.
    pub fn generate_code(&self, crate_prefix: &str) -> String {
        let mut output = String::new();

        // Generate address constant
        let name_upper = snake_case(&self.name).to_uppercase();
        let addr = hex_const(self.base_address as u64);
        writeln!(output, "pub const {name_upper}_ADDR: u32 = {addr};").unwrap();

        // Generate memory region constants and pointers
        if !self.memories.is_empty() {
            self.generate_memory_constants(&mut output);
        }

        // Generate bitfields module
        let bitfields = self.generate_bitfields();
        if !bitfields.is_empty() {
            writeln!(output, "pub mod bits {{").unwrap();
            writeln!(
                output,
                "    //! Types that represent individual registers (bitfields)."
            )
            .unwrap();
            writeln!(output, "    use tock_registers::register_bitfields;").unwrap();
            write!(output, "{bitfields}").unwrap();
            writeln!(output, "}}").unwrap();
        }

        // Generate register structs module
        let reg_structs = self.generate_register_structs(crate_prefix);
        if !reg_structs.is_empty() {
            writeln!(output, "pub mod regs {{").unwrap();
            writeln!(output, "    //! Types that represent registers.").unwrap();
            writeln!(output, "    use tock_registers::register_structs;").unwrap();
            write!(output, "{reg_structs}").unwrap();
            writeln!(output, "}}").unwrap();
        }

        output
    }

    /// Generate memory region constants and pointers.
    fn generate_memory_constants(&self, output: &mut String) {
        // Sort memories by offset for deterministic output
        let mut sorted_memories: Vec<_> = self.memories.iter().collect();
        sorted_memories.sort_by_key(|m| m.offset);

        writeln!(output).unwrap();
        writeln!(output, "// Memory regions").unwrap();
        for mem in sorted_memories {
            let mem_upper = snake_case(&mem.name).to_uppercase();
            let absolute_addr = self.base_address + mem.offset;
            let addr_hex = hex_const(absolute_addr as u64);
            let size_hex = hex_const(mem.size_bytes as u64);

            // Generate offset constant
            let offset_hex = hex_const(mem.offset as u64);
            writeln!(output, "pub const {mem_upper}_OFFSET: u32 = {offset_hex};").unwrap();
            // Generate size constant
            writeln!(output, "pub const {mem_upper}_SIZE: usize = {size_hex};").unwrap();
            // Generate pointer constant
            writeln!(
                output,
                "pub const {mem_upper}_PTR: *mut u8 = {addr_hex} as *mut u8;"
            )
            .unwrap();
        }
    }

    /// Generate `register_bitfields!` macro invocations for all register types.
    ///
    /// Register types are grouped by width (u8, u16, u32, u64) and each width
    /// gets its own `register_bitfields!` block.
    fn generate_bitfields(&self) -> String {
        // Group register types by width
        let mut tokens_by_width: std::collections::BTreeMap<u8, String> =
            std::collections::BTreeMap::new();

        // Sort register types alphabetically for deterministic output
        let mut sorted_types: Vec<_> = self.register_types.iter().collect();
        sorted_types.sort_by(|a, b| a.name.cmp(&b.name));

        for rt in sorted_types {
            if rt.fields.is_empty() {
                continue;
            }
            // Skip types with only one field that spans the whole register
            // (no meaningful bitfield decomposition)
            if rt.fields.len() == 1
                && rt.fields[0].offset == 0
                && rt.fields[0].width == rt.width as usize
                && rt.fields[0].enum_values.is_empty()
            {
                continue;
            }

            let name = camel_case(&rt.name);
            let mut field_tokens = format!("        pub {name} [\n");

            for field in &rt.fields {
                // Add description as doc comment if present
                if let Some(desc) = &field.description {
                    for line in desc.lines() {
                        writeln!(field_tokens, "            /// {line}").unwrap();
                    }
                }

                let field_name = camel_case(&field.name);
                let offset = field.offset;
                let width = field.width;

                if field.enum_values.is_empty() {
                    writeln!(
                        field_tokens,
                        "            {field_name} OFFSET({offset}) NUMBITS({width}) [],"
                    )
                    .unwrap();
                } else {
                    writeln!(
                        field_tokens,
                        "            {field_name} OFFSET({offset}) NUMBITS({width}) ["
                    )
                    .unwrap();
                    for (variant_name, variant_value) in &field.enum_values {
                        let variant_ident = camel_case(variant_name);
                        let variant_val = hex_const(*variant_value);
                        writeln!(
                            field_tokens,
                            "                {variant_ident} = {variant_val},"
                        )
                        .unwrap();
                    }
                    writeln!(field_tokens, "            ],").unwrap();
                }
            }

            writeln!(field_tokens, "        ],").unwrap();

            // Add to the appropriate width group
            tokens_by_width
                .entry(rt.width)
                .or_default()
                .push_str(&field_tokens);
        }

        if tokens_by_width.is_empty() {
            return String::new();
        }

        let mut output = String::new();

        // Generate separate register_bitfields! blocks for each width
        for (width, tokens) in tokens_by_width {
            let width_type = match width {
                8 => "u8",
                16 => "u16",
                64 => "u64",
                _ => "u32",
            };
            writeln!(output, "    register_bitfields! {{").unwrap();
            writeln!(output, "        {width_type},").unwrap();
            write!(output, "{tokens}").unwrap();
            writeln!(output, "    }}").unwrap();
        }

        output
    }

    /// Generate `register_structs!` macro invocation for register instances.
    ///
    /// Handles:
    /// - Deduplication of registers at the same offset (merging R/W capabilities)
    /// - Reserved padding between registers
    /// - Array registers
    /// - Correct width-based type selection (u8/u16/u32/u64)
    fn generate_register_structs(&self, crate_prefix: &str) -> String {
        if self.registers.is_empty() {
            return String::new();
        }

        let struct_name = camel_case(&self.name);
        let mut output = String::new();
        writeln!(output, "    register_structs! {{").unwrap();
        writeln!(output, "        pub {struct_name} {{").unwrap();

        let mut next_offset: usize = 0;
        let mut reserved_count = 0;

        // Sort registers by offset
        let mut sorted_regs = self.registers.clone();
        sorted_regs.sort_by_key(|r| r.offset);

        // Deduplicate registers at the same offset by merging read/write capabilities.
        // This handles cases like TX_DATA_PORT (write-only) and RX_DATA_PORT (read-only)
        // both at offset 0x8 in i3c - they become a single ReadWrite register.
        let mut deduped_regs: Vec<GeneratedRegister> = Vec::new();
        for reg in sorted_regs {
            if let Some(last) = deduped_regs.last_mut() {
                if last.offset == reg.offset {
                    // Merge: combine read/write capabilities, keep first name and type
                    last.can_read = last.can_read || reg.can_read;
                    last.can_write = last.can_write || reg.can_write;
                    continue;
                }
            }
            deduped_regs.push(reg);
        }

        for reg in &deduped_regs {
            let reg_offset = reg.offset;

            // Add reserved padding if needed
            if reg_offset > next_offset {
                writeln!(
                    output,
                    "            (0x{next_offset:x} => _reserved{reserved_count}),"
                )
                .unwrap();
                reserved_count += 1;
            }

            let name = snake_case(&reg.name);
            let reg_type = if reg.can_read && reg.can_write {
                "ReadWrite"
            } else if reg.can_read {
                "ReadOnly"
            } else {
                "WriteOnly"
            };

            // Map register width to Rust type
            let width_type = match reg.width {
                8 => "u8",
                16 => "u16",
                64 => "u64",
                _ => "u32", // Default to u32 for 32-bit and any other width
            };

            let has_bitfield = reg.type_name.is_some()
                && self.register_types.iter().any(|rt| {
                    Some(&rt.name) == reg.type_name.as_ref()
                        && !(rt.fields.len() == 1
                            && rt.fields[0].offset == 0
                            && rt.fields[0].width == rt.width as usize
                            && rt.fields[0].enum_values.is_empty())
                        && !rt.fields.is_empty()
                });

            let type_str = if has_bitfield {
                let type_name = camel_case(reg.type_name.as_ref().unwrap());
                format!(
                    "tock_registers::registers::{reg_type}<{width_type}, {crate_prefix}bits::{type_name}::Register>"
                )
            } else {
                format!("tock_registers::registers::{reg_type}<{width_type}>")
            };

            let type_str = if let Some(size) = reg.array_size {
                if size > 1 {
                    format!("[{type_str}; {size}]")
                } else {
                    type_str
                }
            } else {
                type_str
            };

            writeln!(
                output,
                "            (0x{reg_offset:x} => pub {name}: {type_str}),"
            )
            .unwrap();

            // Calculate register size in bytes based on width
            let reg_byte_size = (reg.width as usize + 7) / 8;
            let reg_size = if let Some(size) = reg.array_size {
                reg_byte_size * size
            } else {
                reg_byte_size
            };
            next_offset = reg_offset + reg_size;
        }

        writeln!(output, "            (0x{next_offset:x} => @END),").unwrap();
        writeln!(output, "        }}").unwrap();
        writeln!(output, "    }}").unwrap();

        output
    }
}
