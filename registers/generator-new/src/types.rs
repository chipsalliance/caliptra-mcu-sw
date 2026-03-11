// Licensed under the Apache-2.0 license

//! Core data types for the SystemRDL code generator.
//!
//! This module contains the internal representation of a parsed SystemRDL design.
//! The [`World`] struct is the root container that holds all parsed components
//! and instances. Components are stored in an arena for efficient reference by index.
//!
//! ## Architecture Overview
//!
//! ```text
//! World
//! ├── component_arena: Vec<AllComponent>   # All component types
//! │   ├── AddrMap    # Address maps (top-level containers)
//! │   ├── Reg        # Register definitions
//! │   ├── RegFile    # Register file containers
//! │   ├── Field      # Bit fields within registers
//! │   └── Mem        # Memory regions (SRAM, tables)
//! │
//! ├── instance_arena: Vec<Instance>        # All instantiations
//! │   └── References component_arena by index
//! │
//! └── param_scope_stack: Vec<HashMap>      # Parameter resolution
//! ```
//!
//! ## Component Hierarchy
//!
//! - **AddrMap**: Top-level container, can contain registers, regfiles, nested addrmaps
//! - **RegFile**: Groups related registers together
//! - **Reg**: Individual register with fields
//! - **Field**: Bit field within a register (offset, width, access permissions)
//! - **Mem**: Memory region (SRAM, tables) with entries and width

use crate::value::Value;
use mcu_registers_systemrdl_new::ast::{ComponentType, ParamDefElem, PrimaryLiteral, PropertyType};
use std::collections::HashMap;

/// Index into the component arena.
pub type ComponentIdx = usize;

/// Index into the instance arena.
pub type InstanceIdx = usize;

/// Boolean true as an integer (1-bit, value 1).
pub const TRUE: Integer = Integer { width: 1, value: 1 };

/// Boolean false as an integer (1-bit, value 0).
pub const FALSE: Integer = Integer { width: 1, value: 0 };

//=============================================================================
// World - Root container for parsed RDL
//=============================================================================

/// The root container for a parsed SystemRDL design.
///
/// World uses arena allocation for components and instances, allowing efficient
/// cross-references via indices. This avoids lifetime issues that would arise
/// from using direct references.
#[derive(Clone, Default)]
pub struct World {
    /// Top-level component children (typically addrmaps).
    pub child_components: Vec<ComponentIdx>,

    /// Top-level enum definitions.
    pub enums: Vec<Enum>,

    /// Arena of all component types (registers, regfiles, addrmaps, fields, etc.).
    /// Components are added but never deleted, so indices remain stable.
    pub component_arena: Vec<AllComponent>,

    /// Arena of all component instances.
    /// Instances reference their type via ComponentIdx.
    pub instance_arena: Vec<Instance>,

    /// Stack of parameter scopes for resolving parameterized components.
    /// Each scope maps parameter names to their values.
    pub param_scope_stack: Vec<HashMap<String, Value>>,
}

//=============================================================================
// AllComponent - Enum of all component types
//=============================================================================

/// Unified enum for all SystemRDL component types.
///
/// This allows storing heterogeneous components in a single arena while
/// maintaining type safety through pattern matching.
#[derive(Clone)]
pub enum AllComponent {
    AddrMap(AddrMapType),
    Reg(RegisterType),
    RegFile(RegisterFileType),
    Field(FieldType),
    Mem(MemType),
}

impl AllComponent {
    /// Get mutable reference to contained AddrMapType, if this is an addrmap.
    pub fn as_addrmap_mut(&mut self) -> Option<&mut AddrMapType> {
        if let AllComponent::AddrMap(addrmap) = self {
            Some(addrmap)
        } else {
            None
        }
    }

    /// Get reference to contained AddrMapType, if this is an addrmap.
    pub fn as_addrmap(&self) -> Option<&AddrMapType> {
        if let AllComponent::AddrMap(addrmap) = self {
            Some(addrmap)
        } else {
            None
        }
    }
}

//=============================================================================
// Instance - Represents a placed component
//=============================================================================

/// An instance of a component at a specific offset.
///
/// Instances connect a component type (via type_idx) to a location in the
/// address space. Array instances have array_size set.
#[derive(Clone, Default)]
pub struct Instance {
    /// Instance name (e.g., "status_reg").
    pub name: String,

    /// Byte offset from parent's base address.
    pub offset: usize,

    /// Width in bytes (derived from component type).
    pub width: usize,

    /// Optional description from RDL.
    pub desc: Option<String>,

    /// For array instances, dimensions (e.g., [4] or [2,3]).
    pub array_size: Option<Vec<usize>>,

    /// Index into component_arena for this instance's type.
    pub type_idx: ComponentIdx,

    /// Parent component index (if nested).
    pub parent: Option<ComponentIdx>,

    /// Child instance indices.
    pub children: Vec<InstanceIdx>,

    /// Resolved parameters for this instance.
    pub parameters: HashMap<String, Value>,
}

//=============================================================================
// Component Trait - Common interface for all components
//=============================================================================

/// Common interface for all component types.
///
/// This trait provides uniform access to component properties regardless
/// of the specific component type.
pub trait Component {
    /// Get the component's name, if it has one.
    fn name(&self) -> Option<&str>;

    /// Get the component type (AddrMap, Reg, RegFile, Field, Mem).
    fn component_type(&self) -> ComponentType;

    /// Get the parent component index.
    fn parent(&self) -> Option<ComponentIdx>;

    /// Get the width in bits (for registers) or bytes (for memories).
    fn width(&self) -> usize;

    /// Get the offset within parent.
    fn offset(&self) -> usize;

    /// Get the fields defined in this component.
    fn fields(&self) -> &HashMap<String, ComponentIdx>;

    /// Get child component indices.
    fn children(&self) -> &[ComponentIdx];

    /// Get enum definitions within this component.
    fn enums(&self) -> &[Enum];

    /// Get property values.
    fn properties(&self) -> &HashMap<String, StringOrInt>;

    /// Get parameter definitions.
    fn parameters(&self) -> &HashMap<String, ParamDefElem>;

    /// Try to get this as a FieldType reference.
    fn as_field(&self) -> Option<&FieldType> {
        None
    }
}

//=============================================================================
// Implement Component trait for AllComponent
//=============================================================================

impl Component for AllComponent {
    fn name(&self) -> Option<&str> {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.name(),
            AllComponent::Reg(reg) => reg.name(),
            AllComponent::RegFile(regfile) => regfile.name(),
            AllComponent::Field(field) => field.name(),
            AllComponent::Mem(mem) => mem.name(),
        }
    }

    fn component_type(&self) -> ComponentType {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.component_type(),
            AllComponent::Reg(reg) => reg.component_type(),
            AllComponent::RegFile(regfile) => regfile.component_type(),
            AllComponent::Field(field) => field.component_type(),
            AllComponent::Mem(mem) => mem.component_type(),
        }
    }

    fn parent(&self) -> Option<ComponentIdx> {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.parent(),
            AllComponent::Reg(reg) => reg.parent(),
            AllComponent::RegFile(regfile) => regfile.parent(),
            AllComponent::Field(field) => field.parent(),
            AllComponent::Mem(mem) => mem.parent(),
        }
    }

    fn width(&self) -> usize {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.width(),
            AllComponent::Reg(reg) => reg.width(),
            AllComponent::RegFile(regfile) => regfile.width(),
            AllComponent::Field(field) => field.width(),
            AllComponent::Mem(mem) => mem.width(),
        }
    }

    fn offset(&self) -> usize {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.offset(),
            AllComponent::Reg(reg) => reg.offset(),
            AllComponent::RegFile(regfile) => regfile.offset(),
            AllComponent::Field(field) => field.offset(),
            AllComponent::Mem(_) => 0,
        }
    }

    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.fields(),
            AllComponent::Reg(reg) => reg.fields(),
            AllComponent::RegFile(regfile) => regfile.fields(),
            AllComponent::Field(field) => field.fields(),
            AllComponent::Mem(_) => {
                static EMPTY: std::sync::LazyLock<HashMap<String, ComponentIdx>> =
                    std::sync::LazyLock::new(HashMap::new);
                &EMPTY
            }
        }
    }

    fn children(&self) -> &[ComponentIdx] {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.children(),
            AllComponent::Reg(reg) => reg.children(),
            AllComponent::RegFile(regfile) => regfile.children(),
            AllComponent::Field(field) => field.children(),
            AllComponent::Mem(mem) => mem.children(),
        }
    }

    fn enums(&self) -> &[Enum] {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.enums(),
            AllComponent::Reg(reg) => reg.enums(),
            AllComponent::RegFile(regfile) => regfile.enums(),
            AllComponent::Field(field) => field.enums(),
            AllComponent::Mem(mem) => mem.enums(),
        }
    }

    fn properties(&self) -> &HashMap<String, StringOrInt> {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.properties(),
            AllComponent::Reg(reg) => reg.properties(),
            AllComponent::RegFile(regfile) => regfile.properties(),
            AllComponent::Field(field) => field.properties(),
            AllComponent::Mem(mem) => mem.properties(),
        }
    }

    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        match self {
            AllComponent::AddrMap(addrmap) => addrmap.parameters(),
            AllComponent::Reg(reg) => reg.parameters(),
            AllComponent::RegFile(regfile) => regfile.parameters(),
            AllComponent::Field(field) => field.parameters(),
            AllComponent::Mem(mem) => mem.parameters(),
        }
    }
}

//=============================================================================
// Integer - Verilog-style integer with width
//=============================================================================

/// A sized integer value, similar to Verilog integers.
#[derive(Clone, Debug, Copy)]
pub struct Integer {
    /// Width in bits (Verilog supports very large, but we limit to 64).
    pub width: u8,
    /// The integer value.
    pub value: u64,
}

impl Integer {
    /// Add a value to this integer, preserving width.
    pub fn add(&self, val: u64) -> Integer {
        Integer {
            width: self.width,
            value: self.value + val,
        }
    }
}

//=============================================================================
// Enum types
//=============================================================================

/// A single value in an enumeration.
#[derive(Clone, Debug)]
pub struct EnumValue {
    pub name: String,
    pub value: Integer,
}

/// An enumeration definition.
#[derive(Clone, Debug)]
pub struct Enum {
    pub name: String,
    pub values: Vec<EnumValue>,
}

//=============================================================================
// StringOrInt - Property value type
//=============================================================================

/// Property values can be either strings or integers.
#[derive(Clone, Debug)]
pub enum StringOrInt {
    String(String),
    Int(Integer),
}

impl std::fmt::Display for StringOrInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringOrInt::String(s) => write!(f, "{}", s),
            StringOrInt::Int(i) => write!(f, "{}", i.value),
        }
    }
}

//=============================================================================
// Parameters
//=============================================================================

/// Parameter set for a component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameters {
    pub params: HashMap<String, PrimaryLiteral>,
}

/// A parameter definition with type and default value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterDefinition {
    pub ty: PropertyType,
    pub default: PrimaryLiteral,
}

//=============================================================================
// FieldType - Bit field within a register
//=============================================================================

/// A bit field type definition.
#[derive(Clone, Default)]
pub struct FieldType {
    pub parent: Option<ComponentIdx>,
    pub name: Option<String>,
    pub properties: HashMap<String, StringOrInt>,
    pub enums: Vec<Enum>,
    pub _fields: HashMap<String, ComponentIdx>, // placeholder
    pub _parameters: HashMap<String, ParamDefElem>, // placeholder
}

impl Component for FieldType {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn as_field(&self) -> Option<&FieldType> {
        Some(self)
    }
    fn component_type(&self) -> ComponentType {
        ComponentType::Field
    }
    fn parent(&self) -> Option<ComponentIdx> {
        self.parent
    }
    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        &self._fields
    }
    fn width(&self) -> usize {
        0
    }
    fn offset(&self) -> usize {
        0
    }
    fn children(&self) -> &[ComponentIdx] {
        &[]
    }
    fn enums(&self) -> &[Enum] {
        &self.enums
    }
    fn properties(&self) -> &HashMap<String, StringOrInt> {
        &self.properties
    }
    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        &self._parameters
    }
}

//=============================================================================
// MemType - Memory region (SRAM, tables)
//=============================================================================

/// A memory region component (SRAM, tables, etc.).
#[derive(Clone, Default, Debug)]
pub struct MemType {
    pub parent: Option<ComponentIdx>,
    pub name: Option<String>,
    /// Number of entries in the memory.
    pub entries: usize,
    /// Width of each entry in bits.
    pub width: usize,
    pub properties: HashMap<String, StringOrInt>,
}

impl Component for MemType {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn component_type(&self) -> ComponentType {
        ComponentType::Mem
    }
    fn parent(&self) -> Option<ComponentIdx> {
        self.parent
    }
    fn width(&self) -> usize {
        self.width
    }
    fn offset(&self) -> usize {
        0
    }
    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        static EMPTY: std::sync::LazyLock<HashMap<String, ComponentIdx>> =
            std::sync::LazyLock::new(HashMap::new);
        &EMPTY
    }
    fn children(&self) -> &[ComponentIdx] {
        &[]
    }
    fn enums(&self) -> &[Enum] {
        &[]
    }
    fn properties(&self) -> &HashMap<String, StringOrInt> {
        &self.properties
    }
    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        static EMPTY: std::sync::LazyLock<HashMap<String, ParamDefElem>> =
            std::sync::LazyLock::new(HashMap::new);
        &EMPTY
    }
}

//=============================================================================
// FieldInstance - Placed field within a register
//=============================================================================

/// An instance of a field within a register.
#[derive(Clone, Debug)]
pub struct FieldInstance {
    /// Field name.
    pub id: String,
    /// Bit offset within the register.
    pub offset: usize,
    /// Width in bits.
    pub width: usize,
}

//=============================================================================
// RegInstance - Placed register within a regfile
//=============================================================================

/// An instance of a register within a regfile.
#[derive(Clone, Debug)]
pub struct RegInstance {
    /// Register name.
    pub id: String,
    /// Byte offset within the regfile.
    pub offset: usize,
    /// Index into component_arena for the register type.
    pub type_idx: ComponentIdx,
    /// For array instances, dimensions.
    pub array_size: Option<Vec<usize>>,
}

//=============================================================================
// RegisterType - Register definition
//=============================================================================

/// A register type definition.
#[derive(Clone, Default)]
pub struct RegisterType {
    pub parent: Option<ComponentIdx>,
    pub name: Option<String>,
    /// Named fields within this register.
    pub fields: HashMap<String, ComponentIdx>,
    /// Ordered list of field instances.
    pub field_instances: Vec<FieldInstance>,
    /// Enum definitions within this register.
    pub enums: Vec<Enum>,
    /// Property values.
    pub properties: HashMap<String, StringOrInt>,
    /// Parameter definitions.
    pub parameters: HashMap<String, ParamDefElem>,
}

impl std::fmt::Debug for RegisterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Register {{ field_instances: {:?}, properties: {:?} }}",
            self.field_instances, self.properties
        )
    }
}

impl Component for RegisterType {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn component_type(&self) -> ComponentType {
        ComponentType::Reg
    }
    fn parent(&self) -> Option<ComponentIdx> {
        self.parent
    }
    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        &self.fields
    }
    fn width(&self) -> usize {
        0
    }
    fn offset(&self) -> usize {
        0
    }
    fn children(&self) -> &[ComponentIdx] {
        &[]
    }
    fn enums(&self) -> &[Enum] {
        &[]
    }
    fn properties(&self) -> &HashMap<String, StringOrInt> {
        &self.properties
    }
    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        &self.parameters
    }
}

//=============================================================================
// RegisterFileType - Regfile definition
//=============================================================================

/// A register file type definition.
#[derive(Clone, Default)]
pub struct RegisterFileType {
    pub parent: Option<ComponentIdx>,
    pub name: String,
    /// Named fields (registers) within this regfile.
    pub fields: HashMap<String, ComponentIdx>,
    /// Field instances (not commonly used in regfiles).
    pub field_instances: Vec<FieldInstance>,
    /// Register instances within this regfile.
    pub reg_instances: Vec<RegInstance>,
    /// Enum definitions.
    pub enums: Vec<Enum>,
    /// Property values.
    pub properties: HashMap<String, StringOrInt>,
    /// Parameter definitions.
    pub parameters: HashMap<String, ParamDefElem>,
}

impl std::fmt::Debug for RegisterFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RegisterFile {{ reg_instances: {:?}, properties: {:?} }}",
            self.reg_instances, self.properties
        )
    }
}

impl Component for RegisterFileType {
    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }
    fn component_type(&self) -> ComponentType {
        ComponentType::RegFile
    }
    fn parent(&self) -> Option<ComponentIdx> {
        self.parent
    }
    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        &self.fields
    }
    fn width(&self) -> usize {
        0
    }
    fn offset(&self) -> usize {
        0
    }
    fn children(&self) -> &[ComponentIdx] {
        &[]
    }
    fn enums(&self) -> &[Enum] {
        &[]
    }
    fn properties(&self) -> &HashMap<String, StringOrInt> {
        &self.properties
    }
    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        &self.parameters
    }
}

//=============================================================================
// RegisterInstance (unused but kept for potential future use)
//=============================================================================

/// A register instance (currently unused).
#[derive(Clone)]
#[allow(dead_code)]
pub struct RegisterInstance {
    pub name: String,
    pub offset: Option<usize>,
    pub width: usize,
    pub type_: ComponentIdx,
}

//=============================================================================
// AddrMapType - Address map definition
//=============================================================================

/// An address map type definition.
///
/// Address maps are the top-level containers in SystemRDL. They can contain
/// registers, regfiles, nested addrmaps, and memory regions.
#[derive(Clone, Default)]
pub struct AddrMapType {
    pub name: String,
    pub offset: usize,
    pub width: usize,
    pub parent: Option<ComponentIdx>,
    /// Child component type indices.
    pub children: Vec<ComponentIdx>,
    /// Child instance indices.
    pub child_instances: Vec<InstanceIdx>,
    /// Named fields/registers.
    pub fields: HashMap<String, ComponentIdx>,
    /// Enum definitions.
    pub enums: Vec<Enum>,
    /// Property values.
    pub properties: HashMap<String, StringOrInt>,
    /// Parameter definitions.
    pub parameters: HashMap<String, ParamDefElem>,
}

impl Component for AddrMapType {
    fn name(&self) -> Option<&str> {
        Some(&self.name)
    }
    fn component_type(&self) -> ComponentType {
        ComponentType::AddrMap
    }
    fn parent(&self) -> Option<ComponentIdx> {
        self.parent
    }
    fn fields(&self) -> &HashMap<String, ComponentIdx> {
        &self.fields
    }
    fn width(&self) -> usize {
        self.width
    }
    fn offset(&self) -> usize {
        self.offset
    }
    fn children(&self) -> &[ComponentIdx] {
        &self.children
    }
    fn enums(&self) -> &[Enum] {
        &self.enums
    }
    fn properties(&self) -> &HashMap<String, StringOrInt> {
        &self.properties
    }
    fn parameters(&self) -> &HashMap<String, ParamDefElem> {
        &self.parameters
    }
}
