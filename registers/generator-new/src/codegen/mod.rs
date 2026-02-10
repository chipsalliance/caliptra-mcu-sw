// Licensed under the Apache-2.0 license

#![allow(dead_code)]
//! Main code generation logic for converting SystemRDL to tock-registers Rust code.
//!
//! This module contains:
//! - Type definitions for the internal SystemRDL representation
//! - Entry point functions for code generation
//!
//! The implementation is split across submodules:
//! - `parse`: Parsing SystemRDL AST into internal representation
//! - `generate`: Converting internal representation to Rust code

mod generate;
mod parse;

use anyhow::bail;
use mcu_registers_systemrdl_new::ast::{
    ArrayOrRange, BinaryOp, ComponentBody, ComponentBodyElem, ComponentInsts, ComponentType,
    ConstantExpr, ConstantExprContinue, ConstantPrimary, ConstantPrimaryBase, Description, EnumDef,
    ExplicitOrDefaultPropAssignment, ExplicitPropertyAssignment, IdentityOrPropKeyword,
    InstanceOrPropRef, ParamDef, ParamDefElem, ParamElem, PostPropAssignment, PrimaryLiteral,
    PropAssignmentRhs, PropertyAssignment, PropertyType, Root, UnaryOp,
};
use mcu_registers_systemrdl_new::FsFileSource;
use std::collections::HashMap;
use std::path::Path;

use crate::config::NameConfig;
use crate::output::{
    GeneratedAddrMap, GeneratedField, GeneratedMemory, GeneratedRegister, GeneratedRegisterType,
};
use crate::util::snake_case;
use crate::value::Value;

use crate::config::FilterConfig;

const TRUE: Integer = Integer { width: 1, value: 1 };
const FALSE: Integer = Integer { width: 1, value: 0 };

#[derive(Clone, Default)]
struct World {
    /// List of component children.
    child_components: Vec<ComponentIdx>,
    enums: Vec<Enum>,
    /// Holds all of the components so that they can be referenced by index.
    /// They can be added but never deleted.
    component_arena: Vec<AllComponent>,
    /// Holds all of the instances so that they can be referenced by index.
    /// They can be added but never deleted.
    instance_arena: Vec<Instance>,
    /// Current parameter scope for resolving parameter references.
    /// This is a stack of scopes - each entry is a map of parameter names to values.
    param_scope_stack: Vec<HashMap<String, Value>>,
}

type ComponentIdx = usize;
type InstanceIdx = usize;

#[derive(Clone)]
enum AllComponent {
    AddrMap(AddrMapType),
    Reg(RegisterType),
    RegFile(RegisterFileType),
    Field(FieldType),
    Mem(MemType),
}

impl AllComponent {
    fn as_addrmap_mut(&mut self) -> Option<&mut AddrMapType> {
        if let AllComponent::AddrMap(addrmap) = self {
            Some(addrmap)
        } else {
            None
        }
    }
    fn as_addrmap(&self) -> Option<&AddrMapType> {
        if let AllComponent::AddrMap(addrmap) = self {
            Some(addrmap)
        } else {
            None
        }
    }
}

#[derive(Clone, Default)]
struct Instance {
    name: String,
    offset: usize,
    width: usize,
    desc: Option<String>,
    array_size: Option<Vec<usize>>,
    type_idx: ComponentIdx,
    parent: Option<ComponentIdx>,
    children: Vec<InstanceIdx>,
    parameters: HashMap<String, Value>,
}

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

#[derive(Clone, Default)]
struct FieldType {
    parent: Option<ComponentIdx>,
    name: Option<String>,
    properties: HashMap<String, StringOrInt>,
    enums: Vec<Enum>,
    _fields: HashMap<String, ComponentIdx>, // just a placeholder
    _parameters: HashMap<String, ParamDefElem>, // just a placeholder
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

/// Represents a memory region (SRAM, tables, etc.)
#[derive(Clone, Default, Debug)]
struct MemType {
    parent: Option<ComponentIdx>,
    name: Option<String>,
    /// Number of entries in the memory
    entries: usize,
    /// Width of each entry in bits
    width: usize,
    properties: HashMap<String, StringOrInt>,
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

#[derive(Clone, Debug)]
struct FieldInstance {
    id: String,
    offset: usize,
    width: usize,
}

/// Represents an instance of a register within a regfile
#[derive(Clone, Debug)]
struct RegInstance {
    id: String,
    offset: usize,
    type_idx: ComponentIdx,
    array_size: Option<Vec<usize>>,
}

#[derive(Clone, Default)]
struct RegisterType {
    parent: Option<ComponentIdx>,
    name: Option<String>,
    fields: HashMap<String, ComponentIdx>,
    field_instances: Vec<FieldInstance>,
    enums: Vec<Enum>,
    properties: HashMap<String, StringOrInt>,
    parameters: HashMap<String, ParamDefElem>,
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

#[derive(Clone, Default)]
struct RegisterFileType {
    parent: Option<ComponentIdx>,
    name: String,
    fields: HashMap<String, ComponentIdx>,
    field_instances: Vec<FieldInstance>,
    reg_instances: Vec<RegInstance>,
    enums: Vec<Enum>,
    properties: HashMap<String, StringOrInt>,
    parameters: HashMap<String, ParamDefElem>,
}

impl std::fmt::Debug for RegisterFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Register {{ field_instances: {:?}, properties: {:?} }}",
            self.field_instances, self.properties
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

#[derive(Clone, Debug)]
enum StringOrInt {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Parameters {
    params: HashMap<String, PrimaryLiteral>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterDefinition {
    ty: PropertyType,
    default: PrimaryLiteral,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Integer {
    width: u8, // Verilog supports larger numbers, but we don't
    value: u64,
}

impl Integer {
    fn add(&self, val: u64) -> Integer {
        Integer {
            width: self.width,
            value: self.value + val,
        }
    }
}

#[derive(Clone, Debug)]
struct EnumValue {
    name: String,
    value: Integer,
}

#[derive(Clone, Debug)]
struct Enum {
    name: String,
    values: Vec<EnumValue>,
}

/// Component is the type of an instance.
trait Component {
    fn as_field(&self) -> Option<&FieldType> {
        None
    }
    fn name(&self) -> Option<&str>;
    fn component_type(&self) -> ComponentType;
    fn parent(&self) -> Option<ComponentIdx>;
    fn width(&self) -> usize;
    fn offset(&self) -> usize;
    fn fields(&self) -> &HashMap<String, ComponentIdx>;
    fn children(&self) -> &[ComponentIdx];
    fn enums(&self) -> &[Enum];
    fn properties(&self) -> &HashMap<String, StringOrInt>;
    fn parameters(&self) -> &HashMap<String, ParamDefElem>;
}

#[derive(Clone)]
struct RegisterInstance {
    name: String,
    offset: Option<usize>,
    width: usize,
    type_: ComponentIdx,
}

#[derive(Clone, Default)]
struct AddrMapType {
    name: String,
    offset: usize,
    width: usize,
    parent: Option<ComponentIdx>,
    children: Vec<ComponentIdx>,
    child_instances: Vec<InstanceIdx>,
    fields: HashMap<String, ComponentIdx>,
    enums: Vec<Enum>,
    properties: HashMap<String, StringOrInt>,
    parameters: HashMap<String, ParamDefElem>,
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

/// Parse RDL input and return debug representation (for testing).
#[allow(unused)]
pub fn generate_tock_registers(input: &str, _addrmaps: &[&str]) -> anyhow::Result<String> {
    let root = mcu_registers_systemrdl_new::parse(input)?;
    Ok(format!("{:?}", root))
}

/// Generate tock-registers code from an RDL file.
///
/// Uses default name configuration which strips common suffixes like `_csr`, `_reg`, etc.
pub fn generate_tock_registers_from_file(
    file: &Path,
    addrmaps: &[(&str, usize)],
) -> anyhow::Result<String> {
    generate_tock_registers_from_file_with_config(file, addrmaps, &NameConfig::with_defaults())
}

/// Generate tock-registers code from an RDL file with custom name configuration.
///
/// The `name_config` controls how addrmap names are transformed (e.g., stripping suffixes).
pub fn generate_tock_registers_from_file_with_config(
    file: &Path,
    addrmaps: &[(&str, usize)],
    name_config: &NameConfig,
) -> anyhow::Result<String> {
    generate_tock_registers_from_file_with_filter(file, addrmaps, name_config, &FilterConfig::new())
}

/// Generate tock-registers code from an RDL file with custom name and filter configuration.
///
/// The `name_config` controls how addrmap names are transformed (e.g., stripping suffixes).
/// The `filter_config` controls which registers/blocks are included or excluded.
pub fn generate_tock_registers_from_file_with_filter(
    file: &Path,
    addrmaps: &[(&str, usize)],
    name_config: &NameConfig,
    filter_config: &FilterConfig,
) -> anyhow::Result<String> {
    let src = FsFileSource::new();
    let root = Root::from_file(&src, file)?;

    let world = World::parse(&root)?;

    let mut output = String::new();

    for (addrmap_name, base_offset) in addrmaps.iter() {
        if let Some(result) = world.generate_addrmap_code_with_config(
            addrmap_name,
            *base_offset,
            name_config,
            filter_config,
        )? {
            output += &result;
        }
    }
    Ok(output)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
