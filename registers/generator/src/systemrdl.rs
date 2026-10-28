/*++
Licensed under the Apache-2.0 license.
--*/
use crate::schema::{RegisterBlock, RegisterBlockInstance, RegisterSubBlock, RegisterType};
use crate::{Enum, EnumVariant, FieldType, Register, RegisterField, RegisterWidth};
use caliptra_mcu_registers_systemrdl::{self as systemrdl, Value};
use caliptra_mcu_registers_systemrdl::{ComponentType, ScopeType};
use std::fmt::Display;
use std::rc::Rc;
use systemrdl::{AccessType, InstanceRef, ParentScope, RdlError};

#[derive(Clone, Copy, Default)]
pub enum OnWriteSemantics {
    #[default]
    SystemRdl,
    /// Preserve snapshots generated before onwrite properties were interpreted.
    Legacy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnexpectedScopeType {
        expected: systemrdl::ScopeType,
        actual: systemrdl::ScopeType,
    },
    AddressTooLarge(u64),
    OffsetNotDefined,
    WidthNotDefined,
    ValueNotDefined,
    FieldsCannotHaveMultipleDimensions,
    UnsupportedRegWidth(u64),
    AccessTypeNaUnsupported,
    ResetValueOnRegisterUnsupported,
    RdlError(systemrdl::RdlError<'static>),
    BlockError {
        block_name: String,
        err: Box<Error>,
    },
    FieldError {
        field_name: String,
        err: Box<Error>,
    },
    RegisterError {
        register_name: String,
        err: Box<Error>,
    },
    RegisterTypeError {
        register_type_name: String,
        err: Box<Error>,
    },
    EnumError {
        enum_name: String,
        err: Box<Error>,
    },
    EnumVariantError {
        variant_name: String,
        err: Box<Error>,
    },
}
impl Error {
    pub fn root_cause(&self) -> &Error {
        match self {
            Self::BlockError { err, .. } => err.root_cause(),
            Self::FieldError { err, .. } => err.root_cause(),
            Self::RegisterError { err, .. } => err.root_cause(),
            Self::RegisterTypeError { err, .. } => err.root_cause(),
            Self::EnumError { err, .. } => err.root_cause(),
            Self::EnumVariantError { err, .. } => err.root_cause(),
            err => err,
        }
    }
}
impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedScopeType { expected, actual } => {
                write!(f, "Expect scope of type {expected:?} but was {actual:?}")
            }
            Self::AddressTooLarge(addr) => write!(f, "Address {addr:#x?} too large"),
            Self::OffsetNotDefined => write!(f, "offset was not defined"),
            Self::WidthNotDefined => write!(f, "width was not defined"),
            Self::ValueNotDefined => write!(f, "value was not defined"),
            Self::FieldsCannotHaveMultipleDimensions => {
                write!(f, "fields cannot have multiple dimensions")
            }
            Self::UnsupportedRegWidth(w) => write!(f, "Unsupported register width {w}"),
            Self::AccessTypeNaUnsupported => write!(f, "AccessType 'na' is not supported"),
            Self::ResetValueOnRegisterUnsupported => {
                write!(f, "reset value on register is unsupported")
            }
            Self::RdlError(err) => write!(f, "systemrdl error: {err}"),
            Self::BlockError { block_name, err } => write!(f, "block {block_name:?} {err}"),
            Self::FieldError { field_name, err } => write!(f, "field {field_name:?} {err}"),
            Self::RegisterError { register_name, err } => {
                write!(f, "register {register_name:?} {err}")
            }
            Self::RegisterTypeError {
                register_type_name,
                err,
            } => {
                write!(f, "reg_type {register_type_name:?} {err}")
            }
            Self::EnumError { enum_name, err } => write!(f, "enum {enum_name:?} {err}"),
            Self::EnumVariantError { variant_name, err } => {
                write!(f, "variant {variant_name:?} {err}")
            }
        }
    }
}

fn unpad_description(desc: &str) -> String {
    let ltrim = desc
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.find(|c| c != ' '))
        .min()
        .flatten()
        .unwrap_or(0);
    let mut lines = vec![];
    for l in desc.lines() {
        let trim_start = usize::min(ltrim, l.find(|c| c != ' ').unwrap_or(0));
        lines.push(&l[trim_start..]);
    }
    while let Some(line) = lines.last() {
        if !line.trim().is_empty() {
            break;
        }
        lines.pop();
    }
    lines.join("\n")
}

fn get_property_opt<T: TryFrom<systemrdl::Value, Error = RdlError<'static>>>(
    scope: &systemrdl::Scope,
    name: &'static str,
) -> Result<Option<T>, Error> {
    scope.property_val_opt::<T>(name).map_err(Error::RdlError)
}

fn expect_instance_type(scope: systemrdl::ParentScope, ty: ScopeType) -> Result<(), Error> {
    if scope.scope.ty != ty {
        Err(Error::UnexpectedScopeType {
            expected: ty,
            actual: scope.scope.ty,
        })
    } else {
        Ok(())
    }
}

fn translate_access_type(ty: systemrdl::AccessType) -> Result<FieldType, Error> {
    match ty {
        systemrdl::AccessType::Rw => Ok(FieldType::RW),
        systemrdl::AccessType::R => Ok(FieldType::RO),
        systemrdl::AccessType::W => Ok(FieldType::WO),
        systemrdl::AccessType::Rw1 => Ok(FieldType::RW),
        systemrdl::AccessType::W1 => Ok(FieldType::WO),
        systemrdl::AccessType::Na => Err(Error::AccessTypeNaUnsupported),
    }
}

fn field_width(field: &systemrdl::Instance) -> Result<u64, Error> {
    if field.dimension_sizes.is_empty() {
        return Ok(field
            .scope
            .property_val_opt("fieldwidth")
            .ok()
            .flatten()
            .unwrap_or(1u64));
    }
    if field.dimension_sizes.len() > 1 {
        return Err(Error::FieldsCannotHaveMultipleDimensions);
    }
    Ok(field.dimension_sizes[0])
}

fn translate_enum(name: &str, enm: systemrdl::ParentScope) -> Result<Enum, Error> {
    let wrap_err = |err: Error| Error::EnumError {
        enum_name: name.into(),
        err: Box::new(err),
    };
    expect_instance_type(enm, ComponentType::Enum.into()).map_err(wrap_err)?;
    let mut variants = vec![];
    let mut width = 0;
    for variant in enm.scope.instances.iter() {
        let wrap_err = |err: Error| {
            wrap_err(Error::EnumVariantError {
                variant_name: variant.name.clone(),
                err: Box::new(err),
            })
        };
        if variant.scope.ty != ComponentType::EnumVariant.into() {
            continue;
        }
        let Some(reset) = variant.reset else {
            return Err(wrap_err(Error::ValueNotDefined));
        };
        width = u64::max(width, reset.w());
        variants.push(EnumVariant {
            name: variant.name.clone(),
            value: reset.val() as u32,
        })
    }
    Ok(Enum {
        name: Some(name.to_string()),
        variants,
        bit_width: width as u8,
    })
}

fn translate_field(
    iref: systemrdl::InstanceRef,
    semantics: OnWriteSemantics,
) -> Result<RegisterField, Error> {
    let wrap_err = |err: Error| Error::FieldError {
        field_name: iref.instance.name.clone(),
        err: Box::new(err),
    };
    expect_instance_type(iref.scope, ComponentType::Field.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let access_ty: AccessType = get_property_opt(&inst.scope, "sw")?.unwrap_or_default();
    let mut field_type = translate_access_type(access_ty).map_err(wrap_err)?;

    let onwrite = match semantics {
        OnWriteSemantics::SystemRdl => {
            get_property_opt::<systemrdl::OnWriteType>(&inst.scope, "onwrite")?
        }
        OnWriteSemantics::Legacy => None,
    };
    if get_property_opt::<bool>(&inst.scope, "woclr")? == Some(true)
        || onwrite == Some(systemrdl::OnWriteType::WoClr)
    {
        field_type = FieldType::W1C;
    } else if get_property_opt::<bool>(&inst.scope, "woset")? == Some(true)
        || onwrite == Some(systemrdl::OnWriteType::WoSet)
    {
        field_type = FieldType::W1S;
    } else if get_property_opt::<bool>(&inst.scope, "wclr")? == Some(true)
        || onwrite == Some(systemrdl::OnWriteType::WClr)
    {
        field_type = FieldType::WC;
    }

    let enum_type =
        if let Ok(Some(systemrdl::EnumReference(eref))) = inst.scope.property_val_opt("encode") {
            if let Some(enm) = iref.scope.lookup_typedef(&eref) {
                Some(Rc::new(translate_enum(&eref, enm).map_err(wrap_err)?))
            } else {
                None
            }
        } else {
            None
        };

    let description: String = inst
        .scope
        .property_val_opt("desc")
        .unwrap()
        .unwrap_or_default();

    // First try to get the reset value from the "reset" property in the field's scope,
    // then fall back to the Instance's reset field (used for assignment syntax like FIELD = value)
    let default_val = inst
        .scope
        .property_val_opt::<systemrdl::Bits>("reset")
        .ok()
        .flatten()
        .map(|b| b.val())
        .or_else(|| inst.reset.map(|b| b.val()))
        .unwrap_or_default();

    let result = RegisterField {
        name: inst.name.clone(),
        ty: field_type,
        default_val,
        comment: unpad_description(&description),
        enum_type,
        position: inst
            .offset
            .ok_or(Error::OffsetNotDefined)
            .map_err(wrap_err)? as u8,
        width: field_width(inst).map_err(wrap_err)? as u8,
    };

    Ok(result)
}

fn translate_register(
    iref: systemrdl::InstanceRef,
    semantics: OnWriteSemantics,
) -> Result<Register, Error> {
    let wrap_err = |err: Error| Error::RegisterError {
        register_name: iref.instance.name.clone(),
        err: Box::new(err),
    };

    expect_instance_type(iref.scope, ComponentType::Reg.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let description: String = inst
        .scope
        .property_val_opt("desc")
        .unwrap()
        .unwrap_or_default();

    if inst.reset.is_some() {
        return Err(wrap_err(Error::ResetValueOnRegisterUnsupported));
    }

    let type_name = if inst.alias_of.is_some() {
        Some(inst.name.clone())
    } else {
        inst.type_name.clone()
    };
    let ty = translate_register_ty(type_name, iref.scope, semantics)?;

    let result = crate::schema::Register {
        name: inst.name.clone(),
        offset: inst
            .offset
            .ok_or(Error::OffsetNotDefined)
            .map_err(wrap_err)?,
        default_val: ty.fields.iter().fold(0, |reset, field| {
            let width_mask = (1 << field.width) - 1;
            reset | ((field.default_val & width_mask) << field.position)
        }),
        comment: unpad_description(&description),
        array_dimensions: inst.dimension_sizes.clone(),
        ty,
    };

    Ok(result)
}

// Translates a memory into a register array
fn translate_mem(iref: systemrdl::InstanceRef, start_offset: u64) -> Result<Register, Error> {
    let wrap_err = |err: Error| Error::RegisterError {
        register_name: iref.instance.name.clone(),
        err: Box::new(err),
    };

    expect_instance_type(iref.scope, ComponentType::Mem.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let description: String = inst
        .scope
        .property_val_opt("desc")
        .unwrap()
        .unwrap_or_default();

    if inst.reset.is_some() {
        return Err(wrap_err(Error::ResetValueOnRegisterUnsupported));
    }

    let mut ty = RegisterType {
        name: inst.type_name.clone(),
        fields: vec![],
        width: RegisterWidth::_32,
    };

    if let Some(Value::U64(memwidth)) = iref.instance.scope.properties.get("memwidth") {
        ty.width = match *memwidth {
            8 => RegisterWidth::_8,
            16 => RegisterWidth::_16,
            32 => RegisterWidth::_32,
            64 => RegisterWidth::_64,
            128 => RegisterWidth::_128,
            _ => return Err(wrap_err(Error::UnsupportedRegWidth(*memwidth))),
        }
    };
    let mut double = 1;
    if ty.width == RegisterWidth::_128 {
        // hack: convert to four u32s
        ty.width = RegisterWidth::_32;
        double = 4;
    } else if ty.width == RegisterWidth::_64 {
        // hack: convert to two u32s
        ty.width = RegisterWidth::_32;
        double = 2;
    }
    let entries = match iref.instance.scope.properties.get("mementries") {
        Some(Value::U64(mementries)) => *mementries * double,
        _ => return Err(wrap_err(Error::ValueNotDefined)),
    };
    let access_type = match iref.instance.scope.properties.get("sw") {
        Some(Value::AccessType(AccessType::Rw)) => FieldType::RW,
        Some(Value::AccessType(AccessType::Rw1)) => FieldType::RW,
        Some(Value::AccessType(AccessType::R)) => FieldType::RO,
        Some(Value::AccessType(AccessType::W)) => FieldType::WO,
        Some(Value::AccessType(AccessType::W1)) => FieldType::WO,
        _ => FieldType::RW,
    };

    ty.fields.push(RegisterField {
        name: "single".to_string(),
        ty: access_type,
        default_val: 0,
        comment: "".to_string(),
        enum_type: None,
        position: 0,
        width: (ty.width.in_bytes() * 8) as u8,
    });

    let result = Register {
        name: inst.name.clone(),
        offset: inst.offset.unwrap_or(start_offset),
        default_val: 0,
        comment: unpad_description(&description),
        array_dimensions: vec![entries],
        ty: Rc::new(ty),
    };

    Ok(result)
}

fn translate_register_ty(
    type_name: Option<String>,
    scope: ParentScope,
    semantics: OnWriteSemantics,
) -> Result<Rc<crate::schema::RegisterType>, Error> {
    let wrap_err = |err: Error| {
        if let Some(ref type_name) = type_name {
            Error::RegisterTypeError {
                register_type_name: type_name.clone(),
                err: Box::new(err),
            }
        } else {
            err
        }
    };

    let regwidth = match get_property_opt(scope.scope, "regwidth").map_err(wrap_err)? {
        Some(8) => crate::schema::RegisterWidth::_8,
        Some(16) => crate::schema::RegisterWidth::_16,
        Some(32) => crate::schema::RegisterWidth::_32,
        Some(64) => crate::schema::RegisterWidth::_64,
        Some(128) => crate::schema::RegisterWidth::_128,
        Some(other) => return Err(wrap_err(Error::UnsupportedRegWidth(other))),
        None => crate::schema::RegisterWidth::_32,
    };

    let mut fields = vec![];
    for field in scope.instance_iter() {
        match translate_field(field, semantics).map_err(wrap_err) {
            Ok(field) => fields.push(field),
            Err(err) => {
                if matches!(err.root_cause(), Error::AccessTypeNaUnsupported) {
                    continue;
                } else {
                    return Err(err);
                }
            }
        }
    }
    Ok(Rc::new(crate::schema::RegisterType {
        name: type_name,
        fields,
        width: regwidth,
    }))
}

pub fn translate_types(scope: systemrdl::ParentScope) -> Result<Vec<Rc<RegisterType>>, Error> {
    translate_types_with_semantics(scope, OnWriteSemantics::SystemRdl)
}

pub fn translate_types_with_semantics(
    scope: systemrdl::ParentScope,
    semantics: OnWriteSemantics,
) -> Result<Vec<Rc<RegisterType>>, Error> {
    let mut result = vec![];
    for (name, subscope) in scope.type_iter() {
        if subscope.scope.ty == ComponentType::Reg.into() {
            result.push(translate_register_ty(
                Some(name.into()),
                subscope,
                semantics,
            )?);
        }
    }
    Ok(result)
}

fn prod(nums: &[u64]) -> u64 {
    if nums.is_empty() {
        1
    } else {
        nums.iter().product()
    }
}

/// Calculates offset automatically.
fn calculate_reg_size(block: &RegisterBlock) -> Option<u64> {
    block
        .registers
        .iter()
        .map(|r| r.offset + r.ty.width.in_bytes() * prod(&r.array_dimensions))
        .max()
}

fn calculate_mem_size(iref: systemrdl::InstanceRef) -> u64 {
    let bits = match iref.instance.scope.properties.get("memwidth") {
        Some(Value::U64(memwidth)) => *memwidth,
        _ => 32,
    };
    let entries = match iref.instance.scope.properties.get("mementries") {
        Some(Value::U64(mementries)) => *mementries,
        _ => panic!("No mementries found for memory"),
    };
    bits / 8 * entries
}

fn translate_block(
    iref: InstanceRef,
    semantics: OnWriteSemantics,
) -> Result<Option<RegisterBlock>, Error> {
    let wrap_err = |err: Error| Error::BlockError {
        block_name: iref.instance.name.clone(),
        err: Box::new(err),
    };
    let inst = iref.instance;
    let mut block = RegisterBlock {
        name: inst.name.clone(),
        ..Default::default()
    };
    if let Some(addr) = inst.offset {
        block.instances.push(RegisterBlockInstance {
            name: inst.name.clone(),
            address: u32::try_from(addr).map_err(|_| wrap_err(Error::AddressTooLarge(addr)))?,
        });
    }
    for (name, ty) in iref.scope.type_iter() {
        if ty.scope.ty == ComponentType::Reg.into() {
            block
                .declared_register_types
                .push(translate_register_ty(Some(name.into()), ty, semantics).map_err(wrap_err)?);
        }
    }

    // special cases: this is a single memory or register instance
    if iref.instance.scope.ty == ComponentType::Mem.into() {
        let mut memory = translate_mem(iref, 0).map_err(wrap_err)?;
        memory.offset = 0;
        block.registers.push(Rc::new(memory));
        return Ok(Some(block));
    } else if iref.instance.scope.ty == ComponentType::Reg.into() {
        let child = iref;
        let mut reg = translate_register(child, semantics).map_err(wrap_err)?;
        if inst.offset.is_some() {
            reg.offset = 0; // the offset will be built into the block
        }
        block.registers.push(Rc::new(reg));
        return Ok(Some(block));
    }

    let mut next_offset = Some(0u64);
    for child in iref.scope.instance_iter() {
        if child.instance.scope.ty == ComponentType::Reg.into() {
            let reg = translate_register(child, semantics).map_err(wrap_err)?;
            block.registers.push(Rc::new(reg));
            next_offset = Some(
                child.instance.offset.unwrap()
                    + (child.instance.element_size()
                        * child.instance.dimension_sizes.iter().product::<u64>()),
            );
        } else if child.instance.scope.ty == ComponentType::Mem.into() {
            let mem_size = calculate_mem_size(child);
            let start_offset = child
                .instance
                .offset
                .or(next_offset.map(|o| {
                    // align according to RDL spec
                    o.next_multiple_of(mem_size.next_power_of_two())
                }))
                .expect("Offset not defined for memory and could not calculate automatically");
            next_offset = Some(start_offset + calculate_mem_size(child));
            block.registers.push(Rc::new(
                translate_mem(child, start_offset).map_err(wrap_err)?,
            ));
        } else if child.instance.scope.ty == ComponentType::RegFile.into() {
            let next_block =
                translate_block(child, semantics)?.expect("Register file must have registers");
            let next_block_size = calculate_reg_size(&next_block);
            let start_offset = child
                .instance
                .offset
                .or(next_offset.map(|o| {
                    if let Some(size) = next_block_size {
                        // align according to RDL spec
                        o.next_multiple_of(size.next_power_of_two())
                    } else {
                        o
                    }
                }))
                .expect(
                    "Offset not defined for register file and could not calculate automatically",
                );
            next_offset = next_block_size.map(|size| start_offset + size);
            block.sub_blocks.push(RegisterSubBlock::Single {
                block: next_block,
                start_offset,
            });
        } else if child.instance.scope.ty == ComponentType::Signal.into()
            || child.instance.scope.ty == ComponentType::Field.into()
        {
            // ignore
            //next_offset = None;
        } else if child.instance.scope.ty == ComponentType::AddrMap.into() {
            let next_block =
                translate_block(child, semantics)?.expect("Addrmap must have registers");
            let next_block_size = calculate_reg_size(&next_block);
            let start_offset = child
                .instance
                .offset
                .or(next_offset.map(|o| {
                    if let Some(size) = next_block_size {
                        // align according to RDL spec
                        o.next_multiple_of(size.next_power_of_two())
                    } else {
                        o
                    }
                }))
                .expect("Offset not defined for addrmap and could not calculate automatically");
            next_offset = next_block_size.map(|size| start_offset + size);
            block.sub_blocks.push(RegisterSubBlock::Single {
                block: next_block,
                start_offset,
            });
        } else {
            panic!("Unknown component scope {:?}", child.instance.scope.ty);
        }
    }
    if block.registers.is_empty() && block.sub_blocks.is_empty() {
        Ok(None)
    } else {
        Ok(Some(block))
    }
}

pub fn translate_addrmap(addrmap: systemrdl::ParentScope) -> Result<Vec<RegisterBlock>, Error> {
    translate_addrmap_with_semantics(addrmap, OnWriteSemantics::SystemRdl)
}

pub fn translate_addrmap_with_semantics(
    addrmap: systemrdl::ParentScope,
    semantics: OnWriteSemantics,
) -> Result<Vec<RegisterBlock>, Error> {
    expect_instance_type(addrmap, ComponentType::AddrMap.into())?;
    let mut blocks = vec![];
    for iref in addrmap.instance_iter() {
        if let Some(b) = translate_block(iref, semantics)? {
            blocks.push(b);
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Source<'a>(&'a str);

    impl systemrdl::FileSource for Source<'_> {
        fn read_to_string(&self, _: &std::path::Path) -> std::io::Result<&str> {
            Ok(self.0)
        }
    }

    fn parse(source: &str) -> systemrdl::Scope {
        systemrdl::Scope::parse_root(&Source(source), &["test.rdl".into()]).unwrap()
    }

    #[test]
    fn aliases_preserve_write_one_semantics_and_legacy_mode() {
        let scope = parse(
            r#"
            addrmap soc {
                reg status_t {field {sw = rw; onwrite = woclr;} pending[29:0] = 0;};
                status_t status @ 0x20;
                alias status status_t set_status @ 0x28;
                set_status.pending->onwrite = woset;
            } instance @ 0x20000000;
        "#,
        );
        let parent = scope.as_parent();
        let instance = parent.instance_iter().next().unwrap();
        let block = translate_block(instance, OnWriteSemantics::SystemRdl)
            .unwrap()
            .unwrap();
        assert_eq!(block.registers[0].ty.fields[0].ty, FieldType::W1C);
        assert_eq!(block.registers[1].ty.fields[0].ty, FieldType::W1S);
        assert_eq!(block.registers[0].ty.fields[0].width, 30);
        assert_eq!(block.registers[0].offset, 0x20);
        assert_eq!(block.registers[1].offset, 0x28);
        block.validate_and_dedup().unwrap();
        let legacy = translate_block(instance, OnWriteSemantics::Legacy)
            .unwrap()
            .unwrap();
        assert_eq!(legacy.registers[0].ty.fields[0].ty, FieldType::RW);
        assert_eq!(legacy.registers[1].ty.fields[0].ty, FieldType::RW);
    }

    #[test]
    fn standalone_memory_has_relative_offsets_and_full_64_bit_capacity() {
        let scope = parse(
            r#"
            mem packet #(longint unsigned ENTRIES = 4) {
                memwidth = 64; mementries = ENTRIES; sw = rw;
            };
            addrmap soc {
                external packet #(.ENTRIES(8192)) packet0 @ 0x30000000;
                external packet #(.ENTRIES(8192)) packet1 @ 0x30010000;
            };
        "#,
        );
        let parent = scope.as_parent();
        let blocks = translate_addrmap(parent.lookup_typedef("soc").unwrap()).unwrap();
        for (block, address) in blocks.iter().zip([0x30000000, 0x30010000]) {
            assert_eq!(block.instances[0].address, address);
            assert_eq!(block.registers.len(), 1);
            let memory = &block.registers[0];
            assert_eq!(memory.offset, 0);
            assert_eq!(memory.ty.width, RegisterWidth::_32);
            assert_eq!(memory.array_dimensions, [16384]);
            assert_eq!(
                memory.array_dimensions[0] * memory.ty.width.in_bytes(),
                0x10000
            );
        }
    }
}
