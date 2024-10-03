/*++
Licensed under the Apache-2.0 license.
--*/
use crate::schema as ureg;
use crate::schema::{RegisterBlock, RegisterBlockInstance};
use registers_systemrdl as systemrdl;
use registers_systemrdl::{ComponentType, ScopeType};
use std::fmt::Display;
use std::rc::Rc;
use systemrdl::{AccessType, InstanceRef, ParentScope, RdlError};
use ureg::{RegisterSubBlock, RegisterType};

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

fn translate_access_type(ty: systemrdl::AccessType) -> Result<ureg::FieldType, Error> {
    match ty {
        systemrdl::AccessType::Rw => Ok(ureg::FieldType::RW),
        systemrdl::AccessType::R => Ok(ureg::FieldType::RO),
        systemrdl::AccessType::W => Ok(ureg::FieldType::WO),
        systemrdl::AccessType::Rw1 => Ok(ureg::FieldType::RW),
        systemrdl::AccessType::W1 => Ok(ureg::FieldType::WO),
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

fn translate_enum(name: &str, enm: systemrdl::ParentScope) -> Result<ureg::Enum, Error> {
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
        variants.push(ureg::EnumVariant {
            name: variant.name.clone(),
            value: reset.val() as u32,
        })
    }
    Ok(ureg::Enum {
        name: Some(name.to_string()),
        variants,
        bit_width: width as u8,
    })
}

fn translate_field(iref: systemrdl::InstanceRef) -> Result<ureg::RegisterField, Error> {
    let wrap_err = |err: Error| Error::FieldError {
        field_name: iref.instance.name.clone(),
        err: Box::new(err),
    };
    expect_instance_type(iref.scope, ComponentType::Field.into()).map_err(wrap_err)?;
    let inst = iref.instance;

    let access_ty: AccessType = get_property_opt(&inst.scope, "sw")?.unwrap_or_default();

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
    let result = ureg::RegisterField {
        name: inst.name.clone(),
        ty: translate_access_type(access_ty).map_err(wrap_err)?,
        default_val: inst.reset.map(|b| b.val()).unwrap_or_default(),
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

fn translate_register(iref: systemrdl::InstanceRef) -> Result<ureg::Register, Error> {
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

    let ty = translate_register_ty(inst.type_name.clone(), iref.scope)?;

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
fn translate_register_ty(
    type_name: Option<String>,
    scope: ParentScope,
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
        match translate_field(field).map_err(wrap_err) {
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
    let mut result = vec![];
    for (name, subscope) in scope.type_iter() {
        if subscope.scope.ty == ComponentType::Reg.into() {
            result.push(translate_register_ty(Some(name.into()), subscope)?);
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

fn translate_block(iref: InstanceRef) -> Result<RegisterBlock, Error> {
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
                .push(translate_register_ty(Some(name.into()), ty).map_err(wrap_err)?);
        }
    }
    let mut next_offset = Some(0u64);
    for child in iref.scope.instance_iter() {
        if child.instance.scope.ty == ComponentType::Reg.into() {
            block
                .registers
                .push(Rc::new(translate_register(child).map_err(wrap_err)?));
        } else if child.instance.scope.ty == ComponentType::RegFile.into() {
            let Some(start_offset) = child.instance.offset.or(next_offset) else {
                panic!("Offset not defined for register file {:?} and could not calculate automatically", child.instance.name);
            };
            let next_block = translate_block(child)?;
            next_offset = calculate_reg_size(&next_block).map(|size| start_offset + size);
            block.sub_blocks.push(RegisterSubBlock::Single {
                block: next_block,
                start_offset,
            });
        } else if child.instance.scope.ty == ComponentType::Signal.into()
            || child.instance.scope.ty == ComponentType::Mem.into()
        {
            // ignore
            next_offset = None;
        } else {
            panic!("Unknown component scope {:?}", child.instance.scope.ty);
        }
    }
    Ok(block)
}

pub fn translate_addrmap(addrmap: systemrdl::ParentScope) -> Result<Vec<RegisterBlock>, Error> {
    expect_instance_type(addrmap, ComponentType::AddrMap.into())?;
    let mut blocks = vec![];
    for iref in addrmap.instance_iter() {
        blocks.push(translate_block(iref)?);
    }
    Ok(blocks)
}
