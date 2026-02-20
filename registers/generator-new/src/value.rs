// Licensed under the Apache-2.0 license.s

use std::ops::{Neg, Not};

use anyhow::bail;
use mcu_registers_systemrdl_new::{
    ast::{
        AccessType, AddressingType, InstanceOrPropRef, InterruptType, OnReadType, OnWriteType,
        PrecedenceType,
    },
    Bits,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    U64(u64),
    Bool(bool),
    Bits(Bits),
    String(String),
    EnumReference(String, String),
    InstanceOrPropRef(InstanceOrPropRef),
    PrecedenceType(PrecedenceType),
    AccessType(AccessType),
    OnReadType(OnReadType),
    OnWriteType(OnWriteType),
    AddressingType(AddressingType),
    InterruptType(InterruptType),
}

impl Value {
    pub fn property_type(&self) -> PropertyType {
        match self {
            Value::U64(_) => PropertyType::U64,
            Value::Bool(_) => PropertyType::Boolean,
            Value::Bits(_) => PropertyType::Bits,
            Value::String(_) => PropertyType::String,
            Value::EnumReference(_, _) => PropertyType::EnumReference,
            Value::InstanceOrPropRef(_) => PropertyType::InstanceOrPropRef,
            Value::PrecedenceType(_) => PropertyType::PrecedenceType,
            Value::AccessType(_) => PropertyType::AccessType,
            Value::OnReadType(_) => PropertyType::OnReadType,
            Value::OnWriteType(_) => PropertyType::OnWriteType,
            Value::AddressingType(_) => PropertyType::AddressingType,
            Value::InterruptType(_) => PropertyType::FieldInterrupt,
        }
    }

    pub fn is_integral(&self) -> bool {
        matches!(self, Value::U64(_) | Value::Bool(_) | Value::Bits(_))
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Value::U64(v) => *v == 0,
            Value::Bool(v) => !(*v),
            Value::Bits(v) => v.val() == 0,
            _ => false,
        }
    }

    pub fn logical_not(&self) -> Value {
        if self.is_zero() {
            Value::Bool(true)
        } else {
            Value::Bool(false)
        }
    }

    pub fn is_bool(&self) -> bool {
        match self {
            Value::U64(v) => *v <= 1,
            Value::Bits(b) => b.w() == 1,
            Value::Bool(_) => true,
            _ => false,
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            Value::Bool(v) => *v,
            Value::U64(v) => *v != 0,
            Value::Bits(b) => b.val() != 0,
            _ => false,
        }
    }

    fn as_u64(&self) -> Result<u64, anyhow::Error> {
        match self {
            Value::U64(v) => Ok(*v),
            Value::Bool(v) => Ok(if *v { 1 } else { 0 }),
            Value::Bits(b) => Ok(b.val()),
            _ => bail!("Cannot convert {:?} to integer", self),
        }
    }

    pub(crate) fn try_andand(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_bool() && rhs.as_bool()))
    }

    pub(crate) fn try_oror(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_bool() || rhs.as_bool()))
    }

    pub(crate) fn try_lt(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? < rhs.as_u64()?))
    }

    pub(crate) fn try_gt(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? > rhs.as_u64()?))
    }

    pub(crate) fn try_lte(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? <= rhs.as_u64()?))
    }

    pub(crate) fn try_gte(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? >= rhs.as_u64()?))
    }

    pub(crate) fn try_eq(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? == rhs.as_u64()?))
    }

    pub(crate) fn try_neq(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::Bool(self.as_u64()? != rhs.as_u64()?))
    }

    pub(crate) fn try_rshift(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()? >> rhs.as_u64()?))
    }

    pub(crate) fn try_lshift(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()? << rhs.as_u64()?))
    }

    pub(crate) fn try_and(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()? & rhs.as_u64()?))
    }

    pub(crate) fn try_or(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()? | rhs.as_u64()?))
    }

    pub(crate) fn try_xor(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()? ^ rhs.as_u64()?))
    }

    pub(crate) fn try_xnor(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(!(self.as_u64()? ^ rhs.as_u64()?)))
    }

    pub(crate) fn try_times(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()?.wrapping_mul(rhs.as_u64()?)))
    }

    pub(crate) fn try_divide(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        let b = rhs.as_u64()?;
        if b == 0 {
            bail!("Division by zero");
        }
        Ok(Value::U64(self.as_u64()? / b))
    }

    pub(crate) fn try_modulus(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        let b = rhs.as_u64()?;
        if b == 0 {
            bail!("Modulus by zero");
        }
        Ok(Value::U64(self.as_u64()? % b))
    }

    pub(crate) fn try_add(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()?.wrapping_add(rhs.as_u64()?)))
    }

    pub(crate) fn try_sub(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()?.wrapping_sub(rhs.as_u64()?)))
    }

    pub(crate) fn try_pow(&self, rhs: &Value) -> Result<Value, anyhow::Error> {
        Ok(Value::U64(self.as_u64()?.pow(rhs.as_u64()? as u32)))
    }
}

impl Not for Value {
    type Output = Value;
    fn not(self) -> Self::Output {
        match self {
            Value::U64(v) => Value::U64(!v),
            Value::Bits(v) => Value::Bits(!v),
            Value::Bool(v) => Value::Bool(!v),
            _ => panic!("Cannot not non-integral value"),
        }
    }
}

impl Neg for Value {
    type Output = Value;
    fn neg(self) -> Self::Output {
        match self {
            Value::U64(v) => Value::U64(v.wrapping_neg()),
            Value::Bits(v) => Value::Bits(v.wrapping_neg()),
            Value::Bool(v) => Value::Bool(!v),
            _ => panic!("Cannot negate non-integral value"),
        }
    }
}

impl From<u64> for Value {
    fn from(val: u64) -> Self {
        Value::U64(val)
    }
}
impl From<bool> for Value {
    fn from(val: bool) -> Self {
        Value::Bool(val)
    }
}
impl From<Bits> for Value {
    fn from(val: Bits) -> Self {
        Value::Bits(val)
    }
}
impl From<String> for Value {
    fn from(val: String) -> Self {
        Value::String(val)
    }
}
impl From<&str> for Value {
    fn from(val: &str) -> Self {
        Value::String(val.into())
    }
}
impl From<PrecedenceType> for Value {
    fn from(val: PrecedenceType) -> Self {
        Value::PrecedenceType(val)
    }
}
impl From<AccessType> for Value {
    fn from(val: AccessType) -> Self {
        Value::AccessType(val)
    }
}
impl From<OnReadType> for Value {
    fn from(val: OnReadType) -> Self {
        Value::OnReadType(val)
    }
}
impl From<OnWriteType> for Value {
    fn from(val: OnWriteType) -> Self {
        Value::OnWriteType(val)
    }
}
impl From<AddressingType> for Value {
    fn from(val: AddressingType) -> Self {
        Value::AddressingType(val)
    }
}
impl From<InterruptType> for Value {
    fn from(val: InterruptType) -> Self {
        Value::InterruptType(val)
    }
}
impl TryFrom<Value> for u64 {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::U64(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::U64,
                value,
            ),
        }
    }
}
impl TryFrom<Value> for bool {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::Boolean,
                value,
            ),
        }
    }
}
impl TryFrom<Value> for Bits {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bits(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::Bits,
                value,
            ),
        }
    }
}
impl TryFrom<Value> for String {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::String(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::String,
                value,
            ),
        }
    }
}
impl TryFrom<Value> for AddressingType {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::AddressingType(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::AddressingType,
                value,
            ),
        }
    }
}
impl TryFrom<Value> for AccessType {
    type Error = anyhow::Error;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::AccessType(value) => Ok(value),
            _ => bail!(
                "Unexpected property type. Expected {:?} but got {:?}",
                PropertyType::AccessType,
                value,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropertyType {
    U64,
    Bits,
    Boolean,
    BooleanOrReference,
    BitOrReference,
    EnumReference,
    // has posedge | negedge | bothedge | level | nonsticky modifiers
    FieldInterrupt,
    PrecedenceType,
    String,
    AccessType,
    InstanceOrPropRef,
    OnReadType,
    OnWriteType,
    AddressingType,
}
