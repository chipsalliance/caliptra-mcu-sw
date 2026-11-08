/*++
Licensed under the Apache-2.0 license.
--*/

use crate::{
    scope::{lookup_parameter, ParameterScope},
    token::Token,
    token_iter::TokenIter,
    value::PropertyType,
    RdlError, Result, Value,
};

#[derive(Clone, Copy)]
enum Operator {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

enum Expression {
    Value(Value),
    Not(Box<Self>),
    Negate(Box<Self>),
    Binary(Operator, Box<Self>, Box<Self>),
    Conditional(Box<Self>, Box<Self>, Box<Self>),
}

pub(crate) fn integer(value: Value) -> Result<'static, u64> {
    match value {
        Value::U64(value) => Ok(value),
        Value::Bits(value) => Ok(value.val()),
        Value::Bool(value) => Ok(u64::from(value)),
        value => Err(RdlError::UnexpectedPropertyType {
            expected_type: PropertyType::U64,
            value,
        }),
    }
}

pub(crate) fn evaluate<'a>(
    tokens: &mut TokenIter<'a>,
    parameters: Option<&ParameterScope<'_>>,
    ty: PropertyType,
) -> Result<'a, Value> {
    let value = Expression::parse(tokens, parameters, ty, 0)?.evaluate()?;
    match ty {
        PropertyType::U64 => Ok(Value::U64(integer(value)?)),
        PropertyType::Boolean => Ok(Value::Bool(integer(value)? != 0)),
        PropertyType::BooleanOrReference if !matches!(value, Value::Reference(_)) => {
            Ok(Value::Bool(integer(value)? != 0))
        }
        PropertyType::Bits | PropertyType::BitOrReference if matches!(value, Value::Bool(_)) => {
            Ok(Value::U64(integer(value)?))
        }
        PropertyType::Bits if matches!(value, Value::U64(_) | Value::Bits(_)) => Ok(value),
        PropertyType::BitOrReference
            if matches!(value, Value::U64(_) | Value::Bits(_) | Value::Reference(_)) =>
        {
            Ok(value)
        }
        PropertyType::BooleanOrReference => Ok(value),
        _ if value.property_type() == ty => Ok(value),
        _ => Err(RdlError::UnexpectedPropertyType {
            expected_type: ty,
            value,
        }),
    }
}

impl Expression {
    fn parse<'a>(
        tokens: &mut TokenIter<'a>,
        parameters: Option<&ParameterScope<'_>>,
        ty: PropertyType,
        minimum_precedence: u8,
    ) -> Result<'a, Self> {
        let mut left = match tokens.peek(0).clone() {
            Token::ParenOpen => {
                tokens.next();
                let expression = Self::parse(tokens, parameters, ty, 0)?;
                tokens.expect(Token::ParenClose)?;
                expression
            }
            Token::Not => {
                tokens.next();
                Self::Not(Box::new(Self::parse(tokens, parameters, ty, 8)?))
            }
            Token::Minus => {
                tokens.next();
                Self::Negate(Box::new(Self::parse(tokens, parameters, ty, 8)?))
            }
            Token::Plus => {
                tokens.next();
                Self::parse(tokens, parameters, ty, 8)?
            }
            Token::Number(value) => {
                tokens.next();
                Self::Value(Value::U64(value))
            }
            Token::Bits(value) => {
                tokens.next();
                Self::Value(Value::Bits(value))
            }
            Token::Identifier("true") => {
                tokens.next();
                Self::Value(Value::Bool(true))
            }
            Token::Identifier("false") => {
                tokens.next();
                Self::Value(Value::Bool(false))
            }
            Token::Identifier(name) if lookup_parameter(parameters, name).is_ok() => {
                tokens.next();
                Self::Value(lookup_parameter(parameters, name)?.clone())
            }
            _ => Self::Value(ty.parse_or_lookup(tokens, parameters)?),
        };
        loop {
            let (operator, precedence) = match tokens.peek(0) {
                Token::Or => (Operator::Or, 1),
                Token::And => (Operator::And, 2),
                Token::EqualEqual => (Operator::Eq, 3),
                Token::NotEquals => (Operator::Ne, 3),
                Token::Less => (Operator::Lt, 4),
                Token::LessEqual => (Operator::Le, 4),
                Token::Greater => (Operator::Gt, 4),
                Token::GreaterEqual => (Operator::Ge, 4),
                Token::ShiftLeft => (Operator::Shl, 5),
                Token::ShiftRight => (Operator::Shr, 5),
                Token::Plus => (Operator::Add, 6),
                Token::Minus => (Operator::Sub, 6),
                Token::Multiply => (Operator::Mul, 7),
                Token::Divide => (Operator::Div, 7),
                Token::Modulo => (Operator::Mod, 7),
                _ => break,
            };
            if precedence < minimum_precedence {
                break;
            }
            tokens.next();
            let right = Self::parse(tokens, parameters, ty, precedence + 1)?;
            left = Self::Binary(operator, Box::new(left), Box::new(right));
        }
        if minimum_precedence == 0 && *tokens.peek(0) == Token::QuestionMark {
            tokens.next();
            let yes = Self::parse(tokens, parameters, ty, 0)?;
            tokens.expect(Token::Colon)?;
            let no = Self::parse(tokens, parameters, ty, 0)?;
            left = Self::Conditional(Box::new(left), Box::new(yes), Box::new(no));
        }
        Ok(left)
    }

    fn evaluate(self) -> Result<'static, Value> {
        let invalid = || RdlError::InvalidExpression("invalid shift or division by zero".into());
        match self {
            Self::Value(value) => Ok(value),
            Self::Not(value) => Ok(Value::Bool(integer(value.evaluate()?)? == 0)),
            Self::Negate(value) => Ok(Value::U64(integer(value.evaluate()?)?.wrapping_neg())),
            Self::Conditional(condition, yes, no) => {
                if integer(condition.evaluate()?)? != 0 {
                    yes.evaluate()
                } else {
                    no.evaluate()
                }
            }
            Self::Binary(operator, left, right) => {
                let left = integer(left.evaluate()?)?;
                if matches!(operator, Operator::And) && left == 0 {
                    return Ok(Value::Bool(false));
                }
                if matches!(operator, Operator::Or) && left != 0 {
                    return Ok(Value::Bool(true));
                }
                let right = integer(right.evaluate()?)?;
                Ok(match operator {
                    Operator::Or => Value::Bool(right != 0),
                    Operator::And => Value::Bool(right != 0),
                    Operator::Eq => Value::Bool(left == right),
                    Operator::Ne => Value::Bool(left != right),
                    Operator::Lt => Value::Bool(left < right),
                    Operator::Le => Value::Bool(left <= right),
                    Operator::Gt => Value::Bool(left > right),
                    Operator::Ge => Value::Bool(left >= right),
                    Operator::Shl => Value::U64(
                        left.checked_shl(right.try_into().map_err(|_| invalid())?)
                            .ok_or_else(invalid)?,
                    ),
                    Operator::Shr => Value::U64(
                        left.checked_shr(right.try_into().map_err(|_| invalid())?)
                            .ok_or_else(invalid)?,
                    ),
                    Operator::Add => Value::U64(left.wrapping_add(right)),
                    Operator::Sub => Value::U64(left.wrapping_sub(right)),
                    Operator::Mul => Value::U64(left.wrapping_mul(right)),
                    Operator::Div => Value::U64(left.checked_div(right).ok_or_else(invalid)?),
                    Operator::Mod => Value::U64(left.checked_rem(right).ok_or_else(invalid)?),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_expression_precedence_and_short_circuit() {
        for (text, expected) in [
            ("2 + 3 * 4", 14),
            ("(2 + 3) * 4", 20),
            ("32 / 4 % 3", 2),
            ("32/4%3", 2),
            ("1 << 2 + 3", 32),
            ("32 >> 2", 8),
            ("!0 && 2 != 3 || 0", 1),
            ("2 <= 2 && 3 > 2 && 4 >= 3 && 1 < 2", 1),
            ("0 && (1 / 0)", 0),
            ("1 || (1 / 0)", 1),
            ("1 ? 28 + 2 : 1 / 0", 30),
            ("0 ? 1 / 0 : 1 ? 7 : 9", 7),
            ("-1 + 2", 1),
            ("+2 == 2", 1),
        ] {
            let mut tokens = TokenIter::from_str(text);
            assert_eq!(
                evaluate(&mut tokens, None, PropertyType::U64).unwrap(),
                Value::U64(expected),
                "{text}"
            );
            tokens.expect(Token::EndOfFile).unwrap();
        }
    }

    #[test]
    fn invalid_arithmetic_and_types_are_rejected() {
        for text in ["1 / 0", "1 % 0", "1 << 64", "1 >> 64"] {
            assert!(
                matches!(
                    evaluate(&mut TokenIter::from_str(text), None, PropertyType::U64),
                    Err(RdlError::InvalidExpression(_))
                ),
                "{text}"
            );
        }
        assert!(evaluate(
            &mut TokenIter::from_str("\"wrong\""),
            None,
            PropertyType::Bits
        )
        .is_err());
        assert!(evaluate(&mut TokenIter::from_str("rw"), None, PropertyType::U64).is_err());
    }

    #[test]
    fn conditional_access_types() {
        for (text, expected) in [
            ("1 ? rw : r", crate::AccessType::Rw),
            ("0 ? rw : r", crate::AccessType::R),
            ("true ? rw : r", crate::AccessType::Rw),
        ] {
            assert_eq!(
                evaluate(
                    &mut TokenIter::from_str(text),
                    None,
                    PropertyType::AccessType
                )
                .unwrap(),
                Value::AccessType(expected),
            );
        }
    }
}
