/*++
Licensed under the Apache-2.0 license.
--*/

use crate::schema::{Register, RegisterBlock, RegisterType, RegisterWidth, ValidatedRegisterBlock};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

fn tweak_keywords(s: &str) -> &str {
    match s {
        "as" => "as_",
        "break" => "break_",
        "const" => "const_",
        "continue" => "continue_",
        "crate" => "crate_",
        "else" => "else_",
        "fn" => "fn_",
        "for" => "for_",
        "if" => "if_",
        "impl" => "impl_",
        "in" => "in_",
        "let" => "let_",
        "loop" => "loop_",
        "match" => "match_",
        "mod" => "mod_",
        "move" => "move_",
        "mut" => "mut_",
        "pub" => "pub_",
        "ref" => "ref_",
        "return" => "return_",
        "self" => "self_",
        "Self" => "Self_",
        "static" => "static_",
        "struct" => "struct_",
        "super" => "super_",
        "trait" => "trait_",
        "true" => "true_",
        "type" => "type_",
        "unsafe" => "unsafe_",
        "use" => "use_",
        "where" => "where_",
        "while" => "while_",
        "async" => "async_",
        "await" => "await_",
        "dyn" => "dyn_",
        "abstract" => "abstract_",
        "become" => "become_",
        "box" => "box_",
        "do" => "do_",
        "final" => "final_",
        "macro" => "macro_",
        "override" => "override_",
        "priv" => "priv_",
        "typeof" => "typeof_",
        "unsized" => "unsized_",
        "virtual" => "virtual_",
        "yield" => "yield_",
        s => s,
    }
}

pub fn snake_case(name: &str) -> String {
    let mut result = String::new();
    if let Some(c) = name.chars().next() {
        if c.is_ascii_digit() {
            result.push('_');
        }
    }
    let mut prev = None;
    for c in name.chars() {
        if c.is_ascii_whitespace() || c.is_ascii_punctuation() {
            if prev != Some('_') {
                result.push('_');
            }
            prev = Some('_');
            continue;
        }
        if let Some(prev) = prev {
            if (prev.is_ascii_lowercase() || prev.is_ascii_digit()) && c.is_ascii_uppercase() {
                result.push('_');
            }
        }
        prev = Some(c);
        result.push(c.to_ascii_lowercase());
    }

    result = result.replace("so_cmgmt", "soc_mgmt"); // hack for SoC
    result = result.replace("i3_c", "i3c_").replace("__", "_"); // hack for I3C
    tweak_keywords(result.trim_end_matches('_')).to_string()
}

#[cfg(test)]
mod snake_case_tests {
    use super::*;

    #[test]
    fn test_snake_ident() {
        assert_eq!("_8_bits", snake_case("8 bits"));
        assert_eq!("_16_bits", snake_case("16_Bits"));
        assert_eq!("_16_bits", snake_case("16Bits"));
        assert_eq!("_16bits", snake_case("16bits"));
        assert_eq!("foo_bar_baz", snake_case("fooBarBaz"));
        assert_eq!("foo_bar_baz", snake_case("FooBarBaz"));
        assert_eq!("foo_bar_baz", snake_case("foo bar baz"));
        assert_eq!("foo_bar_baz", snake_case("foo_bar_baz"));
        assert_eq!("foo_bar_baz", snake_case("FOO BAR BAZ"));
        assert_eq!("foo_bar_baz", snake_case("FOO_BAR_BAZ"));
        assert_eq!("foo_bar_baz", snake_case("FOO BAR BAZ."));
        assert_eq!("foo_bar_baz", snake_case("FOO BAR.BAZ."));
        assert_eq!("foo_bar_baz", snake_case("FOO BAR..BAZ."));

        assert_eq!("fn_", snake_case("fn"));
        assert_eq!("fn_", snake_case("FN"));
    }
}

pub fn camel_case(name: &str) -> String {
    let mut result = String::new();
    if let Some(c) = name.chars().next() {
        if c.is_ascii_digit() {
            result.push('_');
        }
    }
    let mut upper_next = true;
    for c in name.chars() {
        if c.is_ascii_punctuation() || c.is_ascii_whitespace() {
            upper_next = true;
        } else {
            result.push(if upper_next {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            });
            upper_next = false;
        }
    }
    result = result.replace("Socmgmt", "SoCMgmt"); // hack for SoC
    String::from(tweak_keywords(&result))
}

#[cfg(test)]
mod camel_case_tests {
    use super::*;

    #[test]
    fn test_camel_ident() {
        assert_eq!("_8Bits", camel_case("8 bits"));
        assert_eq!("_16Bits", camel_case("16_bits"));
        assert_eq!("FooBarBaz", camel_case("foo bar baz"));
        assert_eq!("FooBarBaz", camel_case("foo_bar_baz"));
        assert_eq!("FooBarBaz", camel_case("FOO BAR BAZ"));
        assert_eq!("FooBarBaz", camel_case("FOO_BAR_BAZ"));
        assert_eq!("FooBarBaz", camel_case("FOO BAR BAZ."));
        assert_eq!("FooBarBaz", camel_case("FOO BAR.BAZ."));
        assert_eq!("Self_", camel_case("self"));
    }
}

pub fn hex_const(val: u64) -> String {
    if val > 9 {
        let mut x = "0x".to_owned();
        for (i, c) in format!("{val:x}").chars().enumerate() {
            if i % 4 == 0 && i != 0 {
                x.push('_');
            }
            x.push(c);
        }
        x
    } else {
        format!("{val}")
    }
}

pub fn has_single_32_bit_field(t: &RegisterType) -> bool {
    t.fields.is_empty()
        || (t.fields.len() == 1
            && t.fields[0].enum_type.is_none()
            && t.fields[0].position == 0
            && t.fields[0].width == 32)
}

fn indent(x: &str, num_spaces: usize) -> String {
    let spaces = " ".repeat(num_spaces);
    // preserve leading and trailing newlines
    let start = if x.starts_with("\n") {
        String::from("\n")
    } else {
        String::new()
    };
    start
        + &x.lines()
            .map(|line| format!("{}{}", spaces, line))
            .collect::<Vec<_>>()
            .join("\n")
        + if x.ends_with("\n") { "\n" } else { "" }
}

fn no_registers(block: &RegisterBlock) -> bool {
    block.registers.is_empty() && block.sub_blocks.iter().all(|sb| no_registers(sb.block()))
}

pub fn generate_code(
    crate_prefix: &str,
    block: &ValidatedRegisterBlock,
    is_root_module: bool,
    register_types_to_crates: &mut HashMap<String, String>,
) -> String {
    let mut defined_bits = HashSet::new();
    let mut bit_tokens = generate_bitfields(
        block.register_types().values().cloned(),
        block.block().name.clone(),
        register_types_to_crates,
        &mut defined_bits,
    );
    bit_tokens += "\n";
    bit_tokens += &generate_bitfields(
        block.block().declared_register_types.iter().cloned(),
        block.block().name.clone(),
        register_types_to_crates,
        &mut defined_bits,
    );
    bit_tokens = indent(&bit_tokens, 4);

    let reg_tokens = if block.block().name.trim().is_empty() || no_registers(block.block()) {
        assert!(block.block().registers.is_empty());
        String::new()
    } else {
        generate_reg_structs(crate_prefix, block.block())
    };

    let address_tokens = generate_address_tokens(block.block());

    let mut tokens = String::new();

    // You can't set no_std in a module
    if is_root_module {
        tokens += "#![no_std]\n";
    }

    if !address_tokens.trim().is_empty() {
        tokens += &address_tokens;
    }

    if !bit_tokens.trim().is_empty() {
        tokens += &format!(
            "pub mod bits {{
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
{bit_tokens}
}}\n"
        );
    }

    if !reg_tokens.trim().is_empty() {
        tokens += &format!(
            "pub mod regs {{
    //! Types that represent registers.
    use tock_registers::register_structs;
{reg_tokens}
}}\n"
        );
    }
    tokens
}

fn generate_address_tokens(block: &RegisterBlock) -> String {
    let mut instance_type_tokens = String::new();

    for instance in block.instances.iter() {
        let name_camel = snake_case(&instance.name).to_uppercase();
        let addr = hex_const(instance.address.into());
        instance_type_tokens += &format!("pub const {name_camel}_ADDR: u32 = {addr};\n");
    }
    instance_type_tokens
}

fn format_comment(comment: &str, indent: usize) -> String {
    if comment.is_empty() {
        return String::new();
    }
    let indent = " ".repeat(indent);
    let mut result = String::new();
    for line in comment.lines() {
        result += &format!("{}/// {}\n", indent, line);
    }
    result
}

fn flatten_registers(block: &RegisterBlock, offset: u64) -> Vec<Register> {
    let mut registers = Vec::new();
    for reg in block.registers.iter() {
        assert!(reg.ty.name.is_some() || has_single_32_bit_field(&reg.ty));
        let mut r = reg.as_ref().clone();
        r.offset += offset;
        registers.push(r);
    }
    for sub_block in block.sub_blocks.iter() {
        registers.extend(flatten_registers(
            sub_block.block(),
            offset + sub_block.start_offset(),
        ));
    }
    registers.sort_by_key(|r| r.offset);
    registers
}

fn generate_reg_structs(crate_prefix: &str, block: &RegisterBlock) -> String {
    let name = &block.name;
    let registers = flatten_registers(block, 0);
    let name = camel_case(name);
    let mut tokens = format!("register_structs! {{\n    pub {name} {{\n");

    let mut last_offset = 1;
    let mut next_offset = 0;
    let mut reserved = 0;
    let mut fields = HashSet::new();
    for reg in registers {
        let mut name = snake_case(&reg.name);
        if fields.contains(&name) {
            let mut i = 0;
            while fields.contains(&format!("{}{}", name, i)) {
                i += 1;
            }
            name = format!("{}{}", name, i);
        }
        fields.insert(name.clone());
        let offset = reg.offset;
        if offset == last_offset {
            println!(
                "Warning: Register {}.{} overlaps with previous register; ignoring it",
                block.name, reg.name
            );
            continue;
        }
        last_offset = offset;
        let row = if reg.can_read() && reg.can_write() {
            "ReadWrite"
        } else if reg.can_read() {
            "ReadOnly"
        } else if reg.can_write() {
            "WriteOnly"
        } else {
            panic!("Should be able to read or write");
        };

        if offset != next_offset {
            tokens += &format!("        (0x{next_offset:x} => _reserved{reserved}),\n");
            reserved += 1;
        }
        let ty = reg.ty.as_ref().clone();
        let kind = if has_single_32_bit_field(&ty) {
            format!("tock_registers::registers::{row}<u32>")
        } else {
            assert!(reg.ty.name.is_some());
            format!(
                "tock_registers::registers::{}<{}, {crate_prefix}bits::{}::Register>",
                row,
                ty.width.rust_primitive_name(),
                camel_case(ty.name.as_ref().unwrap())
            )
        };
        let array_prod = reg.array_dimensions.iter().product::<u64>();
        let kind = if array_prod == 1 {
            kind
        } else {
            assert_eq!(reg.array_dimensions.len(), 1);
            format!("[{}; {}]", kind, array_prod)
        };
        let reg_tokens = format!("(0x{offset:x} => pub {name}: {kind}),\n");
        tokens += &indent(&reg_tokens, 8);
        next_offset =
            offset + reg.ty.width.in_bytes() * reg.array_dimensions.iter().product::<u64>();
    }
    tokens += &format!("        (0x{next_offset:x} => @END),\n");
    tokens += "    }\n";
    tokens += "}\n";
    tokens
}

fn generate_bitfields(
    register_types: impl Iterator<Item = Rc<RegisterType>>,
    reg_crate: String,
    register_types_to_crates: &mut HashMap<String, String>,
    defined_bits: &mut HashSet<String>,
) -> String {
    let mut tokens8 = String::new();
    let mut tokens16 = String::new();
    let mut tokens32 = String::new();
    let mut tokens64 = String::new();
    let mut tokens128 = String::new();

    let mut register_types = register_types.collect::<Vec<_>>();
    register_types.sort_by_key(|rt| rt.name.clone().unwrap());
    for rt in register_types {
        if has_single_32_bit_field(&rt) {
            continue;
        }
        let raw_name = rt.name.clone().unwrap();
        if defined_bits.contains(&raw_name) {
            continue;
        }
        defined_bits.insert(raw_name.clone());
        register_types_to_crates.insert(raw_name.clone(), reg_crate.clone());
        let mut field_tokens = String::new();
        let name = camel_case(&raw_name);
        field_tokens += &format!("pub {name} [\n");
        for field in rt.fields.iter() {
            let mut enum_tokens = String::new();
            if let Some(enum_type) = field.enum_type.as_ref() {
                for variant in enum_type.variants.iter() {
                    let variant_ident = camel_case(&variant.name);
                    let variant_value = hex_const(variant.value as u64);
                    enum_tokens += &format!("{} = {},\n", variant_ident, variant_value);
                }
            }
            if !enum_tokens.is_empty() {
                enum_tokens = format!("\n{}    ", indent(&enum_tokens, 8));
            }
            let comment = format_comment(&field.comment, 4);
            let name = camel_case(field.name.clone().as_ref());
            let position = field.position;
            let numbits = field.width;
            field_tokens += &comment;
            field_tokens +=
                &format!("    {name} OFFSET({position}) NUMBITS({numbits}) [{enum_tokens}],\n");
        }
        field_tokens += "],\n";
        field_tokens = indent(&field_tokens, 8);

        match rt.width {
            RegisterWidth::_8 => {
                tokens8 += &field_tokens;
            }
            RegisterWidth::_16 => {
                tokens16 += &field_tokens;
            }
            RegisterWidth::_32 => {
                tokens32 += &field_tokens;
            }
            RegisterWidth::_64 => {
                tokens64 += &field_tokens;
            }
            RegisterWidth::_128 => {
                tokens128 += &field_tokens;
            }
        }
    }

    if tokens8.is_empty()
        && tokens16.is_empty()
        && tokens32.is_empty()
        && tokens64.is_empty()
        && tokens128.is_empty()
    {
        return String::new();
    }

    let mut tokens = String::new();
    tokens += "register_bitfields! {\n    ";
    if !tokens8.is_empty() {
        tokens += "u8,\n";
        tokens += &tokens8;
    }
    if !tokens16.is_empty() {
        tokens += "u16,\n";
        tokens += &tokens16;
    }
    if !tokens32.is_empty() {
        tokens += "u32,\n";
        tokens += &tokens32;
    }
    if !tokens64.is_empty() {
        tokens += "u64,\n";
        tokens += &tokens64;
    }
    if !tokens128.is_empty() {
        tokens += "u128,\n";
        tokens += &tokens128;
    }
    tokens += "}";

    tokens
}
