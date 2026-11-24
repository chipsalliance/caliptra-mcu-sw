/*++
Licensed under the Apache-2.0 license.
--*/

use crate::schema::RegisterType;

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
        let mut x = String::new();
        for (i, c) in format!("{val:x}").chars().rev().enumerate() {
            if i % 4 == 0 && i != 0 {
                x.push('_');
            }
            x.push(c);
        }
        "0x".to_string() + &x.chars().rev().collect::<String>()
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
