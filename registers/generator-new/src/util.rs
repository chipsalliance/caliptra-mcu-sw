// Licensed under the Apache-2.0 license

//! Utility functions for name conversion and formatting.
//!
//! This module provides functions for converting between naming conventions
//! (snake_case, CamelCase) and formatting values for Rust code generation.

/// Converts a name to snake_case.
///
/// Handles various edge cases:
/// - Leading digits get underscore prefix
/// - Punctuation and whitespace become underscores
/// - CamelCase transitions get underscore separators
/// - Rust keywords get underscore suffix
///
/// # Examples
/// ```
/// use mcu_registers_generator_new::util::snake_case;
/// assert_eq!(snake_case("MyRegister"), "my_register");
/// assert_eq!(snake_case("I3C_CTRL"), "i3c_ctrl");
/// ```
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

    // Fix common naming issues
    result = result.replace("so_cmgmt", "soc_mgmt");
    result = result.replace("i3_c", "i3c_").replace("__", "_");
    tweak_keywords(result.trim_end_matches('_')).to_string()
}

/// Converts a name to CamelCase (PascalCase).
///
/// Handles various edge cases:
/// - Leading digits get underscore prefix
/// - Punctuation and whitespace start a new word
/// - Rust keywords get underscore suffix
///
/// # Examples
/// ```
/// use mcu_registers_generator_new::util::camel_case;
/// assert_eq!(camel_case("my_register"), "MyRegister");
/// assert_eq!(camel_case("i3c_ctrl"), "I3cCtrl");
/// ```
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
    // Fix common naming issues
    result = result.replace("Socmgmt", "SoCMgmt");
    String::from(tweak_keywords(&result))
}

/// Appends underscore suffix to Rust keywords to avoid conflicts.
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

/// Formats an integer as a hex constant with underscores for readability.
///
/// Values <= 9 are formatted as decimal; larger values use hex with
/// underscore separators every 4 digits.
///
/// # Examples
/// ```
/// use mcu_registers_generator_new::util::hex_const;
/// assert_eq!(hex_const(5), "5");
/// assert_eq!(hex_const(0x1234), "0x1234");
/// assert_eq!(hex_const(0x12345678), "0x1234_5678");
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snake_case() {
        assert_eq!(snake_case("MyRegister"), "my_register");
        assert_eq!(snake_case("I3C_CTRL"), "i3c_ctrl");
        // All-uppercase sequences stay lowercase without separators
        assert_eq!(snake_case("HTTPServer"), "httpserver");
        assert_eq!(snake_case("type"), "type_");
    }

    #[test]
    fn test_camel_case() {
        assert_eq!(camel_case("my_register"), "MyRegister");
        assert_eq!(camel_case("i3c_ctrl"), "I3cCtrl");
        assert_eq!(camel_case("HTTP_SERVER"), "HttpServer");
    }

    #[test]
    fn test_hex_const() {
        assert_eq!(hex_const(0), "0");
        assert_eq!(hex_const(9), "9");
        assert_eq!(hex_const(10), "0xa");
        assert_eq!(hex_const(0x1234), "0x1234");
        assert_eq!(hex_const(0x12345678), "0x1234_5678");
    }
}
