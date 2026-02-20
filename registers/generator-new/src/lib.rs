// Licensed under the Apache-2.0 license

//! SystemRDL to tock-registers Rust code generator.
//!
//! This crate provides a code generator that converts SystemRDL register
//! descriptions into Rust code compatible with the tock-registers crate.
//!
//! ## Usage
//!
//! ```no_run
//! use std::path::Path;
//! use mcu_registers_generator_new::{
//!     generate_tock_registers_from_file,
//!     generate_tock_registers_from_file_with_config,
//!     NameConfig,
//! };
//!
//! // Generate code from an RDL file
//! let code = generate_tock_registers_from_file(
//!     Path::new("my_device.rdl"),
//!     &[("my_addrmap", 0x1000_0000)],
//! ).unwrap();
//!
//! // Or with custom name configuration
//! let config = NameConfig::with_defaults()
//!     .add_suffix("_extra");
//! let code = generate_tock_registers_from_file_with_config(
//!     Path::new("my_device.rdl"),
//!     &[("my_addrmap", 0x1000_0000)],
//!     &config,
//! ).unwrap();
//! ```
//!
//! ## Module Organization
//!
//! - [`util`]: Name conversion utilities (snake_case, camel_case, hex formatting)
//! - [`config`]: Configuration for name transformations ([`NameConfig`])
//! - [`types`]: Internal data structures for parsed RDL
//! - [`output`]: Generated output types and code generation
//! - [`codegen`]: Main code generation logic and public API

pub mod config;
pub mod output;
pub mod types;
pub mod util;

mod codegen;
mod value;

// Re-export main public API
pub use codegen::{
    generate_tock_registers_from_file, generate_tock_registers_from_file_with_config,
    generate_tock_registers_from_file_with_filter,
};
pub use config::FilterConfig;
pub use config::NameConfig;
pub use output::{
    GeneratedAddrMap, GeneratedField, GeneratedMemory, GeneratedRegister, GeneratedRegisterType,
};
