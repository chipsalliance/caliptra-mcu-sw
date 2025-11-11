// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Result};
use mcu_builder::PROJECT_ROOT;
use proc_macro2::{Ident, Literal, TokenStream};
use quote::{format_ident, quote};
use registers_generator::{
    camel_case, has_single_32_bit_field, hex_const, snake_case, FieldType, Register, RegisterBlock,
    RegisterBlockInstance, RegisterWidth, ValidatedRegisterBlock,
};
use registers_systemrdl::ParentScope;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::LazyLock;

static HEADER_PREFIX: &str = r"/*
Licensed under the Apache-2.0 license.
";

static HEADER_SUFFIX: &str = r"
*/
";

static SKIP_TYPES: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    HashSet::from([
        "csrng", "hmac", "kv_read", "hmac512", "sha256", "sha512", "spi_host",
    ])
});

pub(crate) fn autogen(
    check: bool,
    extra_files: &[PathBuf],
    extra_addrmap: &[String],
) -> Result<()> {
    let sub_dir = &PROJECT_ROOT.join("hw").join("caliptra-ss").to_path_buf();
    let registers_dest_dir = &PROJECT_ROOT
        .join("registers")
        .join("generated-firmware")
        .join("src")
        .to_path_buf();
    let bus_dest_dir = &PROJECT_ROOT
        .join("registers")
        .join("generated-emulator")
        .join("src")
        .to_path_buf();

    let rdl_files = [
        "hw/caliptra-ss/src/integration/rtl/soc_address_map.rdl",
        "hw/mcu.rdl",
    ];
    let mut rdl_files: Vec<PathBuf> = rdl_files.iter().map(|s| PROJECT_ROOT.join(s)).collect();
    rdl_files.extend_from_slice(extra_files);

    let mut temp_rdl = tempfile::NamedTempFile::new()?;
    if !extra_addrmap.is_empty() {
        let mut map = String::new();
        map += "addrmap extra {\n";
        for s in extra_addrmap.iter() {
            if let Some(eq) = s.find("@") {
                let typ = s[..eq].trim();
                let addr = s[eq + 1..].trim();
                map += &format!("{} {} @ {};\n", typ, typ, addr);
            } else {
                bail!(
                    "Invalid addrmap entry: {} (should be in the form type@address)",
                    s
                );
            };
        }
        map += "};\n";
        write!(temp_rdl, "{}", map)?;
        temp_rdl.flush()?;
        rdl_files.push(temp_rdl.path().to_path_buf());
    }

    // eliminate duplicate type names
    let patches = [
        (
            PROJECT_ROOT.join("hw/caliptra-ss/src/mci/rtl/mci_top.rdl"),
            // this is legal but our parser doesn't understand it
            r#"mem {name="MCU SRAM";"#,
            r#"external mem {name="MCU SRAM";"#,
        ),
        (
            PROJECT_ROOT.join("hw/caliptra-ss/src/mci/rtl/mci_top.rdl"),
            r"external mcu_sram @ 0xC0_0000;",
            r"mcu_sram @ 0xC0_0000;",
        ),
        (
            PROJECT_ROOT.join(
                "hw/caliptra-ss/third_party/i3c-core/src/rdl/target_transaction_interface.rdl",
            ),
            "QUEUE_THLD_CTRL",
            "TTI_QUEUE_THLD_CTRL",
        ),
        (
            PROJECT_ROOT.join(
                "hw/caliptra-ss/third_party/i3c-core/src/rdl/target_transaction_interface.rdl",
            ),
            "QUEUE_SIZE",
            "TTI_QUEUE_SIZE",
        ),
        (
            PROJECT_ROOT.join(
                "hw/caliptra-ss/third_party/i3c-core/src/rdl/target_transaction_interface.rdl",
            ),
            "IBI_PORT",
            "TTI_IBI_PORT",
        ),
        (
            PROJECT_ROOT.join(
                "hw/caliptra-ss/third_party/i3c-core/src/rdl/target_transaction_interface.rdl",
            ),
            "DATA_BUFFER_THLD_CTRL",
            "TTI_DATA_BUFFER_THLD_CTRL",
        ),
        (
            PROJECT_ROOT.join(
                "hw/caliptra-ss/third_party/i3c-core/src/rdl/target_transaction_interface.rdl",
            ),
            "RESET_CONTROL",
            "TTI_RESET_CONTROL",
        ),
        (
            PROJECT_ROOT.join("hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl"),
            "INTERRUPT_ENABLE",
            "OTP_INTERRUPT_ENABLE",
        ),
        (
            PROJECT_ROOT.join("hw/caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl.rdl"),
            "STATUS",
            "OTP_STATUS",
        ),
    ];

    for rdl in rdl_files.iter() {
        if !rdl.exists() {
            bail!("RDL file not found: {:?} -- ensure that you have run `git submodule init` and `git submodule update --recursive`", rdl);
        }
    }

    let sub_commit_id = run_cmd_stdout(
        Command::new("git")
            .current_dir(sub_dir)
            .arg("rev-parse")
            .arg("HEAD"),
        None,
    )?;
    let sub_git_status = run_cmd_stdout(
        Command::new("git")
            .current_dir(sub_dir)
            .arg("status")
            .arg("--porcelain"),
        None,
    )?;

    let mut header = HEADER_PREFIX.to_string();
    write!(
        &mut header,
        "\n generated by registers_generator with caliptra-ss repo at {sub_commit_id}",
    )?;
    if !sub_git_status.is_empty() {
        write!(
            &mut header,
            "\n\nWarning: caliptra-ss was dirty:{sub_git_status}"
        )?;
    }
    if (!extra_addrmap.is_empty()) || (!extra_files.is_empty()) {
        write!(
            &mut header,
            "\n\nWarning: processed using extra RDL files and addrmap entries: {:?}, {:?}\n",
            extra_files, extra_addrmap
        )?;
    }
    header.push_str(HEADER_SUFFIX);

    let file_source = registers_systemrdl::FsFileSource::new();
    for patch in patches {
        file_source.add_patch(&patch.0, patch.1, patch.2);
    }
    let scope = registers_systemrdl::Scope::parse_root(&file_source, &rdl_files)
        .map_err(|s| anyhow!(s.to_string()))?;
    let scope = scope.as_parent();

    let addrmap = scope.lookup_typedef("soc").unwrap();
    let addrmap2 = scope.lookup_typedef("mcu").unwrap();
    let mut scopes = vec![addrmap, addrmap2];
    if !extra_addrmap.is_empty() {
        let addrmap3 = scope.lookup_typedef("extra").unwrap();
        scopes.push(addrmap3);
    }

    // These are types like kv_read_ctrl_reg that are used by multiple crates
    let root_block = RegisterBlock {
        declared_register_types: registers_generator::translate_types(scope)?,
        ..Default::default()
    };
    let root_block = root_block.validate_and_dedup()?;

    let mut register_types_to_crates = HashMap::new();

    generate_fw_registers(
        check,
        root_block.clone(),
        &scopes.clone(),
        header.clone(),
        registers_dest_dir,
        &mut register_types_to_crates,
    )?;
    let _defines = generate_defines(check, header.clone(), registers_dest_dir)?;
    generate_emulator_types(
        check,
        &scopes,
        bus_dest_dir,
        header.clone(),
        &register_types_to_crates,
    )?;
    autogen_fuses(check, registers_dest_dir)
}

/// Generate types used by the emulator.
fn generate_emulator_types(
    check: bool,
    scopes: &[ParentScope],
    dest_dir: &Path,
    header: String,
    register_types_to_crates: &HashMap<String, String>,
) -> Result<()> {
    let file_action = if check {
        file_check_contents
    } else {
        delete_rust_files(dest_dir)?;
        write_file
    };
    let mut lib_code = TokenStream::new();
    let mut blocks = vec![];
    for scope in scopes.iter() {
        blocks.extend(registers_generator::translate_addrmap(*scope)?);
    }
    let mut validated_blocks = vec![];

    for block in blocks.iter_mut() {
        if block.name.starts_with("caliptra_") {
            block.name = block.name[9..].to_string();
        }
        while block.name.ends_with("_reg")
            || block.name.ends_with("_csr")
            || block.name.ends_with("_top")
            || block.name.ends_with("_ifc")
        {
            block.name = block.name[0..block.name.len() - 4].to_string();
        }
        if block.name.ends_with("_ctrl") {
            block.name = block.name[0..block.name.len() - 5].to_string();
        }
        if block.name == "I3CCSR" {
            block.name = "i3c".to_string();
        }
        if SKIP_TYPES.contains(block.name.as_str()) {
            continue;
        }
        let block = block.clone().validate_and_dedup()?;
        validated_blocks.push(block);
    }

    validated_blocks.sort_by_key(|b| b.block().name.clone());

    for block in validated_blocks.iter() {
        let rblock = block.block();
        let mut code = TokenStream::new();
        code.extend(quote! {
            #[allow(unused_imports)]
            use tock_registers::interfaces::{Readable, Writeable};
        });
        //code.extend(emu_make_data_types(block)?);
        code.extend(emu_make_peripheral_trait(
            rblock.clone(),
            register_types_to_crates,
        )?);
        code.extend(emu_make_peripheral_bus_impl(rblock.clone())?);

        let dest_file = dest_dir.join(format!("{}.rs", rblock.name));
        file_action(&dest_file, &rustfmt(&(header.clone() + &code.to_string()))?)?;
        let block_name = format_ident!("{}", rblock.name);
        lib_code.extend(quote! {
            pub mod #block_name;
        });
    }
    let root_bus_code = emu_make_root_bus(
        validated_blocks
            .iter()
            .filter(|b| !SKIP_TYPES.contains(b.block().name.as_str())),
    )?;
    let root_bus_file = dest_dir.join("root_bus.rs");
    file_action(
        &root_bus_file,
        &rustfmt(&(header.clone() + &root_bus_code.to_string()))?,
    )?;

    lib_code.extend(quote! { pub mod root_bus; });

    let lib_file = dest_dir.join("lib.rs");
    file_action(
        &lib_file,
        &rustfmt(&(header.clone() + &lib_code.to_string()))?,
    )?;
    Ok(())
}

/// Collect all registers from the block and all subblocks, also returning the subblock name
/// and starting offset for the subblock that contains the register.
fn flatten_registers(
    offset: u64,
    block_base_name: String,
    block: &RegisterBlock,
) -> Vec<(u64, String, Rc<Register>)> {
    let mut registers: Vec<(u64, String, Rc<Register>)> = block
        .registers
        .clone()
        .into_iter()
        .map(|r| (offset, block_base_name.clone(), r))
        .collect();
    block.sub_blocks.iter().for_each(|sb| {
        let new_name = if block_base_name.is_empty() {
            sb.block().name.clone()
        } else {
            format!("{}_{}", block_base_name, sb.block().name)
        };
        registers.extend(flatten_registers(
            offset + sb.start_offset(),
            new_name,
            sb.block(),
        ));
    });
    registers
}

/// Make a peripheral trait that the emulator code can implement.
fn emu_make_peripheral_trait(
    block: RegisterBlock,
    register_types_to_crates: &HashMap<String, String>,
) -> Result<TokenStream> {
    let base = camel_ident(block.name.as_str());
    let periph = format_ident!("{}Peripheral", base);
    let generated_struct = format_ident!("{}Generated", base);
    let mut fn_tokens = TokenStream::new();
    let mut struct_fields = TokenStream::new();
    let mut struct_defaults = TokenStream::new();
    let mut impl_tokens = TokenStream::new();
    let mut state_field_names = HashSet::new();

    let registers = flatten_registers(0, String::new(), &block);
    for (_, base_name, reg_rc) in registers.iter() {
        if reg_rc.name == "MCU_CLK_GATING_EN" {
            continue;
        }
        if reg_rc.name == "TERMINATION_EXTCAP_HEADER" {
            continue;
        }
        if !reg_rc.can_read() && !reg_rc.can_write() {
            continue;
        }

        let register = reg_rc.as_ref();
        let base_prefix = if base_name.is_empty() {
            String::new()
        } else {
            format!("{}_", snake_case(base_name.as_str()))
        };
        let reg_snake = snake_case(register.name.as_str());
        let method_suffix = format!("{base_prefix}{reg_snake}").replace("__", "_");
        let read_name = format_ident!("read_{}", method_suffix);
        let write_name = format_ident!("write_{}", method_suffix);
        let state_ident = format_ident!("{}", method_suffix);

        if state_field_names.insert(method_suffix.clone()) {
            let default_literal = hex_literal(register.default_val);
            if register.is_array() {
                let len = register.array_dimensions.iter().product::<u64>() as usize;
                let len_literal = Literal::usize_unsuffixed(len);
                struct_fields.extend(quote! {
                    #state_ident: Vec<caliptra_emu_types::RvData>,
                });
                struct_defaults.extend(quote! {
                    #state_ident: vec![#default_literal as caliptra_emu_types::RvData; #len_literal],
                });
            } else {
                struct_fields.extend(quote! {
                    #state_ident: caliptra_emu_types::RvData,
                });
                struct_defaults.extend(quote! {
                    #state_ident: #default_literal as caliptra_emu_types::RvData,
                });
            }
        }

        let is_simple = has_single_32_bit_field(&register.ty);

        if is_simple {
            if register.can_read() {
                if register.is_array() {
                    fn_tokens.extend(quote! {
                        fn #read_name(&mut self, index: usize) -> caliptra_emu_types::RvData {
                            if let Some(generated) = self.generated() {
                                return generated.#read_name(index);
                            }
                            0
                        }
                    });
                    impl_tokens.extend(quote! {
                        fn #read_name(&mut self, index: usize) -> caliptra_emu_types::RvData {
                            self.#state_ident[index]
                        }
                    });
                } else {
                    fn_tokens.extend(quote! {
                        fn #read_name(&mut self) -> caliptra_emu_types::RvData {
                            if let Some(generated) = self.generated() {
                                return generated.#read_name();
                            }
                            0
                        }
                    });
                    impl_tokens.extend(quote! {
                        fn #read_name(&mut self) -> caliptra_emu_types::RvData {
                            self.#state_ident
                        }
                    });
                }
            }
            if register.can_write() {
                if register.is_array() {
                    fn_tokens.extend(quote! {
                        fn #write_name(&mut self, val: caliptra_emu_types::RvData, index: usize) {
                            if let Some(generated) = self.generated() {
                                generated.#write_name(val, index);
                            }
                        }
                    });
                    let target_expr = quote! { self.#state_ident[index] };
                    let write_logic =
                        make_register_write_logic(register, target_expr.clone(), quote! { val });
                    impl_tokens.extend(quote! {
                        fn #write_name(&mut self, val: caliptra_emu_types::RvData, index: usize) {
                            #write_logic
                        }
                    });
                } else {
                    fn_tokens.extend(quote! {
                        fn #write_name(&mut self, val: caliptra_emu_types::RvData) {
                            if let Some(generated) = self.generated() {
                                generated.#write_name(val);
                            }
                        }
                    });
                    let target_expr = quote! { self.#state_ident };
                    let write_logic =
                        make_register_write_logic(register, target_expr.clone(), quote! { val });
                    impl_tokens.extend(quote! {
                        fn #write_name(&mut self, val: caliptra_emu_types::RvData) {
                            #write_logic
                        }
                    });
                }
            }
        } else {
            if register_types_to_crates
                .get(register.ty.name.as_ref().unwrap())
                .is_none()
            {
                let mut i: Vec<_> = register_types_to_crates.keys().collect();
                i.sort();
            }
            let rcrate = format_ident!(
                "{}",
                register_types_to_crates
                    .get(register.ty.name.as_ref().unwrap())
                    .unwrap()
            );
            let tyn = camel_ident(register.ty.name.as_ref().unwrap());
            let read_val = quote! { registers_generated :: #rcrate :: bits :: #tyn :: Register };
            let prim = format_ident!("{}", register.ty.width.rust_primitive_name());
            let fulltyn = quote! { caliptra_emu_bus::ReadWriteRegister::<#prim, #read_val> };
            if register.can_read() {
                if register.is_array() {
                    fn_tokens.extend(quote! {
                        fn #read_name(&mut self, index: usize) -> #fulltyn {
                            if let Some(generated) = self.generated() {
                                return generated.#read_name(index);
                            }
                            caliptra_emu_bus::ReadWriteRegister :: new(0)
                        }
                    });
                    impl_tokens.extend(quote! {
                        fn #read_name(&mut self, index: usize) -> #fulltyn {
                            caliptra_emu_bus::ReadWriteRegister::new(self.#state_ident[index])
                        }
                    });
                } else {
                    fn_tokens.extend(quote! {
                        fn #read_name(&mut self) -> #fulltyn {
                            if let Some(generated) = self.generated() {
                                return generated.#read_name();
                            }
                            caliptra_emu_bus::ReadWriteRegister :: new(0)
                        }
                    });
                    impl_tokens.extend(quote! {
                        fn #read_name(&mut self) -> #fulltyn {
                            caliptra_emu_bus::ReadWriteRegister::new(self.#state_ident)
                        }
                    });
                }
            }
            if register.can_write() {
                if register.is_array() {
                    fn_tokens.extend(quote! {
                        fn #write_name(&mut self, val: #fulltyn, index: usize) {
                            if let Some(generated) = self.generated() {
                                generated.#write_name(val, index);
                            }
                        }
                    });
                    let target_expr = quote! { self.#state_ident[index] };
                    let write_logic = make_register_write_logic(
                        register,
                        target_expr.clone(),
                        quote! { val.reg.get() },
                    );
                    impl_tokens.extend(quote! {
                        fn #write_name(&mut self, val: #fulltyn, index: usize) {
                            #write_logic
                        }
                    });
                } else {
                    fn_tokens.extend(quote! {
                        fn #write_name(&mut self, val: #fulltyn) {
                            if let Some(generated) = self.generated() {
                                generated.#write_name(val);
                            }
                        }
                    });
                    let target_expr = quote! { self.#state_ident };
                    let write_logic = make_register_write_logic(
                        register,
                        target_expr.clone(),
                        quote! { val.reg.get() },
                    );
                    impl_tokens.extend(quote! {
                        fn #write_name(&mut self, val: #fulltyn) {
                            #write_logic
                        }
                    });
                }
            }
        }
    }

    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        pub trait #periph {
            fn set_dma_ram(&mut self, _ram: std::rc::Rc<std::cell::RefCell<caliptra_emu_bus::Ram>>) {}
            fn set_dma_rom_sram(&mut self, _ram: std::rc::Rc<std::cell::RefCell<caliptra_emu_bus::Ram>>) {}
            fn register_event_channels(
                &mut self,
                _events_to_caliptra: std::sync::mpsc::Sender<caliptra_emu_bus::Event>,
                _events_from_caliptra: std::sync::mpsc::Receiver<caliptra_emu_bus::Event>,
                _events_to_mcu: std::sync::mpsc::Sender<caliptra_emu_bus::Event>,
                _events_from_mcu: std::sync::mpsc::Receiver<caliptra_emu_bus::Event>,
            ) {
            }
            fn poll(&mut self) {}
            fn warm_reset(&mut self) {}
            fn update_reset(&mut self) {}
            fn generated(&mut self) -> Option<&mut #generated_struct> {
                None
            }
            #fn_tokens
        }
    });

    tokens.extend(quote! {
        #[derive(Clone, Debug)]
        pub struct #generated_struct {
            #struct_fields
        }

        impl Default for #generated_struct {
            fn default() -> Self {
                Self {
                    #struct_defaults
                }
            }
        }

        impl #generated_struct {
            pub fn new() -> Self {
                Self::default()
            }

            fn reset_state(&mut self) {
                *self = Self::default();
            }
        }

        impl #periph for #generated_struct {
            fn generated(&mut self) -> Option<&mut #generated_struct> {
                Some(self)
            }
            fn warm_reset(&mut self) {
                self.reset_state();
            }

            fn update_reset(&mut self) {
                self.reset_state();
            }

            #impl_tokens
        }
    });

    Ok(tokens)
}

fn camel_ident(s: &str) -> Ident {
    format_ident!("{}", camel_case(s))
}

fn snake_ident(s: &str) -> Ident {
    format_ident!("{}", snake_case(s))
}

fn make_register_write_logic(
    register: &Register,
    target_expr: TokenStream,
    write_val_expr: TokenStream,
) -> TokenStream {
    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        let write_val = (#write_val_expr) as caliptra_emu_types::RvData;
    });

    if register.ty.fields.is_empty() {
        tokens.extend(quote! {
            let new_val = write_val;
            #target_expr = new_val;
        });
        return tokens;
    }

    let current_ident = format_ident!("current_val");
    tokens.extend(quote! {
        let #current_ident = #target_expr;
        let mut new_val = #current_ident;
    });

    for (idx, field) in register.ty.fields.iter().enumerate() {
        let mask_literal = hex_literal(field.mask());
        let mask_expr = quote! { (#mask_literal as caliptra_emu_types::RvData) };
        match field.ty {
            FieldType::RO => {}
            FieldType::RW | FieldType::WO | FieldType::WRC => {
                tokens.extend(quote! {
                    new_val = (new_val & !#mask_expr) | (write_val & #mask_expr);
                });
            }
            FieldType::WC => {
                tokens.extend(quote! {
                    new_val &= !#mask_expr;
                });
            }
            FieldType::W1C => {
                let bits_ident = format_ident!("bits_to_clear_{idx}");
                tokens.extend(quote! {
                    let #bits_ident = write_val & #mask_expr;
                    new_val &= !#bits_ident;
                });
            }
            FieldType::W1S => {
                let bits_ident = format_ident!("bits_to_set_{idx}");
                tokens.extend(quote! {
                    let #bits_ident = write_val & #mask_expr;
                    new_val |= #bits_ident;
                });
            }
        }
    }

    tokens.extend(quote! {
        #target_expr = new_val;
    });

    tokens
}

/// Make a peripheral Bus implementation that can be hooked up to a root bus.
fn emu_make_peripheral_bus_impl(block: RegisterBlock) -> Result<TokenStream> {
    let base = camel_ident(block.name.as_str());
    let periph = format_ident!("{}Peripheral", base);
    let bus = format_ident!("{}Bus", base);
    let mut read_tokens = TokenStream::new();
    let mut write_tokens = TokenStream::new();
    let registers = flatten_registers(0, String::new(), &block);
    let mut ranges_with_writer: HashSet<(u64, u64)> = HashSet::new();
    registers.iter().for_each(|(offset, _, r)| {
        let start = offset + r.offset;
        let end = start + r.ty.width.in_bytes() * r.array_dimensions.iter().product::<u64>();
        let has_writer = if has_single_32_bit_field(&r.ty) {
            r.ty.fields
                .first()
                .map(|f| f.ty.can_write())
                .unwrap_or(false)
        } else {
            r.can_write()
        };
        if has_writer {
            ranges_with_writer.insert((start, end));
        }
    });
    let mut emitted_write_ranges: HashSet<(u64, u64)> = HashSet::new();
    registers.iter().for_each(|(offset, base_name, r)| {
        // skip as this register is not defined yet
        if r.name == "MCU_CLK_GATING_EN" {
            return;
        }
        // skip these are they are just for discovery
        if r.name == "TERMINATION_EXTCAP_HEADER" {
            return;
        }
        let base_field = snake_ident(r.name.as_str());
        let base_name = if base_name.is_empty() {
            base_name.clone()
        } else {
            format!("{}_", snake_ident(base_name.as_str()))
        };
        let read_name = format_ident!(
            "{}",
            format!("read_{}{}", base_name, base_field).replace("__", "_")
        );
        let write_name = format_ident!(
            "{}",
            format!("write_{}{}", base_name, base_field).replace("__", "_"),
        );
        let start = offset + r.offset;
        let end =
            start + r.ty.width.in_bytes() * r.array_dimensions.iter().product::<u64>();
        let a = hex_literal(start);
        let b = hex_literal(end);
        assert_eq!(r.ty.width, RegisterWidth::_32);
        if has_single_32_bit_field(&r.ty) {
            if r.ty.fields[0].ty.can_read() {
                if r.is_array() {
                    if start == 0 {
                        read_tokens.extend(quote! {
                            #a..#b => Ok(self.periph.#read_name(addr as usize / 4)),
                        });
                    } else {
                        read_tokens.extend(quote! {
                            #a..#b => Ok(self.periph.#read_name((addr as usize - #a) / 4)),
                        });
                    }
                } else {
                    read_tokens.extend(quote! {
                        #a..#b => Ok(self.periph.#read_name()),
                    });
                }
            }
            if r.ty.fields[0].ty.can_write() {
                if emitted_write_ranges.insert((start, end)) {
                    if r.is_array() {
                        if start == 0 {
                            write_tokens.extend(quote! {
                                #a..#b => {
                                    self.periph.#write_name(val, addr as usize / 4);
                                    Ok(())
                                }
                            });
                        } else {
                            write_tokens.extend(quote! {
                                #a..#b => {
                                    self.periph.#write_name(val, (addr as usize - #a) / 4);
                                    Ok(())
                                }
                            });
                        }
                    } else {
                        write_tokens.extend(quote! {
                            #a..#b => {
                                self.periph.#write_name(val);
                                Ok(())
                            }
                        });
                    }
                }
            } else if r.can_read() && !ranges_with_writer.contains(&(start, end)) {
                write_tokens.extend(quote! {
                    #a..#b => Ok(()),
                });
            }
        } else {
            if r.can_read() {
                if r.is_array() {
                    if offset + r.offset == 0 {
                        read_tokens.extend(quote! {
                            #a..#b => Ok(caliptra_emu_types::RvData::from(self.periph.#read_name(addr as usize / 4).reg.get())),
                        });
                    } else {
                        read_tokens.extend(quote! {
                            #a..#b => Ok(caliptra_emu_types::RvData::from(self.periph.#read_name((addr as usize - #a) / 4).reg.get())),
                        });
                    }
                } else {
                    read_tokens.extend(quote! {
                        #a..#b => Ok(caliptra_emu_types::RvData::from(self.periph.#read_name().reg.get())),
                    });
                }
            }
            if r.can_write() {
                if emitted_write_ranges.insert((start, end)) {
                    if r.is_array() {
                        if start == 0 {
                            write_tokens.extend(quote! {
                                #a..#b => {
                                    self.periph.#write_name(caliptra_emu_bus::ReadWriteRegister::new(val), addr as usize / 4);
                                    Ok(())
                                }
                            });
                        } else {
                            write_tokens.extend(quote! {
                                #a..#b => {
                                    self.periph.#write_name(caliptra_emu_bus::ReadWriteRegister::new(val), (addr as usize - #a) / 4);
                                    Ok(())
                                }
                            });
                        }
                    } else {
                        write_tokens.extend(quote! {
                            #a..#b => {
                                self.periph.#write_name(caliptra_emu_bus::ReadWriteRegister::new(val));
                                Ok(())
                            }
                        });
                    }
                }
            } else if r.can_read() && !ranges_with_writer.contains(&(start, end)) {
                write_tokens.extend(quote! {
                    #a..#b => Ok(()),
                });
            }
        }
    });

    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        pub struct #bus {
            pub periph: Box<dyn #periph>,
        }
        impl caliptra_emu_bus::Bus for #bus {
            fn read(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
                if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
                    return Err(caliptra_emu_bus::BusError::LoadAddrMisaligned);
                }
                match addr {
                    #read_tokens
                    _ => Err(caliptra_emu_bus::BusError::LoadAccessFault),
                }
            }
            fn write(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr, val: caliptra_emu_types::RvData) -> Result<(), caliptra_emu_bus::BusError> {
                if addr & 0x3 != 0 || size != caliptra_emu_types::RvSize::Word {
                    return Err(caliptra_emu_bus::BusError::StoreAddrMisaligned);
                }
                match addr {
                    #write_tokens
                    _ => Err(caliptra_emu_bus::BusError::StoreAccessFault),
                }
            }
            fn poll(&mut self) {
                self.periph.poll();
            }
            fn warm_reset(&mut self) {
                self.periph.warm_reset();
            }
            fn update_reset(&mut self) {
                self.periph.update_reset();
            }
        }
    });
    Ok(tokens)
}

/// Calculate the width of a register block.
fn whole_width(block: &RegisterBlock) -> u64 {
    let a = block
        .registers
        .iter()
        .map(|r| r.offset + r.ty.width.in_bytes() * r.array_dimensions.iter().product::<u64>())
        .max()
        .unwrap_or_default();
    let b = block
        .sub_blocks
        .iter()
        .map(|sb| sb.start_offset() + whole_width(sb.block()))
        .max()
        .unwrap_or_default();
    a.max(b)
}

fn hex_literal(val: u64) -> Literal {
    Literal::from_str(&hex_const(val)).unwrap()
}

// Make the root bus that can be used by the emulator.
fn emu_make_root_bus<'a>(
    blocks: impl Iterator<Item = &'a ValidatedRegisterBlock>,
) -> Result<TokenStream> {
    let mut read_tokens = TokenStream::new();
    let mut write_tokens = TokenStream::new();
    let mut poll_tokens = TokenStream::new();
    let mut warm_reset_tokens = TokenStream::new();
    let mut update_reset_tokens = TokenStream::new();
    let mut incoming_event_tokens = TokenStream::new();
    let mut register_outgoing_events_tokens = TokenStream::new();
    let mut field_tokens = TokenStream::new();
    let mut constructor_tokens = TokenStream::new();
    let mut constructor_params_tokens = TokenStream::new();
    let mut offset_fields = TokenStream::new();
    let mut offset_defaults = TokenStream::new();

    let mut blocks_sorted = blocks.collect::<Vec<_>>();
    blocks_sorted.sort_by_key(|b| b.block().instances[0].address);

    for block in blocks_sorted {
        let rblock = block.block();
        if SKIP_TYPES.contains(rblock.name.as_str()) {
            continue;
        }
        assert_eq!(rblock.instances.len(), 1);
        let snake_base = snake_ident(rblock.name.as_str());
        let periph_field = format_ident!("{}_periph", snake_base);
        let offset_field = format_ident!("{}_offset", snake_base);
        let size_field = format_ident!("{}_size", snake_base);
        let camel_base = camel_ident(rblock.name.as_str());
        let crate_name = format_ident!("{}", rblock.name);
        let periph = format_ident!("{}Peripheral", camel_base);
        let bus = format_ident!("{}Bus", camel_base);
        constructor_params_tokens.extend(quote! {
            #periph_field: Option<Box<dyn crate::#crate_name::#periph>>,
        });
        constructor_tokens.extend(quote! {
            #periph_field: #periph_field.map(|p| crate::#crate_name::#bus { periph: p }),
        });
        field_tokens.extend(quote! {
            pub #periph_field: Option<crate::#crate_name::#bus>,
        });
        let addr = hex_literal(rblock.instances[0].address as u64);
        let size = hex_literal(whole_width(rblock));

        offset_fields.extend(quote! {
            pub #offset_field: u32,
            pub #size_field: u32,
        });
        offset_defaults.extend(quote! {
            #offset_field: #addr,
            #size_field: #size,
        });

        read_tokens.extend(quote! {
            if addr >= self.offsets.#offset_field && addr < self.offsets.#offset_field + self.offsets.#size_field {
                if let Some(periph) = self.#periph_field.as_mut() {
                    return periph.read(size, addr - self.offsets.#offset_field);
                }
            }
        });
        write_tokens.extend(quote! {
            if addr >= self.offsets.#offset_field && addr < self.offsets.#offset_field + self.offsets.#size_field {
                if let Some(periph) = self.#periph_field.as_mut() {
                    return periph.write(size, addr - self.offsets.#offset_field, val);
                }
            }
        });
        poll_tokens.extend(quote! {
            if let Some(periph) = self.#periph_field.as_mut() {
                periph.poll();
            }
        });
        warm_reset_tokens.extend(quote! {
            if let Some(periph) = self.#periph_field.as_mut() {
                periph.warm_reset();
            }
        });
        update_reset_tokens.extend(quote! {
            if let Some(periph) = self.#periph_field.as_mut() {
                periph.update_reset();
            }
        });
        incoming_event_tokens.extend(quote! {
            if let Some(periph) = self.#periph_field.as_mut() {
                periph.incoming_event(event.clone());
            }
        });
        register_outgoing_events_tokens.extend(quote! {
            if let Some(periph) = self.#periph_field.as_mut() {
                periph.register_outgoing_events(sender.clone());
            }
        });
    }
    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        /// Offsets for peripherals mounted to the root bus.
        #[derive(Clone, Debug)]
        pub struct AutoRootBusOffsets {
            #offset_fields
        }

        impl Default for AutoRootBusOffsets {
            fn default() -> Self {
                Self {
                    #offset_defaults
                }
            }
        }

        pub struct AutoRootBus {
            delegates: Vec<Box<dyn caliptra_emu_bus::Bus>>,
            offsets: AutoRootBusOffsets,
            #field_tokens
        }
        impl AutoRootBus {
            #[allow(clippy::too_many_arguments)]
            pub fn new(
                delegates: Vec<Box<dyn caliptra_emu_bus::Bus>>,
                offsets: Option<AutoRootBusOffsets>,
                #constructor_params_tokens
            ) -> Self {
                Self {
                    delegates,
                    offsets: offsets.unwrap_or_default(),
                    #constructor_tokens
                }
            }
        }
        impl caliptra_emu_bus::Bus for AutoRootBus {
            fn read(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr) -> Result<caliptra_emu_types::RvData, caliptra_emu_bus::BusError> {
                #read_tokens
                for delegate in self.delegates.iter_mut() {
                    let result = delegate.read(size, addr);
                    if !matches!(result, Err(caliptra_emu_bus::BusError::LoadAccessFault)) {
                        return result;
                    }
                }
                Err(caliptra_emu_bus::BusError::LoadAccessFault)
            }
            fn write(&mut self, size: caliptra_emu_types::RvSize, addr: caliptra_emu_types::RvAddr, val: caliptra_emu_types::RvData) -> Result<(), caliptra_emu_bus::BusError> {
                #write_tokens
                for delegate in self.delegates.iter_mut() {
                    let result = delegate.write(size, addr, val);
                    if !matches!(result, Err(caliptra_emu_bus::BusError::StoreAccessFault)) {
                        return result;
                    }
                }
                Err(caliptra_emu_bus::BusError::StoreAccessFault)
            }
            fn poll(&mut self) {
                #poll_tokens
                for delegate in self.delegates.iter_mut() {
                    delegate.poll();
                }
            }
            fn warm_reset(&mut self) {
                #warm_reset_tokens
                for delegate in self.delegates.iter_mut() {
                    delegate.warm_reset();
                }
            }
            fn update_reset(&mut self) {
                #update_reset_tokens
                for delegate in self.delegates.iter_mut() {
                    delegate.update_reset();
                }
            }
            fn incoming_event(&mut self, event: std::rc::Rc<caliptra_emu_bus::Event>) {
                #incoming_event_tokens
                for delegate in self.delegates.iter_mut() {
                    delegate.incoming_event(event.clone());
                }
            }
            fn register_outgoing_events(&mut self, sender: std::sync::mpsc::Sender<caliptra_emu_bus::Event>) {
                #register_outgoing_events_tokens
                for delegate in self.delegates.iter_mut() {
                    delegate.register_outgoing_events(sender.clone());
                }
            }
}
    });
    Ok(tokens)
}

fn delete_rust_files(dir: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .map(|ext| ext == "rs")
                .unwrap_or_default()
        {
            println!("Deleting existing file {}", entry.path().display());
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Generate read/write registers used by the firmware.
fn generate_fw_registers(
    check: bool,
    mut root_block: ValidatedRegisterBlock,
    scopes: &[ParentScope],
    header: String,
    dest_dir: &Path,
    register_types_to_crates: &mut HashMap<String, String>,
) -> Result<()> {
    let file_action = if check {
        file_check_contents
    } else {
        delete_rust_files(dest_dir)?;
        write_file
    };

    let mut blocks = vec![];
    for scope in scopes.iter() {
        blocks.extend(registers_generator::translate_addrmap(*scope)?);
    }
    let mut validated_blocks = vec![];
    for mut block in blocks {
        if block.name.starts_with("caliptra_") {
            block.name = block.name[9..].to_string();
        }
        if block.name.ends_with("_reg")
            || block.name.ends_with("_csr")
            || block.name.ends_with("_top")
        {
            block.name = block.name[0..block.name.len() - 4].to_string();
        }
        if block.name.ends_with("_ifc") {
            block.name = block.name[0..block.name.len() - 4].to_string();
        }
        if block.name == "I3CCSR" {
            block.name = "i3c".to_string();
        }
        if SKIP_TYPES.contains(block.name.as_str()) {
            continue;
        }
        if block.name == "soc_ifc" {
            block.rename_enum_variants(&[
                ("DEVICE_UNPROVISIONED", "UNPROVISIONED"),
                ("DEVICE_MANUFACTURING", "MANUFACTURING"),
                ("DEVICE_PRODUCTION", "PRODUCTION"),
            ]);
            // Move the TRNG retrieval registers into an independent block;
            // these need to be owned by a separate driver than the rest of
            // soc_ifc.
            let mut trng_block = RegisterBlock {
                name: "soc_ifc_trng".into(),
                instances: vec![RegisterBlockInstance {
                    name: "soc_ifc_trng_reg".into(),
                    address: block.instances[0].address,
                }],
                ..Default::default()
            };
            block.registers.retain(|field| {
                if matches!(field.name.as_str(), "CPTRA_TRNG_DATA" | "CPTRA_TRNG_STATUS") {
                    trng_block.registers.push(field.clone());
                    false // remove field from soc_ifc
                } else {
                    true // keep field
                }
            });
            let trng_block = trng_block.validate_and_dedup()?;
            validated_blocks.push(trng_block);
        }

        let block = block.validate_and_dedup()?;
        validated_blocks.push(block);
    }
    let mut root_submod_tokens = String::new();

    let mut all_blocks: Vec<_> = std::iter::once(&mut root_block)
        .chain(validated_blocks.iter_mut())
        .collect();
    registers_generator::filter_unused_types(&mut all_blocks);

    for block in validated_blocks {
        // Only generate addresses for this since the types are covered elsewhere
        let addr_only = block.block().name == "secondary_flash_ctrl";
        let module_ident = block.block().name.clone();
        let dest_file = dest_dir.join(format!("{}.rs", block.block().name));
        let tokens = registers_generator::generate_code(
            &format!("crate::{}::", block.block().name),
            &block,
            false,
            register_types_to_crates,
            addr_only,
        );
        root_submod_tokens += &format!("pub mod {module_ident};\n");
        file_action(
            &dest_file,
            &rustfmt(&(header.clone() + &tokens.to_string()))?,
        )?;
    }
    let root_type_tokens = registers_generator::generate_code(
        "crate::",
        &root_block,
        true,
        register_types_to_crates,
        false,
    );
    let recursion = "#![recursion_limit = \"2048\"]\n";
    let root_tokens = root_type_tokens;
    let defines_mod = "pub mod defines;\n";
    let fuses_tokens = "pub mod fuses;\n";
    file_action(
        &dest_dir.join("lib.rs"),
        &rustfmt(
            &(header.clone()
                + recursion
                + &root_tokens.to_string()
                + &root_submod_tokens
                + defines_mod
                + fuses_tokens),
        )?,
    )?;
    Ok(())
}

fn generate_defines(check: bool, header: String, dest_dir: &Path) -> Result<HashMap<String, u32>> {
    let file_action = if check {
        file_check_contents
    } else {
        write_file
    };

    let mut defines_map = HashMap::new();

    let define_files = ["hw/caliptra-ss/src/riscv_core/veer_el2/rtl/defines/css_mcu0_defines.h"];
    let define_files: Vec<PathBuf> = define_files.iter().map(|s| PROJECT_ROOT.join(s)).collect();
    for define_file in define_files.iter() {
        if !define_file.exists() {
            bail!("Define file not found: {:?} -- ensure that you have run `git submodule init` and `git submodule update --recursive`", define_file);
        }
    }

    let mut defines = String::new();
    for define_file in define_files.iter() {
        let define_data = std::fs::read_to_string(define_file)?;
        let (new_defines, entries) = generate_defines_from_file(define_data);
        defines += &new_defines;
        for (k, v) in entries {
            defines_map.insert(k, v);
        }
    }

    file_action(
        &dest_dir.join("defines.rs"),
        &rustfmt(&(header.clone() + &defines))?,
    )?;

    Ok(defines_map)
}

fn generate_defines_from_file(source: String) -> (String, Vec<(String, u32)>) {
    // quick and dirty C header file parser
    let mut result = String::new();
    let mut entries = vec![];
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with("/*") {
            continue;
        }
        if !line.starts_with("#define") {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 3 {
            continue;
        }
        let name = snake_case(parts[1]).to_uppercase();
        let value = parts[2];
        if let Some(value) = value.strip_prefix("0x") {
            if let Ok(value32) = u32::from_str_radix(value, 16) {
                entries.push((name.clone(), value32));
                result += &format!("pub const {}: u32 = {};\n", name, hex_const(value32.into()));
            }
        } else if let Ok(value32) = value.parse::<u32>() {
            entries.push((name.clone(), value32));
            result += &format!("pub const {}: u32 = {};\n", name, value32);
        }
    }
    (result, entries)
}

/// Run a command and return its stdout as a string.
fn run_cmd_stdout(cmd: &mut Command, input: Option<&[u8]>) -> Result<String> {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        std::io::Write::write_all(&mut stdin, input)?;
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into())
    } else {
        bail!(
            "Process {:?} {:?} exited with status code {:?} stderr {}",
            cmd.get_program(),
            cmd.get_args(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

#[derive(Debug, Deserialize)]
struct OtpMmap {
    partitions: Vec<OtpPartition>,
}

#[derive(Debug, Deserialize)]
struct OtpPartition {
    name: String,
    size: Option<String>, // bytes
    secret: bool,
    items: Vec<OtpPartitionItem>,
    desc: String,
    sw_digest: bool,
    hw_digest: bool,
    zeroizable: bool,
}

#[derive(Debug, Deserialize)]
struct OtpPartitionItem {
    name: String,
    size: String, // bytes
}

/// Autogenerate fuse map code from hjson file used to generate OTP controller config.
fn autogen_fuses(check: bool, dest_dir: &Path) -> Result<()> {
    let file_action = if check {
        file_check_contents
    } else {
        write_file
    };

    let mmap_hjson = &PROJECT_ROOT
        .join("hw/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson")
        .to_path_buf();

    let otp: OtpMmap = serde_hjson::from_str(std::fs::read_to_string(mmap_hjson)?.as_str())?;

    let mut output = "".to_string();

    let mut header = HEADER_PREFIX.to_string();
    write!(
        &mut header,
        "\n generated by registers_generator with otp_ctrl_mmap.hjson"
    )?;
    header.push_str(HEADER_SUFFIX);

    output += "use zeroize::Zeroize;";

    output += "/// Fuses contains the data in the OTP controller laid out as described in the controller configuration.\n";
    output += "#[derive(Zeroize)]\n";
    output += "pub struct Fuses {\n";

    let mut impl_output = "impl Fuses {\n".to_string();
    let mut default_impl_output = "impl Default for Fuses {\n".to_string();
    default_impl_output += "fn default() -> Self {\n";
    default_impl_output += "Self {\n";

    let mut const_output = "".to_string();

    let mut offset = 0;
    otp.partitions.iter().for_each(|partition| {
        let name = snake_case(&partition.name);
        let digest_size: usize = if partition.hw_digest || partition.sw_digest {
            8
        } else {
            0
        };
        let zeroize_size = if partition.zeroizable { 8 } else { 0 };

        let calculated_size = partition
            .items
            .iter()
            .map(|i| i.size.parse::<usize>().unwrap())
            .sum::<usize>();

        let calculated_size = if digest_size == 8 {
            // digests need to be aligned to 8-byte boundary
            calculated_size.next_multiple_of(8) + digest_size + zeroize_size
        } else {
            // partitions need to be aligned to 4-byte boundary
            calculated_size.next_multiple_of(4) + zeroize_size
        };

        let size = partition
            .size
            .as_ref()
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(calculated_size);

        if name != "vendor_test_partition" {
            assert_eq!(calculated_size, size);
        }

        output += &format!("/// {}\n", &partition.desc.replace("\n", "\n/// "));
        if !partition.secret {
            output += "#[zeroize(skip)]\n";
        }
        output += &format!("pub {}: [u8; {}],\n", name, size);
        default_impl_output += &format!("{}: [0; {}],\n", name, size);
        const_output += &format!(
            "pub const {}_BYTE_OFFSET: usize = 0x{:x};\n",
            name.to_uppercase(),
            offset
        );
        const_output += &format!(
            "pub const {}_BYTE_SIZE: usize = 0x{:x};\n",
            name.to_uppercase(),
            size,
        );

        let mut item_offset: usize = offset;
        partition.items.iter().for_each(|item| {
            let item_name = snake_case(&item.name);
            let item_size = item.size.parse::<usize>().unwrap();
            // digests need to be 8-byte aligned
            if item_name.to_ascii_lowercase().ends_with("digest") {
                item_offset = item_offset.next_multiple_of(8);
            }
            if item_size == 1 {
                impl_output += &format!("pub fn {}(&self) -> u8 {{\n", item_name);
                impl_output += &format!("    self.{}[{}]\n", name, item_offset - offset);
                impl_output += "}\n";
            } else {
                impl_output += &format!("pub fn {}(&self) -> &[u8] {{\n", item_name);
                impl_output += &format!(
                    "    &self.{}[{}..{}]\n",
                    name,
                    (item_offset - offset),
                    (item_offset + item_size - offset)
                );
                impl_output += "}\n";
            }
            item_offset += item_size;
        });
        output += "\n";
        offset += size;
        println!("Partition {} size {} bytes", partition.name, size)
    });
    output += "}\n";
    default_impl_output += "}\n}\n}\n";
    impl_output += "}\n";

    output += &impl_output;
    output += &default_impl_output;
    output += &const_output;

    let fuses_file = dest_dir.join("fuses.rs");
    file_action(
        &fuses_file,
        &rustfmt(&(header.clone() + &output.to_string()))?,
    )?;

    Ok(())
}

/// Format the given Rust code using rustfmt.
fn rustfmt(code: &str) -> Result<String> {
    run_cmd_stdout(
        Command::new("rustfmt")
            .arg("--emit=stdout")
            .arg("--config=normalize_comments=true,normalize_doc_attributes=true"),
        Some(code.as_bytes()),
    )
}

fn write_file(dest_file: &Path, contents: &str) -> Result<()> {
    println!("Writing to {dest_file:?}");
    std::fs::write(PROJECT_ROOT.join(dest_file), contents)?;
    Ok(())
}

fn file_check_contents(dest_file: &Path, expected_contents: &str) -> Result<()> {
    println!("Checking file {dest_file:?}");
    let actual_contents = std::fs::read(dest_file)?;
    if actual_contents != expected_contents.as_bytes() {
        bail!(
            "{dest_file:?} does not match the generator output. If this is \
            unexpected, ensure that the caliptra-rtl, caliptra-ss, and i3c-core \
            submodules are pointing to the correct commits and/or run
            \"git submodule update\". Otherwise, run \
            \"cargo xtask registers-autogen\" to update this file."
        );
    }
    Ok(())
}
