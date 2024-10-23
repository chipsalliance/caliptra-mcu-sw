// Licensed under the Apache-2.0 license

use crate::{DynError, PROJECT_ROOT};
use quote::__private::TokenStream;
use quote::{format_ident, quote};
use registers_generator::{
    camel_ident, has_single_32_bit_field, hex_literal, snake_ident, Register, RegisterBlock,
    RegisterBlockInstance, RegisterType, RegisterWidth, ValidatedRegisterBlock,
};
use registers_systemrdl::ParentScope;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::rc::Rc;
use std::sync::LazyLock;

static HEADER_PREFIX: &str = r"/*
Licensed under the Apache-2.0 license.
";

static HEADER_SUFFIX: &str = r"
*/
";

static SKIP_TYPES: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    HashSet::from([
        "hmac",
        "sha512",
        "sha256",
        "csrng",
        "entropy_src",
        "sha512_acc",
    ])
});

pub(crate) fn autogen(check: bool) -> Result<(), DynError> {
    let sub_dir = &PROJECT_ROOT.join("hw").join("caliptra-ss").to_path_buf();
    let rtl_dir = &sub_dir.join("caliptra-rtl").to_path_buf();
    let i3c_dir = &PROJECT_ROOT.join("hw").join("i3c-core").to_path_buf();
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
    // TODO: the parsing is too fragile and requires the files to be passed in in a specific order
    // TODO: these don't seem right. We shouldn't have these crypto accelerators in the MCU.
    let rdl_files: Vec<PathBuf> = [
        "hw/caliptra-ss/src/mci/rtl/mci_reg.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/csrng/data/csrng.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/keyvault/rtl/kv_def.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/entropy_src/data/entropy_src.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/hmac/rtl/hmac_reg.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/sha256/rtl/sha256_reg.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/sha512/rtl/sha512_reg.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/soc_ifc/rtl/mbox_csr.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/soc_ifc/rtl/sha512_acc_csr.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/soc_ifc/rtl/soc_ifc_reg.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/spi_host/data/spi_host.rdl",
        "hw/caliptra-ss/caliptra-rtl/src/uart/data/uart.rdl",
        "hw/i3c-core/src/rdl/registers.rdl",
        "hw/caliptra-ss/src/mcu/rtl/caliptra_mcu_reg.rdl",
        "hw/el2_pic_ctrl.rdl",
        "hw/clp2.rdl",
    ]
    .iter()
    .map(|s| PROJECT_ROOT.join(s))
    .collect();

    // eliminate duplicate type names
    let patches = vec![
        (
            PROJECT_ROOT.join("hw/i3c-core/src/rdl/target_transaction_interface.rdl"),
            "QUEUE_THLD_CTRL",
            "TTI_QUEUE_THLD_CTRL",
        ),
        (
            PROJECT_ROOT.join("hw/i3c-core/src/rdl/target_transaction_interface.rdl"),
            "QUEUE_SIZE",
            "TTI_QUEUE_SIZE",
        ),
        (
            PROJECT_ROOT.join("hw/i3c-core/src/rdl/target_transaction_interface.rdl"),
            "IBI_PORT",
            "TTI_IBI_PORT",
        ),
        (
            PROJECT_ROOT.join("hw/i3c-core/src/rdl/target_transaction_interface.rdl"),
            "DATA_BUFFER_THLD_CTRL",
            "TTI_DATA_BUFFER_THLD_CTRL",
        ),
        (
            PROJECT_ROOT.join("hw/i3c-core/src/rdl/target_transaction_interface.rdl"),
            "RESET_CONTROL",
            "TTI_RESET_CONTROL",
        ),
    ];

    for rdl in rdl_files.iter() {
        if !rdl.exists() {
            return Err(format!("RDL file not found: {:?} -- ensure that you have run `git submodule init` and `git submodule update --recursive`", rdl).into());
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

    let i3c_commit_id = run_cmd_stdout(
        Command::new("git")
            .current_dir(i3c_dir)
            .arg("rev-parse")
            .arg("HEAD"),
        None,
    )?;
    let i3c_git_status = run_cmd_stdout(
        Command::new("git")
            .current_dir(i3c_dir)
            .arg("status")
            .arg("--porcelain"),
        None,
    )?;

    let rtl_commit_id = run_cmd_stdout(
        Command::new("git")
            .current_dir(rtl_dir)
            .arg("rev-parse")
            .arg("HEAD"),
        None,
    )?;
    let rtl_git_status = run_cmd_stdout(
        Command::new("git")
            .current_dir(rtl_dir)
            .arg("status")
            .arg("--porcelain"),
        None,
    )?;
    let mut header = HEADER_PREFIX.to_string();
    write!(
        &mut header,
        "\n generated by registers_generator with caliptra-rtl repo at {rtl_commit_id}, caliptra-ss repo at {sub_commit_id}, and i3c-core repo at {i3c_commit_id}",
    )?;
    if !i3c_git_status.is_empty() {
        write!(
            &mut header,
            "\n\nWarning: i3c-core was dirty:{i3c_git_status}"
        )?;
    }
    if !sub_git_status.is_empty() {
        write!(
            &mut header,
            "\n\nWarning: caliptra-ss was dirty:{sub_git_status}"
        )?;
    }
    if !rtl_git_status.is_empty() {
        write!(
            &mut header,
            "\n\nWarning: caliptra-rtl was dirty:{rtl_git_status}"
        )?;
    }
    header.push_str(HEADER_SUFFIX);

    let file_source = registers_systemrdl::FsFileSource::new();
    for patch in patches {
        file_source.add_patch(&patch.0, patch.1, patch.2);
    }
    let scope = registers_systemrdl::Scope::parse_root(&file_source, &rdl_files)
        .map_err(|s| s.to_string())?;
    let scope = scope.as_parent();

    let addrmap = scope.lookup_typedef("clp").unwrap();
    let addrmap2 = scope.lookup_typedef("clp2").unwrap();
    let scopes = vec![addrmap, addrmap2];

    // These are types like kv_read_ctrl_reg that are used by multiple crates
    let root_block = RegisterBlock {
        declared_register_types: registers_generator::translate_types(scope)?,
        ..Default::default()
    };
    let root_block = root_block.validate_and_dedup()?;

    generate_fw_registers(
        root_block.clone(),
        &scopes.clone(),
        header.clone(),
        registers_dest_dir,
        check,
    )?;
    //generate_emulator_types(root_block, &scopes, bus_dest_dir, header.clone())
    Ok(())
}

// /// Generate types used by the emulator.
// fn generate_emulator_types(
//     root_block: ValidatedRegisterBlock,
//     scopes: &[ParentScope],
//     dest_dir: &Path,
//     header: String,
// ) -> Result<(), DynError> {
//     let mut lib_code = TokenStream::new();
//     let mut blocks = vec![];
//     for scope in scopes.iter() {
//         blocks.extend(registers_generator::translate_addrmap(*scope)?);
//     }
//     let mut validated_blocks = vec![];

//     for block in blocks.iter_mut() {
//         if block.name.ends_with("_reg") || block.name.ends_with("_csr") {
//             block.name = block.name[0..block.name.len() - 4].to_string();
//         }
//         if block.name.ends_with("_ctrl") {
//             block.name = block.name[0..block.name.len() - 5].to_string();
//         }
//         if block.name.ends_with("_ifc") {
//             block.name = block.name[0..block.name.len() - 4].to_string();
//         }
//         if SKIP_TYPES.contains(block.name.as_str()) {
//             continue;
//         }
//         remove_reg_prefixes(
//             &mut block.registers,
//             &format!("{}_", block.name.to_ascii_lowercase()),
//         );
//         let block = block.clone().validate_and_dedup()?;
//         validated_blocks.push(block);
//     }

//     let mut generated_types = HashSet::new();

//     for block in validated_blocks.iter() {
//         let rblock = block.block();
//         let mut code = TokenStream::new();
//         code.extend(emu_make_data_types(block)?);
//         code.extend(emu_make_peripheral_trait(
//             rblock.clone(),
//             &mut generated_types,
//         )?);
//         code.extend(emu_make_peripheral_bus_impl(rblock.clone())?);

//         let dest_file = dest_dir.join(format!("{}.rs", rblock.name));
//         write_file(&dest_file, &rustfmt(&(header.clone() + &code.to_string()))?)?;
//         let block_name = format_ident!("{}", rblock.name);
//         lib_code.extend(quote! {
//             pub mod #block_name;
//         });
//     }
//     let root_bus_code = emu_make_root_bus(
//         validated_blocks
//             .iter()
//             .filter(|b| !SKIP_TYPES.contains(b.block().name.as_str())),
//     )?;
//     let root_bus_file = dest_dir.join("root_bus.rs");
//     write_file(
//         &root_bus_file,
//         &rustfmt(&(header.clone() + &root_bus_code.to_string()))?,
//     )?;

//     lib_code.extend(quote! { pub mod root_bus; });

//     let enum_tokens = generate_enums(root_block.enum_types().values().map(AsRef::as_ref));
//     lib_code.extend(quote! {
//         pub mod enums {
//             //! Enumerations used by some register fields.
//             #enum_tokens
//         }
//     });

//     let lib_file = dest_dir.join("lib.rs");
//     write_file(
//         &lib_file,
//         &rustfmt(&(header.clone() + &lib_code.to_string()))?,
//     )?;
//     Ok(())
// }

// /// Make data accessors types for the emulator peripheral.
// fn emu_make_data_types(block: &ValidatedRegisterBlock) -> Result<TokenStream, DynError> {
//     let mut tokens = TokenStream::new();
//     let mut generated = HashSet::new();

//     let registers = flatten_registers(0, String::new(), block.block());
//     registers.iter().for_each(|(_, _, r)| {
//         // skip as this register is not defined yet
//         if r.name == "MCU_CLK_GATING_EN" {
//             return;
//         }
//         // skip these are they are just for discovery
//         if r.name == "TERMINATION_EXTCAP_HEADER" {
//             return;
//         }
//         let ty = if r.ty.name.is_none() {
//             let mut ty = r.ty.as_ref().clone();
//             ty.name = Some(r.name.clone());
//             ty
//         } else {
//             r.ty.as_ref().clone()
//         };
//         if !has_single_32_bit_field(&r.ty) {
//             let name = ty.name.as_ref().unwrap().clone();
//             if !generated.contains(&name) {
//                 generated.insert(name);
//                 tokens.extend(generate_register(&ty, true, true));
//             }
//         }
//     });
//     let enum_tokens = generate_enums(block.enum_types().values().map(AsRef::as_ref));
//     tokens.extend(quote! {
//         pub mod enums {
//             //! Enumerations used by some register fields.
//             #enum_tokens
//         }
//     });
//     Ok(tokens)
// }

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

fn make_anon_type(offset: u64, reg: Rc<Register>) -> RegisterType {
    let reg_name = snake_ident(&reg.name);
    let mut new_ty = reg.ty.as_ref().clone();
    new_ty.name = Some(format!("{}_o{}", reg_name, offset + reg.offset));
    new_ty
}

// /// Make a peripheral trait that the emulator code can implement.
// fn emu_make_peripheral_trait(
//     block: RegisterBlock,
//     generated: &mut HashSet<String>,
// ) -> Result<TokenStream, DynError> {
//     let base = camel_ident(block.name.as_str());
//     let periph = format_ident!("{}Peripheral", base);
//     let mut fn_tokens = TokenStream::new();
//     let mut anon_type_tokens = TokenStream::new();

//     let registers = flatten_registers(0, String::new(), &block);
//     registers.iter().for_each(|(_, base_name, r)| {
//         // skip as this register is not defined yet
//         if r.name == "MCU_CLK_GATING_EN" {
//             return;
//         }
//         // skip these are they are just for discovery
//         if r.name == "TERMINATION_EXTCAP_HEADER" {
//             return;
//         }
//         let ty = if r.ty.name.is_none() {
//             let new_ty = make_anon_type(r.offset, r.clone());
//             if !generated.contains(new_ty.name.as_ref().unwrap()) {
//                 generated.insert(new_ty.name.as_ref().unwrap().clone());
//                 anon_type_tokens.extend(generate_register(&new_ty, true, true));
//             }
//             new_ty
//         } else {
//             r.ty.as_ref().clone()
//         };
//         let base_field = snake_ident(r.name.as_str());
//         let base_name = if base_name.is_empty() {
//             base_name.clone()
//         } else {
//             format!("{}_", snake_ident(base_name.as_str()))
//         };
//         let read_name = format_ident!(
//             "{}",
//             format!("read_{}{}", base_name, base_field).replace("__", "_")
//         );
//         let write_name = format_ident!(
//             "{}",
//             format!("write_{}{}", base_name, base_field).replace("__", "_"),
//         );
//         if has_single_32_bit_field(&r.ty) {
//             fn_tokens.extend(quote! {
//                 fn #read_name(&mut self) -> u32 { 0 }
//                 fn #write_name(&mut self, _val: u32) {}
//             });
//         } else {
//             let read_val = read_val_ident("", &ty);
//             let write_val = write_val_ident("", &ty);
//             fn_tokens.extend(quote! {
//                 fn #read_name(&mut self) -> #write_val { #write_val::default() }
//                 fn #write_name(&mut self, _val: #read_val) {}
//             });
//         }
//     });
//     let mut tokens = TokenStream::new();
//     tokens.extend(quote! {
//         pub trait #periph {
//             fn poll(&mut self) {}
//             fn warm_reset(&mut self) {}
//             fn update_reset(&mut self) {}
//             #fn_tokens
//         }
//         #anon_type_tokens
//     });
//     Ok(tokens)
// }

// /// Make a peripheral Bus implementation that can be hooked up to a root bus.
// fn emu_make_peripheral_bus_impl(block: RegisterBlock) -> Result<TokenStream, DynError> {
//     let base = camel_ident(block.name.as_str());
//     let periph = format_ident!("{}Peripheral", base);
//     let bus = format_ident!("{}Bus", base);
//     let mut read_tokens = TokenStream::new();
//     let mut write_tokens = TokenStream::new();
//     let registers = flatten_registers(0, String::new(), &block);
//     registers.iter().for_each(|(offset, base_name, r)| {
//         // skip as this register is not defined yet
//         if r.name == "MCU_CLK_GATING_EN" {
//             return;
//         }
//         // skip these are they are just for discovery
//         if r.name == "TERMINATION_EXTCAP_HEADER" {
//             return;
//         }
//         let ty = if r.ty.name.is_none() {
//             make_anon_type(r.offset, r.clone())
//         } else {
//             r.ty.as_ref().clone()
//         };
//         let base_field = snake_ident(r.name.as_str());
//         let base_name = if base_name.is_empty() {
//             base_name.clone()
//         } else {
//             format!("{}_", snake_ident(base_name.as_str()))
//         };
//         let read_name = format_ident!(
//             "{}",
//             format!("read_{}{}", base_name, base_field).replace("__", "_")
//         );
//         let write_name = format_ident!(
//             "{}",
//             format!("write_{}{}", base_name, base_field).replace("__", "_"),
//         );
//         let a = hex_literal(offset + r.offset);
//         let a1 = hex_literal(offset + r.offset + 1);
//         let a3 = hex_literal(offset + r.offset + 3);
//         if has_single_32_bit_field(&r.ty) {
//             if r.ty.fields[0].ty.can_write() {
//                 read_tokens.extend(quote! {
//                     (emulator_types::RvSize::Word, #a) => Ok(emulator_types::RvData::from(self.periph.#read_name())),
//                     (emulator_types::RvSize::Word, #a1 ..= #a3) => Err(emulator_bus::BusError::LoadAddrMisaligned),
//                 });
//             }
//             if r.ty.fields[0].ty.can_read() {
//                 write_tokens.extend(quote! {
//                     (emulator_types::RvSize::Word, #a) => {
//                         self.periph.#write_name(val);
//                         Ok(())
//                     }
//                     (emulator_types::RvSize::Word, #a1 ..= #a3) => Err(emulator_bus::BusError::StoreAddrMisaligned),
//                 });
//             }
//         } else {
//             let read_val = read_val_ident("", &ty);
//             match r.ty.width {
//                 RegisterWidth::_8 => {
//                     read_tokens.extend(quote! {
//                         (emulator_types::RvSize::Byte, #a) => Ok(emulator_types::RvData::from(self.periph.#read_name())),
//                     });
//                     write_tokens.extend(quote! {
//                         (emulator_types::RvSize::Byte, #a) => {
//                             self.periph.#write_name(#read_val::from(val));
//                             Ok(())
//                         }
//                     });
//                 }
//                 RegisterWidth::_16 => {
//                     read_tokens.extend(quote! {
//                         (emulator_types::RvSize::HalfWord, #a) => Ok(emulator_types::RvData::from(self.periph.#read_name())),
//                         (emulator_types::RvSize::HalfWord, #a1) => Err(emulator_bus::BusError::LoadAddrMisaligned),
//                     });
//                     write_tokens.extend(quote! {
//                         (emulator_types::RvSize::HalfWord, #a) => {
//                             self.periph.#write_name(#read_val::from(val));
//                             Ok(())
//                         }
//                         (emulator_types::RvSize::HalfWord, #a1) => Err(emulator_bus::BusError::StoreAddrMisaligned),
//                     });

//                 },
//                 RegisterWidth::_32 => {
//                     read_tokens.extend(quote! {
//                         (emulator_types::RvSize::Word, #a) => Ok(emulator_types::RvData::from(self.periph.#read_name())),
//                         (emulator_types::RvSize::Word, #a1 ..= #a3) => Err(emulator_bus::BusError::LoadAddrMisaligned),
//                     });
//                     write_tokens.extend(quote! {
//                         (emulator_types::RvSize::Word, #a) => {
//                             self.periph.#write_name(#read_val::from(val));
//                             Ok(())
//                         }
//                         (emulator_types::RvSize::Word, #a1 ..= #a3) => Err(emulator_bus::BusError::StoreAddrMisaligned),
//                     });
//                 },
//                 RegisterWidth::_64 => todo!(),
//                 RegisterWidth::_128 => todo!(),
//             }
//         }
//     });
//     let mut tokens = TokenStream::new();
//     tokens.extend(quote! {
//         pub struct #bus {
//             pub periph: Box<dyn #periph>,
//         }
//         impl emulator_bus::Bus for #bus {
//             fn read(&mut self, size: emulator_types::RvSize, addr: emulator_types::RvAddr) -> Result<emulator_types::RvData, emulator_bus::BusError> {
//                 match (size, addr) {
//                     #read_tokens
//                     _ => Err(emulator_bus::BusError::LoadAccessFault),
//                 }
//             }
//             fn write(&mut self, size: emulator_types::RvSize, addr: emulator_types::RvAddr, val: emulator_types::RvData) -> Result<(), emulator_bus::BusError> {
//                 match (size, addr) {
//                     #write_tokens
//                     _ => Err(emulator_bus::BusError::StoreAccessFault),
//                 }

//             }
//             fn poll(&mut self) {
//                 self.periph.poll();
//             }
//             fn warm_reset(&mut self) {
//                 self.periph.warm_reset();
//             }
//             fn update_reset(&mut self) {
//                 self.periph.update_reset();
//             }
//         }
//     });
//     Ok(tokens)
// }

/// Calculate the width of a register block.
fn whole_width(block: &RegisterBlock) -> u64 {
    let a = block
        .registers
        .iter()
        .map(|r| r.offset + r.ty.width.in_bytes())
        .sum::<u64>();
    let b = block
        .sub_blocks
        .iter()
        .map(|sb| sb.start_offset() + whole_width(sb.block()))
        .sum::<u64>();
    a.max(b)
}

/// Make the root bus that can be used by the emulator.
fn emu_make_root_bus<'a>(
    blocks: impl Iterator<Item = &'a ValidatedRegisterBlock>,
) -> Result<TokenStream, DynError> {
    let mut read_tokens = TokenStream::new();
    let mut write_tokens = TokenStream::new();
    let mut poll_tokens = TokenStream::new();
    let mut warm_reset_tokens = TokenStream::new();
    let mut update_reset_tokens = TokenStream::new();
    let mut field_tokens = TokenStream::new();
    let mut constructor_tokens = TokenStream::new();
    let mut constructor_params_tokens = TokenStream::new();

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
        let a = hex_literal(rblock.instances[0].address as u64);
        let b = hex_literal(rblock.instances[0].address as u64 + whole_width(rblock));
        read_tokens.extend(quote! {
            #a..=#b => {
                if let Some(periph) = self.#periph_field.as_mut() {
                    periph.read(size, addr)
                } else {
                    Err(emulator_bus::BusError::LoadAccessFault)
                }
            }
        });
        write_tokens.extend(quote! {
            #a..=#b => {
                if let Some(periph) = self.#periph_field.as_mut() {
                    periph.write(size, addr, val)
                } else {
                    Err(emulator_bus::BusError::StoreAccessFault)
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
    }
    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
            pub struct AutoRootBus {
                delegate: Option<Box<dyn emulator_bus::Bus>>,
                #field_tokens
            }
            impl AutoRootBus {
                #[allow(clippy::too_many_arguments)]
                pub fn new(
                    delegate: Option<Box<dyn emulator_bus::Bus>>,
                    #constructor_params_tokens
                ) -> Self {
                    Self {
                        delegate,
                        #constructor_tokens
                    }
                }
            }
            impl emulator_bus::Bus for AutoRootBus {
                fn read(&mut self, size: emulator_types::RvSize, addr: emulator_types::RvAddr) -> Result<emulator_types::RvData, emulator_bus::BusError> {
                    let result = match addr {
                        #read_tokens
                        _ => Err(emulator_bus::BusError::LoadAccessFault),
                    };
                    if let Some(delegate) = self.delegate.as_mut() {
                        match result {
                            Err(emulator_bus::BusError::LoadAccessFault) => delegate.read(size, addr),
                            _ => result,
                        }
                    } else {
                        result
                    }
                }
                fn write(&mut self, size: emulator_types::RvSize, addr: emulator_types::RvAddr, val: emulator_types::RvData) -> Result<(), emulator_bus::BusError> {
                    let result = match addr {
                        #write_tokens
                        _ => Err(emulator_bus::BusError::StoreAccessFault),
                    };
                    if let Some(delegate) = self.delegate.as_mut() {
                        match result {
                            Err(emulator_bus::BusError::StoreAccessFault) => delegate.write(size, addr, val),
                            _ => result,
                        }
                    } else {
                        result
                    }
                }
                fn poll(&mut self) {
                    #poll_tokens
                    if let Some(delegate) = self.delegate.as_mut() {
                        delegate.poll();
                    }
                }
                fn warm_reset(&mut self) {
                    #warm_reset_tokens
                    if let Some(delegate) = self.delegate.as_mut() {
                        delegate.warm_reset();
                    }
                }
                fn update_reset(&mut self) {
                    #update_reset_tokens
                    if let Some(delegate) = self.delegate.as_mut() {
                        delegate.update_reset();
                    }
                }
            }
        });
    Ok(tokens)
}

/// Generate read/write registers used by the firmware.
fn generate_fw_registers(
    mut root_block: ValidatedRegisterBlock,
    scopes: &[ParentScope],
    header: String,
    dest_dir: &Path,
    check: bool,
) -> Result<(), DynError> {
    let file_action = if check {
        file_check_contents
    } else {
        write_file
    };

    let mut extern_types = HashMap::new();
    registers_generator::build_extern_types(&root_block, quote! { crate }, &mut extern_types);

    let mut blocks = vec![];
    for scope in scopes.iter() {
        blocks.extend(registers_generator::translate_addrmap(*scope)?);
    }
    let mut validated_blocks = vec![];
    for mut block in blocks {
        if block.name.ends_with("_reg") || block.name.ends_with("_csr") {
            block.name = block.name[0..block.name.len() - 4].to_string();
        }
        if SKIP_TYPES.contains(block.name.as_str()) {
            continue;
        }
        remove_reg_prefixes(
            &mut block.registers,
            &format!("{}_", block.name.to_ascii_lowercase()),
        );
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
        let module_ident = format_ident!("{}", block.block().name);
        registers_generator::build_extern_types(
            &block,
            quote! { crate::#module_ident },
            &mut extern_types,
        );
        validated_blocks.push(block);
    }
    let mut root_submod_tokens = TokenStream::new();

    let mut all_blocks: Vec<_> = std::iter::once(&mut root_block)
        .chain(validated_blocks.iter_mut())
        .collect();
    registers_generator::filter_unused_types(&mut all_blocks);

    for block in validated_blocks {
        let module_ident = format_ident!("{}", block.block().name);
        let dest_file = dest_dir.join(format!("{}.rs", block.block().name));

        let tokens = registers_generator::generate_code(
            &format!("crate::{}::", block.block().name),
            &block,
            registers_generator::Options {
                extern_types: extern_types.clone(),
                module: quote! { #module_ident },
            },
        );
        root_submod_tokens.extend(quote! { pub mod #module_ident; });
        file_action(
            &dest_file,
            &rustfmt(&(header.clone() + &tokens.to_string()))?,
        )?;
    }
    let root_type_tokens = registers_generator::generate_code(
        "crate::",
        &root_block,
        registers_generator::Options {
            extern_types: extern_types.clone(),
            ..Default::default()
        },
    );
    //let root_tokens = quote! { #root_type_tokens #root_submod_tokens };
    let root_tokens = root_type_tokens;
    file_action(
        &dest_dir.join("lib.rs"),
        &rustfmt(&(header.clone() + &root_tokens.to_string() + &root_submod_tokens.to_string()))?,
    )?;
    Ok(())
}

/// Run a command and return its stdout as a string.
fn run_cmd_stdout(cmd: &mut Command, input: Option<&[u8]>) -> Result<String, DynError> {
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
        Err(format!(
            "Process {:?} {:?} exited with status code {:?} stderr {}",
            cmd.get_program(),
            cmd.get_args(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
        .into())
    }
}

/// Remove the given prefix from the register names, if present.
fn remove_reg_prefixes(registers: &mut [Rc<Register>], prefix: &str) {
    for reg in registers.iter_mut() {
        if reg.name.to_ascii_lowercase().starts_with(prefix) {
            let reg = Rc::make_mut(reg);
            reg.name = reg.name[prefix.len()..].to_string();
        }
    }
}

/// Format the given Rust code using rustfmt.
fn rustfmt(code: &str) -> Result<String, DynError> {
    run_cmd_stdout(
        Command::new("rustfmt")
            .arg("--emit=stdout")
            .arg("--config=normalize_comments=true,normalize_doc_attributes=true"),
        Some(code.as_bytes()),
    )
}

fn write_file(dest_file: &Path, contents: &str) -> Result<(), DynError> {
    println!("Writing to {dest_file:?}");
    std::fs::write(PROJECT_ROOT.join(dest_file), contents)?;
    Ok(())
}

fn file_check_contents(dest_file: &Path, expected_contents: &str) -> Result<(), DynError> {
    println!("Checking file {dest_file:?}");
    let actual_contents = std::fs::read(dest_file)?;
    if actual_contents != expected_contents.as_bytes() {
        return Err(format!(
            "{dest_file:?} does not match the generator output. If this is \
            unexpected, ensure that the caliptra-rtl, caliptra-ss, and i3c-core \
            submodules are pointing to the correct commits and/or run
            \"git submodule update\". Otherwise, run \
            \"cargo xtask registers-autogen\" to update this file."
        )
        .into());
    }
    Ok(())
}
