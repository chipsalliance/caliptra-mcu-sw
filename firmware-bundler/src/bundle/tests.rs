// Licensed under the Apache-2.0 license

use super::*;
use crate::build::{BuiltApp, BuiltBinary};
use crate::manifest::{Binary, Memory};
use crate::tbf::create_tbf_header;
use caliptra_mcu_tbf_header::TbfHeaderTypes;
use std::process::Command;

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[test]
fn linked_apps_follow_allocated_tbf_chain() {
    let temp = tempfile::Builder::new()
        .prefix("bundle-chain-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let common = Common::new_for_test(temp.path().to_path_buf());
    std::fs::write(
        &common.manifest,
        r#"
[platform]
name = "chain-test"
tuple = "riscv32imc-unknown-none-elf"
dynamic_sizing = true
rom = { offset = 0, size = 0x1000 }
runtime_memory = { sram = { offset = 0x10000, size = 0x20000 } }
[kernel]
name = "kernel"
stack = 0x100
[[app]]
name = "first"
stack = 0x100
[[app]]
name = "second"
stack = 0x100
"#,
    )
    .unwrap();
    let manifest = common.manifest().unwrap();
    let binary_dir = common.release_dir().unwrap();
    std::fs::create_dir_all(&binary_dir).unwrap();
    let source = temp.path().join("probe.rs");
    let object = temp.path().join("probe.o");
    std::fs::write(
        &source,
        "#![no_std]\n#[no_mangle]\npub extern \"C\" fn start() {}\n",
    )
    .unwrap();
    run(Command::new("rustc")
        .args([
            "--crate-type=lib",
            "--emit=obj",
            "--target=riscv32imc-unknown-none-elf",
            "-Cpanic=abort",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object));
    let sysroot = crate::utils::find_sysroot().unwrap();
    let linker = crate::utils::find_file(
        &sysroot,
        &format!("rust-lld{}", std::env::consts::EXE_SUFFIX),
    )
    .unwrap();
    let objcopy = crate::utils::objcopy().unwrap();
    let mut apps = Vec::new();
    // The first allocation ends at 0x20000, leaving a gap before the next header.
    for (name, offset, size) in [("first", 0x1c000, 0x4000), ("second", 0x21000, 0x1000)] {
        let header = create_tbf_header(&Binary::new_for_test(name, size, 0x100, None, 0)).unwrap();
        let header_size = header.generate().unwrap().get_ref().len();
        let elf = binary_dir.join(name);
        let binary = elf.with_extension("bin");
        let script = temp.path().join(format!("{name}.ld"));
        std::fs::write(
            &script,
            format!(
                "ENTRY(start)\nSECTIONS {{ . = {:#x}; .text : {{ *(.text*) }} }}\n",
                offset + header_size as u64
            ),
        )
        .unwrap();
        run(Command::new(&linker)
            .args(["-flavor", "gnu", "-m", "elf32lriscv", "-T"])
            .arg(&script)
            .arg(&object)
            .arg("-o")
            .arg(&elf));
        run(Command::new(&objcopy)
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&binary));
        apps.push(BuiltApp {
            binary: BuiltBinary {
                name: name.into(),
                elf,
                binary,
            },
            header,
            instruction_block: Memory { offset, size },
        });
    }
    let kernel = binary_dir.join("kernel.bin");
    std::fs::write(&kernel, [0u8; 4]).unwrap();
    let output = BuildOutput {
        rom: None,
        runtime: RuntimeVariant::Kernel((
            BuiltBinary {
                name: "kernel".into(),
                elf: kernel.with_extension(""),
                binary: kernel,
            },
            Memory {
                offset: 0x10000,
                size: 0xc000,
            },
        )),
        apps,
    };
    bundle(&manifest, &output, &common, &BundleArgs::default()).unwrap();
    let bytes = std::fs::read(binary_dir.join("runtime-chain-test.bin")).unwrap();
    let mut cursor = 0xc000;
    for (app, expected_size) in output.apps.iter().zip([0x5000, 0x1000]) {
        assert_eq!(cursor as u64, app.instruction_block.offset - 0x10000);
        assert_eq!(u16_at(&bytes, cursor), 2);
        let header_size = u16_at(&bytes, cursor + 2) as usize;
        let total_size = u32_at(&bytes, cursor + 4) as usize;
        assert_eq!(total_size, expected_size);
        let checksum = bytes[cursor..cursor + header_size]
            .chunks_exact(4)
            .fold(0, |sum, word| sum ^ u32_at(word, 0));
        assert_eq!(checksum, 0);
        let mut tlv = cursor + 16;
        let mut program_found = false;
        while tlv + 4 <= cursor + header_size {
            let kind = u16_at(&bytes, tlv);
            let length = u16_at(&bytes, tlv + 2) as usize;
            if kind == TbfHeaderTypes::Program as u16 {
                assert_eq!(u32_at(&bytes, tlv + 4), 0);
                assert_eq!(u32_at(&bytes, tlv + 16) as usize, total_size);
                program_found = true;
            }
            tlv += (4 + length).next_multiple_of(4);
        }
        assert!(program_found);
        let app_bytes = std::fs::read(&app.binary.binary).unwrap();
        assert!(!app_bytes.is_empty());
        let payload = cursor + header_size;
        assert_eq!(&bytes[payload..payload + app_bytes.len()], app_bytes);
        assert!(bytes[payload + app_bytes.len()..cursor + total_size]
            .iter()
            .all(|byte| *byte == 0));
        cursor += total_size;
    }
    assert_eq!(cursor, bytes.len());

    let app = &output.apps[1];
    let header_size = app.header.generate().unwrap().get_ref().len();
    let oversized = vec![0u8; app.instruction_block.size as usize - header_size + 1];
    std::fs::write(&app.binary.binary, oversized).unwrap();
    assert!(generate_tbf_header(
        app.header.clone(),
        app.instruction_block.clone(),
        app.binary.elf.clone(),
        app.binary.binary.clone(),
    )
    .is_err());
}
