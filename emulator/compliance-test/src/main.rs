/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    Test-runner for risc-v compliance tests from https://github.com/riscv-non-isa/riscv-arch-test.

--*/

use caliptra_emu_types::RvSize;
use clap::{arg, value_parser};
use emulator_bus::{Bus, Clock, Ram};
use emulator_cpu::{Cpu, Pic, StepAction};
use fs::TempDir;
use std::error::Error;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::{env::set_var, rc::Rc};
use test_data::{get_binary_data, get_signature_data, run_riscof};

mod exec;
mod fs;
mod test_data;

pub struct TestInfo {
    extension: &'static str,
    name: &'static str,
}
#[rustfmt::skip]
static TESTS_TO_RUN: &[TestInfo] = &[
    TestInfo { extension: "C", name: "cadd-01", },
    TestInfo { extension: "C", name: "caddi-01", },
    TestInfo { extension: "C", name: "caddi16sp-01", },
    TestInfo { extension: "C", name: "caddi4spn-01", },
    TestInfo { extension: "C", name: "cand-01", },
    TestInfo { extension: "C", name: "candi-01", },
    TestInfo { extension: "C", name: "cbeqz-01", },
    TestInfo { extension: "C", name: "cbnez-01", },
    TestInfo { extension: "C", name: "cebreak-01", },
    TestInfo { extension: "C", name: "cj-01", },
    TestInfo { extension: "C", name: "cjal-01", },
    TestInfo { extension: "C", name: "cjalr-01", },
    TestInfo { extension: "C", name: "cjr-01", },
    TestInfo { extension: "C", name: "cli-01", },
    TestInfo { extension: "C", name: "clui-01", },
    TestInfo { extension: "C", name: "clw-01", },
    TestInfo { extension: "C", name: "clwsp-01", },
    TestInfo { extension: "C", name: "cmv-01", },
    TestInfo { extension: "C", name: "cnop-01", },
    TestInfo { extension: "C", name: "cor-01", },
    TestInfo { extension: "C", name: "cslli-01", },
    TestInfo { extension: "C", name: "csrai-01", },
    TestInfo { extension: "C", name: "csrli-01", },
    TestInfo { extension: "C", name: "csub-01", },
    TestInfo { extension: "C", name: "csw-01", },
    TestInfo { extension: "C", name: "cswsp-01", },
    TestInfo { extension: "C", name: "cxor-01", },
    TestInfo { extension: "I", name: "add-01", },
    TestInfo { extension: "I", name: "addi-01", },
    TestInfo { extension: "I", name: "and-01", },
    TestInfo { extension: "I", name: "andi-01", },
    TestInfo { extension: "I", name: "auipc-01", },
    TestInfo { extension: "I", name: "beq-01", },
    TestInfo { extension: "I", name: "bge-01", },
    TestInfo { extension: "I", name: "bgeu-01", },
    TestInfo { extension: "I", name: "blt-01", },
    TestInfo { extension: "I", name: "bltu-01", },
    TestInfo { extension: "I", name: "bne-01", },
    TestInfo { extension: "I", name: "fence-01", },
    TestInfo { extension: "I", name: "jal-01", },
    TestInfo { extension: "I", name: "jalr-01", },
    TestInfo { extension: "I", name: "lb-align-01", },
    TestInfo { extension: "I", name: "lbu-align-01", },
    TestInfo { extension: "I", name: "lh-align-01", },
    TestInfo { extension: "I", name: "lhu-align-01", },
    TestInfo { extension: "I", name: "lui-01", },
    TestInfo { extension: "I", name: "lw-align-01", },
    TestInfo { extension: "I", name: "misalign1-jalr-01", },
    TestInfo { extension: "I", name: "or-01", },
    TestInfo { extension: "I", name: "ori-01", },
    TestInfo { extension: "I", name: "sb-align-01", },
    TestInfo { extension: "I", name: "sh-align-01", },
    TestInfo { extension: "I", name: "sll-01", },
    TestInfo { extension: "I", name: "slli-01", },
    TestInfo { extension: "I", name: "slt-01", },
    TestInfo { extension: "I", name: "slti-01", },
    TestInfo { extension: "I", name: "sltiu-01", },
    TestInfo { extension: "I", name: "sltu-01", },
    TestInfo { extension: "I", name: "sra-01", },
    TestInfo { extension: "I", name: "srai-01", },
    TestInfo { extension: "I", name: "srl-01", },
    TestInfo { extension: "I", name: "srli-01", },
    TestInfo { extension: "I", name: "sub-01", },
    TestInfo { extension: "I", name: "sw-align-01", },
    TestInfo { extension: "I", name: "xor-01", },
    TestInfo { extension: "I", name: "xori-01", },
    TestInfo { extension: "M", name: "div-01", },
    TestInfo { extension: "M", name: "divu-01", },
    TestInfo { extension: "M", name: "mul-01", },
    TestInfo { extension: "M", name: "mulh-01", },
    TestInfo { extension: "M", name: "mulhsu-01", },
    TestInfo { extension: "M", name: "mulhu-01", },
    TestInfo { extension: "M", name: "rem-01", },
    TestInfo { extension: "M", name: "remu-01", },
    TestInfo { extension: "privilege", name: "ebreak", },
    TestInfo { extension: "privilege", name: "ecall", },
    TestInfo { extension: "privilege", name: "misalign-beq-01", },
    TestInfo { extension: "privilege", name: "misalign-bge-01", },
    TestInfo { extension: "privilege", name: "misalign-bgeu-01", },
    TestInfo { extension: "privilege", name: "misalign-blt-01", },
    TestInfo { extension: "privilege", name: "misalign-bltu-01", },
    TestInfo { extension: "privilege", name: "misalign-bne-01", },
    TestInfo { extension: "privilege", name: "misalign-jal-01", },
    // These tests do not work right now because misaligned reads may or may not succeed.
    // See https://github.com/riscv-non-isa/riscv-arch-test?tab=readme-ov-file#test-disclaimers
    //TestInfo { extension: "privilege", name: "misalign-lh-01", },
    //TestInfo { extension: "privilege", name: "misalign-lhu-01", },
    //TestInfo { extension: "privilege", name: "misalign-lw-01", },
    //TestInfo { extension: "privilege", name: "misalign-sh-01", },
    //TestInfo { extension: "privilege", name: "misalign-sw-01", },
    TestInfo { extension: "privilege", name: "misalign2-jalr-01", },
    TestInfo { extension: "Zifencei", name: "Fencei", },
    TestInfo { extension: "B", name: "andn-01", },
    TestInfo { extension: "B", name: "bclr-01", },
    TestInfo { extension: "B", name: "bclri-01", },
    TestInfo { extension: "B", name: "bext-01", },
    TestInfo { extension: "B", name: "bexti-01", },
    TestInfo { extension: "B", name: "binv-01", },
    TestInfo { extension: "B", name: "binvi-01", },
    TestInfo { extension: "B", name: "bset-01", },
    TestInfo { extension: "B", name: "bseti-01", },
    TestInfo { extension: "B", name: "clmul-01", },
    TestInfo { extension: "B", name: "clmulh-01", },
    TestInfo { extension: "B", name: "clmulr-01", },
    TestInfo { extension: "B", name: "clz-01", },
    TestInfo { extension: "B", name: "cpop-01", },
    TestInfo { extension: "B", name: "ctz-01", },
    TestInfo { extension: "B", name: "max-01", },
    TestInfo { extension: "B", name: "maxu-01", },
    TestInfo { extension: "B", name: "min-01", },
    TestInfo { extension: "B", name: "minu-01", },
    TestInfo { extension: "B", name: "orcb_32-01", },
    TestInfo { extension: "B", name: "orn-01", },
    TestInfo { extension: "B", name: "rev8_32-01", },
    TestInfo { extension: "B", name: "rol-01", },
    TestInfo { extension: "B", name: "ror-01", },
    TestInfo { extension: "B", name: "rori-01", },
    TestInfo { extension: "B", name: "sext.b-01", },
    TestInfo { extension: "B", name: "sext.h-01", },
    TestInfo { extension: "B", name: "sh1add-01", },
    TestInfo { extension: "B", name: "sh2add-01", },
    TestInfo { extension: "B", name: "sh3add-01", },
    TestInfo { extension: "B", name: "xnor-01", },
    TestInfo { extension: "B", name: "zext.h_32-01", },
];

fn into_io_error(err: impl Into<Box<dyn Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(ErrorKind::Other, err)
}

fn check_reference_data(expected_txt: &str, bus: &mut impl Bus) -> std::io::Result<()> {
    let mut addr = 0x1000;
    for line in expected_txt.lines() {
        let expected_word = u32::from_str_radix(line, 16).map_err(into_io_error)?;
        let actual_word = match bus.read(RvSize::Word, addr) {
            Ok(val) => val,
            Err(err) => {
                return Err(into_io_error(format!(
                    "Error accessing memory for comparison with reference data: {:?}",
                    err
                )))
            }
        };
        if expected_word != actual_word {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                format!(
                    "At addr {:#x}, expected {:#010x} but was {:#010x}",
                    addr, expected_word, actual_word
                ),
            ));
        }
        addr += 4;
    }
    Ok(())
}

fn is_test_complete(bus: &mut impl Bus) -> bool {
    bus.read(RvSize::Word, 0x0).unwrap() != 0
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = clap::Command::new("compliance-test")
        .about("RISC-V compliance suite runner")
        .arg(arg!(--test_root_path <DIR> "Path to directory containing https://github.com/riscv-non-isa/riscv-arch-test").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--compiler <FILE> "Path to risc-v build of gcc").required(false).default_value("riscv64-unknown-elf-gcc").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--objcopy <FILE> "Path to risc-v build of objcopy").required(false).default_value("riscv64-unknown-elf-objcopy").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--objdump <FILE> "Path to risc-v build of objdump").required(false).default_value("riscv64-unknown-elf-objdump").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--riscof <FILE> "Path to riscof").required(false).default_value("riscof").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--riscv_sim_rv32 <FILE> "Path to riscv_sim_RV32").required(false).default_value("riscv_sim_RV32").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--spike <FILE> "Path to spike").required(false).default_value("spike").value_parser(value_parser!(PathBuf)))
        .get_matches();

    set_var("RISCV_CC", args.get_one::<PathBuf>("compiler").unwrap());
    set_var("RISCV_OBJCOPY", args.get_one::<PathBuf>("objcopy").unwrap());
    set_var("RISCV_OBJDUMP", args.get_one::<PathBuf>("objdump").unwrap());
    set_var("RISCV_SPIKE", args.get_one::<PathBuf>("spike").unwrap());
    set_var(
        "RISCV_SIM_RV32",
        args.get_one::<PathBuf>("riscv_sim_rv32").unwrap(),
    );

    let temp_dir = TempDir::new()?;

    run_riscof(
        args.get_one::<PathBuf>("riscof").unwrap().clone(),
        args.get_one::<PathBuf>("test_root_path").unwrap().clone(),
        temp_dir.path().to_owned(),
    )?;

    for test in TESTS_TO_RUN.iter() {
        println!("Running test {}/{}", test.extension, test.name);

        let binary = get_binary_data(test, temp_dir.path().to_owned())?;
        let reference_txt = get_signature_data(test, temp_dir.path().to_owned())?;

        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut cpu = Cpu::new(Ram::new(binary), clock, pic);
        cpu.write_pc(0x3000);
        while !is_test_complete(&mut cpu.bus) {
            match cpu.step(None) {
                StepAction::Continue => continue,
                _ => break,
            }
        }
        if !is_test_complete(&mut cpu.bus) {
            Err(std::io::Error::new(
                ErrorKind::Other,
                "test did not complete",
            ))?;
        }

        check_reference_data(&reference_txt, &mut cpu.bus)?;
        println!("PASSED");
        drop(cpu);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    #[test]
    fn test_check_reference_data() {
        let mut ram_bytes = vec![0u8; 4096];
        ram_bytes.extend(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let clock = Rc::new(Clock::new());
        let pic = Rc::new(Pic::new());
        let mut cpu = Cpu::new(Ram::new(ram_bytes), clock, pic);

        check_reference_data("03020100\n07060504\n", &mut cpu.bus).unwrap();
        assert_eq!(
            check_reference_data("03050100\n07060503\n", &mut cpu.bus)
                .err()
                .unwrap()
                .to_string(),
            "At addr 0x1000, expected 0x03050100 but was 0x03020100"
        );
        assert_eq!(
            check_reference_data("03020100\n07060502", &mut cpu.bus)
                .err()
                .unwrap()
                .to_string(),
            "At addr 0x1004, expected 0x07060502 but was 0x07060504"
        );
    }
}
