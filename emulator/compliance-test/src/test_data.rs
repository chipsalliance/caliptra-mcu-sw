/*++

Licensed under the Apache-2.0 license.

File Name:

    test_data.rs

Abstract:

    Performs chores such as setting up the riscof environment and reading files
    from it.

--*/

use crate::{
    exec::exec,
    fs::{read, read_to_string},
    TestInfo,
};
use std::{error::Error, path::PathBuf, process::Command};

/// Run riscof to setup the environment
pub fn run_riscof(
    riscof_path: PathBuf,
    test_root_path: PathBuf,
    work_dir: PathBuf,
) -> Result<(), Box<dyn Error>> {
    exec(
        Command::new(riscof_path)
            .arg("run")
            .arg("--config")
            .arg("emulator/compliance-test/dut-plugin/config.ini")
            .arg("--suite")
            .arg(test_root_path.join("riscv-test-suite/rv32i_m"))
            .arg("--env")
            .arg(test_root_path.join("riscv-test-suite/env"))
            .arg("--work-dir")
            .arg(work_dir),
    )?;
    Ok(())
}

/// Get the dut path to the given test
fn get_test_dut_path(test: &TestInfo, work_dir: PathBuf) -> PathBuf {
    let path: PathBuf = [
        work_dir.as_os_str().to_str().unwrap(),
        test.extension,
        "src",
        &format!("{}.S", test.name),
        "dut",
    ]
    .iter()
    .collect();
    path
}

/// Get the signature file of the given test
fn get_signature_path(test: &TestInfo, work_dir: PathBuf) -> PathBuf {
    let mut path = get_test_dut_path(test, work_dir);
    path.push("DUT-spike.signature");
    path
}

/// Read signature data into a string or return an error
pub fn get_signature_data(test: &TestInfo, work_dir: PathBuf) -> std::io::Result<String> {
    let data = read_to_string(get_signature_path(test, work_dir))?;
    Ok(data)
}

/// Get the binary file of the given test
fn get_binary_path(test: &TestInfo, work_dir: PathBuf) -> PathBuf {
    let mut path = get_test_dut_path(test, work_dir);
    path.push("my.bin");
    path
}

/// Read binary data into a Vec or return an error
pub fn get_binary_data(test: &TestInfo, work_dir: PathBuf) -> std::io::Result<Vec<u8>> {
    let data = read(get_binary_path(test, work_dir))?;
    Ok(data)
}
