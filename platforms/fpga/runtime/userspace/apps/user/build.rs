/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file for FPGA user app

--*/

fn main() {
    println!("cargo:rerun-if-changed=../app_layout.ld");
    println!("cargo:rerun-if-changed=../fpga-user-app-layout.ld");
}
