/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    Cargo build file

--*/

fn main() {
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=kernel_layout.ld");
}
