// Licensed under the Apache-2.0 license.

fn main() {
    println!("cargo:rustc-link-arg=-Trom/layout.ld");
    println!("cargo:rerun-if-changed=layout.ld");
    println!("cargo:rerun-if-changed=build.rs");
}
