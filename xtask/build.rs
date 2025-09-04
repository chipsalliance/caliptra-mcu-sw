// Licensed under the Apache-2.0 license

fn main() {
    // On Windows, we need to provide CFI stubs
    #[cfg(windows)]
    {
        // Compile the CFI stubs for Windows
        cc::Build::new()
            .file("../emulator/cbinding/cfi_stubs.c")
            .compile("cfi_stubs");

        println!("cargo:rerun-if-changed=../emulator/cbinding/cfi_stubs.c");
    }
}
