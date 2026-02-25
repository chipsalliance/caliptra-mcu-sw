// Licensed under the Apache-2.0 license

pub mod lib_generator;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../",
    "target/provisioning/fuses/test.rs"
));
