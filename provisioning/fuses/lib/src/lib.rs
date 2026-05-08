// Licensed under the Apache-2.0 license
#![no_std]

use registers_generated::fuses::*;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../",
    "target/provisioning/fuses/test.rs"
));
