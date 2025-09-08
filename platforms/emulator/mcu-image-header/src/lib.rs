// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct McuImageHeader {
    pub svn: u16,
    pub reserved1: u16,
    pub reserved2: u32,
}
