// Licensed under the Apache-2.0 license

use crate::DefaultSyscalls;
use libtock_platform::{ErrorCode, Syscalls};

pub struct System {}

impl System {
    pub fn exit(code: u32) {
        DefaultSyscalls::command(DRIVER_NUM, cmd::EXIT, code, 0)
            .to_result::<(), ErrorCode>()
            .unwrap();
    }
}

pub const DRIVER_NUM: u32 = 0xC000_0000;

mod cmd {
    pub const EXIT: u32 = 1;
}
