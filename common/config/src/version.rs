// Licensed under the Apache-2.0 license

pub const MCU_RUNTIME_VERSION_MAJOR: u32 = 2;
pub const MCU_RUNTIME_VERSION_MINOR: u32 = 1;
pub const MCU_RUNTIME_VERSION_PATCH: u32 = 0;

// MCU Runtime Version - 32 bits
// Major - 8 bits [31:24]
// Minor - 8 bits [23:16]
// Patch - 16 bits [15:0]
pub const fn get_mcu_runtime_version() -> u32 {
    ((MCU_RUNTIME_VERSION_MAJOR & 0xFF) << 24)
        | ((MCU_RUNTIME_VERSION_MINOR & 0xFF) << 16)
        | (MCU_RUNTIME_VERSION_PATCH & 0xFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcu_runtime_version_is_packed_as_major_minor_patch() {
        assert_eq!(get_mcu_runtime_version(), 0x0201_0000);
    }
}
