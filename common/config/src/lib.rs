// Licensed under the Apache-2.0 license

#![cfg_attr(target_arch = "riscv32", no_std)]

/// Configures the memory map for the MCU.
/// These are the defaults that can be overridden and provided to the ROM and runtime builds.
#[repr(C)]
pub struct McuMemoryMap {
    pub rom_offset: u32,
    pub rom_size: u32,
    pub rom_stack_size: u32,
    pub sram_offset: u32,
    pub sram_size: u32,
    pub pic_offset: u32,
    pub dccm_offset: u32,
    pub dccm_size: u32,
    pub i3c_offset: u32,
    pub i3c_size: u32,
    pub mci_offset: u32,
    pub mci_size: u32,
    pub mbox_offset: u32,
    pub mbox_size: u32,
    pub soc_offset: u32,
    pub soc_size: u32,
    pub otp_offset: u32,
    pub otp_size: u32,
    pub lc_offset: u32,
    pub lc_size: u32,
}

impl Default for McuMemoryMap {
    fn default() -> Self {
        McuMemoryMap {
            rom_offset: 0x8000_0000,
            rom_size: 32 * 1024,
            rom_stack_size: 0x3000,
            dccm_offset: 0x5000_0000,
            dccm_size: 16 * 1024,
            sram_offset: 0x4000_0000,
            sram_size: 384 * 1024,
            pic_offset: 0x6000_0000,
            i3c_offset: 0x2000_4000,
            i3c_size: 0x1000,
            mci_offset: 0x2100_0000,
            mci_size: 0xe0_0000,
            mbox_offset: 0x3002_0000,
            mbox_size: 0x28,
            soc_offset: 0x3003_0000,
            soc_size: 0x5e0,
            otp_offset: 0x7000_0000,
            otp_size: 0x140,
            lc_offset: 0x7000_0400,
            lc_size: 0x8c,
        }
    }
}

impl McuMemoryMap {
    #[cfg(not(target_arch = "riscv32"))]
    pub fn hash_map(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert("ROM_OFFSET".to_string(), format!("0x{:x}", self.rom_offset));
        map.insert("ROM_SIZE".to_string(), format!("0x{:x}", self.rom_size));
        map.insert(
            "ROM_STACK_SIZE".to_string(),
            format!("0x{:x}", self.rom_stack_size),
        );
        map.insert(
            "SRAM_OFFSET".to_string(),
            format!("0x{:x}", self.sram_offset),
        );
        map.insert("SRAM_SIZE".to_string(), format!("0x{:x}", self.sram_size));
        map.insert("PIC_OFFSET".to_string(), format!("0x{:x}", self.pic_offset));
        map.insert(
            "DCCM_OFFSET".to_string(),
            format!("0x{:x}", self.dccm_offset),
        );
        map.insert("DCCM_SIZE".to_string(), format!("0x{:x}", self.dccm_size));
        map.insert("I3C_OFFSET".to_string(), format!("0x{:x}", self.i3c_offset));
        map.insert("I3C_SIZE".to_string(), format!("0x{:x}", self.i3c_size));
        map.insert("MCI_OFFSET".to_string(), format!("0x{:x}", self.mci_offset));
        map.insert("MCI_SIZE".to_string(), format!("0x{:x}", self.mci_size));
        map.insert(
            "MBOX_OFFSET".to_string(),
            format!("0x{:x}", self.mbox_offset),
        );
        map.insert("MBOX_SIZE".to_string(), format!("0x{:x}", self.mbox_size));
        map.insert("SOC_OFFSET".to_string(), format!("0x{:x}", self.soc_offset));
        map.insert("SOC_SIZE".to_string(), format!("0x{:x}", self.soc_size));
        map.insert("OTP_OFFSET".to_string(), format!("0x{:x}", self.otp_offset));
        map.insert("OTP_SIZE".to_string(), format!("0x{:x}", self.otp_size));
        map.insert("LC_OFFSET".to_string(), format!("0x{:x}", self.lc_offset));
        map.insert("LC_SIZE".to_string(), format!("0x{:x}", self.lc_size));
        map
    }
}
