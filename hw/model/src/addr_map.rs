// Licensed under the Apache-2.0 license

//! Address map of the bus that the hardware models expose to the host.
//!
//! All models decode the same addresses, so that tests do not depend on the
//! model they run on. The FPGA model translates them to its own MMIO mappings
//! instead of using the addresses of the FPGA platform.

use caliptra_mcu_config::McuMemoryMap;
use caliptra_mcu_config_emulator::EMULATOR_MEMORY_MAP;

/// MCU peripherals are decoded at the addresses of the emulator platform.
const MAP: McuMemoryMap = EMULATOR_MEMORY_MAP;

pub const I3C_ADDR: u32 = MAP.i3c_offset;
pub const I3C_END: u32 = I3C_ADDR + MAP.i3c_size;

pub const MCI_ADDR: u32 = MAP.mci_offset;
pub const MCI_END: u32 = MCI_ADDR + MAP.mci_size;

// Offsets of the blocks inside MCI. They are fixed by the hardware, see
// `mci_top.rdl` in caliptra-ss.
pub const MCI_TRACE_BUFFER_OFFSET: u32 = 0x1_0000;
pub const MCI_MBOX_0_OFFSET: u32 = 0x40_0000;
pub const MCI_MBOX_1_OFFSET: u32 = 0x80_0000;
pub const MCI_MCU_SRAM_OFFSET: u32 = 0xc0_0000;

pub const TRACE_BUFFER_ADDR: u32 = MCI_ADDR + MCI_TRACE_BUFFER_OFFSET;
/// MCU mailbox 0, which extends up to [`MBOX_1_ADDR`].
pub const MBOX_0_ADDR: u32 = MCI_ADDR + MCI_MBOX_0_OFFSET;
/// MCU mailbox 1, which extends up to [`MCU_SRAM_ADDR`].
pub const MBOX_1_ADDR: u32 = MCI_ADDR + MCI_MBOX_1_OFFSET;
pub const MCU_SRAM_ADDR: u32 = MCI_ADDR + MCI_MCU_SRAM_OFFSET;

pub const OTP_CTRL_ADDR: u32 = MAP.otp_offset;
pub const OTP_CTRL_END: u32 = OTP_CTRL_ADDR + MAP.otp_size;

pub const LC_CTRL_ADDR: u32 = MAP.lc_offset;
pub const LC_CTRL_END: u32 = LC_CTRL_ADDR + MAP.lc_size;

// The SoC-facing Caliptra registers are decoded at the addresses that
// caliptra-sw uses for them (`SocToCaliptraBus` in caliptra-emu-periph), which
// are independent of where a platform maps them for the MCU.
/// Base of the Caliptra peripheral address space.
pub const CALIPTRA_ADDR: u32 = 0x3000_0000;
pub const CALIPTRA_MBOX_OFFSET: u32 = 0x2_0000;
pub const CALIPTRA_SOC_IFC_OFFSET: u32 = 0x3_0000;

pub const CALIPTRA_MBOX_ADDR: u32 = CALIPTRA_ADDR + CALIPTRA_MBOX_OFFSET;
pub const CALIPTRA_SOC_IFC_ADDR: u32 = CALIPTRA_ADDR + CALIPTRA_SOC_IFC_OFFSET;
/// End of the SoC-facing Caliptra registers, which start at [`CALIPTRA_MBOX_ADDR`].
pub const CALIPTRA_SOC_END: u32 = CALIPTRA_SOC_IFC_ADDR + 0x1_0000;
