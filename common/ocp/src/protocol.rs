// Licensed under the Apache-2.0 license

//! OCP Secure Firmware Recovery protocol definitions (spec v1.1, Section 9).

pub mod device_reset;
pub mod indirect_ctrl;
pub mod indirect_fifo_ctrl;
pub mod indirect_fifo_status;
pub mod indirect_status;
pub mod prot_cap;
pub mod recovery_ctrl;
pub mod recovery_status;

/// Recovery interface command codes.
///
/// Each variant corresponds to a block command defined in the Recovery Command
/// Summary (Section 8, Table 1). The discriminant is the 8-bit command code
/// used on the wire (SMBus command byte, I3C command field, USB wValue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryCommand {
    ProtCap = 0x22,
    DeviceId = 0x23,
    DeviceStatus = 0x24,
    DeviceReset = 0x25,
    RecoveryCtrl = 0x26,
    RecoveryStatus = 0x27,
    HwStatus = 0x28,
    IndirectCtrl = 0x29,
    IndirectStatus = 0x2A,
    IndirectData = 0x2B,
    Vendor = 0x2C,
    IndirectFifoCtrl = 0x2D,
    IndirectFifoStatus = 0x2E,
    IndirectFifoData = 0x2F,
}
