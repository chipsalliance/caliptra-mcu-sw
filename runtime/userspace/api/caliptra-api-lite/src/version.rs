// Licensed under the Apache-2.0 license

//! Minimal Caliptra Core `VERSION` mailbox helper.

use crate::raw::{raw_mailbox_execute, CMD_VERSION};
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

const REQ_SIZE: usize = 4;
const RSP_SIZE: usize = 36;
const HW_REV_OFFSET: usize = 12;
const ROM_FMC_REV_OFFSET: usize = 16;
const RUNTIME_REV_OFFSET: usize = 20;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreFirmwareVersion {
    pub hardware: u32,
    pub rom: u16,
    pub fmc: u16,
    pub runtime: u32,
}

pub async fn core_firmware_version() -> McuResult<CoreFirmwareVersion> {
    let mut req = [0u8; REQ_SIZE];
    let mut rsp = [0u8; RSP_SIZE];

    let len = raw_mailbox_execute(CMD_VERSION, &mut req, &mut rsp).await?;
    parse_version_response(&rsp, len)
}

fn parse_version_response(rsp: &[u8; RSP_SIZE], len: usize) -> McuResult<CoreFirmwareVersion> {
    if len != RSP_SIZE {
        return Err(INVARIANT);
    }

    let hardware = read_u32(rsp, HW_REV_OFFSET)?;
    let rom_fmc = read_u32(rsp, ROM_FMC_REV_OFFSET)?;
    let runtime = read_u32(rsp, RUNTIME_REV_OFFSET)?;

    Ok(CoreFirmwareVersion {
        hardware,
        rom: rom_fmc as u16,
        fmc: (rom_fmc >> 16) as u16,
        runtime,
    })
}

fn read_u32(buf: &[u8], offset: usize) -> McuResult<u32> {
    let bytes = buf
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(INVARIANT)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_version_fields() {
        let mut rsp = [0u8; RSP_SIZE];
        rsp[HW_REV_OFFSET..HW_REV_OFFSET + 4].copy_from_slice(&0x0000_0112u32.to_le_bytes());
        rsp[ROM_FMC_REV_OFFSET..ROM_FMC_REV_OFFSET + 4]
            .copy_from_slice(&0x0841_0842u32.to_le_bytes());
        rsp[RUNTIME_REV_OFFSET..RUNTIME_REV_OFFSET + 4]
            .copy_from_slice(&0x0201_0001u32.to_le_bytes());

        assert_eq!(
            parse_version_response(&rsp, RSP_SIZE),
            Ok(CoreFirmwareVersion {
                hardware: 0x0000_0112,
                rom: 0x0842,
                fmc: 0x0841,
                runtime: 0x0201_0001,
            })
        );
        assert_eq!(parse_version_response(&rsp, RSP_SIZE - 1), Err(INVARIANT));
    }
}
