// Licensed under the Apache-2.0 license

//! Minimal Caliptra Core `CAPABILITIES` mailbox helper.

use crate::raw::{raw_mailbox_execute, CMD_CAPABILITIES};
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;

pub const CORE_CAPABILITIES_SIZE: usize = 16;

const REQ_SIZE: usize = 4;
const RSP_SIZE: usize = 8 + CORE_CAPABILITIES_SIZE;
const CAPABILITIES_OFFSET: usize = 8;

pub async fn core_capabilities() -> McuResult<[u8; CORE_CAPABILITIES_SIZE]> {
    let mut req = [0u8; REQ_SIZE];
    let mut rsp = [0u8; RSP_SIZE];

    let len = raw_mailbox_execute(CMD_CAPABILITIES, &mut req, &mut rsp).await?;
    parse_capabilities_response(&rsp, len)
}

fn parse_capabilities_response(
    rsp: &[u8; RSP_SIZE],
    len: usize,
) -> McuResult<[u8; CORE_CAPABILITIES_SIZE]> {
    if len != RSP_SIZE {
        return Err(INVARIANT);
    }

    rsp[CAPABILITIES_OFFSET..].try_into().map_err(|_| INVARIANT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_core_capabilities_without_filtering_bits() {
        let mut rsp = [0u8; RSP_SIZE];
        let expected = [
            0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22,
            0x33, 0x44,
        ];
        rsp[CAPABILITIES_OFFSET..].copy_from_slice(&expected);

        assert_eq!(parse_capabilities_response(&rsp, RSP_SIZE), Ok(expected));
        assert_eq!(
            parse_capabilities_response(&rsp, RSP_SIZE - 1),
            Err(INVARIANT)
        );
    }
}
