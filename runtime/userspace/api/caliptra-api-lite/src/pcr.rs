// Licensed under the Apache-2.0 license

//! PCR31 extension via Caliptra `EXTEND_PCR`.
//!
//! This module only encodes and executes the mailbox command. It does not write
//! Measurement API stores or append entries to Caliptra's internal PCR log.

use mcu_error::codes::INTERNAL_BUG;
use mcu_error::McuResult;

use crate::slice::{checked_slice_mut, copy_bytes};
use crate::wire::{mbox_execute, populate_checksum, CMD_EXTEND_PCR, MBOX_RESP_HEADER_SIZE};

/// Caliptra PCR used for stash-measurement style extensions.
pub const PCR31_INDEX: u32 = 31;
/// SHA-384 measurement width extended into PCR31.
pub const PCR31_MEASUREMENT_SIZE: usize = 48;

const EXTEND_PCR31_REQ_LEN: usize = 4 + 4 + PCR31_MEASUREMENT_SIZE;
const _: () = assert!(EXTEND_PCR31_REQ_LEN == 56);

/// Extend Caliptra PCR31 with a SHA-384 measurement.
#[inline(never)]
pub async fn extend_pcr31(measurement: &[u8; PCR31_MEASUREMENT_SIZE]) -> McuResult<()> {
    let req = build_extend_pcr31_req(measurement)?;
    let mut rsp = [0u8; MBOX_RESP_HEADER_SIZE];
    let rsp_len = mbox_execute(CMD_EXTEND_PCR, &req, &mut rsp).await?;
    if rsp_len < MBOX_RESP_HEADER_SIZE {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

fn build_extend_pcr31_req(
    measurement: &[u8; PCR31_MEASUREMENT_SIZE],
) -> McuResult<[u8; EXTEND_PCR31_REQ_LEN]> {
    let mut req = [0u8; EXTEND_PCR31_REQ_LEN];
    copy_bytes(
        checked_slice_mut(&mut req, 4, 4)?,
        &PCR31_INDEX.to_le_bytes(),
    )?;
    copy_bytes(
        checked_slice_mut(&mut req, 8, PCR31_MEASUREMENT_SIZE)?,
        measurement,
    )?;
    populate_checksum(CMD_EXTEND_PCR, &mut req)?;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::calc_checksum;

    #[test]
    fn extend_pcr31_wire_layout() {
        assert_eq!(CMD_EXTEND_PCR, 0x5043_5245);
        assert_eq!(PCR31_INDEX, 31);
        assert_eq!(EXTEND_PCR31_REQ_LEN, 56);
        assert_eq!(PCR31_MEASUREMENT_SIZE, 48);
    }

    #[test]
    fn request_builder_uses_pcr31_and_preserves_measurement() {
        let measurement = [0xa5; PCR31_MEASUREMENT_SIZE];

        let req = build_extend_pcr31_req(&measurement).unwrap();
        let mut checksum_input = req;
        checksum_input[0..4].fill(0);

        assert_eq!(
            req.get(0..4).and_then(|s| s.first_chunk::<4>()),
            Some(&calc_checksum(CMD_EXTEND_PCR, &checksum_input).to_le_bytes())
        );
        assert_eq!(
            req.get(4..8).and_then(|s| s.first_chunk::<4>()),
            Some(&PCR31_INDEX.to_le_bytes())
        );
        assert_eq!(req.get(8..), Some(&measurement[..]));
    }
}
