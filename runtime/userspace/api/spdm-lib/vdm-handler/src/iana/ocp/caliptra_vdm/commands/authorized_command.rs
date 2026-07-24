// Licensed under the Apache-2.0 license

//! AUTHORIZED_COMMAND (0x12): dispatches authorization subcommands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmAuthorization;
use caliptra_mcu_mbox_common::messages::HybridSignature;
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use zerocopy::FromBytes;

/// MC_GET_AUTH_CMD_CHALLENGE sub-command (`MACC`).
pub const GET_AUTH_CHALLENGE_CMD_ID: u32 = 0x4D41_4343;
/// MC_FE_PROG sub-command (`MCFP`).
pub const FE_PROG_CMD_ID: u32 = 0x4D43_4650;

pub(crate) async fn handle<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let Some(sub_cmd_bytes) = req.get(..4) else {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    };
    let sub_cmd = u32::from_le_bytes([
        sub_cmd_bytes[0],
        sub_cmd_bytes[1],
        sub_cmd_bytes[2],
        sub_cmd_bytes[3],
    ]);
    let payload = &req[4..];
    match sub_cmd {
        GET_AUTH_CHALLENGE_CMD_ID => handle_get_auth_challenge(cmds, payload, scratch, out).await,
        FE_PROG_CMD_ID => handle_fe_prog(cmds, payload, scratch, out).await,
        _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidParameter),
    }
}

async fn handle_get_auth_challenge<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    if let Err(code) = super::require_empty(req) {
        return CaliptraVdmCmdResult::Error(code);
    }
    let data = match super::write_success(out) {
        Ok(data) => data,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    match cmds.get_auth_challenge(scratch, data).await {
        Ok(n) => CaliptraVdmCmdResult::Response(1 + n),
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

async fn handle_fe_prog<H, A>(
    cmds: &H,
    req: &[u8],
    scratch: &A,
    out: &mut [u8],
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmAuthorization,
    A: SpdmPalAlloc,
{
    let (partition, sig) = match parse_fe_prog_req(req) {
        Ok(parsed) => parsed,
        Err(code) => return CaliptraVdmCmdResult::Error(code),
    };
    match cmds.program_field_entropy(partition, sig, scratch).await {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}

fn parse_fe_prog_req(req: &[u8]) -> Result<(u32, &HybridSignature), CaliptraCompletionCode> {
    const PARTITION_LEN: usize = core::mem::size_of::<u32>();
    if req.len() != PARTITION_LEN + core::mem::size_of::<HybridSignature>() {
        return Err(CaliptraCompletionCode::InvalidPayloadSize);
    }

    let partition = u32::from_le_bytes(req[..PARTITION_LEN].try_into().unwrap());
    let sig = HybridSignature::ref_from_bytes(&req[PARTITION_LEN..])
        .map_err(|_| CaliptraCompletionCode::InvalidParameter)?;
    Ok((partition, sig))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;

    #[test]
    fn fe_prog_request_allows_unaligned_input() {
        const PARTITION: u32 = 3;
        let mut storage = vec![0u8; 1 + 4 + core::mem::size_of::<HybridSignature>()];
        storage[1..5].copy_from_slice(&PARTITION.to_le_bytes());

        let (partition, _) = parse_fe_prog_req(&storage[1..]).unwrap();
        assert_eq!(partition, PARTITION);
    }
}
