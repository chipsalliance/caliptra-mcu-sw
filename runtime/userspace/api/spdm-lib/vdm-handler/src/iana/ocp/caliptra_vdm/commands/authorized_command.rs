// Licensed under the Apache-2.0 license

//! AUTHORIZED_COMMAND (0x12): dispatches authorization subcommands.

use caliptra_mcu_spdm_traits::SpdmPalAlloc;

use crate::iana::ocp::caliptra_vdm::CaliptraVdmAuthorization;
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// ECC P-384 public-key coordinate size (bytes).
const ECC_P384_COORD_SIZE: usize = 48;
/// ML-DSA-87 public-key size (bytes).
const MLDSA87_PUB_KEY_SIZE: usize = 2592;

// Canonical wire layout (after the AUTHORIZED_COMMAND sub-command id):
//   partition(4) | sig(HybridSignature) | nonce(48) | ecc_pub_x(48) | ecc_pub_y(48) | mldsa_pub(2592)
#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
struct FeProgVdmReq {
    partition: u32,
    sig: HybridSignature,
    nonce: [u8; AUTH_CMD_NONCE_LEN],
    ecc_pub_x: [u8; ECC_P384_COORD_SIZE],
    ecc_pub_y: [u8; ECC_P384_COORD_SIZE],
    mldsa_pub: [u8; MLDSA87_PUB_KEY_SIZE],
}

const _: () = assert!(
    core::mem::size_of::<FeProgVdmReq>()
        == core::mem::size_of::<u32>()
            + core::mem::size_of::<HybridSignature>()
            + AUTH_CMD_NONCE_LEN
            + 2 * ECC_P384_COORD_SIZE
            + MLDSA87_PUB_KEY_SIZE
);

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
    let Ok(fe_req) = FeProgVdmReq::ref_from_bytes(req) else {
        return CaliptraVdmCmdResult::Error(if req.len() != core::mem::size_of::<FeProgVdmReq>() {
            CaliptraCompletionCode::InvalidPayloadSize
        } else {
            CaliptraCompletionCode::InvalidParameter
        });
    };
    match cmds
        .program_field_entropy(
            fe_req.partition,
            &fe_req.sig,
            &fe_req.nonce,
            &fe_req.ecc_pub_x,
            &fe_req.ecc_pub_y,
            &fe_req.mldsa_pub,
            scratch,
        )
        .await
    {
        Ok(()) => match super::write_success(out) {
            Ok(_) => CaliptraVdmCmdResult::Response(1),
            Err(code) => CaliptraVdmCmdResult::Error(code),
        },
        Err(code) => CaliptraVdmCmdResult::Error(code),
    }
}
