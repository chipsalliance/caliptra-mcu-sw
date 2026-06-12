// Licensed under the Apache-2.0 license

//! EXPORT_IDEVID_CSR (0x0C): exports an IDevID CSR.

use mcu_spdm_lite_traits::{SpdmPalAlloc, SpdmPalIo};

use crate::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CALIPTRA_VDM_COMMAND_VERSION,
};
use crate::iana::ocp::caliptra_vdm::CaliptraVdmCommands;

const REQ_LEN: usize = 4;
const CSR_LEN_FIELD: usize = 4;
const CSR_PAYLOAD_HEADER_LEN: usize = 2 + 1 + CSR_LEN_FIELD;
const INLINE_PREFIX_LEN: usize = 1 + CSR_LEN_FIELD;

pub(crate) async fn handle<H, A, I>(
    cmds: &H,
    req: &[u8],
    command_code: u8,
    inline_payload: &mut [u8],
    large: &mut [u8],
    scratch: &A,
    io: &I,
) -> CaliptraVdmCmdResult
where
    H: CaliptraVdmCommands,
    A: SpdmPalAlloc,
    I: SpdmPalIo,
{
    if req.len() != REQ_LEN {
        return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InvalidPayloadSize);
    }
    let algorithm = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);

    if large.len() > CSR_PAYLOAD_HEADER_LEN {
        let data_len = match cmds
            .export_idevid_csr(algorithm, scratch, io, &mut large[CSR_PAYLOAD_HEADER_LEN..])
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(code),
        };

        if INLINE_PREFIX_LEN + data_len <= inline_payload.len() {
            inline_payload[0] = CaliptraCompletionCode::Success as u8;
            inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
            inline_payload[INLINE_PREFIX_LEN..INLINE_PREFIX_LEN + data_len]
                .copy_from_slice(&large[CSR_PAYLOAD_HEADER_LEN..CSR_PAYLOAD_HEADER_LEN + data_len]);
            CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
        } else {
            large[0] = CALIPTRA_VDM_COMMAND_VERSION;
            large[1] = command_code;
            large[2] = CaliptraCompletionCode::Success as u8;
            large[3..CSR_PAYLOAD_HEADER_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
            CaliptraVdmCmdResult::Large(CSR_PAYLOAD_HEADER_LEN + data_len)
        }
    } else {
        if inline_payload.len() <= INLINE_PREFIX_LEN {
            return CaliptraVdmCmdResult::Error(CaliptraCompletionCode::InsufficientResources);
        }
        let data_len = match cmds
            .export_idevid_csr(
                algorithm,
                scratch,
                io,
                &mut inline_payload[INLINE_PREFIX_LEN..],
            )
            .await
        {
            Ok(n) => n,
            Err(code) => return CaliptraVdmCmdResult::Error(code),
        };
        inline_payload[0] = CaliptraCompletionCode::Success as u8;
        inline_payload[1..INLINE_PREFIX_LEN].copy_from_slice(&(data_len as u32).to_le_bytes());
        CaliptraVdmCmdResult::Response(INLINE_PREFIX_LEN + data_len)
    }
}
