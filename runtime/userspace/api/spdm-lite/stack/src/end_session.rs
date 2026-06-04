// Licensed under the Apache-2.0 license

//! END_SESSION handler.

use mcu_spdm_lite_codec::{EndSessionReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion};
use zerocopy::FromBytes;

use crate::error::{SpdmResult, SPDM_INVALID_REQUEST};

/// Size of the END_SESSION_ACK SPDM message (common header + 2 reserved).
pub(crate) const END_SESSION_ACK_SPDM_SIZE: usize = SpdmMsgHdrPdu::SIZE + 2;

/// Handle a decrypted END_SESSION request.
#[inline(always)]
pub(crate) fn handle_end_session(
    version: SpdmVersion,
    spdm_msg: &[u8],
) -> SpdmResult<[u8; END_SESSION_ACK_SPDM_SIZE]> {
    let (hdr, rest) = SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != version.to_u8() {
        return Err(crate::error::SPDM_VERSION_MISMATCH);
    }

    let (req, after) =
        EndSessionReqBody::ref_from_prefix(rest).map_err(|_| SPDM_INVALID_REQUEST)?;
    if !after.is_empty() || !req.reserved_is_zero() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let mut rsp_buf = [0u8; END_SESSION_ACK_SPDM_SIZE];
    rsp_buf[0] = version.to_u8();
    rsp_buf[1] = ReqRespCode::END_SESSION_ACK.0;
    Ok(rsp_buf)
}
