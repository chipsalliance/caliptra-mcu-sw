// Licensed under the Apache-2.0 license

//! END_SESSION handler.

use caliptra_mcu_spdm_codec::{EndSessionReqBody, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion};
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(version: SpdmVersion, attributes: u8, reserved: u8) -> [u8; 4] {
        [
            version.to_u8(),
            ReqRespCode::END_SESSION.0,
            attributes,
            reserved,
        ]
    }

    #[test]
    fn valid_request_returns_exact_ack() {
        for attributes in [0, EndSessionReqBody::CLEAR_NEGOTIATED_STATE] {
            let response =
                handle_end_session(SpdmVersion::V12, &request(SpdmVersion::V12, attributes, 0))
                    .unwrap();

            assert_eq!(
                response,
                [
                    SpdmVersion::V12.to_u8(),
                    ReqRespCode::END_SESSION_ACK.0,
                    0,
                    0,
                ]
            );
        }
    }

    #[test]
    fn rejects_version_mismatch_reserved_fields_truncation_and_trailing_data() {
        assert_eq!(
            handle_end_session(SpdmVersion::V12, &request(SpdmVersion::V11, 0, 0)),
            Err(crate::error::SPDM_VERSION_MISMATCH)
        );
        assert_eq!(
            handle_end_session(SpdmVersion::V12, &request(SpdmVersion::V12, 0, 1)),
            Err(SPDM_INVALID_REQUEST)
        );
        assert_eq!(
            handle_end_session(SpdmVersion::V12, &request(SpdmVersion::V12, 2, 0)),
            Err(SPDM_INVALID_REQUEST)
        );
        assert_eq!(
            handle_end_session(
                SpdmVersion::V12,
                &[SpdmVersion::V12.to_u8(), ReqRespCode::END_SESSION.0, 0]
            ),
            Err(SPDM_INVALID_REQUEST)
        );

        let mut trailing = request(SpdmVersion::V12, 0, 0).to_vec();
        trailing.push(0);
        assert_eq!(
            handle_end_session(SpdmVersion::V12, &trailing),
            Err(SPDM_INVALID_REQUEST)
        );
    }
}
