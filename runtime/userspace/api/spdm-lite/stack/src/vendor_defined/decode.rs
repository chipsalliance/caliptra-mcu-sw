// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED request decoding.

use mcu_spdm_lite_codec::{SpdmMsgHdrPdu, StandardsBodyId, VendorDefinedReqPdu, WireReader};
use mcu_spdm_lite_traits::{SpdmPal, SpdmPalIo, SpdmPalIoKind, SpdmVdmBackend, VdmRequest};
use zerocopy::{little_endian::U16, FromBytes};

use crate::error::{
    SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNEXPECTED_REQUEST, SPDM_UNSUPPORTED_REQUEST,
    SPDM_VERSION_MISMATCH,
};
use crate::stack::{ConnectionState, Phase};

pub(super) fn decode_vendor_defined_request<'a, Pal, Vdm>(
    state: &ConnectionState<Pal::State>,
    io: &impl SpdmPalIo,
    req: &'a [u8],
    backend: &Vdm,
) -> SpdmResult<VdmRequest<'a>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    Vdm::Error: Into<crate::error::SpdmError>,
{
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }

    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }

    let mut reader = WireReader::new(body);
    let req_pdu = reader.read::<VendorDefinedReqPdu>()?;
    let standard_id =
        StandardsBodyId::from_u16(req_pdu.standard_id.get()).ok_or(SPDM_INVALID_REQUEST)?;
    let Some(expected_vendor_id_len) = standard_id.vendor_id_len() else {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    };
    if req_pdu.vendor_id_len != expected_vendor_id_len {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vendor_id = reader.take(req_pdu.vendor_id_len as usize)?;
    let req_len = reader.read::<U16>()?.get() as usize;
    let vdm_payload = reader.take(req_len)?;
    if !reader.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }

    let vdm_req = VdmRequest {
        standard_id: standard_id.as_u16(),
        vendor_id,
        secure_session: io.kind() == SpdmPalIoKind::SecuredMessage,
        payload: vdm_payload,
    };
    if !backend.match_request(&vdm_req) {
        return Err(SPDM_UNSUPPORTED_REQUEST);
    }
    Ok(vdm_req)
}
