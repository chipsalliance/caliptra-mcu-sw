// Licensed under the Apache-2.0 license

//! VENDOR_DEFINED response construction.

use mcu_spdm_lite_codec::{
    ReqRespCode, SpdmMsgHdrPdu, StandardsBodyId, VendorDefinedRspPdu, WireWriter,
};
use mcu_spdm_lite_traits::{
    NoLargeResponseStorage, PalBytes, SpdmPal, SpdmPalIoTransport, SpdmVdmBackend,
    VdmLargeResponseWriter, VdmRequest, VdmResponseBuffers, VdmResponseKind,
};
use zerocopy::little_endian::U16;

use crate::error::{SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED};
use crate::stack::ConnectionState;

pub(super) async fn build_vendor_defined_response<'a, Pal, Vdm>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    req: VdmRequest<'_>,
    backend: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>>
where
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    Vdm::Error: Into<crate::error::SpdmError>,
{
    let vendor_id_len = req.vendor_id.len();
    let fixed_len = SpdmMsgHdrPdu::SIZE
        + VendorDefinedRspPdu::SIZE
        + vendor_id_len
        + core::mem::size_of::<U16>();
    let max_rsp_len = state
        .effective_data_transfer_size(pal)
        .checked_sub(fixed_len)
        .ok_or(SPDM_UNSPECIFIED)?;
    if max_rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }

    let head = pal.header_size();
    let mut rsp = alloc_padded(pal, io, head + fixed_len + max_rsp_len)?;
    let payload_len_pos = payload_len_offset(vendor_id_len);
    let payload_len_offset = head + payload_len_pos;
    let payload_offset = payload_len_offset + core::mem::size_of::<U16>();

    encode_vendor_defined_response_prefix(
        &mut rsp[head..head + fixed_len],
        state.version,
        StandardsBodyId::from_u16(req.standard_id).ok_or(SPDM_INVALID_REQUEST)?,
        req.vendor_id,
    )?;

    let large_capacity = pal.capacity();
    let large_total_len = if large_capacity >= fixed_len {
        pal.write(0, &rsp[head..head + fixed_len])?;
        let large_payload_capacity = large_capacity - fixed_len;
        let response = backend
            .handle_request(
                req,
                VdmResponseBuffers {
                    inline: &mut rsp[payload_offset..payload_offset + max_rsp_len],
                    large: Some(VdmLargeResponseWriter::new(
                        pal,
                        fixed_len,
                        large_payload_capacity,
                    )),
                },
            )
            .await
            .map_err(Into::into)?;
        match response {
            VdmResponseKind::Inline(rsp_len) => {
                finish_inline_response::<Pal>(
                    &mut rsp,
                    head,
                    fixed_len,
                    pal,
                    payload_len_offset,
                    max_rsp_len,
                    rsp_len,
                )?;
                return Ok(rsp);
            }
            VdmResponseKind::Large(rsp_len) => {
                if rsp_len > large_payload_capacity || rsp_len > u16::MAX as usize {
                    return Err(SPDM_UNSPECIFIED);
                }
                pal.write(payload_len_pos, &(rsp_len as u16).to_le_bytes())?;
                fixed_len + rsp_len
            }
        }
    } else {
        let response = backend
            .handle_request(
                req,
                VdmResponseBuffers::<Pal> {
                    inline: &mut rsp[payload_offset..payload_offset + max_rsp_len],
                    large: None,
                },
            )
            .await
            .map_err(Into::into)?;
        match response {
            VdmResponseKind::Inline(rsp_len) => {
                finish_inline_response::<Pal>(
                    &mut rsp,
                    head,
                    fixed_len,
                    pal,
                    payload_len_offset,
                    max_rsp_len,
                    rsp_len,
                )?;
                return Ok(rsp);
            }
            VdmResponseKind::Large(_) => return Err(SPDM_UNSPECIFIED),
        }
    };

    if large_total_len <= fixed_len + max_rsp_len {
        pal.read(0, &mut rsp[head..head + large_total_len])?;
        shrink_padded(pal, &mut rsp, head + large_total_len)?;
        return Ok(rsp);
    }

    if !state.chunking_enabled() || large_total_len > state.effective_max_spdm_msg_size(pal) {
        return Err(SPDM_UNSPECIFIED);
    }
    crate::chunk::start_buffered_large_response(state, pal, io, large_total_len)
}

pub(super) async fn build_vendor_defined_response_into<S, Vdm>(
    state: &ConnectionState<S>,
    req: VdmRequest<'_>,
    backend: &Vdm,
    out: &mut [u8],
) -> SpdmResult<usize>
where
    Vdm: SpdmVdmBackend,
    Vdm::Error: Into<crate::error::SpdmError>,
{
    let vendor_id_len = req.vendor_id.len();
    let fixed_len = SpdmMsgHdrPdu::SIZE
        + VendorDefinedRspPdu::SIZE
        + vendor_id_len
        + core::mem::size_of::<U16>();
    let max_rsp_len = out.len().checked_sub(fixed_len).ok_or(SPDM_UNSPECIFIED)?;
    if max_rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }

    let payload_len_pos = payload_len_offset(vendor_id_len);
    let payload_offset = payload_len_pos + core::mem::size_of::<U16>();
    encode_vendor_defined_response_prefix(
        &mut out[..fixed_len],
        state.version,
        StandardsBodyId::from_u16(req.standard_id).ok_or(SPDM_INVALID_REQUEST)?,
        req.vendor_id,
    )?;

    let response = backend
        .handle_request(
            req,
            VdmResponseBuffers::<NoLargeResponseStorage> {
                inline: &mut out[payload_offset..payload_offset + max_rsp_len],
                large: None,
            },
        )
        .await
        .map_err(Into::into)?;
    let VdmResponseKind::Inline(rsp_len) = response else {
        return Err(SPDM_UNSPECIFIED);
    };
    if rsp_len > max_rsp_len || rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }
    out[payload_len_pos..payload_len_pos + core::mem::size_of::<U16>()]
        .copy_from_slice(&(rsp_len as u16).to_le_bytes());
    Ok(fixed_len + rsp_len)
}

#[inline]
fn payload_len_offset(vendor_id_len: usize) -> usize {
    SpdmMsgHdrPdu::SIZE + VendorDefinedRspPdu::SIZE + vendor_id_len
}

fn encode_vendor_defined_response_prefix(
    buf: &mut [u8],
    version: mcu_spdm_lite_codec::SpdmVersion,
    standard_id: StandardsBodyId,
    vendor_id: &[u8],
) -> SpdmResult<()> {
    let fixed_len = payload_len_offset(vendor_id.len()) + core::mem::size_of::<U16>();
    let mut writer = WireWriter::new(buf.get_mut(..fixed_len).ok_or(SPDM_UNSPECIFIED)?);
    writer.write(&SpdmMsgHdrPdu::new(
        version,
        ReqRespCode::VENDOR_DEFINED_RESPONSE,
    ))?;
    writer.write(&VendorDefinedRspPdu {
        param1: 0,
        param2: 0,
        standard_id: U16::new(standard_id.as_u16()),
        vendor_id_len: vendor_id.len() as u8,
    })?;
    writer.write_bytes(vendor_id)?;
    writer.write(&U16::new(0))?;
    Ok(())
}

fn finish_inline_response<Pal: SpdmPal>(
    rsp: &mut PalBytes<'_, Pal>,
    head: usize,
    fixed_len: usize,
    pal: &Pal,
    payload_len_offset: usize,
    max_rsp_len: usize,
    rsp_len: usize,
) -> SpdmResult<()> {
    if rsp_len > max_rsp_len || rsp_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }
    rsp[payload_len_offset..payload_len_offset + core::mem::size_of::<U16>()]
        .copy_from_slice(&(rsp_len as u16).to_le_bytes());
    shrink_padded(pal, rsp, head + fixed_len + rsp_len)?;
    Ok(())
}

fn padded_len<Pal: SpdmPal>(pal: &Pal, raw_len: usize) -> SpdmResult<usize> {
    let align = pal.send_len_alignment();
    debug_assert!(align > 0 && align.is_power_of_two());
    raw_len
        .checked_add(align - 1)
        .map(|len| len & !(align - 1))
        .ok_or(SPDM_UNSPECIFIED)
}

fn alloc_padded<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &Pal::Io<'_>,
    raw_len: usize,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let alloc_len = padded_len(pal, raw_len)?;
    let mut buf = pal.alloc_bytes(io, alloc_len)?;
    for b in &mut buf[raw_len..alloc_len] {
        *b = 0;
    }
    Ok(buf)
}

fn shrink_padded<Pal: SpdmPal>(
    pal: &Pal,
    rsp: &mut PalBytes<'_, Pal>,
    raw_len: usize,
) -> SpdmResult<()> {
    let shrink_len = padded_len(pal, raw_len)?;
    for b in &mut rsp[raw_len..shrink_len] {
        *b = 0;
    }
    Pal::shrink_bytes(rsp, shrink_len)?;
    Ok(())
}
