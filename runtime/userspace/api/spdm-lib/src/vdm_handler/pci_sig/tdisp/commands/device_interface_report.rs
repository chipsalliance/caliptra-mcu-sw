// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::error_response;
use crate::vdm_handler::pci_sig::tdisp::protocol::*;
use crate::vdm_handler::pci_sig::tdisp::{TdispCmdResult, TdispResponder};
use crate::vdm_handler::{VdmError, VdmResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub(crate) struct GetDeviceIntfReportReq {
    offset: u16,
    length: u16,
}

impl CommonCodec for GetDeviceIntfReportReq {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct GetDeviceIntfReportRespHdr {
    portion_length: u16,
    remainder_length: u16,
}
impl CommonCodec for GetDeviceIntfReportRespHdr {}

pub(crate) async fn handle_get_device_interface_report(
    tdisp_responder: &mut TdispResponder<'_>,
    req_hdr: &TdispMessageHeader,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<TdispCmdResult> {
    let interface_id = req_hdr.interface_id;
    if tdisp_responder
        .state
        .interface_state(interface_id)
        .is_none()
    {
        return error_response!(TdispError::InvalidInterface);
    }

    let req = GetDeviceIntfReportReq::decode(req_buf).map_err(VdmError::Codec)?;

    let mut intf_report_len: u16 = 0;
    match tdisp_responder
        .driver
        .get_device_interface_report_len(interface_id.function_id, &mut intf_report_len)
        .await
    {
        Ok(0) => {
            if req.offset as usize >= intf_report_len as usize {
                return error_response!(TdispError::InvalidRequest);
            }
        }

        Ok(err_code) => return error_response!(err_code.into()),
        Err(_) => return error_response!(TdispError::Unspecified),
    }

    let avail_buf_size = rsp_buf.tailroom() as u16;
    let remainder_len = intf_report_len.saturating_sub(req.offset);
    let portion_len = remainder_len.min(req.length).min(avail_buf_size);

    let rsp_hdr = GetDeviceIntfReportRespHdr {
        portion_length: portion_len,
        remainder_length: remainder_len.saturating_sub(portion_len),
    };
    let rsp_hdr_len = rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    rsp_buf
        .put_data(portion_len as usize)
        .map_err(VdmError::Codec)?;
    let report_portion_buf = rsp_buf
        .data_mut(portion_len as usize)
        .map_err(VdmError::Codec)?;

    let mut copied = 0usize;
    match tdisp_responder
        .driver
        .get_device_interface_report(
            interface_id.function_id,
            req.offset,
            report_portion_buf,
            &mut copied,
        )
        .await
    {
        Ok(0) => {
            if copied != portion_len as usize {
                return error_response!(TdispError::Unspecified);
            }
            let len = rsp_hdr_len + portion_len as usize;
            rsp_buf.push_data(len).map_err(VdmError::Codec)?;
            Ok(TdispCmdResult::Response(len))
        }
        Ok(err_code) => {
            error_response!(err_code.into())
        }
        Err(_) => {
            error_response!(TdispError::Unspecified)
        }
    }
}
