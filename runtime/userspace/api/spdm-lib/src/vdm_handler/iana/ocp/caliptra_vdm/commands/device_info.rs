// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraVdmCmdResult, CaliptraVdmError,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_external_cmds_common::{DeviceInfo, Uid, UnifiedCommandHandler, MAX_UID_LEN};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct DeviceInfoReq {
    info_index: u32,
}

impl CommonCodec for DeviceInfoReq {}

pub(crate) async fn handle_device_info(
    handler: &dyn UnifiedCommandHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let req = DeviceInfoReq::decode(req_buf).map_err(VdmError::Codec)?;

    let mut info = DeviceInfo::Uid(Uid::default());
    match handler.get_device_info(req.info_index, &mut info).await {
        Ok(()) => {
            let DeviceInfo::Uid(uid) = &info;
            let data_len = uid.len.min(MAX_UID_LEN);
            let mut len = (CaliptraVdmError::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(&uid.unique_chip_id[..data_len], rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(_) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::InvalidData,
        )),
    }
}
