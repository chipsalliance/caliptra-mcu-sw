// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, FirmwareVersion};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct FirmwareVersionReq {
    area_index: u32,
}

impl CommonCodec for FirmwareVersionReq {}

pub(crate) async fn handle_firmware_version(
    handler: &dyn CaliptraCmdHandler,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let req = FirmwareVersionReq::decode(req_buf).map_err(VdmError::Codec)?;

    let mut version = FirmwareVersion::default();
    match handler
        .get_firmware_version(req.area_index, &mut version)
        .await
    {
        Ok(()) => {
            let mut len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(&version.ver_str[..version.len], rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
