// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraCompletionCode, CaliptraVdmCmdResult,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_common_commands::{CaliptraCmdHandler, DeviceId};

pub(crate) async fn handle_device_id(
    handler: &dyn CaliptraCmdHandler,
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let mut device_id = DeviceId::default();
    match handler.get_device_id(&mut device_id).await {
        Ok(()) => {
            let mut len = (CaliptraCompletionCode::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += device_id
                .vendor_id
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += device_id
                .device_id
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += device_id
                .subsystem_vendor_id
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += device_id
                .subsystem_id
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(e) => Ok(CaliptraVdmCmdResult::ErrorResponse(e)),
    }
}
