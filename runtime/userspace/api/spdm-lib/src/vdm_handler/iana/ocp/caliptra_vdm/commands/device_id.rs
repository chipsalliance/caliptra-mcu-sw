// Licensed under the Apache-2.0 license

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraVdmCmdResult, CaliptraVdmError,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_external_cmds_common::{DeviceId, UnifiedCommandHandler};

pub(crate) async fn handle_device_id(
    handler: &dyn UnifiedCommandHandler,
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let mut device_id = DeviceId::default();
    match handler.get_device_id(&mut device_id).await {
        Ok(()) => {
            let mut len = (CaliptraVdmError::Success as u8)
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
        Err(_) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::GeneralError,
        )),
    }
}
