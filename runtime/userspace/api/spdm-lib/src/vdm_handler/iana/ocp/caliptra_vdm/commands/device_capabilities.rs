// Licensed under the Apache-2.0 license

use crate::codec::{encode_u8_slice, Codec, MessageBuf};
use crate::vdm_handler::iana::ocp::caliptra_vdm::protocol::{
    CaliptraVdmCmdResult, CaliptraVdmError,
};
use crate::vdm_handler::{VdmError, VdmResult};
use caliptra_mcu_external_cmds_common::{DeviceCapabilities, UnifiedCommandHandler};
use zerocopy::IntoBytes;

pub(crate) async fn handle_device_capabilities(
    handler: &dyn UnifiedCommandHandler,
    _req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<CaliptraVdmCmdResult> {
    let mut caps = DeviceCapabilities::default();
    match handler.get_device_capabilities(&mut caps).await {
        Ok(()) => {
            let mut len = (CaliptraVdmError::Success as u8)
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
            len += encode_u8_slice(caps.as_bytes(), rsp_buf).map_err(VdmError::Codec)?;
            Ok(CaliptraVdmCmdResult::Response(len))
        }
        Err(_) => Ok(CaliptraVdmCmdResult::ErrorResponse(
            CaliptraVdmError::GeneralError,
        )),
    }
}
