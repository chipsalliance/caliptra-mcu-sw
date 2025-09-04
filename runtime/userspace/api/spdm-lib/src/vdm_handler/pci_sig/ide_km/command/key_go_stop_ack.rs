// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver;
use crate::vdm_handler::pci_sig::ide_km::protocol::*;
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct KeySetGoStop {
    reserved1: u16,
    stream_id: u8,
    reserved2: u8,
    key_info: KeyInfo,
    port_index: u8,
}
impl CommonCodec for KeySetGoStop {}

pub(crate) async fn handle_key_set_go_stop(
    key_set_go: bool,
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    ide_km_driver: &dyn IdeDriver,
) -> crate::vdm_handler::VdmResult<usize> {
    let key_set_go_stop =
        KeySetGoStop::decode(req_buf).map_err(crate::vdm_handler::VdmError::Codec)?;

    if key_set_go {
        ide_km_driver
            .key_set_go(
                key_set_go_stop.stream_id,
                key_set_go_stop.key_info,
                key_set_go_stop.port_index,
            )
            .await
            .map_err(crate::vdm_handler::VdmError::IdeKmDriver)?;
    } else {
        ide_km_driver
            .key_set_stop(
                key_set_go_stop.stream_id,
                key_set_go_stop.key_info,
                key_set_go_stop.port_index,
            )
            .await
            .map_err(crate::vdm_handler::VdmError::IdeKmDriver)?;
    }

    // Generate KEY_GO_STOP_ACK response
    let key_go_stop_ack = KeySetGoStop {
        reserved1: 0,
        stream_id: key_set_go_stop.stream_id,
        reserved2: 0,
        key_info: key_set_go_stop.key_info,
        port_index: key_set_go_stop.port_index,
    };
    key_go_stop_ack
        .encode(rsp_buf)
        .map_err(crate::vdm_handler::VdmError::Codec)
}
