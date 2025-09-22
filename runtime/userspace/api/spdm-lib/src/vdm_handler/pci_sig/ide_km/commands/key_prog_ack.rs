// Licensed under the Apache-2.0 license
use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver;
use crate::vdm_handler::pci_sig::ide_km::protocol::*;
use crate::vdm_handler::{VdmError, VdmResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct KeyProg {
    reserved: u16,
    stream_id: u8,
    status: u8,
    key_info: KeyInfo,
    port_index: u8,
}

impl CommonCodec for KeyProg {}

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct KeyData {
    key: [u32; IDE_STREAM_KEY_SIZE_DW],
    iv: [u32; IDE_STREAM_IV_SIZE_DW],
}

impl CommonCodec for KeyData {}

async fn process_key_prog(
    req_buf: &mut MessageBuf<'_>,
    key_prog: &KeyProg,
    ide_km_driver: &dyn IdeDriver,
) -> VdmResult<u8> {
    let key_data = KeyData::decode(req_buf).map_err(VdmError::Codec)?;

    ide_km_driver
        .key_prog(
            key_prog.stream_id,
            key_prog.key_info,
            key_prog.port_index,
            &key_data.key,
            &key_data.iv,
        )
        .await
        .map_err(VdmError::IdeKmDriver)
}

pub(crate) async fn handle_key_prog(
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    ide_km_driver: &dyn crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver,
) -> VdmResult<usize> {
    let mut key_prog = KeyProg::decode(req_buf).map_err(VdmError::Codec)?;
    // Process KEY_PROG request
    let status = process_key_prog(req_buf, &key_prog, ide_km_driver).await?;

    // Generate KEY_PROG_ACK response
    let ide_km_rsp_hdr = IdeKmHdr {
        object_id: IdeKmCommand::KeyProgAck as u8,
    };
    let mut len = ide_km_rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    // Update status in the response
    key_prog.status = status;

    len += key_prog.encode(rsp_buf).map_err(VdmError::Codec)?;
    Ok(len)
}
