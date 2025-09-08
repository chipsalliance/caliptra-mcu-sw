// Licensed under the Apache-2.0 license

use crate::codec::{Codec, CommonCodec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver;
use crate::vdm_handler::pci_sig::ide_km::protocol::{IdeKmCommand, IdeKmHdr};
use crate::vdm_handler::{VdmError, VdmResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct Query {
    reserved: u8,
    port_index: u8,
}

impl CommonCodec for Query {}

fn process_query_req(req_buf: &mut MessageBuf<'_>) -> VdmResult<u8> {
    let query_req = Query::decode(req_buf).map_err(VdmError::Codec)?;
    Ok(query_req.port_index)
}

async fn generate_query_resp(
    port_index: u8,
    ide_km_driver: &dyn IdeDriver,
    rsp_buf: &mut MessageBuf<'_>,
) -> VdmResult<usize> {
    let ide_km_rsp_hdr = IdeKmHdr {
        object_id: IdeKmCommand::QueryResp as u8,
    };
    let mut len = ide_km_rsp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    // Encode Query response header
    let query_resp_hdr = Query {
        reserved: 0,
        port_index,
    };

    len += query_resp_hdr.encode(rsp_buf).map_err(VdmError::Codec)?;

    // Port configuration
    let port_config = ide_km_driver
        .port_config(port_index)
        .map_err(VdmError::IdeKmDriver)?;
    len += port_config.encode(rsp_buf).map_err(VdmError::Codec)?;

    // IDE capability and control registers
    let ide_reg_blk = ide_km_driver
        .ide_reg_block(port_index)
        .map_err(VdmError::IdeKmDriver)?;
    len += ide_reg_blk.encode(rsp_buf).map_err(VdmError::Codec)?;

    // Link IDE register blocks
    let ide_cap_reg = ide_reg_blk.ide_cap_reg;
    if ide_cap_reg.link_ide_stream_supported() == 1 {
        let num_link_ide_streams = ide_cap_reg.num_tcs_supported_for_link_ide();
        for blk_idx in 0..num_link_ide_streams {
            let link_ide_reg_blk = ide_km_driver
                .link_ide_reg_block(port_index, blk_idx)
                .map_err(VdmError::IdeKmDriver)?;
            len += link_ide_reg_blk.encode(rsp_buf).map_err(VdmError::Codec)?;
        }
    }

    // Selective IDE register blocks
    if ide_cap_reg.selective_ide_stream_supported() == 1 {
        let num_selective_ide_streams = ide_cap_reg.num_selective_ide_streams_supported();
        for blk_idx in 0..num_selective_ide_streams {
            let selective_ide_reg_blk = ide_km_driver
                .selective_ide_reg_block(port_index, blk_idx)
                .map_err(VdmError::IdeKmDriver)?;
            len += selective_ide_reg_blk
                .encode(rsp_buf)
                .map_err(VdmError::Codec)?;
        }
    }

    rsp_buf.push_data(len).map_err(VdmError::Codec)?;

    Ok(len)
}

pub(crate) async fn handle_query(
    req_buf: &mut MessageBuf<'_>,
    rsp_buf: &mut MessageBuf<'_>,
    ide_km_driver: &dyn IdeDriver,
) -> VdmResult<usize> {
    let port_index = process_query_req(req_buf)?;

    generate_query_resp(port_index, ide_km_driver, rsp_buf).await
}
