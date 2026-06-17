// Licensed under the Apache-2.0 license

use mcu_spdm_lite_codec::errors::SPDM_INVALID_REQUEST;
use mcu_spdm_lite_codec::{
    IdeKmHdr, IdeRegBlock, LinkIdeStreamRegBlock, PortConfig, Query, SelectiveIdeStreamRegBlock,
    WireReader, WireWriter,
};
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc};
use zerocopy::{Immutable, IntoBytes};

use crate::pci_sig::ide_km::{map_ide_error, IdeDriver};

pub(crate) trait QueryResponseWriter {
    fn position(&self) -> usize;
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ()>;

    fn write<T: IntoBytes + Immutable + ?Sized>(&mut self, value: &T) -> Result<(), ()> {
        self.write_bytes(value.as_bytes())
    }
}

impl QueryResponseWriter for WireWriter<'_> {
    fn position(&self) -> usize {
        self.position()
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.write_bytes(bytes).map_err(|_| ())
    }
}

pub(crate) fn handle_query<D, W, Alloc>(
    driver: &D,
    scratch: &Alloc,
    reader: &mut WireReader<'_>,
    writer: &mut W,
) -> McuResult<usize>
where
    D: IdeDriver,
    W: QueryResponseWriter,
    Alloc: SpdmPalAlloc,
{
    let query = *reader.read::<Query>().map_err(|_| SPDM_INVALID_REQUEST)?;
    generate_query_resp(query.port_index, driver, scratch, writer)
}

fn generate_query_resp<D, W, Alloc>(
    port_index: u8,
    driver: &D,
    scratch: &Alloc,
    writer: &mut W,
) -> McuResult<usize>
where
    D: IdeDriver,
    W: QueryResponseWriter,
    Alloc: SpdmPalAlloc,
{
    writer
        .write(&IdeKmHdr {
            object_id: mcu_spdm_lite_codec::IDE_KM_OBJECT_ID_QUERY_RESP,
        })
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    writer
        .write(&Query {
            reserved: 0,
            port_index,
        })
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    let port_config: PortConfig = driver
        .port_config(port_index, scratch)
        .map_err(map_ide_error)?;
    writer
        .write(&port_config)
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    let ide_reg_block: IdeRegBlock = driver
        .ide_reg_block(port_index, scratch)
        .map_err(map_ide_error)?;
    writer
        .write(&ide_reg_block)
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    let ide_cap_reg = ide_reg_block.ide_cap_reg;
    if ide_cap_reg.link_ide_stream_supported() == 1 {
        for block_index in 0..ide_cap_reg.num_tcs_supported_for_link_ide() {
            let block: LinkIdeStreamRegBlock = driver
                .link_ide_reg_block(port_index, block_index, scratch)
                .map_err(map_ide_error)?;
            writer.write(&block).map_err(|_| SPDM_INVALID_REQUEST)?;
        }
    }

    if ide_cap_reg.selective_ide_stream_supported() == 1 {
        for block_index in 0..ide_cap_reg.num_selective_ide_streams_supported() {
            let block: SelectiveIdeStreamRegBlock = driver
                .selective_ide_reg_block(port_index, block_index, scratch)
                .map_err(map_ide_error)?;
            write_selective_ide_stream_reg_block(&block, writer)?;
        }
    }

    Ok(writer.position())
}

fn write_selective_ide_stream_reg_block<W>(
    block: &SelectiveIdeStreamRegBlock,
    writer: &mut W,
) -> McuResult<()>
where
    W: QueryResponseWriter,
{
    let count = block.capability_reg.num_addr_association_reg_blocks() as usize;
    if count > mcu_spdm_lite_codec::MAX_SELECTIVE_IDE_ADDR_ASSOC_BLOCK_COUNT {
        return Err(SPDM_INVALID_REQUEST);
    }

    writer
        .write(&block.capability_reg)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer
        .write(&block.ctrl_reg)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer
        .write(&block.status_reg)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer
        .write(&block.rid_association_reg_1)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer
        .write(&block.rid_association_reg_2)
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    for reg in block.addr_association_reg_block.iter().take(count) {
        writer.write(reg).map_err(|_| SPDM_INVALID_REQUEST)?;
    }

    Ok(())
}
