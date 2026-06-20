// Licensed under the Apache-2.0 license

use mcu_spdm_lite_codec::errors::SPDM_INVALID_REQUEST;
use mcu_spdm_lite_codec::{KeySetGoStop, WireReader, WireWriter};
use mcu_spdm_lite_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::ide_km::{map_ide_error, IdeDriver};

use super::key_go_stop_ack::write_key_go_stop_ack;

pub(crate) async fn handle_key_set_go<D, Alloc>(
    driver: &D,
    scratch: &Alloc,
    reader: &mut WireReader<'_>,
    writer: &mut WireWriter<'_>,
) -> McuResult<usize>
where
    D: IdeDriver,
    Alloc: SpdmPalAlloc,
{
    let key_set_go = *reader
        .read::<KeySetGoStop>()
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    driver
        .key_set_go(
            key_set_go.stream_id,
            key_set_go.key_info,
            key_set_go.port_index,
            scratch,
        )
        .await
        .map_err(map_ide_error)?;

    write_key_go_stop_ack(key_set_go, writer)
}
