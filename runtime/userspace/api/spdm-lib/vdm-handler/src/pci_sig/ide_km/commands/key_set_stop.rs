// Licensed under the Apache-2.0 license

use caliptra_mcu_spdm_codec::errors::SPDM_INVALID_REQUEST;
use caliptra_mcu_spdm_codec::{KeySetGoStop, WireReader, WireWriter};
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::ide_km::{map_ide_error, IdeDriver};

use super::key_go_stop_ack::write_key_go_stop_ack;

pub(crate) async fn handle_key_set_stop<D, Alloc>(
    driver: &D,
    scratch: &Alloc,
    reader: &mut WireReader<'_>,
    writer: &mut WireWriter<'_>,
) -> McuResult<usize>
where
    D: IdeDriver,
    Alloc: SpdmPalAlloc,
{
    let key_set_stop = *reader
        .read::<KeySetGoStop>()
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    driver
        .key_set_stop(
            key_set_stop.stream_id,
            key_set_stop.key_info,
            key_set_stop.port_index,
            scratch,
        )
        .await
        .map_err(map_ide_error)?;

    write_key_go_stop_ack(key_set_stop, writer)
}
