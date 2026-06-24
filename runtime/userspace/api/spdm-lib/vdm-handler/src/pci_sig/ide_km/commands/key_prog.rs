// Licensed under the Apache-2.0 license

use caliptra_mcu_spdm_codec::errors::SPDM_INVALID_REQUEST;
use caliptra_mcu_spdm_codec::{IdeKmHdr, KeyData, KeyProg, WireReader, WireWriter};
use caliptra_mcu_spdm_traits::{McuResult, SpdmPalAlloc};

use crate::pci_sig::ide_km::{map_ide_error, IdeDriver};

pub(crate) async fn handle_key_prog<D, Alloc>(
    driver: &D,
    scratch: &Alloc,
    reader: &mut WireReader<'_>,
    writer: &mut WireWriter<'_>,
) -> McuResult<usize>
where
    D: IdeDriver,
    Alloc: SpdmPalAlloc,
{
    let mut key_prog = *reader.read::<KeyProg>().map_err(|_| SPDM_INVALID_REQUEST)?;
    let key_data = reader.read::<KeyData>().map_err(|_| SPDM_INVALID_REQUEST)?;
    let status = driver
        .key_prog(
            key_prog.stream_id,
            key_prog.key_info,
            key_prog.port_index,
            &key_data.key,
            &key_data.iv,
            scratch,
        )
        .await
        .map_err(map_ide_error)?;

    key_prog.status = status;
    writer
        .write(&IdeKmHdr {
            object_id: caliptra_mcu_spdm_codec::IDE_KM_OBJECT_ID_KEY_PROG_ACK,
        })
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    writer.write(&key_prog).map_err(|_| SPDM_INVALID_REQUEST)?;
    Ok(writer.position())
}
