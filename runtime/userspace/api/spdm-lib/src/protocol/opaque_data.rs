// Licensed under the Apache-2.0 license

use crate::codec::{decode_u8_slice, encode_u8_slice, Codec, CommonCodec, MessageBuf};
use crate::error::{CommandError, CommandResult};
use zerocopy::{FromBytes, Immutable, IntoBytes};

pub(crate) const OPAQUE_DATA_LEN_MAX_SIZE: usize = 1024; // Maximum size for opaque data

#[derive(FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct OpaqueDataLen {
    len: u16,
}
impl CommonCodec for OpaqueDataLen {}

pub(crate) fn encode_opaque_data(
    buf: &mut MessageBuf<'_>,
    opaque_data: &[u8],
) -> CommandResult<usize> {
    let opaque_data_len = OpaqueDataLen {
        len: opaque_data.len() as u16,
    };
    let mut len = opaque_data_len
        .encode(buf)
        .map_err(|e| (false, CommandError::Codec(e)))?;

    if !opaque_data.is_empty() {
        len += encode_u8_slice(opaque_data, buf).map_err(|e| (false, CommandError::Codec(e)))?;
    }

    Ok(len)
}

pub(crate) fn decode_opaque_data(
    buf: &mut MessageBuf<'_>,
) -> CommandResult<([u8; OPAQUE_DATA_LEN_MAX_SIZE], usize)> {
    let opaque_data_len =
        OpaqueDataLen::decode(buf).map_err(|e| (false, CommandError::Codec(e)))?;
    let data_len = opaque_data_len.len as usize;
    let mut opaque_data = [0u8; OPAQUE_DATA_LEN_MAX_SIZE];
    if data_len > 0 {
        decode_u8_slice(buf, &mut opaque_data[..data_len])
            .map_err(|e| (false, CommandError::Codec(e)))?;
    }
    Ok((opaque_data, data_len))
}
