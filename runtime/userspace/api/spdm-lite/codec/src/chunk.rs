// Licensed under the Apache-2.0 license

//! SPDM chunking wire types.

use zerocopy::{
    little_endian::U16, little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

/// CHUNK_SEND sender attribute bit: this is the final chunk.
pub const CHUNK_ATTR_LAST_CHUNK: u8 = 0x01;
/// CHUNK_SEND_ACK receiver attribute bit: an early error was detected.
pub const CHUNK_ACK_ATTR_EARLY_ERROR: u8 = 0x01;

/// CHUNK_RESPONSE body bytes before optional LargeResponseSize and chunk data.
pub const CHUNK_RESPONSE_FIXED_BODY_SIZE: usize = ChunkResponseBody::SIZE;

/// Size of the LargeResponseSize field in the first CHUNK_RESPONSE.
pub const LARGE_RESPONSE_SIZE_FIELD_SIZE: usize = 4;

/// 10-byte CHUNK_SEND request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendReqBody {
    pub chunk_sender_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
    pub reserved: U16,
    pub chunk_size: U32,
}

impl ChunkSendReqBody {
    pub const SIZE: usize = 10;
}

const _: () = assert!(core::mem::size_of::<ChunkSendReqBody>() == ChunkSendReqBody::SIZE);

/// 4-byte CHUNK_SEND_ACK response body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendAckBody {
    pub chunk_receiver_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkSendAckBody {
    pub const SIZE: usize = 4;
}

const _: () = assert!(core::mem::size_of::<ChunkSendAckBody>() == ChunkSendAckBody::SIZE);

/// 4-byte CHUNK_GET request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkGetReqBody {
    pub param1: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkGetReqBody {
    pub const SIZE: usize = 4;
}

const _: () = assert!(core::mem::size_of::<ChunkGetReqBody>() == ChunkGetReqBody::SIZE);

/// 10-byte CHUNK_RESPONSE body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkResponseBody {
    pub chunk_sender_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
    pub reserved: U16,
    pub chunk_size: U32,
}

impl ChunkResponseBody {
    pub const SIZE: usize = 10;
}

const _: () = assert!(core::mem::size_of::<ChunkResponseBody>() == ChunkResponseBody::SIZE);
