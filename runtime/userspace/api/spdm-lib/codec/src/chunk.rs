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
    // TODO
    // SPDM 1.4 extends the sequence number to 32-bit.
    // We leave it at 16-bit for now and error if a larger sequence number is encountered.
    // See: https://github.com/chipsalliance/caliptra-mcu-sw/issues/2165
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
pub struct ChunkSendAckBodyV13 {
    pub chunk_receiver_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkSendAckBodyV13 {
    pub const SIZE: usize = 4;
}

const _: () = assert!(core::mem::size_of::<ChunkSendAckBodyV13>() == ChunkSendAckBodyV13::SIZE);

/// 6-byte CHUNK_SEND_ACK response body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkSendAckBodyV14 {
    pub chunk_receiver_attr: u8,
    pub handle: u8,
    pub chunk_seq_num: U32,
}

impl ChunkSendAckBodyV14 {
    pub const SIZE: usize = 6;
}

const _: () = assert!(core::mem::size_of::<ChunkSendAckBodyV14>() == ChunkSendAckBodyV14::SIZE);

pub trait ChunkGetReqBody {
    /// Size of the request
    fn size(&self) -> usize;

    /// Get Param1 of the request.
    fn get_param1(&self) -> u8;

    /// Get the chunk handle of the request.
    fn get_handle(&self) -> u8;

    /// Get the chunk sequence number for this request.
    ///
    /// <= SPDM 1.3 sequence numbers are limited to 16-bit.
    fn get_chunk_seq_num(&self) -> u32;
}

/// 4-byte CHUNK_GET request body after the SPDM common header.
///
/// Applicable to SPDM 1.3 and lower.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkGetReqBodyV13 {
    pub param1: u8,
    pub handle: u8,
    pub chunk_seq_num: U16,
}

impl ChunkGetReqBodyV13 {
    pub const SIZE: usize = 4;
}

impl ChunkGetReqBody for ChunkGetReqBodyV13 {
    fn size(&self) -> usize {
        ChunkGetReqBodyV13::SIZE
    }

    fn get_param1(&self) -> u8 {
        self.param1
    }

    fn get_handle(&self) -> u8 {
        self.handle
    }

    fn get_chunk_seq_num(&self) -> u32 {
        self.chunk_seq_num.get() as u32
    }
}

const _: () = assert!(core::mem::size_of::<ChunkGetReqBodyV13>() == ChunkGetReqBodyV13::SIZE);

/// 6-byte CHUNK_GET v1.4 request body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkGetReqBodyV14 {
    pub param1: u8,
    pub handle: u8,
    pub chunk_seq_num: U32,
}

impl ChunkGetReqBodyV14 {
    pub const SIZE: usize = 6;
}

impl ChunkGetReqBody for ChunkGetReqBodyV14 {
    fn size(&self) -> usize {
        ChunkGetReqBodyV14::SIZE
    }

    fn get_param1(&self) -> u8 {
        self.param1
    }

    fn get_handle(&self) -> u8 {
        self.handle
    }

    fn get_chunk_seq_num(&self) -> u32 {
        self.chunk_seq_num.get()
    }
}

const _: () = assert!(core::mem::size_of::<ChunkGetReqBodyV14>() == ChunkGetReqBodyV14::SIZE);

/// 10-byte CHUNK_RESPONSE body after the SPDM common header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ChunkResponseBody {
    pub chunk_sender_attr: u8,
    pub handle: u8,
    // TODO
    // SPDM 1.4 extends the sequence number to 32-bit.
    // We leave it at 16-bit for now and error if a larger sequence number is encountered.
    // See: https://github.com/chipsalliance/caliptra-mcu-sw/issues/2165
    pub chunk_seq_num: U16,
    pub reserved: U16,
    pub chunk_size: U32,
}

impl ChunkResponseBody {
    pub const SIZE: usize = 10;
}

const _: () = assert!(core::mem::size_of::<ChunkResponseBody>() == ChunkResponseBody::SIZE);
