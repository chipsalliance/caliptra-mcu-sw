// Licensed under the Apache-2.0 license

//! Boot source provider messaging protocol packet definitions.

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    InitiateBootRequest = 0x01,
    ImageMetadataRequest = 0x02,
    ImageDownloadRequest = 0x03,
    ChunkAck = 0x04,
    Finalize = 0x05,
    InitiateBootResponse = 0x81,
    ImageMetadataResponse = 0x82,
    ImageChunk = 0x83,
    FinalizeAck = 0x85,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::InitiateBootRequest),
            0x02 => Some(Self::ImageMetadataRequest),
            0x03 => Some(Self::ImageDownloadRequest),
            0x04 => Some(Self::ChunkAck),
            0x05 => Some(Self::Finalize),
            0x81 => Some(Self::InitiateBootResponse),
            0x82 => Some(Self::ImageMetadataResponse),
            0x83 => Some(Self::ImageChunk),
            0x85 => Some(Self::FinalizeAck),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success = 0x00,
    InProgress = 0x01,
}

impl Status {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Success),
            0x01 => Some(Self::InProgress),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidMessageType = 0x01,
    InvalidFirmwareId = 0x02,
    ImageNotFound = 0x03,
    ChecksumMismatch = 0x04,
    TransferTimeout = 0x05,
    SourceNotReady = 0x06,
    InvalidParameters = 0x07,
    CorruptedData = 0x08,
    InsufficientSpace = 0x09,
    ChecksumVerificationFailed = 0x0A,
    FlashWriteFailed = 0x0B,
    FlashStagingNotAvailable = 0x0C,
    FlashCommitFailed = 0x0D,
    FlashVerificationFailed = 0x0E,
    Unknown = 0xFF,
}

impl ErrorCode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::InvalidMessageType),
            0x02 => Some(Self::InvalidFirmwareId),
            0x03 => Some(Self::ImageNotFound),
            0x04 => Some(Self::ChecksumMismatch),
            0x05 => Some(Self::TransferTimeout),
            0x06 => Some(Self::SourceNotReady),
            0x07 => Some(Self::InvalidParameters),
            0x08 => Some(Self::CorruptedData),
            0x09 => Some(Self::InsufficientSpace),
            0x0A => Some(Self::ChecksumVerificationFailed),
            0x0B => Some(Self::FlashWriteFailed),
            0x0C => Some(Self::FlashStagingNotAvailable),
            0x0D => Some(Self::FlashCommitFailed),
            0x0E => Some(Self::FlashVerificationFailed),
            0xFF => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub const FIRMWARE_ID_CALIPTRA_FMC_RT: u8 = 0x00;
pub const FIRMWARE_ID_SOC_MANIFEST: u8 = 0x01;
pub const FIRMWARE_ID_MCU_RT: u8 = 0x02;

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct InitiateBootRequest {
    pub message_type: u8,
    pub reserved: [u8; 3],
    pub protocol_version: u32,
    pub flags: BootFlags,
}

impl InitiateBootRequest {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(protocol_version: u32, flags: BootFlags) -> Self {
        Self {
            message_type: MessageType::InitiateBootRequest.as_u8(),
            reserved: [0u8; 3],
            protocol_version,
            flags,
        }
    }
}

bitfield! {
    #[repr(C)]
    #[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Default)]
    pub struct BootFlags(u32);
    impl Debug;
    pub flash_writeback, set_flash_writeback: 0;
    pub flash_commit_policy, set_flash_commit_policy: 1;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct InitiateBootResponse {
    pub message_type: u8,
    pub status: u8,
    pub reserved: [u8; 2],
}

impl InitiateBootResponse {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(status: Status) -> Self {
        Self {
            message_type: MessageType::InitiateBootResponse.as_u8(),
            status: status.as_u8(),
            reserved: [0u8; 2],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ImageMetadataRequest {
    pub message_type: u8,
    pub firmware_id: u8,
    pub reserved: [u8; 2],
}

impl ImageMetadataRequest {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(firmware_id: u8) -> Self {
        Self {
            message_type: MessageType::ImageMetadataRequest.as_u8(),
            firmware_id,
            reserved: [0u8; 2],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ImageMetadataResponse {
    pub message_type: u8,
    pub status: u8,
    pub reserved0: [u8; 2],
    pub image_size: u32,
    pub checksum: [u8; 32],
    pub version: u32,
    pub flags: u32,
    pub reserved1: u32,
}

impl ImageMetadataResponse {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub const FLAG_COMPRESSED: u32 = 1 << 0;
    pub const FLAG_SIGNED: u32 = 1 << 1;

    pub fn new(image_size: u32, checksum: [u8; 32], version: u32, flags: u32) -> Self {
        Self {
            message_type: MessageType::ImageMetadataResponse.as_u8(),
            status: Status::Success.as_u8(),
            reserved0: [0u8; 2],
            image_size,
            checksum,
            version,
            flags,
            reserved1: 0,
        }
    }

    pub fn error(status: ErrorCode) -> Self {
        Self {
            message_type: MessageType::ImageMetadataResponse.as_u8(),
            status: status.as_u8(),
            reserved0: [0u8; 2],
            image_size: 0,
            checksum: [0u8; 32],
            version: 0,
            flags: 0,
            reserved1: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ImageDownloadRequest {
    pub message_type: u8,
    pub firmware_id: u8,
    pub reserved0: [u8; 2],
    pub reserved1: u32,
    pub reserved2: u32,
}

impl ImageDownloadRequest {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(firmware_id: u8) -> Self {
        Self {
            message_type: MessageType::ImageDownloadRequest.as_u8(),
            firmware_id,
            reserved0: [0u8; 2],
            reserved1: 0,
            reserved2: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ImageChunkHeader {
    pub message_type: u8,
    pub status: u8,
    pub sequence_number: u16,
    pub offset: u32,
    pub chunk_size: u32,
}

impl ImageChunkHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(sequence_number: u16, offset: u32, chunk_size: u32) -> Self {
        Self {
            message_type: MessageType::ImageChunk.as_u8(),
            status: Status::Success.as_u8(),
            sequence_number,
            offset,
            chunk_size,
        }
    }

    pub fn error(status: ErrorCode) -> Self {
        Self {
            message_type: MessageType::ImageChunk.as_u8(),
            status: status.as_u8(),
            sequence_number: 0,
            offset: 0,
            chunk_size: 0,
        }
    }

    pub fn total_size(&self) -> usize {
        Self::SIZE + self.chunk_size as usize
    }

    pub fn parse_from(buf: &[u8]) -> Option<(&Self, &[u8])> {
        if buf.len() < Self::SIZE {
            return None;
        }
        let (header_bytes, rest) = buf.split_at(Self::SIZE);
        let header = Self::ref_from_bytes(header_bytes).ok()?;
        let payload_len = header.chunk_size as usize;
        if rest.len() < payload_len {
            return None;
        }
        Some((header, &rest[..payload_len]))
    }

    pub fn write_to_buf(&self, payload: &[u8], buf: &mut [u8]) -> Option<usize> {
        let total = Self::SIZE + payload.len();
        if buf.len() < total {
            return None;
        }
        buf[..Self::SIZE].copy_from_slice(self.as_bytes());
        buf[Self::SIZE..total].copy_from_slice(payload);
        Some(total)
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, Immutable, KnownLayout)]
pub struct ImageChunk {
    pub header: ImageChunkHeader,
    pub data: [u8],
}

impl ImageChunk {
    pub fn parse_from(buf: &[u8]) -> Option<&Self> {
        if buf.len() < ImageChunkHeader::SIZE {
            return None;
        }
        let (header, _) = ImageChunkHeader::ref_from_prefix(buf).ok()?;
        let total = ImageChunkHeader::SIZE.checked_add(header.chunk_size as usize)?;
        if buf.len() < total {
            return None;
        }
        Self::ref_from_bytes(&buf[..total]).ok()
    }

    pub fn payload(&self) -> &[u8] {
        &self.data
    }

    pub fn is_last_chunk(&self, max_chunk_size: u32) -> bool {
        self.header.chunk_size < max_chunk_size
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ChunkAck {
    pub message_type: u8,
    pub firmware_id: u8,
    pub sequence_number: u16,
    pub reserved: u32,
    pub flags: ChunkAckFlags,
}

impl ChunkAck {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(firmware_id: u8, sequence_number: u16, flags: ChunkAckFlags) -> Self {
        Self {
            message_type: MessageType::ChunkAck.as_u8(),
            firmware_id,
            sequence_number,
            reserved: 0,
            flags,
        }
    }
}

bitfield! {
    #[repr(C)]
    #[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Default)]
    pub struct ChunkAckFlags(u32);
    impl Debug;
    pub ready_for_next, set_ready_for_next: 0;
    pub error_detected, set_error_detected: 1;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FinalizeRequest {
    pub message_type: u8,
    pub status: u8,
    pub error_code: u16,
    pub reserved: u32,
}

impl FinalizeRequest {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn success() -> Self {
        Self {
            message_type: MessageType::Finalize.as_u8(),
            status: Status::Success.as_u8(),
            error_code: 0,
            reserved: 0,
        }
    }

    pub fn error(status: ErrorCode, error_code: u16) -> Self {
        Self {
            message_type: MessageType::Finalize.as_u8(),
            status: status.as_u8(),
            error_code,
            reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FinalizeAck {
    pub message_type: u8,
    pub status: u8,
    pub reserved0: [u8; 2],
    pub cleanup_flags: CleanupFlags,
    pub reserved1: u32,
}

impl FinalizeAck {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(status: Status, cleanup_flags: CleanupFlags) -> Self {
        Self {
            message_type: MessageType::FinalizeAck.as_u8(),
            status: status.as_u8(),
            reserved0: [0u8; 2],
            cleanup_flags,
            reserved1: 0,
        }
    }
}

bitfield! {
    #[repr(C)]
    #[derive(Copy, Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Default)]
    pub struct CleanupFlags(u32);
    impl Debug;
    pub clear_toc, set_clear_toc: 0;
    pub reset_connection, set_reset_connection: 1;
}

pub fn peek_message_type(buf: &[u8]) -> Option<u8> {
    buf.first().copied()
}

pub fn parse_fixed<T: FromBytes + KnownLayout + Immutable>(buf: &[u8]) -> Option<&T> {
    T::ref_from_prefix(buf).ok().map(|(val, _rest)| val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;

    // -----------------------------------------------------------------------
    // Enum round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn message_type_round_trip() {
        let variants = [
            (0x01, MessageType::InitiateBootRequest),
            (0x02, MessageType::ImageMetadataRequest),
            (0x03, MessageType::ImageDownloadRequest),
            (0x04, MessageType::ChunkAck),
            (0x05, MessageType::Finalize),
            (0x81, MessageType::InitiateBootResponse),
            (0x82, MessageType::ImageMetadataResponse),
            (0x83, MessageType::ImageChunk),
            (0x85, MessageType::FinalizeAck),
        ];
        for (raw, expected) in variants {
            assert_eq!(MessageType::from_u8(raw), Some(expected));
            assert_eq!(expected.as_u8(), raw);
        }
    }

    #[test]
    fn message_type_invalid() {
        assert_eq!(MessageType::from_u8(0x00), None);
        assert_eq!(MessageType::from_u8(0x06), None);
        assert_eq!(MessageType::from_u8(0x84), None);
        assert_eq!(MessageType::from_u8(0xFF), None);
    }

    #[test]
    fn status_round_trip() {
        assert_eq!(Status::from_u8(0x00), Some(Status::Success));
        assert_eq!(Status::from_u8(0x01), Some(Status::InProgress));
        assert_eq!(Status::Success.as_u8(), 0x00);
        assert_eq!(Status::InProgress.as_u8(), 0x01);
        assert_eq!(Status::from_u8(0x02), None);
    }

    #[test]
    fn error_code_round_trip() {
        let variants = [
            (0x01, ErrorCode::InvalidMessageType),
            (0x02, ErrorCode::InvalidFirmwareId),
            (0x03, ErrorCode::ImageNotFound),
            (0x04, ErrorCode::ChecksumMismatch),
            (0x05, ErrorCode::TransferTimeout),
            (0x06, ErrorCode::SourceNotReady),
            (0x07, ErrorCode::InvalidParameters),
            (0x08, ErrorCode::CorruptedData),
            (0x09, ErrorCode::InsufficientSpace),
            (0x0A, ErrorCode::ChecksumVerificationFailed),
            (0x0B, ErrorCode::FlashWriteFailed),
            (0x0C, ErrorCode::FlashStagingNotAvailable),
            (0x0D, ErrorCode::FlashCommitFailed),
            (0x0E, ErrorCode::FlashVerificationFailed),
            (0xFF, ErrorCode::Unknown),
        ];
        for (raw, expected) in variants {
            assert_eq!(ErrorCode::from_u8(raw), Some(expected));
            assert_eq!(expected.as_u8(), raw);
        }
        assert_eq!(ErrorCode::from_u8(0x00), None);
        assert_eq!(ErrorCode::from_u8(0x10), None);
    }

    // -----------------------------------------------------------------------
    // Bitfield tests
    // -----------------------------------------------------------------------

    #[test]
    fn boot_flags_bitfield() {
        let mut flags = BootFlags(0);
        assert!(!flags.flash_writeback());
        assert!(!flags.flash_commit_policy());

        flags.set_flash_writeback(true);
        assert!(flags.flash_writeback());
        assert!(!flags.flash_commit_policy());

        flags.set_flash_commit_policy(true);
        assert!(flags.flash_writeback());
        assert!(flags.flash_commit_policy());
        assert_eq!(flags.0, 0b11);
    }

    #[test]
    fn chunk_ack_flags_bitfield() {
        let mut flags = ChunkAckFlags(0);
        assert!(!flags.ready_for_next());
        assert!(!flags.error_detected());

        flags.set_ready_for_next(true);
        assert!(flags.ready_for_next());

        flags.set_error_detected(true);
        assert!(flags.error_detected());
        assert_eq!(flags.0, 0b11);
    }

    #[test]
    fn cleanup_flags_bitfield() {
        let mut flags = CleanupFlags(0);
        assert!(!flags.clear_toc());
        assert!(!flags.reset_connection());

        flags.set_clear_toc(true);
        assert!(flags.clear_toc());

        flags.set_reset_connection(true);
        assert!(flags.reset_connection());
        assert_eq!(flags.0, 0b11);
    }

    // -----------------------------------------------------------------------
    // Packet struct layout size tests
    // -----------------------------------------------------------------------

    #[test]
    fn packet_sizes() {
        assert_eq!(InitiateBootRequest::SIZE, 12);
        assert_eq!(InitiateBootResponse::SIZE, 4);
        assert_eq!(ImageMetadataRequest::SIZE, 4);
        assert_eq!(ImageMetadataResponse::SIZE, 52);
        assert_eq!(ImageDownloadRequest::SIZE, 12);
        assert_eq!(ImageChunkHeader::SIZE, 12);
        assert_eq!(ChunkAck::SIZE, 12);
        assert_eq!(FinalizeRequest::SIZE, 8);
        assert_eq!(FinalizeAck::SIZE, 12);
    }

    // -----------------------------------------------------------------------
    // Packet construction + zerocopy serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn initiate_boot_request_serialization() {
        let mut flags = BootFlags(0);
        flags.set_flash_writeback(true);
        let pkt = InitiateBootRequest::new(1, flags);

        assert_eq!(pkt.message_type, MessageType::InitiateBootRequest.as_u8());
        assert_eq!(pkt.protocol_version, 1);
        assert!(pkt.flags.flash_writeback());
        assert!(!pkt.flags.flash_commit_policy());

        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 0x01); // message type
        assert_eq!(bytes[1..4], [0, 0, 0]); // reserved
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1); // version
        assert_eq!(bytes[8], 0x01); // flags bit 0 set
    }

    #[test]
    fn initiate_boot_response_serialization() {
        let pkt = InitiateBootResponse::new(Status::Success);

        assert_eq!(pkt.message_type, MessageType::InitiateBootResponse.as_u8());
        assert_eq!(pkt.status, 0x00);

        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 0x81);
        assert_eq!(bytes[1], 0x00);
    }

    #[test]
    fn image_metadata_request_serialization() {
        let pkt = ImageMetadataRequest::new(FIRMWARE_ID_MCU_RT);

        assert_eq!(pkt.message_type, MessageType::ImageMetadataRequest.as_u8());
        assert_eq!(pkt.firmware_id, 0x02);

        let bytes = pkt.as_bytes();
        assert_eq!(bytes[0], 0x02);
        assert_eq!(bytes[1], 0x02);
    }

    #[test]
    fn image_metadata_response_success() {
        let checksum = [0xAB; 32];
        let pkt = ImageMetadataResponse::new(4096, checksum, 3, ImageMetadataResponse::FLAG_SIGNED);

        assert_eq!(pkt.message_type, MessageType::ImageMetadataResponse.as_u8());
        assert_eq!(pkt.status, Status::Success.as_u8());
        assert_eq!(pkt.image_size, 4096);
        assert_eq!(pkt.checksum, [0xAB; 32]);
        assert_eq!(pkt.version, 3);
        assert_eq!(pkt.flags, ImageMetadataResponse::FLAG_SIGNED);
    }

    #[test]
    fn image_metadata_response_error() {
        let pkt = ImageMetadataResponse::error(ErrorCode::ImageNotFound);

        assert_eq!(pkt.status, ErrorCode::ImageNotFound.as_u8());
        assert_eq!(pkt.image_size, 0);
    }

    #[test]
    fn image_download_request_serialization() {
        let pkt = ImageDownloadRequest::new(FIRMWARE_ID_SOC_MANIFEST);

        assert_eq!(pkt.message_type, MessageType::ImageDownloadRequest.as_u8());
        assert_eq!(pkt.firmware_id, 0x01);
    }

    #[test]
    fn chunk_ack_serialization() {
        let mut flags = ChunkAckFlags(0);
        flags.set_ready_for_next(true);
        let pkt = ChunkAck::new(FIRMWARE_ID_CALIPTRA_FMC_RT, 42, flags);

        assert_eq!(pkt.message_type, MessageType::ChunkAck.as_u8());
        assert_eq!(pkt.firmware_id, 0x00);
        assert_eq!(pkt.sequence_number, 42);
        assert!(pkt.flags.ready_for_next());
        assert!(!pkt.flags.error_detected());
    }

    #[test]
    fn finalize_request_success() {
        let pkt = FinalizeRequest::success();

        assert_eq!(pkt.message_type, MessageType::Finalize.as_u8());
        assert_eq!(pkt.status, Status::Success.as_u8());
        assert_eq!(pkt.error_code, 0);
    }

    #[test]
    fn finalize_request_error() {
        let pkt = FinalizeRequest::error(ErrorCode::FlashCommitFailed, 0x1234);

        assert_eq!(pkt.status, ErrorCode::FlashCommitFailed.as_u8());
        assert_eq!(pkt.error_code, 0x1234);
    }

    #[test]
    fn finalize_ack_serialization() {
        let mut flags = CleanupFlags(0);
        flags.set_clear_toc(true);
        flags.set_reset_connection(true);
        let pkt = FinalizeAck::new(Status::Success, flags);

        assert_eq!(pkt.message_type, MessageType::FinalizeAck.as_u8());
        assert_eq!(pkt.status, 0x00);
        assert!(pkt.cleanup_flags.clear_toc());
        assert!(pkt.cleanup_flags.reset_connection());
    }

    // -----------------------------------------------------------------------
    // Image chunk header variable-length tests
    // -----------------------------------------------------------------------

    #[test]
    fn image_chunk_header_new() {
        let hdr = ImageChunkHeader::new(5, 1024, 512);

        assert_eq!(hdr.message_type, MessageType::ImageChunk.as_u8());
        assert_eq!(hdr.status, Status::Success.as_u8());
        assert_eq!(hdr.sequence_number, 5);
        assert_eq!(hdr.offset, 1024);
        assert_eq!(hdr.chunk_size, 512);
        assert_eq!(hdr.total_size(), ImageChunkHeader::SIZE + 512);
    }

    #[test]
    fn image_chunk_header_error() {
        let hdr = ImageChunkHeader::error(ErrorCode::TransferTimeout);

        assert_eq!(hdr.status, ErrorCode::TransferTimeout.as_u8());
        assert_eq!(hdr.chunk_size, 0);
    }

    #[test]
    fn image_chunk_write_and_parse() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let hdr = ImageChunkHeader::new(1, 0, payload.len() as u32);

        let mut buf = [0u8; 64];
        let written = hdr.write_to_buf(&payload, &mut buf).unwrap();
        assert_eq!(written, ImageChunkHeader::SIZE + 4);

        let (parsed_hdr, parsed_payload) = ImageChunkHeader::parse_from(&buf[..written]).unwrap();
        assert_eq!(parsed_hdr.sequence_number, 1);
        assert_eq!(parsed_hdr.offset, 0);
        assert_eq!(parsed_hdr.chunk_size, 4);
        assert_eq!(parsed_payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn image_chunk_write_buf_too_small() {
        let payload = [0u8; 16];
        let hdr = ImageChunkHeader::new(0, 0, payload.len() as u32);

        let mut buf = [0u8; 4]; // way too small
        assert!(hdr.write_to_buf(&payload, &mut buf).is_none());
    }

    #[test]
    fn image_chunk_parse_buf_too_small_for_header() {
        let buf = [0u8; 4];
        assert!(ImageChunkHeader::parse_from(&buf).is_none());
    }

    #[test]
    fn image_chunk_parse_buf_too_small_for_payload() {
        let hdr = ImageChunkHeader::new(0, 0, 100);
        let mut buf = [0u8; ImageChunkHeader::SIZE];
        buf[..ImageChunkHeader::SIZE].copy_from_slice(hdr.as_bytes());
        // Header says chunk_size=100 but only 0 bytes follow
        assert!(ImageChunkHeader::parse_from(&buf).is_none());
    }

    // -----------------------------------------------------------------------
    // ImageChunk DST tests
    // -----------------------------------------------------------------------

    #[test]
    fn image_chunk_dst_parse() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let hdr = ImageChunkHeader::new(3, 256, payload.len() as u32);

        let mut buf = [0u8; 64];
        hdr.write_to_buf(&payload, &mut buf).unwrap();

        let chunk = ImageChunk::parse_from(&buf).unwrap();
        assert_eq!(chunk.header.message_type, MessageType::ImageChunk.as_u8());
        assert_eq!(chunk.header.status, Status::Success.as_u8());
        assert_eq!(chunk.header.sequence_number, 3);
        assert_eq!(chunk.header.offset, 256);
        assert_eq!(chunk.header.chunk_size, 4);
        assert_eq!(chunk.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn image_chunk_dst_zero_payload() {
        let hdr = ImageChunkHeader::new(0, 0, 0);
        let buf = hdr.as_bytes();

        let chunk = ImageChunk::parse_from(buf).unwrap();
        assert_eq!(chunk.header.chunk_size, 0);
        assert!(chunk.payload().is_empty());
    }

    #[test]
    fn image_chunk_dst_borrows_from_buffer() {
        // Verify the DST borrows directly — no copy
        let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let hdr = ImageChunkHeader::new(0, 0, payload.len() as u32);
        let mut buf = [0u8; 64];
        hdr.write_to_buf(&payload, &mut buf).unwrap();

        let chunk = ImageChunk::parse_from(&buf).unwrap();
        // The payload data should match what's in the buffer
        assert_eq!(chunk.payload(), &payload);
        // And it should point into the same buffer
        let payload_ptr = chunk.payload().as_ptr();
        let buf_data_ptr = buf[ImageChunkHeader::SIZE..].as_ptr();
        assert_eq!(payload_ptr, buf_data_ptr);
    }

    #[test]
    fn image_chunk_dst_buf_too_small_for_header() {
        let buf = [0u8; 4];
        assert!(ImageChunk::parse_from(&buf).is_none());
    }

    #[test]
    fn image_chunk_dst_buf_too_small_for_payload() {
        let hdr = ImageChunkHeader::new(0, 0, 100);
        let buf = hdr.as_bytes();
        // Only header bytes, no payload
        assert!(ImageChunk::parse_from(buf).is_none());
    }

    #[test]
    fn image_chunk_dst_is_last_chunk() {
        let max_chunk_size = 512;
        let payload = [0u8; 256];
        let hdr = ImageChunkHeader::new(0, 0, payload.len() as u32);
        let mut buf = [0u8; 512];
        hdr.write_to_buf(&payload, &mut buf).unwrap();

        let chunk = ImageChunk::parse_from(&buf).unwrap();
        assert!(chunk.is_last_chunk(max_chunk_size));

        // Full-sized chunk is NOT the last
        let full_payload = [0u8; 512];
        let hdr = ImageChunkHeader::new(0, 0, full_payload.len() as u32);
        let mut buf = [0u8; 1024];
        hdr.write_to_buf(&full_payload, &mut buf).unwrap();

        let chunk = ImageChunk::parse_from(&buf).unwrap();
        assert!(!chunk.is_last_chunk(max_chunk_size));
    }

    // -----------------------------------------------------------------------
    // Parsing helpers
    // -----------------------------------------------------------------------

    #[test]
    fn peek_message_type_works() {
        let pkt = InitiateBootRequest::new(1, BootFlags(0));
        let bytes = pkt.as_bytes();
        assert_eq!(peek_message_type(bytes), Some(0x01));
    }

    #[test]
    fn peek_message_type_empty() {
        assert_eq!(peek_message_type(&[]), None);
    }

    #[test]
    fn parse_fixed_works() {
        let pkt = ImageMetadataRequest::new(FIRMWARE_ID_CALIPTRA_FMC_RT);
        let bytes = pkt.as_bytes();

        let parsed: &ImageMetadataRequest = parse_fixed(bytes).unwrap();
        assert_eq!(
            parsed.message_type,
            MessageType::ImageMetadataRequest.as_u8()
        );
        assert_eq!(parsed.firmware_id, FIRMWARE_ID_CALIPTRA_FMC_RT);
    }

    #[test]
    fn parse_fixed_too_short() {
        let buf = [0u8; 2];
        assert!(parse_fixed::<ImageMetadataRequest>(&buf).is_none());
    }

    // -----------------------------------------------------------------------
    // Zerocopy round-trip: serialize then deserialize from bytes
    // -----------------------------------------------------------------------

    #[test]
    fn zerocopy_round_trip_all_packets() {
        // InitiateBootRequest
        let orig = InitiateBootRequest::new(42, BootFlags(0b11));
        let parsed = InitiateBootRequest::ref_from_bytes(orig.as_bytes()).unwrap();
        assert_eq!(parsed.protocol_version, 42);
        assert!(parsed.flags.flash_writeback());
        assert!(parsed.flags.flash_commit_policy());

        // InitiateBootResponse
        let orig = InitiateBootResponse::new(Status::InProgress);
        let parsed = InitiateBootResponse::ref_from_bytes(orig.as_bytes()).unwrap();
        assert_eq!(parsed.status, Status::InProgress.as_u8());

        // ImageMetadataResponse
        let orig = ImageMetadataResponse::new(8192, [0xFF; 32], 7, 0);
        let parsed = ImageMetadataResponse::ref_from_bytes(orig.as_bytes()).unwrap();
        assert_eq!(parsed.image_size, 8192);
        assert_eq!(parsed.checksum, [0xFF; 32]);
        assert_eq!(parsed.version, 7);

        // FinalizeRequest
        let orig = FinalizeRequest::error(ErrorCode::CorruptedData, 0xBEEF);
        let parsed = FinalizeRequest::ref_from_bytes(orig.as_bytes()).unwrap();
        assert_eq!(parsed.status, ErrorCode::CorruptedData.as_u8());
        assert_eq!(parsed.error_code, 0xBEEF);

        // FinalizeAck
        let orig = FinalizeAck::new(Status::Success, CleanupFlags(0b01));
        let parsed = FinalizeAck::ref_from_bytes(orig.as_bytes()).unwrap();
        assert!(parsed.cleanup_flags.clear_toc());
        assert!(!parsed.cleanup_flags.reset_connection());
    }
}
