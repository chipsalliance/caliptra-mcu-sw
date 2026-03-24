// Licensed under the Apache-2.0 license

//! Protocol message handlers.
//!
//! Each handler parses the incoming request, performs the required action
//! (including DHCP and TFTP network operations via lwIP),
//! and writes a response via the mailbox.

use caliptra_mcu_boot_source_protocol::messages::*;
use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMboxError, NetworkMboxStatus, Result,
};
use lwip_rs::ip::Ipv6Addr;
use zerocopy::{Immutable, IntoBytes};

use crate::network;
use crate::toc::Toc;

/// Timeout in milliseconds for the blocking DHCP path.
const DHCP_TIMEOUT_MS: u64 = 30_000;

/// Timeout in milliseconds for a single blocking TFTP transfer.
const TFTP_TIMEOUT_MS: u64 = 30_000;

/// Timeout in milliseconds for polling TFTP data after a ChunkAck.
const CHUNK_ACK_POLL_TIMEOUT_MS: u64 = 10_000;

/// Default fallback TFTP server IPv6 address (used when DHCPv4 is unavailable).
///
/// This should be overridden in the final product. For now it is a
/// link-local placeholder.
const V6_FALLBACK_SERVER: Ipv6Addr = Ipv6Addr::from_raw([0, 0, 0, 0]);

/// Default fallback boot file name for IPv6 (null-terminated).
const V6_FALLBACK_BOOT_FILE: &[u8] = b"boot.cfg\0";

// ---------------------------------------------------------------------------
// Mailbox response helpers
// ---------------------------------------------------------------------------

pub fn send_packet_response<'a, T, M>(mbox: &M, packet: &T) -> Result<()>
where
    T: IntoBytes + Immutable + ?Sized,
    M: NetworkMailbox<'a>,
{
    let bytes = packet.as_bytes();
    let dlen = bytes.len();
    let dw_iter = bytes.chunks(4).map(|chunk| {
        let mut dw = [0u8; 4];
        dw[..chunk.len()].copy_from_slice(chunk);
        u32::from_le_bytes(dw)
    });
    mbox.send_response(dw_iter, dlen)?;
    mbox.set_target_status(NetworkMboxStatus::CmdComplete)
}

pub fn send_error<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    msg_type: MessageType,
    error: ErrorCode,
) -> Result<()> {
    match msg_type {
        MessageType::InitiateBootResponse => {
            let mut bytes = [0u8; InitiateBootResponse::SIZE];
            bytes[0] = MessageType::InitiateBootResponse.as_u8();
            bytes[1] = error.as_u8();
            send_packet_response(mbox, &bytes)
        }
        MessageType::ImageMetadataResponse => {
            let pkt = ImageMetadataResponse::error(error);
            send_packet_response(mbox, &pkt)
        }
        MessageType::ImageChunk => {
            let pkt = ImageChunkHeader::error(error);
            send_packet_response(mbox, &pkt)
        }
        MessageType::FinalizeAck => {
            let mut bytes = [0u8; FinalizeAck::SIZE];
            bytes[0] = MessageType::FinalizeAck.as_u8();
            bytes[1] = error.as_u8();
            send_packet_response(mbox, &bytes)
        }
        _ => Err(NetworkMboxError::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Parse the InitiateBootRequest, save boot flags, and start DHCP.
///
/// The actual DHCP polling and TFTP TOC download happen incrementally in
/// the main loop. This avoids blocking inside a mailbox callback where
/// the emulator cannot process ethernet RX.
pub fn handle_initiate_boot_start(
    data: &[u8],
    boot_flags: &core::cell::Cell<BootFlags>,
) -> Result<()> {
    let req: &InitiateBootRequest = match parse_fixed(data) {
        Some(r) => r,
        None => return Err(NetworkMboxError::InvalidArgument),
    };

    boot_flags.set(req.flags);
    network::start_dhcp().map_err(|_| NetworkMboxError::Failed)?;
    Ok(())
}

/// Performs DHCP, TFTP TOC fetch, and sends `InitiateBootResponse`.
///
/// **NOTE**: This function blocks inside the caller's context (e.g. a
/// mailbox callback) and cannot receive ethernet RX packets on emulated
/// platforms. Prefer the async variant: [`handle_initiate_boot_start`]
/// paired with `poll_dhcp` / `poll_tftp_toc` in the main loop.
pub fn handle_initiate_boot<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    data: &[u8],
    boot_flags: &core::cell::Cell<BootFlags>,
    toc: &mut Toc,
    dhcp_result: &mut Option<network::DhcpResult>,
) -> Result<()> {
    let req: &InitiateBootRequest = match parse_fixed(data) {
        Some(r) => r,
        None => {
            return send_error(
                mbox,
                MessageType::InitiateBootResponse,
                ErrorCode::InvalidParameters,
            )
        }
    };

    boot_flags.set(req.flags);

    // Run DHCP to obtain network configuration.
    let result = network::run_dhcp(DHCP_TIMEOUT_MS, V6_FALLBACK_SERVER, V6_FALLBACK_BOOT_FILE)
        .map_err(|_| {
            let _ = send_error(
                mbox,
                MessageType::InitiateBootResponse,
                ErrorCode::SourceNotReady,
            );
            NetworkMboxError::Failed
        })?;

    // Initialize TFTP client for later image downloads.
    network::init_tftp().map_err(|_| {
        let _ = send_error(
            mbox,
            MessageType::InitiateBootResponse,
            ErrorCode::SourceNotReady,
        );
        NetworkMboxError::Failed
    })?;

    // Fetch the TOC config file via TFTP.
    let mut fname_buf = [0u8; 128];
    let len = result.boot_file_len.min(127);
    fname_buf[..len].copy_from_slice(&result.boot_file[..len]);
    fname_buf[len] = 0;

    network::start_tftp_get(&result.server_ip, &fname_buf[..len + 1]).map_err(|_| {
        let _ = send_error(
            mbox,
            MessageType::InitiateBootResponse,
            ErrorCode::SourceNotReady,
        );
        NetworkMboxError::Failed
    })?;

    // Poll until the TOC download completes.
    let start = network::now_ms();
    loop {
        network::poll();
        if network::tftp_is_complete() {
            break;
        }
        if network::now_ms().wrapping_sub(start) >= TFTP_TIMEOUT_MS {
            break;
        }
    }

    if network::tftp_has_error() || !network::tftp_is_complete() {
        let _ = send_error(
            mbox,
            MessageType::InitiateBootResponse,
            ErrorCode::SourceNotReady,
        );
        return Err(NetworkMboxError::Failed);
    }

    // Read the TOC data and parse it.
    let mut toc_buf = [0u8; network::TFTP_CHUNK_BUF_SIZE];
    let toc_len = network::take_tftp_chunk(&mut toc_buf);
    if !toc.parse(&toc_buf[..toc_len]) {
        let _ = send_error(
            mbox,
            MessageType::InitiateBootResponse,
            ErrorCode::CorruptedData,
        );
        return Err(NetworkMboxError::Failed);
    }

    *dhcp_result = Some(result);

    let resp = InitiateBootResponse::new(Status::Success);
    send_packet_response(mbox, &resp)
}

pub fn handle_image_metadata<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    data: &[u8],
    toc: &Toc,
) -> Result<()> {
    let req: &ImageMetadataRequest = match parse_fixed(data) {
        Some(r) => r,
        None => {
            return send_error(
                mbox,
                MessageType::ImageMetadataResponse,
                ErrorCode::InvalidParameters,
            )
        }
    };

    match toc.find(req.firmware_id) {
        Some(entry) => {
            let mut checksum = [0u8; 32];
            checksum[..4].copy_from_slice(&entry.image_checksum.to_le_bytes());
            let resp = ImageMetadataResponse::new(entry.image_size, checksum, 0, 0);
            send_packet_response(mbox, &resp)
        }
        None => send_error(
            mbox,
            MessageType::ImageMetadataResponse,
            ErrorCode::ImageNotFound,
        ),
    }
}

/// Starts a TFTP GET for the requested firmware and sends the first chunk.
pub fn handle_image_download<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    data: &[u8],
    toc: &Toc,
    seq: &core::cell::Cell<u16>,
    offset: &core::cell::Cell<u32>,
) -> core::result::Result<u8, NetworkMboxError> {
    let req: &ImageDownloadRequest = match parse_fixed(data) {
        Some(r) => r,
        None => {
            let _ = send_error(mbox, MessageType::ImageChunk, ErrorCode::InvalidParameters);
            return Err(NetworkMboxError::InvalidArgument);
        }
    };

    if toc.find(req.firmware_id).is_none() {
        let _ = send_error(mbox, MessageType::ImageChunk, ErrorCode::ImageNotFound);
        return Err(NetworkMboxError::InvalidArgument);
    }

    seq.set(0);
    offset.set(0);

    // Send an initial zero-payload header to acknowledge the download started.
    // TFTP GET is deferred to poll_chunk_data to avoid filling the buffer
    // before the MCU can drain it.
    let hdr = ImageChunkHeader::new(0, 0, 0);
    send_packet_response(mbox, &hdr)?;
    Ok(req.firmware_id)
}

/// Polls for TFTP data and sends the next chunk. Returns `true` if last chunk.
pub fn handle_chunk_ack<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    data: &[u8],
    max_chunk_size: usize,
    seq: &core::cell::Cell<u16>,
    offset: &core::cell::Cell<u32>,
) -> core::result::Result<bool, NetworkMboxError> {
    let _ack: &ChunkAck = match parse_fixed(data) {
        Some(a) => a,
        None => {
            let _ = send_error(mbox, MessageType::ImageChunk, ErrorCode::InvalidParameters);
            return Err(NetworkMboxError::InvalidArgument);
        }
    };

    // Poll network to receive more TFTP data.
    let start = network::now_ms();
    loop {
        network::poll();
        if network::tftp_buffered_len() > 0 || network::tftp_is_complete() {
            break;
        }
        if network::now_ms().wrapping_sub(start) >= CHUNK_ACK_POLL_TIMEOUT_MS {
            break;
        }
    }

    if network::tftp_has_error() {
        let _ = send_error(mbox, MessageType::ImageChunk, ErrorCode::CorruptedData);
        return Err(NetworkMboxError::Failed);
    }

    let s = seq.get();
    let o = offset.get();

    // Read available data from the TFTP buffer.
    let mut chunk_buf = [0u8; 4096];
    let chunk_max = max_chunk_size.min(chunk_buf.len());
    let chunk_len = network::take_tftp_chunk(&mut chunk_buf[..chunk_max]);

    let is_last = network::tftp_is_complete() && network::tftp_buffered_len() == 0;

    let hdr = ImageChunkHeader::new(s, o, chunk_len as u32);
    let hdr_bytes = hdr.as_bytes();
    let total_len = ImageChunkHeader::SIZE + chunk_len;

    let combined_iter = hdr_bytes
        .iter()
        .chain(chunk_buf[..chunk_len].iter())
        .copied();
    let dw_iter = DwordIterator::new(combined_iter, total_len);
    mbox.send_response(dw_iter, total_len)?;
    mbox.set_target_status(NetworkMboxStatus::CmdComplete)?;

    seq.set(s.wrapping_add(1));
    offset.set(o.wrapping_add(chunk_len as u32));

    if is_last {
        network::reset_tftp_state();
    }

    Ok(is_last)
}

/// Validate a ChunkAck without sending a response.
/// Returns `Ok(())` if the ack is valid.
pub fn validate_chunk_ack(data: &[u8]) -> Result<()> {
    let _ack: &ChunkAck = match parse_fixed(data) {
        Some(a) => a,
        None => return Err(NetworkMboxError::InvalidArgument),
    };
    Ok(())
}

/// Send the next TFTP chunk via the mailbox. Returns `true` if this was the last chunk.
pub fn send_next_chunk<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    max_chunk_size: usize,
    seq: &core::cell::Cell<u16>,
    offset: &core::cell::Cell<u32>,
) -> core::result::Result<bool, NetworkMboxError> {
    if network::tftp_has_error() {
        let _ = send_error(mbox, MessageType::ImageChunk, ErrorCode::CorruptedData);
        return Err(NetworkMboxError::Failed);
    }

    let s = seq.get();
    let o = offset.get();

    let mut chunk_buf = [0u8; 4096];
    let chunk_max = max_chunk_size.min(chunk_buf.len());
    let chunk_len = network::take_tftp_chunk(&mut chunk_buf[..chunk_max]);

    let is_last = network::tftp_is_complete() && network::tftp_buffered_len() == 0;

    let hdr = ImageChunkHeader::new(s, o, chunk_len as u32);
    let hdr_bytes = hdr.as_bytes();
    let total_len = ImageChunkHeader::SIZE + chunk_len;

    let combined_iter = hdr_bytes
        .iter()
        .chain(chunk_buf[..chunk_len].iter())
        .copied();
    let dw_iter = DwordIterator::new(combined_iter, total_len);
    mbox.send_response(dw_iter, total_len)?;
    mbox.set_target_status(NetworkMboxStatus::CmdComplete)?;

    seq.set(s.wrapping_add(1));
    offset.set(o.wrapping_add(chunk_len as u32));

    if is_last {
        network::reset_tftp_state();
    }

    Ok(is_last)
}

pub fn handle_finalize<'a, M: NetworkMailbox<'a>>(
    mbox: &M,
    data: &[u8],
    toc: &mut Toc,
) -> Result<()> {
    let _req: &FinalizeRequest = match parse_fixed(data) {
        Some(r) => r,
        None => return send_error(mbox, MessageType::FinalizeAck, ErrorCode::InvalidParameters),
    };

    toc.clear();

    network::cleanup_tftp();
    network::shutdown();

    let resp = FinalizeAck::new(Status::Success, CleanupFlags(0));
    send_packet_response(mbox, &resp)
}

// ---------------------------------------------------------------------------
// DwordIterator
// ---------------------------------------------------------------------------

/// Packs a byte stream into little-endian u32 dwords.
pub(crate) struct DwordIterator<I: Iterator<Item = u8>> {
    inner: I,
    remaining: usize,
}

impl<I: Iterator<Item = u8>> DwordIterator<I> {
    pub fn new(inner: I, total_bytes: usize) -> Self {
        Self {
            inner,
            remaining: total_bytes,
        }
    }
}

impl<I: Iterator<Item = u8>> Iterator for DwordIterator<I> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.remaining == 0 {
            return None;
        }
        let mut dw = [0u8; 4];
        for byte in dw.iter_mut() {
            if self.remaining == 0 {
                break;
            }
            if let Some(b) = self.inner.next() {
                *byte = b;
                self.remaining -= 1;
            } else {
                break;
            }
        }
        Some(u32::from_le_bytes(dw))
    }
}
