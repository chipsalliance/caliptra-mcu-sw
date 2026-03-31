// Licensed under the Apache-2.0 license

//! Network-based image provider for i3c recovery.
//!
//! Downloads firmware images from the Network Coprocessor via the
//! boot-source protocol over the network mailbox.

use core::cell::Cell;

use caliptra_mcu_boot_source_protocol::messages::{
    BootFlags, ChunkAck, ChunkAckFlags, FinalizeRequest, ImageChunkHeader, ImageDownloadRequest,
    ImageMetadataRequest, ImageMetadataResponse, InitiateBootRequest, InitiateBootResponse, Status,
    FIRMWARE_ID_CALIPTRA_FMC_RT, FIRMWARE_ID_MCU_RT, FIRMWARE_ID_SOC_MANIFEST,
};
use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMailboxClient, NetworkMboxError, NetworkMboxStatus,
    NetworkMboxTargetStatus, Result,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::recovery::ImageProvider;

/// MCU clock frequency in Hz (400 MHz).
const CLOCK_FREQ_HZ: u64 = 400_000_000;

/// Timeout in seconds for any single network operation.
const NETWORK_OP_TIMEOUT_SECS: u64 = 30;

/// Timeout in cycles for any single network operation.
const NETWORK_OP_TIMEOUT_CYCLES: u64 = CLOCK_FREQ_HZ * NETWORK_OP_TIMEOUT_SECS;

/// Maximum response size in dwords. Must fit ImageChunkHeader (12) + max payload (1024).
const MAX_RESP_DW: usize = 276;

/// Internal state for tracking the current protocol phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    WaitInitiateBootResponse,
    WaitMetadataResponse,
    WaitImageChunk,
    Done,
    Error,
}

/// Network-based image provider that downloads firmware via the
/// boot-source protocol over the network mailbox.
pub struct NetworkImageProvider<'a, M: NetworkMailbox<'a>> {
    mbox: &'a M,
    phase: Cell<Phase>,
    /// Image size returned by ImageMetadataResponse.
    image_size: Cell<u32>,
    /// Bytes downloaded so far across all chunks.
    bytes_received: Cell<u32>,
    /// Sequence number of the last received chunk.
    last_seq: Cell<u16>,
    /// Whether InitiateBoot has already been performed.
    initiated: Cell<bool>,
    /// Whether the first ImageDownloadRequest has been sent for the current image.
    download_started: Cell<bool>,
    /// Firmware ID of the current download.
    firmware_id: Cell<u8>,
    /// Buffer for the latest received chunk payload.
    chunk_buf: core::cell::UnsafeCell<[u8; 1024]>,
    /// Number of valid bytes in chunk_buf.
    chunk_len: Cell<usize>,
    /// Offset into chunk_buf that has been consumed by `next_bytes`.
    chunk_consumed: Cell<usize>,
    /// Set to true if an error occurs during a callback.
    had_error: Cell<bool>,
}

impl<'a, M: NetworkMailbox<'a>> NetworkImageProvider<'a, M> {
    pub fn new(mbox: &'a M) -> Self {
        Self {
            mbox,
            phase: Cell::new(Phase::Idle),
            image_size: Cell::new(0),
            bytes_received: Cell::new(0),
            last_seq: Cell::new(0),
            initiated: Cell::new(false),
            download_started: Cell::new(false),
            firmware_id: Cell::new(0),
            chunk_buf: core::cell::UnsafeCell::new([0u8; 1024]),
            chunk_len: Cell::new(0),
            chunk_consumed: Cell::new(0),
            had_error: Cell::new(false),
        }
    }

    /// Send a boot-source protocol packet via the network mailbox.
    fn send_packet<T: IntoBytes + zerocopy::Immutable>(&self, pkt: &T) -> Result<()> {
        let bytes = pkt.as_bytes();
        let dlen = bytes.len();
        let iter = bytes.chunks(4).map(|chunk| {
            let mut dw = [0u8; 4];
            unsafe {
                core::ptr::copy_nonoverlapping(chunk.as_ptr(), dw.as_mut_ptr(), chunk.len());
            }
            u32::from_le_bytes(dw)
        });
        self.mbox.send_request(0, 0, iter, dlen)
    }

    /// Send a packet, retrying on `Locked` while polling the driver.
    fn send_with_retry<T: IntoBytes + zerocopy::Immutable>(&self, pkt: &T) -> Result<()> {
        let start = caliptra_mcu_romtime::mcycle();
        loop {
            match self.send_packet(pkt) {
                Ok(()) => return Ok(()),
                Err(NetworkMboxError::Locked) => {
                    self.mbox.poll();
                    if caliptra_mcu_romtime::mcycle().wrapping_sub(start)
                        >= NETWORK_OP_TIMEOUT_CYCLES
                    {
                        return Err(NetworkMboxError::Timeout);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Poll the driver until the phase transitions away from `wait_phase`.
    fn poll_until_phase_change(&self, wait_phase: Phase) -> Result<()> {
        let start = caliptra_mcu_romtime::mcycle();
        loop {
            self.mbox.poll();
            let p = self.phase.get();
            if p != wait_phase {
                if p == Phase::Error {
                    return Err(NetworkMboxError::Failed);
                }
                return Ok(());
            }
            if caliptra_mcu_romtime::mcycle().wrapping_sub(start) >= NETWORK_OP_TIMEOUT_CYCLES {
                return Err(NetworkMboxError::Timeout);
            }
        }
    }

    /// Perform the InitiateBoot handshake (only once per boot session).
    pub fn ensure_initiated(&self) -> Result<()> {
        if self.initiated.get() {
            return Ok(());
        }
        let pkt = InitiateBootRequest::new(1, BootFlags(0));
        self.phase.set(Phase::WaitInitiateBootResponse);
        match self.send_with_retry(&pkt) {
            Ok(()) => {}
            Err(e) => {
                return Err(e);
            }
        }
        match self.poll_until_phase_change(Phase::WaitInitiateBootResponse) {
            Ok(()) => {}
            Err(e) => {
                return Err(e);
            }
        }
        self.initiated.set(true);
        Ok(())
    }

    /// Request metadata for the given firmware ID and return the image size.
    fn request_metadata(&self, firmware_id: u8) -> Result<u32> {
        let pkt = ImageMetadataRequest::new(firmware_id);
        self.phase.set(Phase::WaitMetadataResponse);
        self.send_with_retry(&pkt)?;
        self.poll_until_phase_change(Phase::WaitMetadataResponse)?;
        Ok(self.image_size.get())
    }

    /// Start the image download for the current firmware_id.
    fn start_download(&self) -> Result<()> {
        let pkt = ImageDownloadRequest::new(self.firmware_id.get());
        self.phase.set(Phase::WaitImageChunk);
        self.send_with_retry(&pkt)?;
        self.poll_until_phase_change(Phase::WaitImageChunk)?;
        self.download_started.set(true);
        Ok(())
    }

    /// Send a ChunkAck and wait for the next chunk.
    fn request_next_chunk(&self) -> Result<()> {
        let mut flags = ChunkAckFlags(0);
        flags.set_ready_for_next(true);
        let pkt = ChunkAck::new(self.firmware_id.get(), self.last_seq.get(), flags);
        self.phase.set(Phase::WaitImageChunk);
        self.send_with_retry(&pkt)?;
        self.poll_until_phase_change(Phase::WaitImageChunk)?;
        Ok(())
    }

    /// Ensure there is unconsumed chunk data available. If the local buffer
    /// is exhausted and more image bytes remain, fetch the next chunk.
    fn ensure_chunk_data(&self) -> Result<()> {
        if self.chunk_consumed.get() < self.chunk_len.get() {
            return Ok(());
        }
        if self.bytes_received.get() >= self.image_size.get() {
            return Ok(());
        }
        if !self.download_started.get() {
            self.start_download()?;
        } else {
            self.request_next_chunk()?;
        }
        Ok(())
    }

    /// Send FinalizeRequest to clean up the network session.
    pub fn finalize(&self) -> Result<()> {
        let pkt = FinalizeRequest::success();
        self.send_with_retry(&pkt)?;
        // We don't strictly need to wait for the ack in the provider.
        Ok(())
    }

    /// Get a mutable reference to the chunk buffer.
    ///
    /// # Safety
    /// Safe in bare-metal single-threaded context.
    fn chunk_buf_mut(&self) -> &mut [u8; 1024] {
        unsafe { &mut *self.chunk_buf.get() }
    }

    fn chunk_buf_ref(&self) -> &[u8; 1024] {
        unsafe { &*self.chunk_buf.get() }
    }
}

impl<'a, M: NetworkMailbox<'a>> NetworkMailboxClient for NetworkImageProvider<'a, M> {
    fn request_received(
        &self,
        _command: u32,
        _user: u32,
        rx_buf: &'static mut [u32],
        _dlen: usize,
    ) -> Result<()> {
        self.mbox.restore_rx_buffer(rx_buf);
        Ok(())
    }

    fn response_received(
        &self,
        status: NetworkMboxTargetStatus,
        rx_buf: &'static mut [u32],
        dlen: usize,
    ) {
        let copy_len = dlen.min(MAX_RESP_DW * 4);
        let dw_len = copy_len.div_ceil(4);
        let mut local_dw = [0u32; MAX_RESP_DW];
        for i in 0..dw_len {
            unsafe {
                local_dw
                    .as_mut_ptr()
                    .add(i)
                    .write(rx_buf.as_ptr().add(i).read_volatile());
            }
        }
        let bytes =
            unsafe { core::slice::from_raw_parts(local_dw.as_ptr().cast::<u8>(), copy_len) };

        if status.status != NetworkMboxStatus::CmdComplete {
            self.had_error.set(true);
            self.phase.set(Phase::Error);
            self.mbox.restore_rx_buffer(rx_buf);
            return;
        }

        match self.phase.get() {
            Phase::WaitInitiateBootResponse => {
                if let Ok((resp, _)) = InitiateBootResponse::ref_from_prefix(bytes) {
                    if resp.status == Status::Success.as_u8() {
                        self.phase.set(Phase::Idle);
                    } else {
                        self.phase.set(Phase::Error);
                    }
                } else {
                    self.phase.set(Phase::Error);
                }
            }
            Phase::WaitMetadataResponse => {
                if let Ok((resp, _)) = ImageMetadataResponse::ref_from_prefix(bytes) {
                    if resp.status == Status::Success.as_u8() {
                        self.image_size.set(resp.image_size);
                        self.phase.set(Phase::Idle);
                    } else {
                        self.phase.set(Phase::Error);
                    }
                } else {
                    self.phase.set(Phase::Error);
                }
            }
            Phase::WaitImageChunk => {
                if let Ok((hdr, _)) = ImageChunkHeader::ref_from_prefix(bytes) {
                    if hdr.status != Status::Success.as_u8() {
                        self.phase.set(Phase::Error);
                        self.mbox.restore_rx_buffer(rx_buf);
                        return;
                    }
                    let chunk_size = hdr.chunk_size as usize;
                    let payload_start = ImageChunkHeader::SIZE;
                    let payload_end = payload_start + chunk_size;

                    if chunk_size > 0
                        && chunk_size <= self.chunk_buf_ref().len()
                        && payload_end <= copy_len
                    {
                        let buf = self.chunk_buf_mut();
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                bytes.as_ptr().add(payload_start),
                                buf.as_mut_ptr(),
                                chunk_size,
                            );
                        }
                    }
                    self.chunk_len.set(chunk_size);
                    self.chunk_consumed.set(0);
                    self.last_seq.set(hdr.sequence_number);
                    self.bytes_received
                        .set(self.bytes_received.get() + chunk_size as u32);
                    self.phase.set(Phase::Done);
                } else {
                    self.phase.set(Phase::Error);
                }
            }
            _ => {
                self.phase.set(Phase::Error);
            }
        }

        self.mbox.restore_rx_buffer(rx_buf);
    }

    fn send_done(&self, _result: Result<()>) {}
}

/// Convert a recovery image index to a boot-source protocol firmware ID.
fn recovery_img_index_to_firmware_id(recovery_image_index: u32) -> core::result::Result<u8, ()> {
    match recovery_image_index {
        0 => Ok(FIRMWARE_ID_CALIPTRA_FMC_RT),
        1 => Ok(FIRMWARE_ID_SOC_MANIFEST),
        2 => Ok(FIRMWARE_ID_MCU_RT),
        _ => Err(()),
    }
}

impl<'a, M: NetworkMailbox<'a>> ImageProvider for NetworkImageProvider<'a, M> {
    fn image_ready(&mut self, image_index: u32) -> core::result::Result<usize, ()> {
        let firmware_id = recovery_img_index_to_firmware_id(image_index)?;
        self.firmware_id.set(firmware_id);
        self.bytes_received.set(0);
        self.last_seq.set(0);
        self.download_started.set(false);
        self.chunk_len.set(0);
        self.chunk_consumed.set(0);
        self.had_error.set(false);

        self.ensure_initiated().map_err(|_| ())?;
        let size = self.request_metadata(firmware_id).map_err(|_| ())?;
        Ok(size as usize)
    }

    fn next_bytes(&mut self, data: &mut [u8]) -> core::result::Result<(), ()> {
        let mut written = 0;
        while written < data.len() {
            self.ensure_chunk_data().map_err(|_| ())?;

            let consumed = self.chunk_consumed.get();
            let chunk_len = self.chunk_len.get();
            if consumed > chunk_len || chunk_len > self.chunk_buf_ref().len() {
                return Err(());
            }
            let available = chunk_len - consumed;
            if available == 0 {
                if self.bytes_received.get() >= self.image_size.get() {
                    // All network data received and chunk buffer is empty.
                    break;
                }
                // Zero-length chunk (e.g. initial ack from ImageDownloadRequest).
                // Retry ensure_chunk_data which will request the next real chunk.
                continue;
            }

            let to_copy = available.min(data.len() - written);
            let buf = self.chunk_buf_ref();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(consumed),
                    data.as_mut_ptr().add(written),
                    to_copy,
                );
            }
            self.chunk_consumed.set(consumed + to_copy);
            written += to_copy;
        }
        Ok(())
    }

    fn bytes_loaded(&self) -> usize {
        self.bytes_received.get() as usize
    }
}

/// Thin wrapper that holds a shared reference to a [`NetworkImageProvider`]
/// and implements [`ImageProvider`] via delegation. This allows the provider
/// to be simultaneously registered as a `NetworkMailboxClient` (which holds
/// `&self`) and used as an `ImageProvider` (which requires `&mut self`).
pub struct NetworkImageProviderRef<'a, 'b, M: NetworkMailbox<'a>>(
    pub &'b NetworkImageProvider<'a, M>,
);

impl<'a, M: NetworkMailbox<'a>> ImageProvider for NetworkImageProviderRef<'a, '_, M> {
    fn image_ready(&mut self, image_index: u32) -> core::result::Result<usize, ()> {
        let firmware_id = recovery_img_index_to_firmware_id(image_index)?;
        self.0.firmware_id.set(firmware_id);
        self.0.bytes_received.set(0);
        self.0.last_seq.set(0);
        self.0.download_started.set(false);
        self.0.chunk_len.set(0);
        self.0.chunk_consumed.set(0);
        self.0.had_error.set(false);

        self.0.ensure_initiated().map_err(|_| ())?;
        let size = self.0.request_metadata(firmware_id).map_err(|_| ())?;
        Ok(size as usize)
    }

    fn next_bytes(&mut self, data: &mut [u8]) -> core::result::Result<(), ()> {
        let mut written = 0;
        while written < data.len() {
            self.0.ensure_chunk_data().map_err(|_| ())?;

            let consumed = self.0.chunk_consumed.get();
            let chunk_len = self.0.chunk_len.get();
            if consumed > chunk_len || chunk_len > self.0.chunk_buf_ref().len() {
                return Err(());
            }
            let available = chunk_len - consumed;
            if available == 0 {
                if self.0.bytes_received.get() >= self.0.image_size.get() {
                    // All network data received and chunk buffer is empty.
                    break;
                }
                // Zero-length chunk (e.g. initial ack from ImageDownloadRequest).
                // Retry ensure_chunk_data which will request the next real chunk.
                continue;
            }

            let to_copy = available.min(data.len() - written);
            let buf = self.0.chunk_buf_ref();
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(consumed),
                    data.as_mut_ptr().add(written),
                    to_copy,
                );
            }
            self.0.chunk_consumed.set(consumed + to_copy);
            written += to_copy;
        }
        Ok(())
    }

    fn bytes_loaded(&self) -> usize {
        self.0.bytes_received.get() as usize
    }
}
