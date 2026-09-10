// Licensed under the Apache-2.0 license

//! Boot source provider application.
//!
//! Implements the boot source protocol over the network mailbox, handling
//! requests from the MCU ROM/Runtime. Uses lwIP for DHCP configuration
//! and TFTP image downloads.

use caliptra_mcu_boot_source_protocol::messages::*;
use caliptra_mcu_network_hil::ethernet::Ethernet;
use caliptra_mcu_network_hil::network_mbox::{
    NetworkMailbox, NetworkMailboxClient, NetworkMboxError, NetworkMboxTargetStatus, Result,
};
use caliptra_mcu_network_hil::timers::Timers;
use core::cell::{Cell, UnsafeCell};

use crate::handler;
use crate::network;
use crate::toc::Toc;

/// IP version to use for network boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// Use IPv4 (DHCPv4 + TFTP over IPv4).
    V4,
    /// Use IPv6 (Stateful DHCPv6 + TFTP over IPv6).
    #[cfg(feature = "ipv6-boot")]
    V6,
}

/// Minimum free space in the TFTP chunk buffer before accepting another RX packet.
const TFTP_RX_THRESHOLD: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Waiting for InitiateBootRequest.
    Idle,
    /// DHCP is in progress. Polling until an address is obtained.
    DhcpInProgress,
    /// DHCP done, TFTP TOC download in progress.
    TftpTocInProgress,
    /// DHCP and TOC fetch completed. Ready to serve image requests.
    Ready,
    /// TFTP GET for image started; waiting for first data or an ack to serve.
    Streaming,
    /// ChunkAck received; polling for TFTP data to send the next chunk.
    ChunkPending,
}

pub struct BootSourceApp<'a, M: NetworkMailbox<'a>> {
    mbox: &'a M,
    state: Cell<AppState>,
    toc: UnsafeCell<Toc>,
    boot_flags: Cell<BootFlags>,
    /// Active TFTP transfer state: firmware ID being downloaded.
    active_firmware_id: Cell<u8>,
    /// Sequence number for the current image transfer.
    sequence_number: Cell<u16>,
    /// Byte offset into the current image transfer.
    transfer_offset: Cell<u32>,
    /// Maximum payload bytes per chunk (based on mailbox SRAM size).
    max_chunk_size: usize,
    dhcp_result: UnsafeCell<Option<network::DhcpResult>>,
    /// Whether the TFTP GET for the current image has been started.
    tftp_started: Cell<bool>,
    /// IP version to use for network boot.
    ip_version: IpVersion,
}

impl<'a, M: NetworkMailbox<'a>> BootSourceApp<'a, M> {
    pub fn new(mbox: &'a M, max_chunk_size: usize, ip_version: IpVersion) -> Self {
        Self {
            mbox,
            state: Cell::new(AppState::Idle),
            toc: UnsafeCell::new(Toc::new()),
            boot_flags: Cell::new(BootFlags(0)),
            active_firmware_id: Cell::new(0),
            sequence_number: Cell::new(0),
            transfer_offset: Cell::new(0),
            max_chunk_size,
            dhcp_result: UnsafeCell::new(None),
            tftp_started: Cell::new(false),
            ip_version,
        }
    }

    /// Must be called once before [`run_loop`](Self::run_loop).
    pub fn init(
        &'a self,
        eth: &'static mut dyn Ethernet,
        timer: &'static dyn Timers,
    ) -> core::result::Result<(), network::NetworkError> {
        network::init_lwip(eth, timer)?;
        self.mbox.set_client(self);
        self.mbox.enable();
        Ok(())
    }

    /// Main polling loop. Runs forever, processing mailbox requests and
    /// network traffic.
    pub fn run_loop(&self) -> ! {
        loop {
            self.mbox.poll();

            // During TFTP streaming, limit RX to prevent buffer overflow.
            // Only receive when there's room for at least one TFTP block.
            let state = self.state.get();
            if state == AppState::ChunkPending || state == AppState::Streaming {
                let space =
                    network::TFTP_CHUNK_BUF_SIZE.saturating_sub(network::tftp_buffered_len());
                if space >= TFTP_RX_THRESHOLD {
                    network::poll_limited(1);
                } else {
                    // Buffer near-full: only process lwIP timers, skip RX.
                    network::poll_limited(0);
                }
            } else {
                network::poll();
            }

            match state {
                AppState::DhcpInProgress => {
                    self.poll_dhcp();
                }
                AppState::TftpTocInProgress => {
                    self.poll_tftp_toc();
                }
                AppState::ChunkPending => {
                    self.poll_chunk_data();
                }
                _ => {}
            }
        }
    }

    /// # Safety
    /// Safe in bare-metal single-threaded context where the mailbox
    /// driver serializes callbacks.
    #[allow(clippy::mut_from_ref)]
    fn toc_mut(&self) -> &mut Toc {
        unsafe { &mut *self.toc.get() }
    }

    fn toc_ref(&self) -> &Toc {
        unsafe { &*self.toc.get() }
    }

    fn dhcp_result_ref(&self) -> &Option<network::DhcpResult> {
        unsafe { &*self.dhcp_result.get() }
    }

    #[allow(clippy::mut_from_ref)]
    fn dhcp_result_mut(&self) -> &mut Option<network::DhcpResult> {
        unsafe { &mut *self.dhcp_result.get() }
    }

    /// Poll DHCP progress. Called each iteration of `run_loop` while in
    /// `DhcpInProgress`. When an address is obtained, starts the TFTP TOC
    /// download and transitions to `TftpTocInProgress`.
    fn poll_dhcp(&self) {
        let has_addr = match self.ip_version {
            IpVersion::V4 => network::dhcp_has_address(),
            #[cfg(feature = "ipv6-boot")]
            IpVersion::V6 => network::dhcp6_has_address(),
        };

        if has_addr {
            caliptra_mcu_network_drivers::println!("[boot-src] DHCP complete");
            let result = match self.ip_version {
                IpVersion::V4 => network::take_dhcp_result(),
                #[cfg(feature = "ipv6-boot")]
                IpVersion::V6 => network::take_dhcp6_result(),
            };
            let result = match result {
                Some(r) => r,
                None => {
                    let _ = handler::send_error(
                        self.mbox,
                        MessageType::InitiateBootResponse,
                        ErrorCode::SourceNotReady,
                    );
                    self.state.set(AppState::Idle);
                    return;
                }
            };

            // Initialize TFTP client.
            if network::init_tftp().is_err() {
                let _ = handler::send_error(
                    self.mbox,
                    MessageType::InitiateBootResponse,
                    ErrorCode::SourceNotReady,
                );
                self.state.set(AppState::Idle);
                return;
            }

            // Start TFTP GET for the TOC/boot file.
            let mut fname_buf = [0u8; 128];
            let len = result.boot_file_len.min(127);
            fname_buf[..len].copy_from_slice(&result.boot_file[..len]);
            fname_buf[len] = 0;

            if network::start_tftp_get(&result.server_ip, &fname_buf[..len + 1]).is_err() {
                let _ = handler::send_error(
                    self.mbox,
                    MessageType::InitiateBootResponse,
                    ErrorCode::SourceNotReady,
                );
                self.state.set(AppState::Idle);
                return;
            }

            *self.dhcp_result_mut() = Some(result);
            self.state.set(AppState::TftpTocInProgress);
        }
    }

    /// Poll TFTP TOC download progress. Called each iteration of `run_loop`
    /// while in `TftpTocInProgress`. When the download completes, parses
    /// the TOC and sends `InitiateBootResponse`.
    fn poll_tftp_toc(&self) {
        if network::tftp_has_error() {
            let _ = handler::send_error(
                self.mbox,
                MessageType::InitiateBootResponse,
                ErrorCode::SourceNotReady,
            );
            self.state.set(AppState::Idle);
            return;
        }

        if !network::tftp_is_complete() {
            return;
        }

        // Read and parse the TOC.
        let mut toc_buf = [0u8; network::TFTP_CHUNK_BUF_SIZE];
        let toc_len = network::take_tftp_chunk(&mut toc_buf);
        if !self.toc_mut().parse(&toc_buf[..toc_len]) {
            let _ = handler::send_error(
                self.mbox,
                MessageType::InitiateBootResponse,
                ErrorCode::CorruptedData,
            );
            self.state.set(AppState::Idle);
            return;
        }

        let resp = InitiateBootResponse::new(Status::Success);
        let _ = handler::send_packet_response(self.mbox, &resp);
        self.state.set(AppState::Ready);
    }

    /// Poll for TFTP image data after a ChunkAck. Called each iteration of
    /// `run_loop` while in `ChunkPending`. When data is available, sends the
    /// next chunk response and transitions back to `Streaming` (or `Ready`
    /// if it was the last chunk).
    fn poll_chunk_data(&self) {
        // Start the TFTP GET on the first poll after ImageDownloadRequest.
        // This is deferred from handle_image_download to avoid filling the
        // TFTP buffer while the MCU processes the zero-payload header.
        if !self.tftp_started.get() {
            let entry = match self.toc_ref().find(self.active_firmware_id.get()) {
                Some(e) => e,
                None => {
                    let _ = handler::send_error(
                        self.mbox,
                        MessageType::ImageChunk,
                        ErrorCode::ImageNotFound,
                    );
                    self.state.set(AppState::Ready);
                    return;
                }
            };
            let dhcp = self.dhcp_result_ref();
            let dhcp = match dhcp.as_ref() {
                Some(d) => d,
                None => {
                    let _ = handler::send_error(
                        self.mbox,
                        MessageType::ImageChunk,
                        ErrorCode::SourceNotReady,
                    );
                    self.state.set(AppState::Ready);
                    return;
                }
            };
            let fname = &entry.filename[..entry.filename_len + 1];
            if network::start_tftp_get(&dhcp.server_ip, fname).is_err() {
                let _ = handler::send_error(
                    self.mbox,
                    MessageType::ImageChunk,
                    ErrorCode::SourceNotReady,
                );
                self.state.set(AppState::Ready);
                return;
            }
            self.tftp_started.set(true);
            return; // Let the next poll iteration check for data.
        }

        // Check if TFTP data is available or complete.
        if network::tftp_buffered_len() == 0 && !network::tftp_is_complete() {
            return; // No data yet, keep polling.
        }

        match handler::send_next_chunk(
            self.mbox,
            self.max_chunk_size,
            &self.sequence_number,
            &self.transfer_offset,
        ) {
            Ok(true) => {
                // Last chunk sent — go back to Ready for more images.
                self.state.set(AppState::Ready);
            }
            Ok(false) => {
                // More data to send — wait for next ChunkAck.
                self.state.set(AppState::Streaming);
            }
            Err(_) => {
                // Error sending chunk — reset.
                self.state.set(AppState::Ready);
            }
        }
    }

    fn dispatch(&self, data: &[u8]) -> Result<()> {
        let msg_type_byte = match peek_message_type(data) {
            Some(b) => b,
            None => {
                return Err(NetworkMboxError::InvalidArgument);
            }
        };

        let msg_type = match MessageType::from_u8(msg_type_byte) {
            Some(mt) => mt,
            None => {
                return Err(NetworkMboxError::InvalidArgument);
            }
        };

        match (self.state.get(), msg_type) {
            (AppState::Idle, MessageType::InitiateBootRequest) => {
                handler::handle_initiate_boot_start(data, &self.boot_flags, self.ip_version)?;
                self.state.set(AppState::DhcpInProgress);
                Ok(())
            }
            (AppState::Ready, MessageType::ImageMetadataRequest) => {
                handler::handle_image_metadata(self.mbox, data, self.toc_ref())
            }
            (AppState::Ready, MessageType::ImageDownloadRequest) => {
                let fw_id = handler::handle_image_download(
                    self.mbox,
                    data,
                    self.toc_ref(),
                    &self.sequence_number,
                    &self.transfer_offset,
                )?;
                self.active_firmware_id.set(fw_id);
                self.tftp_started.set(false);
                self.state.set(AppState::Streaming);
                Ok(())
            }
            (AppState::Streaming, MessageType::ChunkAck) => {
                // Validate the ack but don't send a response yet.
                // The actual TFTP data polling and chunk response happen
                // incrementally in run_loop (poll_chunk_data) so that the
                // emulator can process ethernet RX between iterations.
                handler::validate_chunk_ack(data)?;
                self.state.set(AppState::ChunkPending);
                Ok(())
            }
            (_, MessageType::Finalize) => {
                handler::handle_finalize(self.mbox, data, self.toc_mut())?;
                self.state.set(AppState::Idle);
                self.active_firmware_id.set(0);
                self.sequence_number.set(0);
                self.transfer_offset.set(0);
                Ok(())
            }
            _ => Err(NetworkMboxError::InvalidArgument),
        }
    }
}

impl<'a, M: NetworkMailbox<'a>> NetworkMailboxClient for BootSourceApp<'a, M> {
    fn request_received(
        &self,
        _command: u32,
        _user: u32,
        rx_buf: &'static mut [u32],
        dlen: usize,
    ) -> Result<()> {
        // Copy SRAM dwords to a local byte buffer. The mailbox SRAM
        // bus may only support word-aligned 32-bit reads, so we must
        // not reinterpret the SRAM pointer as a byte slice directly.
        const MAX_REQ_BYTES: usize = 256;
        let copy_len = dlen.min(MAX_REQ_BYTES);
        let mut local_buf = [0u8; MAX_REQ_BYTES];
        let dw_len = copy_len.div_ceil(4);
        for (i, &dw) in rx_buf[..dw_len].iter().enumerate() {
            let base = i * 4;
            let bytes = dw.to_le_bytes();
            for j in 0..4 {
                if base + j < copy_len {
                    local_buf[base + j] = bytes[j];
                }
            }
        }

        let result = self.dispatch(&local_buf[..copy_len]);

        self.mbox.restore_rx_buffer(rx_buf);
        result
    }

    fn response_received(
        &self,
        _status: NetworkMboxTargetStatus,
        _rx_buf: &'static mut [u32],
        _dlen: usize,
    ) {
        // Not used — this app operates in receiver mode only.
    }

    fn send_done(&self, _result: Result<()>) {
        // Not used — responses are sent synchronously.
    }
}
