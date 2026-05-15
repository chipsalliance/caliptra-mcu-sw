// Licensed under the Apache-2.0 license

// Based on Tock log capsule with modifications.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

use core::cell::Cell;
use core::mem::size_of;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::flash::{self, Flash};
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

/// Globally declare entry ID type.
type EntryID = usize;

/// Maximum page header size.
pub const PAGE_HEADER_SIZE: usize = size_of::<EntryID>();
/// Maximum entry header size.
pub const ENTRY_HEADER_SIZE: usize = size_of::<usize>();

/// Byte used to pad the end of a page.
const PAD_BYTE: u8 = 0xFF;

/// Log state keeps track of any in-progress asynchronous operations.
#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    NotReady,
    Reconstructing,
    Idle,
    Reading,
    Seeking,
    Appending,
    Syncing,
    Erasing,
}

/// Sub-phase of the boot-time reconstruct flow.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ReconstructPhase {
    Inactive,
    ScanPages { next: usize },
    WalkLastPage,
}

/// Sub-phase of `read()` after the request has been latched.
#[derive(Clone, Copy, PartialEq, Debug)]
enum ReadPhase {
    Inactive,
    LoadingPage,
}

/// Sub-phase of `append()`.
#[derive(Clone, Copy, PartialEq, Debug)]
enum AppendPhase {
    Inactive,
    FlushingForAppend,
}

/// A queued client request.
#[derive(Clone, Copy)]
enum PendingOp {
    Read { length: usize },
    Append { length: usize },
    Seek { entry_id: EntryID },
    Sync,
    Erase,
}

pub struct Log<'a, F: Flash + 'static> {
    /// First physical flash page backing this log.
    base_page: usize,
    /// Number of consecutive flash pages dedicated to this log.
    num_pages: usize,
    /// Capacity of log in bytes.
    capacity: usize,
    /// Underlying volume length in bytes.
    volume_len: usize,
    /// Size of a flash page.
    page_size: usize,
    /// Flash interface.
    driver: &'a F,
    /// Whether or not the log is circular.
    circular: bool,
    /// Buffer for the page currently being appended to.
    pagebuffer: TakeCell<'static, F::Page>,
    /// Logical page index mirrored in `pagebuffer`.
    pagebuffer_logical_page: Cell<Option<usize>>,
    /// Buffer for the most recently read page.
    read_pagebuffer: TakeCell<'static, F::Page>,
    /// Logical page index mirrored in `read_pagebuffer`.
    read_pagebuffer_logical_page: Cell<Option<usize>>,
    /// Read client using Log.
    read_client: OptionalCell<&'a dyn LogReadClient>,
    /// Append client using Log.
    append_client: OptionalCell<&'a dyn LogWriteClient>,
    /// Current operation being executed, if asynchronous.
    state: Cell<State>,
    reconstruct_phase: Cell<ReconstructPhase>,
    read_phase: Cell<ReadPhase>,
    append_phase: Cell<AppendPhase>,
    /// Entry ID of oldest entry remaining in log.
    oldest_entry_id: Cell<EntryID>,
    /// Entry ID of next entry to read.
    read_entry_id: Cell<EntryID>,
    /// Entry ID of next entry to append.
    append_entry_id: Cell<EntryID>,
    reconstruct_oldest: Cell<EntryID>,
    reconstruct_newest: Cell<EntryID>,
    /// Client-provided buffer to read into / write from.
    buffer: TakeCell<'static, [u8]>,
    /// Length of data within buffer.
    length: Cell<usize>,
    /// Whether or not records were lost in the previous append.
    records_lost: Cell<bool>,
    /// Error returned by previously executed operation (or Ok(())).
    error: Cell<Result<(), ErrorCode>>,
    /// Single-slot queue for a request that arrived while busy.
    pending: OptionalCell<PendingOp>,
    /// Deferred call for deferring client callbacks.
    deferred_call: DeferredCall,
}

impl<'a, F: Flash + 'static> Log<'a, F> {
    pub fn new(
        base_page: usize,
        num_pages: usize,
        driver: &'a F,
        pagebuffer: &'static mut F::Page,
        read_pagebuffer: &'static mut F::Page,
        circular: bool,
    ) -> Self {
        let page_size = pagebuffer.as_mut().len();
        let num_pages = if page_size == 0 { 0 } else { num_pages };
        let volume_len = num_pages.saturating_mul(page_size);
        let capacity = volume_len.saturating_sub(PAGE_HEADER_SIZE * num_pages);

        Self {
            base_page,
            num_pages,
            capacity,
            volume_len,
            page_size,
            driver,
            circular,
            pagebuffer: TakeCell::new(pagebuffer),
            pagebuffer_logical_page: Cell::new(None),
            read_pagebuffer: TakeCell::new(read_pagebuffer),
            read_pagebuffer_logical_page: Cell::new(None),
            read_client: OptionalCell::empty(),
            append_client: OptionalCell::empty(),
            state: Cell::new(State::NotReady),
            reconstruct_phase: Cell::new(ReconstructPhase::Inactive),
            read_phase: Cell::new(ReadPhase::Inactive),
            append_phase: Cell::new(AppendPhase::Inactive),
            oldest_entry_id: Cell::new(PAGE_HEADER_SIZE),
            read_entry_id: Cell::new(PAGE_HEADER_SIZE),
            append_entry_id: Cell::new(PAGE_HEADER_SIZE),
            reconstruct_oldest: Cell::new(usize::MAX),
            reconstruct_newest: Cell::new(0),
            buffer: TakeCell::empty(),
            length: Cell::new(0),
            records_lost: Cell::new(false),
            error: Cell::new(Ok(())),
            pending: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
        }
    }

    /// Wire up the capsule. Reconstruct is deferred until the first
    /// client request (read / append / seek / sync / erase).
    pub fn init(&self) {
        if self.state.get() != State::NotReady {
            return;
        }
        if self.num_pages == 0 {
            self.reset_state_empty();
            self.state.set(State::Idle);
        }
    }

    /// Lazily kick off reconstruct on the first client request.
    fn ensure_reconstruct_started(&self) {
        if self.state.get() != State::NotReady {
            return;
        }
        if self.num_pages == 0 {
            self.reset_state_empty();
            self.state.set(State::Idle);
            return;
        }
        self.state.set(State::Reconstructing);
        self.reconstruct_phase
            .set(ReconstructPhase::ScanPages { next: 0 });
        self.reconstruct_oldest.set(usize::MAX);
        self.reconstruct_newest.set(0);
        self.deferred_call.set();
    }

    /// Convert a logical page index into a physical page number for the flash HIL.
    fn physical_page(&self, logical: usize) -> usize {
        self.base_page + logical
    }

    /// Logical page index containing the byte at `pos` within the volume.
    fn logical_page_of_pos(&self, pos: usize) -> usize {
        (pos % self.volume_len) / self.page_size
    }

    /// Logical page index containing the byte addressed by `entry_id`.
    fn logical_page_of_entry(&self, entry_id: EntryID) -> usize {
        self.logical_page_of_pos(entry_id)
    }

    /// Reset state to "empty log".
    fn reset_state_empty(&self) {
        self.oldest_entry_id.set(PAGE_HEADER_SIZE);
        self.read_entry_id.set(PAGE_HEADER_SIZE);
        self.append_entry_id.set(PAGE_HEADER_SIZE);
        self.records_lost.set(false);
        if let Some(pagebuffer) = self.pagebuffer.take() {
            for b in pagebuffer.as_mut().iter_mut() {
                *b = 0;
            }
            // Initialise the page header for logical page 0.
            self.write_page_header_at(pagebuffer, PAGE_HEADER_SIZE);
            self.pagebuffer.replace(pagebuffer);
            // pagebuffer mirrors logical page 0.
            self.pagebuffer_logical_page.set(Some(0));
        }
        // The read cache is invalid until something is appended +
        // flushed (or until we explicitly load a page).
        self.read_pagebuffer_logical_page.set(None);
    }

    fn write_page_header_at(&self, pagebuffer: &mut F::Page, start_entry_id: EntryID) {
        let id_bytes = start_entry_id.to_ne_bytes();
        let page = pagebuffer.as_mut();
        page[..id_bytes.len()].copy_from_slice(&id_bytes[..]);
    }

    /// Read `num_bytes` bytes starting at volume offset `pos` into `out`.
    /// Returns `Some(())` if the bytes are available locally; returns `None`
    /// if a flash read is required first.
    fn try_get_bytes(&self, pos: usize, num_bytes: usize, out: &mut [u8]) -> Option<()> {
        let logical_page = self.logical_page_of_pos(pos);
        let offset = pos % self.page_size;

        // Prefer the writable pagebuffer if it mirrors this page.
        if Some(logical_page) == self.pagebuffer_logical_page.get() {
            let mut got = None;
            self.pagebuffer.map(|pagebuffer| {
                let page = pagebuffer.as_mut();
                if offset + num_bytes <= page.len() {
                    out[..num_bytes].copy_from_slice(&page[offset..offset + num_bytes]);
                    got = Some(());
                }
            });
            return got;
        }

        // Otherwise check the read cache.
        if Some(logical_page) == self.read_pagebuffer_logical_page.get() {
            let mut got = None;
            self.read_pagebuffer.map(|pagebuffer| {
                let page = pagebuffer.as_mut();
                if offset + num_bytes <= page.len() {
                    out[..num_bytes].copy_from_slice(&page[offset..offset + num_bytes]);
                    got = Some(());
                }
            });
            return got;
        }

        None
    }

    /// Single-byte variant of [`try_get_bytes`].
    fn try_get_byte(&self, pos: usize) -> Option<u8> {
        let mut byte = [0u8; 1];
        self.try_get_bytes(pos, 1, &mut byte)?;
        Some(byte[0])
    }

    /// Enqueue a request that arrived while another op is in flight.
    fn enqueue_pending(&self, op: PendingOp) -> Result<(), ErrorCode> {
        if self.pending.is_some() {
            return Err(ErrorCode::BUSY);
        }
        self.pending.set(op);
        Ok(())
    }

    /// Pop and dispatch one pending op. Caller must ensure the log is idle.
    fn dispatch_pending(&self) {
        if self.state.get() != State::Idle {
            return;
        }
        let op = match self.pending.take() {
            Some(op) => op,
            None => return,
        };
        match op {
            PendingOp::Read { length } => {
                let buffer = match self.buffer.take() {
                    Some(b) => b,
                    None => return,
                };
                let _ = self.start_read(buffer, length);
            }
            PendingOp::Append { length } => {
                let buffer = match self.buffer.take() {
                    Some(b) => b,
                    None => return,
                };
                let _ = self.start_append(buffer, length);
            }
            PendingOp::Seek { entry_id } => {
                let _ = self.start_seek(entry_id);
            }
            PendingOp::Sync => {
                let _ = self.start_sync();
            }
            PendingOp::Erase => {
                let _ = self.start_erase();
            }
        }
    }

    fn drive_reconstruct(&self) {
        match self.reconstruct_phase.get() {
            ReconstructPhase::Inactive => {}
            ReconstructPhase::ScanPages { next } => {
                if next >= self.num_pages {
                    if self.reconstruct_oldest.get() == usize::MAX {
                        // No valid pages found — fresh empty log.
                        self.reset_state_empty();
                        self.finish_reconstruct();
                        return;
                    }
                    // Read the newest page so we can walk its entries.
                    self.reconstruct_phase.set(ReconstructPhase::WalkLastPage);
                    let newest_logical = self.logical_page_of_pos(self.reconstruct_newest.get());
                    if let Err(_e) = self.start_read_page(newest_logical) {
                        // Treat unrecoverable reconstruct failure as an
                        // empty log so the device can still come up.
                        self.reset_state_empty();
                        self.finish_reconstruct();
                    }
                } else {
                    // Issue the read for logical page `next`.
                    if let Err(_e) = self.start_read_page(next) {
                        self.reset_state_empty();
                        self.finish_reconstruct();
                    }
                }
            }
            ReconstructPhase::WalkLastPage => {
                // Should not be reachable from a deferred call — the
                // walk is performed inside `read_complete` once the
                // newest page lands in `read_pagebuffer`.
            }
        }
    }

    /// Issue `read_page()` for the supplied logical page. The result
    /// will land in `read_pagebuffer` via `flash::Client::read_complete`.
    fn start_read_page(&self, logical_page: usize) -> Result<(), ErrorCode> {
        let buf = match self.read_pagebuffer.take() {
            Some(b) => b,
            None => return Err(ErrorCode::RESERVE),
        };
        // Invalidate cache before issuing.
        self.read_pagebuffer_logical_page.set(None);
        match self.driver.read_page(self.physical_page(logical_page), buf) {
            Ok(()) => Ok(()),
            Err((ecode, buf)) => {
                self.read_pagebuffer.replace(buf);
                Err(ecode)
            }
        }
    }

    /// Called from `read_complete` while in the `Reconstructing` state.
    fn handle_reconstruct_read(&self, page_buf: &[u8], success: bool) {
        match self.reconstruct_phase.get() {
            ReconstructPhase::ScanPages { next } => {
                let logical_page = next;
                if success && page_buf.len() >= PAGE_HEADER_SIZE {
                    let mut id_bytes = [0u8; PAGE_HEADER_SIZE];
                    id_bytes.copy_from_slice(&page_buf[..PAGE_HEADER_SIZE]);
                    let page_id = EntryID::from_ne_bytes(id_bytes);

                    // Validate: a real page header has page_id %
                    // volume_len equal to its physical-volume offset.
                    if page_id % self.volume_len == logical_page * self.page_size {
                        if page_id < self.reconstruct_oldest.get() {
                            self.reconstruct_oldest.set(page_id);
                        }
                        if page_id > self.reconstruct_newest.get() {
                            self.reconstruct_newest.set(page_id);
                        }
                    }
                }
                self.reconstruct_phase.set(ReconstructPhase::ScanPages {
                    next: logical_page + 1,
                });
                self.deferred_call.set();
            }
            ReconstructPhase::WalkLastPage => {
                // The newest page is now in `read_pagebuffer`.
                let newest_id = self.reconstruct_newest.get();
                let oldest_id = self.reconstruct_oldest.get();

                let mut last_page_len = PAGE_HEADER_SIZE;
                if success {
                    // Walk entries within the page.
                    loop {
                        if last_page_len + ENTRY_HEADER_SIZE > self.page_size {
                            break;
                        }
                        let byte = page_buf[last_page_len];
                        if byte == 0 || byte == PAD_BYTE {
                            break;
                        }
                        // Read entry length header.
                        let mut len_bytes = [0u8; ENTRY_HEADER_SIZE];
                        len_bytes.copy_from_slice(
                            &page_buf[last_page_len..last_page_len + ENTRY_HEADER_SIZE],
                        );
                        let entry_len = usize::from_ne_bytes(len_bytes);
                        let total = entry_len + ENTRY_HEADER_SIZE;
                        if entry_len == 0 || last_page_len + total > self.page_size {
                            break;
                        }
                        last_page_len += total;
                        if last_page_len == self.page_size {
                            break;
                        }
                    }
                }

                self.oldest_entry_id.set(oldest_id + PAGE_HEADER_SIZE);
                self.read_entry_id.set(oldest_id + PAGE_HEADER_SIZE);
                self.append_entry_id.set(newest_id + last_page_len);
                self.records_lost.set(oldest_id != 0);

                // Initialise the writable pagebuffer.
                if let Some(pagebuffer) = self.pagebuffer.take() {
                    let copy_pagebuffer = last_page_len % self.page_size != 0;
                    if copy_pagebuffer {
                        // Mirror the newest page into the writable buffer
                        // so further appends extend it.
                        let dst = pagebuffer.as_mut();
                        dst[..self.page_size].copy_from_slice(&page_buf[..self.page_size]);
                        let logical = self.logical_page_of_pos(newest_id);
                        self.pagebuffer_logical_page.set(Some(logical));
                    } else {
                        // Newest page is full; reset for the next page.
                        for b in pagebuffer.as_mut().iter_mut() {
                            *b = 0;
                        }
                        // Compute the next page's start entry ID.
                        let next_start = newest_id + self.page_size;
                        self.write_page_header_at(pagebuffer, next_start);
                        self.append_entry_id.set(next_start + PAGE_HEADER_SIZE);
                        let logical = self.logical_page_of_pos(next_start);
                        self.pagebuffer_logical_page.set(Some(logical));
                    }
                    self.pagebuffer.replace(pagebuffer);
                }

                // Mark the read cache as containing the newest page.
                let logical = self.logical_page_of_pos(newest_id);
                self.read_pagebuffer_logical_page.set(Some(logical));

                self.finish_reconstruct();
            }
            ReconstructPhase::Inactive => {}
        }
    }

    /// Called when reconstruct finishes successfully.
    fn finish_reconstruct(&self) {
        self.reconstruct_phase.set(ReconstructPhase::Inactive);
        self.state.set(State::Idle);
        // Dispatch any op that arrived during reconstruct.
        if self.pending.is_some() {
            self.dispatch_pending();
        }
    }

    fn start_read(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if buffer.len() < length {
            return Err((ErrorCode::INVAL, buffer));
        }
        if self.read_entry_id.get() > self.append_entry_id.get() {
            // Defensive: invalid state, reset to oldest.
            self.read_entry_id.set(self.oldest_entry_id.get());
            return Err((ErrorCode::CANCEL, buffer));
        }
        if self.read_client.is_none() {
            return Err((ErrorCode::RESERVE, buffer));
        }

        self.state.set(State::Reading);
        self.buffer.replace(buffer);
        self.length.set(length);
        self.read_phase.set(ReadPhase::Inactive);
        // First make sure read_entry_id points at a real entry start
        // (skipping page header / pad bytes if necessary). If the
        // page-skip walks us into an unloaded page, an async read is
        // issued and we resume in `read_complete`.
        self.advance_read_pointer_then_deliver();
        Ok(())
    }

    /// Skip page-header / pad bytes from `read_entry_id` until it lands
    /// on either a real entry start or the append cursor. Loads pages
    /// asynchronously as needed; once the cursor is final, delivers
    /// the entry (or signals end-of-log).
    fn advance_read_pointer_then_deliver(&self) {
        loop {
            let entry_id = self.read_entry_id.get();
            if entry_id >= self.append_entry_id.get() {
                // End of log.
                self.error.set(Err(ErrorCode::FAIL));
                self.length.set(0);
                self.deferred_call.set();
                return;
            }

            // Skip the page header at the very start of a page.
            if entry_id % self.page_size == 0 {
                self.read_entry_id.set(entry_id + PAGE_HEADER_SIZE);
                continue;
            }

            // Need to inspect the byte at `entry_id` to see if it's pad.
            match self.try_get_byte(entry_id) {
                Some(byte) => {
                    if byte == PAD_BYTE {
                        // Skip rest of page (and the next page header).
                        let next = entry_id
                            + (self.page_size - entry_id % self.page_size)
                            + PAGE_HEADER_SIZE;
                        self.read_entry_id.set(next);
                        continue;
                    }
                    // Not pad, not page boundary — entry header should be here.
                    self.deliver_current_entry();
                    return;
                }
                None => {
                    // Page not in any cache — load it.
                    let logical = self.logical_page_of_entry(entry_id);
                    self.read_phase.set(ReadPhase::LoadingPage);
                    if let Err(ecode) = self.start_read_page(logical) {
                        self.error.set(Err(ecode));
                        self.length.set(0);
                        self.deferred_call.set();
                    }
                    return;
                }
            }
        }
    }

    /// Read the entry header at `read_entry_id`, then copy the entry
    /// payload into the client buffer. Issues an async page read first
    /// if the page isn't cached.
    fn deliver_current_entry(&self) {
        let entry_id = self.read_entry_id.get();

        // Read the length header.
        let mut len_bytes = [0u8; ENTRY_HEADER_SIZE];
        if self
            .try_get_bytes(entry_id, ENTRY_HEADER_SIZE, &mut len_bytes)
            .is_none()
        {
            // Need to load the page first.
            let logical = self.logical_page_of_entry(entry_id);
            self.read_phase.set(ReadPhase::LoadingPage);
            if let Err(ecode) = self.start_read_page(logical) {
                self.error.set(Err(ecode));
                self.length.set(0);
                self.deferred_call.set();
            }
            return;
        }
        let entry_len = usize::from_ne_bytes(len_bytes);
        if entry_len == 0 || entry_len > self.page_size - PAGE_HEADER_SIZE - ENTRY_HEADER_SIZE {
            self.error.set(Err(ErrorCode::FAIL));
            self.length.set(0);
            self.deferred_call.set();
            return;
        }

        // Caller's buffer must hold the entire entry.
        let client_len = self.length.get();
        if entry_len > client_len {
            self.error.set(Err(ErrorCode::SIZE));
            self.length.set(0);
            self.deferred_call.set();
            return;
        }

        // Copy entry payload into the client buffer.
        let payload_pos = entry_id + ENTRY_HEADER_SIZE;
        let mut copied = false;
        if let Some(buffer) = self.buffer.take() {
            if self
                .try_get_bytes(payload_pos, entry_len, &mut buffer[..entry_len])
                .is_some()
            {
                copied = true;
            }
            self.buffer.replace(buffer);
        }

        if !copied {
            // Page must have been evicted between header and payload reads.
            let logical = self.logical_page_of_entry(entry_id);
            self.read_phase.set(ReadPhase::LoadingPage);
            if let Err(ecode) = self.start_read_page(logical) {
                self.error.set(Err(ecode));
                self.length.set(0);
                self.deferred_call.set();
            }
            return;
        }

        // Advance read cursor past this entry.
        self.read_entry_id
            .set(entry_id + ENTRY_HEADER_SIZE + entry_len);
        self.length.set(entry_len);
        self.error.set(Ok(()));
        self.deferred_call.set();
    }

    fn start_seek(&self, entry_id: EntryID) -> Result<(), ErrorCode> {
        if entry_id <= self.append_entry_id.get() && entry_id >= self.oldest_entry_id.get() {
            self.read_entry_id.set(entry_id);
            self.state.set(State::Seeking);
            self.error.set(Ok(()));
            self.deferred_call.set();
            Ok(())
        } else {
            Err(ErrorCode::INVAL)
        }
    }

    fn start_sync(&self) -> Result<(), ErrorCode> {
        // Empty pagebuffer (only header) → nothing to flush.
        if self.append_entry_id.get() % self.page_size == PAGE_HEADER_SIZE {
            self.state.set(State::Syncing);
            self.error.set(Ok(()));
            self.deferred_call.set();
            return Ok(());
        }
        let pagebuffer = match self.pagebuffer.take() {
            Some(b) => b,
            None => return Err(ErrorCode::RESERVE),
        };
        self.state.set(State::Syncing);
        self.append_phase.set(AppendPhase::Inactive);
        match self.flush_pagebuffer(pagebuffer) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.state.set(State::Idle);
                Err(e)
            }
        }
    }

    fn start_erase(&self) -> Result<(), ErrorCode> {
        if self.oldest_entry_id.get() == self.append_entry_id.get() && !self.records_lost.get() {
            // Already empty.
            self.state.set(State::Erasing);
            self.error.set(Ok(()));
            self.deferred_call.set();
            return Ok(());
        }
        self.state.set(State::Erasing);
        self.erase_oldest_page()
    }

    fn erase_oldest_page(&self) -> Result<(), ErrorCode> {
        let logical = self.logical_page_of_entry(self.oldest_entry_id.get());
        // Invalidate caches for this page if needed.
        if Some(logical) == self.read_pagebuffer_logical_page.get() {
            self.read_pagebuffer_logical_page.set(None);
        }
        if Some(logical) == self.pagebuffer_logical_page.get() {
            self.pagebuffer_logical_page.set(None);
        }
        self.driver.erase_page(self.physical_page(logical))
    }

    fn start_append(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        let entry_size = length + ENTRY_HEADER_SIZE;
        if length == 0 || buffer.len() < length {
            return Err((ErrorCode::INVAL, buffer));
        }
        if entry_size + PAGE_HEADER_SIZE > self.page_size {
            return Err((ErrorCode::SIZE, buffer));
        }
        if !self.circular && self.append_entry_id.get() + entry_size > self.volume_len {
            return Err((ErrorCode::FAIL, buffer));
        }

        let pagebuffer = match self.pagebuffer.take() {
            Some(b) => b,
            None => return Err((ErrorCode::RESERVE, buffer)),
        };

        self.state.set(State::Appending);
        self.length.set(length);

        let append_entry_id = self.append_entry_id.get();
        let flush_prev_page = append_entry_id % self.page_size == 0;
        let space_remaining = self.page_size - append_entry_id % self.page_size;

        if !flush_prev_page && entry_size <= space_remaining {
            // Fits in current pagebuffer — write & callback.
            self.append_to_pagebuffer(buffer, length, pagebuffer);
            Ok(())
        } else {
            // Need to flush first.
            self.buffer.replace(buffer);
            self.append_phase.set(AppendPhase::FlushingForAppend);
            match self.flush_pagebuffer(pagebuffer) {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.state.set(State::Idle);
                    self.append_phase.set(AppendPhase::Inactive);
                    let buf = self.buffer.take().expect("buffer just stored");
                    Err((e, buf))
                }
            }
        }
    }

    /// Synchronous append into the writable pagebuffer. Caller must have
    /// already verified that the entry fits in the current page.
    fn append_to_pagebuffer(
        &self,
        buffer: &'static mut [u8],
        length: usize,
        pagebuffer: &'static mut F::Page,
    ) {
        let append_entry_id = self.append_entry_id.get();
        let mut page_offset = append_entry_id % self.page_size;

        // Write entry header.
        let len_bytes = length.to_ne_bytes();
        let page = pagebuffer.as_mut();
        page[page_offset..page_offset + ENTRY_HEADER_SIZE].copy_from_slice(&len_bytes);
        page_offset += ENTRY_HEADER_SIZE;

        // Write payload.
        page[page_offset..page_offset + length].copy_from_slice(&buffer[..length]);

        let new_append_entry_id = append_entry_id + length + ENTRY_HEADER_SIZE;
        self.append_entry_id.set(new_append_entry_id);
        // Pagebuffer mirrors the page containing (append_entry_id - 1).
        self.pagebuffer_logical_page
            .set(Some(self.logical_page_of_pos(new_append_entry_id - 1)));

        self.pagebuffer.replace(pagebuffer);
        self.buffer.replace(buffer);
        self.records_lost
            .set(self.oldest_entry_id.get() != PAGE_HEADER_SIZE);
        self.error.set(Ok(()));
        self.deferred_call.set();
    }

    /// Pad the pagebuffer with `PAD_BYTE`, write it to flash, and
    /// advance bookkeeping for an overwritten oldest page if relevant.
    fn flush_pagebuffer(&self, pagebuffer: &'static mut F::Page) -> Result<(), ErrorCode> {
        // Pad end of page.
        let mut pad_ptr = self.append_entry_id.get();
        let page = pagebuffer.as_mut();
        while pad_ptr % self.page_size != 0 {
            page[pad_ptr % self.page_size] = PAD_BYTE;
            pad_ptr += 1;
        }
        // The pagebuffer is now mirrored on flash for the page ending
        // at `pad_ptr`.
        let logical = self.logical_page_of_pos(pad_ptr - self.page_size);

        // Maintain oldest/read cursors when wrapping in a circular log.
        if pad_ptr > self.volume_len {
            let overwritten_logical =
                self.logical_page_of_pos(pad_ptr - self.volume_len - self.page_size);
            // Reframe overwritten_logical's entries.
            let overwritten_page_start =
                (pad_ptr - self.volume_len - self.page_size) / self.page_size * self.page_size;

            let read_entry_id = self.read_entry_id.get();
            if read_entry_id / self.page_size == overwritten_page_start / self.page_size {
                self.read_entry_id.set(
                    read_entry_id + self.page_size + PAGE_HEADER_SIZE
                        - read_entry_id % self.page_size,
                );
            }
            let oldest_entry_id = self.oldest_entry_id.get();
            if oldest_entry_id / self.page_size == overwritten_page_start / self.page_size {
                self.oldest_entry_id.set(oldest_entry_id + self.page_size);
            }
            // Invalidate read cache if it held the page about to be
            // physically overwritten.
            if Some(overwritten_logical) == self.read_pagebuffer_logical_page.get() {
                self.read_pagebuffer_logical_page.set(None);
            }
        }

        match self
            .driver
            .write_page(self.physical_page(logical), pagebuffer)
        {
            Ok(()) => Ok(()),
            Err((ecode, pagebuffer)) => {
                self.pagebuffer.replace(pagebuffer);
                Err(ecode)
            }
        }
    }

    /// Reset the pagebuffer to the start of the next page. Returns
    /// `false` if a non-circular log has hit the end.
    fn reset_pagebuffer(&self, pagebuffer: &mut F::Page) -> bool {
        let mut append_entry_id = self.append_entry_id.get();
        if !self.circular && append_entry_id + self.page_size > self.volume_len {
            return false;
        }

        if append_entry_id % self.page_size != 0 {
            append_entry_id += self.page_size - append_entry_id % self.page_size;
        }

        // Zero the buffer first so stale pad bytes don't trip the
        // entry-walk on the next reconstruct.
        for b in pagebuffer.as_mut().iter_mut() {
            *b = 0;
        }
        self.write_page_header_at(pagebuffer, append_entry_id);

        self.append_entry_id.set(append_entry_id + PAGE_HEADER_SIZE);
        self.pagebuffer_logical_page
            .set(Some(self.logical_page_of_pos(append_entry_id)));
        true
    }

    fn fire_client_callback(&self) {
        let state = self.state.get();
        match state {
            State::Reading | State::Seeking => {
                self.state.set(State::Idle);
                self.read_phase.set(ReadPhase::Inactive);
                self.read_client.map(|client| match state {
                    State::Reading => {
                        if let Some(buffer) = self.buffer.take() {
                            client.read_done(buffer, self.length.get(), self.error.get());
                        }
                    }
                    State::Seeking => client.seek_done(self.error.get()),
                    _ => {}
                });
            }
            State::Appending | State::Syncing | State::Erasing => {
                self.state.set(State::Idle);
                self.append_phase.set(AppendPhase::Inactive);
                self.append_client.map(|client| match state {
                    State::Appending => {
                        if let Some(buffer) = self.buffer.take() {
                            client.append_done(
                                buffer,
                                self.length.get(),
                                self.records_lost.get(),
                                self.error.get(),
                            );
                        }
                    }
                    State::Syncing => client.sync_done(self.error.get()),
                    State::Erasing => client.erase_done(self.error.get()),
                    _ => {}
                });
            }
            State::Idle | State::NotReady | State::Reconstructing => {}
        }

        // Drain a queued op now that we're idle.
        if self.state.get() == State::Idle && self.pending.is_some() {
            self.dispatch_pending();
        }
    }
}

impl<'a, F: Flash + 'static> LogRead<'a> for Log<'a, F> {
    type EntryID = EntryID;

    fn set_read_client(&self, read_client: &'a dyn LogReadClient) {
        self.read_client.set(read_client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if buffer.len() < length {
            return Err((ErrorCode::INVAL, buffer));
        }
        self.ensure_reconstruct_started();
        match self.state.get() {
            State::Idle => self.start_read(buffer, length),
            _ => {
                self.buffer.replace(buffer);
                if let Err(e) = self.enqueue_pending(PendingOp::Read { length }) {
                    let buf = self.buffer.take().expect("buffer just stored");
                    return Err((e, buf));
                }
                Ok(())
            }
        }
    }

    fn log_start(&self) -> Self::EntryID {
        self.oldest_entry_id.get()
    }

    fn log_end(&self) -> Self::EntryID {
        self.append_entry_id.get()
    }

    fn next_read_entry_id(&self) -> Self::EntryID {
        self.read_entry_id.get()
    }

    fn seek(&self, entry_id: Self::EntryID) -> Result<(), ErrorCode> {
        self.ensure_reconstruct_started();
        match self.state.get() {
            State::Idle => self.start_seek(entry_id),
            _ => self.enqueue_pending(PendingOp::Seek { entry_id }),
        }
    }

    fn get_size(&self) -> usize {
        self.capacity
    }
}

impl<'a, F: Flash + 'static> LogWrite<'a> for Log<'a, F> {
    fn set_append_client(&self, append_client: &'a dyn LogWriteClient) {
        self.append_client.set(append_client);
    }

    fn append(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if length == 0 || buffer.len() < length {
            return Err((ErrorCode::INVAL, buffer));
        }
        self.ensure_reconstruct_started();
        match self.state.get() {
            State::Idle => self.start_append(buffer, length),
            _ => {
                self.buffer.replace(buffer);
                if let Err(e) = self.enqueue_pending(PendingOp::Append { length }) {
                    let buf = self.buffer.take().expect("buffer just stored");
                    return Err((e, buf));
                }
                Ok(())
            }
        }
    }

    fn sync(&self) -> Result<(), ErrorCode> {
        self.ensure_reconstruct_started();
        match self.state.get() {
            State::Idle => self.start_sync(),
            _ => self.enqueue_pending(PendingOp::Sync),
        }
    }

    fn erase(&self) -> Result<(), ErrorCode> {
        self.ensure_reconstruct_started();
        match self.state.get() {
            State::Idle => self.start_erase(),
            _ => self.enqueue_pending(PendingOp::Erase),
        }
    }
}

impl<F: Flash + 'static> flash::Client<F> for Log<'_, F> {
    fn read_complete(&self, read_buffer: &'static mut F::Page, result: Result<(), flash::Error>) {
        let success = result.is_ok();

        match self.state.get() {
            State::Reconstructing => {
                // Determine which logical page this completion is for.
                let logical = match self.reconstruct_phase.get() {
                    ReconstructPhase::ScanPages { next } => next,
                    ReconstructPhase::WalkLastPage => {
                        self.logical_page_of_pos(self.reconstruct_newest.get())
                    }
                    ReconstructPhase::Inactive => {
                        // Spurious completion. Park the buffer.
                        self.read_pagebuffer.replace(read_buffer);
                        return;
                    }
                };
                if success {
                    self.read_pagebuffer_logical_page.set(Some(logical));
                } else {
                    self.read_pagebuffer_logical_page.set(None);
                }
                let page_slice: &[u8] = read_buffer.as_mut();
                self.handle_reconstruct_read(page_slice, success);
                self.read_pagebuffer.replace(read_buffer);
            }
            State::Reading => {
                let logical = self.logical_page_of_entry(self.read_entry_id.get());
                if success {
                    self.read_pagebuffer_logical_page.set(Some(logical));
                } else {
                    self.read_pagebuffer_logical_page.set(None);
                    self.read_pagebuffer.replace(read_buffer);
                    self.error.set(Err(ErrorCode::FAIL));
                    self.length.set(0);
                    self.deferred_call.set();
                    return;
                }
                self.read_pagebuffer.replace(read_buffer);
                self.read_phase.set(ReadPhase::Inactive);
                // Continue the read state machine.
                self.advance_read_pointer_then_deliver();
            }
            _ => {
                // Unexpected completion. Park the buffer to avoid leaking it.
                self.read_pagebuffer.replace(read_buffer);
            }
        }
    }

    fn write_complete(&self, pagebuffer: &'static mut F::Page, result: Result<(), flash::Error>) {
        match self.state.get() {
            State::Appending => {
                if result.is_err() {
                    self.pagebuffer.replace(pagebuffer);
                    self.length.set(0);
                    self.records_lost.set(false);
                    self.error.set(Err(ErrorCode::FAIL));
                    self.fire_client_callback();
                    return;
                }
                if self.append_phase.get() == AppendPhase::FlushingForAppend {
                    // Continue the append on the freshly reset page.
                    if !self.reset_pagebuffer(pagebuffer) {
                        // Non-circular log full.
                        self.pagebuffer.replace(pagebuffer);
                        self.length.set(0);
                        self.records_lost.set(false);
                        self.error.set(Err(ErrorCode::CANCEL));
                        self.fire_client_callback();
                        return;
                    }
                    self.append_phase.set(AppendPhase::Inactive);
                    if let Some(buffer) = self.buffer.take() {
                        self.append_to_pagebuffer(buffer, self.length.get(), pagebuffer);
                    } else {
                        self.pagebuffer.replace(pagebuffer);
                        self.error.set(Err(ErrorCode::RESERVE));
                        self.fire_client_callback();
                    }
                } else {
                    // Synchronous append already finished prior to a flush;
                    // shouldn't normally land here.
                    self.pagebuffer.replace(pagebuffer);
                    self.error.set(Ok(()));
                    self.fire_client_callback();
                }
            }
            State::Syncing => {
                if result.is_err() {
                    self.pagebuffer.replace(pagebuffer);
                    self.error.set(Err(ErrorCode::FAIL));
                    self.fire_client_callback();
                    return;
                }
                // If the synced page was full, prepare the next page.
                if self.append_entry_id.get() % self.page_size == 0 {
                    let _ = self.reset_pagebuffer(pagebuffer);
                }
                self.pagebuffer.replace(pagebuffer);
                self.error.set(Ok(()));
                self.fire_client_callback();
            }
            _ => {
                // Unexpected — park.
                self.pagebuffer.replace(pagebuffer);
            }
        }
    }

    fn erase_complete(&self, result: Result<(), flash::Error>) {
        if self.state.get() != State::Erasing {
            return;
        }
        if result.is_err() {
            self.error.set(Err(ErrorCode::FAIL));
            self.fire_client_callback();
            return;
        }

        let oldest_entry_id = self.oldest_entry_id.get();
        if oldest_entry_id + self.page_size >= self.append_entry_id.get() {
            // Erased all pages — reset to empty.
            self.reset_state_empty();
            self.error.set(Ok(()));
            self.fire_client_callback();
        } else {
            // Erase next page.
            self.oldest_entry_id.set(oldest_entry_id + self.page_size);
            match self.erase_oldest_page() {
                Ok(()) => {}
                Err(ErrorCode::BUSY) => {
                    self.read_entry_id
                        .set(core::cmp::max(self.read_entry_id.get(), oldest_entry_id));
                    self.error.set(Err(ErrorCode::BUSY));
                    self.fire_client_callback();
                }
                Err(e) => {
                    self.error.set(Err(e));
                    self.fire_client_callback();
                }
            }
        }
    }
}

impl<F: Flash + 'static> DeferredCallClient for Log<'_, F> {
    fn handle_deferred_call(&self) {
        match self.state.get() {
            State::Reconstructing => self.drive_reconstruct(),
            State::Idle => {
                if self.pending.is_some() {
                    self.dispatch_pending();
                }
            }
            _ => self.fire_client_callback(),
        }
    }

    fn register(&'static self) {
        self.deferred_call.register(self);
    }
}
