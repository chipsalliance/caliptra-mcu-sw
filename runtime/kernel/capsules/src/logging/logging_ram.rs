// Licensed under the Apache-2.0 license

use core::cell::Cell;
use core::mem::size_of;
use kernel::deferred_call::{DeferredCall, DeferredCallClient};
use kernel::hil::log::{LogRead, LogReadClient, LogWrite, LogWriteClient};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

type EntryID = usize;
pub const ENTRY_HEADER_SIZE: usize = size_of::<usize>();

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Idle,
    Reading,
    Seeking,
    Appending,
    Erasing,
}

/// A volatile record log in platform-provided RAM, without Flash page caches.
pub struct Log<'a> {
    storage: TakeCell<'static, [u8]>,
    capacity: usize,
    circular: bool,
    oldest_entry_id: Cell<EntryID>,
    oldest_offset: Cell<usize>,
    append_entry_id: Cell<EntryID>,
    read_entry_id: Cell<EntryID>,
    state: Cell<State>,
    buffer: TakeCell<'static, [u8]>,
    length: Cell<usize>,
    records_lost: Cell<bool>,
    read_client: OptionalCell<&'a dyn LogReadClient>,
    append_client: OptionalCell<&'a dyn LogWriteClient>,
    deferred_call: DeferredCall,
}

impl<'a> Log<'a> {
    pub fn new(storage: &'static mut [u8], circular: bool) -> Self {
        let capacity = storage.len();
        Self {
            storage: TakeCell::new(storage),
            capacity,
            circular,
            oldest_entry_id: Cell::new(0),
            oldest_offset: Cell::new(0),
            append_entry_id: Cell::new(0),
            read_entry_id: Cell::new(0),
            state: Cell::new(State::Idle),
            buffer: TakeCell::empty(),
            length: Cell::new(0),
            records_lost: Cell::new(false),
            read_client: OptionalCell::empty(),
            append_client: OptionalCell::empty(),
            deferred_call: DeferredCall::new(),
        }
    }

    fn ready(&self) -> Result<(), ErrorCode> {
        if self.state.get() != State::Idle {
            Err(ErrorCode::BUSY)
        } else if self.capacity <= ENTRY_HEADER_SIZE {
            Err(ErrorCode::SIZE)
        } else {
            Ok(())
        }
    }

    fn copy_out(storage: &[u8], offset: usize, out: &mut [u8]) {
        let start = offset % storage.len();
        let first = out.len().min(storage.len() - start);
        out[..first].copy_from_slice(&storage[start..start + first]);
        let rest = out.len() - first;
        out[first..].copy_from_slice(&storage[..rest]);
    }

    fn copy_in(storage: &mut [u8], offset: usize, input: &[u8]) {
        let start = offset % storage.len();
        let first = input.len().min(storage.len() - start);
        storage[start..start + first].copy_from_slice(&input[..first]);
        storage[..input.len() - first].copy_from_slice(&input[first..]);
    }

    fn storage_offset(&self, entry_id: EntryID) -> usize {
        // Anchor physical positions independently of wrapping logical IDs.
        (self.oldest_offset.get() + entry_id.wrapping_sub(self.oldest_entry_id.get()))
            % self.capacity
    }

    fn record_length(storage: &[u8], offset: usize, remaining: usize) -> Result<usize, ErrorCode> {
        if remaining < ENTRY_HEADER_SIZE {
            return Err(ErrorCode::INVAL);
        }
        let mut header = [0; ENTRY_HEADER_SIZE];
        Self::copy_out(storage, offset, &mut header);
        let length = usize::from_ne_bytes(header);
        if length == 0
            || length > remaining - ENTRY_HEADER_SIZE
            || length > storage.len() - ENTRY_HEADER_SIZE
        {
            Err(ErrorCode::INVAL)
        } else {
            Ok(length)
        }
    }

    fn complete_read(&self, buffer: &'static mut [u8], length: usize) {
        self.buffer.replace(buffer);
        self.length.set(length);
        self.state.set(State::Reading);
        self.deferred_call.set();
    }
}

impl<'a> LogRead<'a> for Log<'a> {
    type EntryID = EntryID;

    fn set_read_client(&self, client: &'a dyn LogReadClient) {
        self.read_client.set(client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        let result = self.ready().and_then(|()| {
            if self.read_client.is_none() {
                return Err(ErrorCode::RESERVE);
            }
            if length > buffer.len() {
                return Err(ErrorCode::INVAL);
            }
            if self.read_entry_id.get() == self.append_entry_id.get() {
                return Err(ErrorCode::FAIL);
            }
            self.storage
                .map(|storage| {
                    let entry_id = self.read_entry_id.get();
                    let offset = self.storage_offset(entry_id);
                    let size = Self::record_length(
                        storage,
                        offset,
                        self.append_entry_id.get().wrapping_sub(entry_id),
                    )?;
                    if size > length || size > buffer.len() {
                        return Err(ErrorCode::SIZE);
                    }
                    Self::copy_out(storage, offset + ENTRY_HEADER_SIZE, &mut buffer[..size]);
                    self.read_entry_id
                        .set(entry_id.wrapping_add(ENTRY_HEADER_SIZE + size));
                    Ok(size)
                })
                .ok_or(ErrorCode::BUSY)?
        });
        match result {
            Ok(size) => {
                self.complete_read(buffer, size);
                Ok(())
            }
            Err(error) => Err((error, buffer)),
        }
    }

    fn log_start(&self) -> EntryID {
        self.oldest_entry_id.get()
    }

    fn log_end(&self) -> EntryID {
        self.append_entry_id.get()
    }

    fn next_read_entry_id(&self) -> EntryID {
        self.read_entry_id.get()
    }

    fn get_size(&self) -> usize {
        self.capacity
    }

    fn seek(&self, entry_id: EntryID) -> Result<(), ErrorCode> {
        self.ready()?;
        if self.read_client.is_none() {
            return Err(ErrorCode::RESERVE);
        }
        self.storage
            .map(|storage| {
                let oldest = self.oldest_entry_id.get();
                let used = self.append_entry_id.get().wrapping_sub(oldest);
                let target = entry_id.wrapping_sub(oldest);
                if target > used {
                    return Err(ErrorCode::INVAL);
                }
                let mut cursor = 0;
                while cursor < target {
                    cursor += ENTRY_HEADER_SIZE
                        + Self::record_length(
                            storage,
                            self.storage_offset(oldest.wrapping_add(cursor)),
                            used - cursor,
                        )?;
                }
                if cursor != target {
                    return Err(ErrorCode::INVAL);
                }
                Ok(())
            })
            .ok_or(ErrorCode::BUSY)??;
        self.read_entry_id.set(entry_id);
        self.state.set(State::Seeking);
        self.deferred_call.set();
        Ok(())
    }
}

impl<'a> LogWrite<'a> for Log<'a> {
    fn set_append_client(&self, client: &'a dyn LogWriteClient) {
        self.append_client.set(client);
    }

    fn append(
        &self,
        buffer: &'static mut [u8],
        length: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        let result = self.ready().and_then(|()| {
            if self.append_client.is_none() {
                return Err(ErrorCode::RESERVE);
            }
            if length == 0 || length > buffer.len() {
                return Err(ErrorCode::INVAL);
            }
            if length > self.capacity - ENTRY_HEADER_SIZE {
                return Err(ErrorCode::SIZE);
            }
            let total = length + ENTRY_HEADER_SIZE;
            let end = self.append_entry_id.get();
            let new_end = end.wrapping_add(total);
            self.storage
                .map(|storage| {
                    let oldest = self.oldest_entry_id.get();
                    let mut start = oldest;
                    let mut used = end.wrapping_sub(start);
                    if !self.circular && used > self.capacity - total {
                        return Err(ErrorCode::FAIL);
                    }
                    while used > self.capacity - total {
                        let size = ENTRY_HEADER_SIZE
                            + Self::record_length(storage, self.storage_offset(start), used)?;
                        start = start.wrapping_add(size);
                        used -= size;
                    }
                    let records_lost = start != oldest;
                    let start_offset = self.storage_offset(start);
                    let end_offset = self.storage_offset(end);
                    Self::copy_in(storage, end_offset, &length.to_ne_bytes());
                    Self::copy_in(storage, end_offset + ENTRY_HEADER_SIZE, &buffer[..length]);
                    self.records_lost.set(records_lost);
                    if self.read_entry_id.get().wrapping_sub(oldest) < start.wrapping_sub(oldest) {
                        self.read_entry_id.set(start);
                    }
                    self.oldest_entry_id.set(start);
                    self.oldest_offset.set(start_offset);
                    self.append_entry_id.set(new_end);
                    Ok(())
                })
                .ok_or(ErrorCode::BUSY)?
        });
        match result {
            Ok(()) => {
                self.buffer.replace(buffer);
                self.length.set(length);
                self.state.set(State::Appending);
                self.deferred_call.set();
                Ok(())
            }
            Err(error) => Err((error, buffer)),
        }
    }

    fn sync(&self) -> Result<(), ErrorCode> {
        // RAM cannot provide the Log HIL's persistence guarantee.
        Err(ErrorCode::NOSUPPORT)
    }

    fn erase(&self) -> Result<(), ErrorCode> {
        self.ready()?;
        if self.append_client.is_none() {
            return Err(ErrorCode::RESERVE);
        }
        self.storage
            .map(|storage| storage.fill(0))
            .ok_or(ErrorCode::BUSY)?;
        self.oldest_entry_id.set(0);
        self.oldest_offset.set(0);
        self.append_entry_id.set(0);
        self.read_entry_id.set(0);
        self.state.set(State::Erasing);
        self.deferred_call.set();
        Ok(())
    }
}

impl DeferredCallClient for Log<'_> {
    fn register(&'static self) {
        self.deferred_call.register(self);
    }

    fn handle_deferred_call(&self) {
        match self.state.replace(State::Idle) {
            State::Reading => {
                if let Some(buffer) = self.buffer.take() {
                    self.read_client
                        .map(|client| client.read_done(buffer, self.length.get(), Ok(())));
                }
            }
            State::Seeking => {
                self.read_client.map(|client| client.seek_done(Ok(())));
            }
            State::Appending => {
                if let Some(buffer) = self.buffer.take() {
                    self.append_client.map(|client| {
                        client.append_done(
                            buffer,
                            self.length.get(),
                            self.records_lost.get(),
                            Ok(()),
                        );
                    });
                }
            }
            State::Erasing => {
                self.append_client.map(|client| client.erase_done(Ok(())));
            }
            State::Idle => {}
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::cell::RefCell;
    use std::{boxed::Box, vec, vec::Vec};

    #[derive(Debug, PartialEq)]
    enum Event {
        Append(usize, bool),
        Read(Vec<u8>),
        Seek,
        Erase,
    }

    struct Client {
        events: RefCell<Vec<Event>>,
        returned: TakeCell<'static, [u8]>,
    }

    impl Default for Client {
        fn default() -> Self {
            Self {
                events: RefCell::new(Vec::new()),
                returned: TakeCell::empty(),
            }
        }
    }

    impl LogReadClient for Client {
        fn read_done(
            &self,
            buffer: &'static mut [u8],
            length: usize,
            result: Result<(), ErrorCode>,
        ) {
            assert_eq!(result, Ok(()));
            self.events
                .borrow_mut()
                .push(Event::Read(buffer[..length].to_vec()));
            self.returned.replace(buffer);
        }

        fn seek_done(&self, result: Result<(), ErrorCode>) {
            assert_eq!(result, Ok(()));
            self.events.borrow_mut().push(Event::Seek);
        }
    }

    impl LogWriteClient for Client {
        fn append_done(
            &self,
            buffer: &'static mut [u8],
            length: usize,
            lost: bool,
            result: Result<(), ErrorCode>,
        ) {
            assert_eq!(result, Ok(()));
            self.events.borrow_mut().push(Event::Append(length, lost));
            self.returned.replace(buffer);
        }

        fn sync_done(&self, _: Result<(), ErrorCode>) {
            panic!("volatile log must not report persistence");
        }

        fn erase_done(&self, result: Result<(), ErrorCode>) {
            assert_eq!(result, Ok(()));
            self.events.borrow_mut().push(Event::Erase);
        }
    }

    fn bytes(value: u8, len: usize) -> &'static mut [u8] {
        Box::leak(vec![value; len].into_boxed_slice())
    }

    fn setup(capacity: usize) -> (&'static Log<'static>, &'static Client) {
        setup_mode(capacity, true)
    }

    fn setup_mode(capacity: usize, circular: bool) -> (&'static Log<'static>, &'static Client) {
        let client = Box::leak(Box::new(Client::default()));
        let log = Box::leak(Box::new(Log::new(bytes(0, capacity), circular)));
        log.set_read_client(client);
        log.set_append_client(client);
        (log, client)
    }

    fn setup_near_rollover(capacity: usize) -> (&'static Log<'static>, &'static Client) {
        let (log, client) = setup(capacity);
        let start = usize::MAX - ENTRY_HEADER_SIZE - 2;
        log.oldest_entry_id.set(start);
        log.append_entry_id.set(start);
        log.read_entry_id.set(start);
        log.oldest_offset.set(capacity - 2);
        (log, client)
    }

    fn append(log: &Log<'_>, value: u8, len: usize) {
        log.append(bytes(value, len), len).unwrap();
        log.handle_deferred_call();
    }

    fn read(log: &Log<'_>, client: &Client, expected: &[u8]) {
        log.read(bytes(0, expected.len()), expected.len()).unwrap();
        log.handle_deferred_call();
        assert_eq!(
            client.events.borrow().last(),
            Some(&Event::Read(expected.to_vec()))
        );
    }

    #[test]
    fn accepted_buffer_is_retained_and_rejected_operations_do_not_move_cursor() {
        let (log, client) = setup(ENTRY_HEADER_SIZE + 32);
        let input = bytes(0x51, 32);
        let original = input.as_ptr();
        log.append(input, 32).unwrap();
        assert!(client.events.borrow().is_empty());
        let other = bytes(0x62, 16);
        let other_ptr = other.as_ptr();
        let (error, other) = log.append(other, 16).unwrap_err();
        assert_eq!(error, ErrorCode::BUSY);
        assert_eq!(other.as_ptr(), other_ptr);
        assert_eq!(log.erase(), Err(ErrorCode::BUSY));
        log.handle_deferred_call();
        assert_eq!(client.returned.take().unwrap().as_ptr(), original);
        assert_eq!(
            client.events.borrow().last(),
            Some(&Event::Append(32, false))
        );

        let position = log.next_read_entry_id();
        let (error, _) = log.read(bytes(0, 31), 31).unwrap_err();
        assert_eq!(error, ErrorCode::SIZE);
        assert_eq!(log.next_read_entry_id(), position);
        assert_eq!(log.seek(position + 1), Err(ErrorCode::INVAL));
        assert_eq!(log.next_read_entry_id(), position);
        read(log, client, &[0x51; 32]);
        assert_eq!(log.read(bytes(0, 32), 32).unwrap_err().0, ErrorCode::FAIL);
    }

    #[test]
    fn circular_wrap_preserves_complete_records_and_reports_loss() {
        let capacity = 3 * ENTRY_HEADER_SIZE + 29;
        let (log, client) = setup(capacity);
        append(log, 1, 13);
        let second = log.log_end();
        append(log, 2, 19);
        append(log, 3, 7);
        assert_eq!(client.events.borrow().last(), Some(&Event::Append(7, true)));
        assert_eq!(log.log_start(), second);
        assert_eq!(log.next_read_entry_id(), second);
        assert_eq!(log.seek(0), Err(ErrorCode::INVAL));
        read(log, client, &[2; 19]);
        read(log, client, &[3; 7]);

        for value in 4..20 {
            append(log, value, capacity - ENTRY_HEADER_SIZE);
            assert_eq!(
                client.events.borrow().last(),
                Some(&Event::Append(capacity - ENTRY_HEADER_SIZE, true))
            );
            read(log, client, &vec![value; capacity - ENTRY_HEADER_SIZE]);
        }
    }

    #[test]
    fn clear_is_partition_local_and_ram_has_no_persistence_sync() {
        let (a, ac) = setup(64);
        let (b, bc) = setup(64);
        append(a, 0x11, 12);
        append(b, 0x22, 12);
        assert_eq!(a.sync(), Err(ErrorCode::NOSUPPORT));
        a.erase().unwrap();
        assert_ne!(ac.events.borrow().last(), Some(&Event::Erase));
        a.handle_deferred_call();
        assert_eq!(ac.events.borrow().last(), Some(&Event::Erase));
        assert_eq!(
            (a.log_start(), a.log_end(), a.next_read_entry_id()),
            (0, 0, 0)
        );
        assert_eq!(a.read(bytes(0, 12), 12).unwrap_err().0, ErrorCode::FAIL);
        read(b, bc, &[0x22; 12]);
        append(a, 0x33, 12);
        read(a, ac, &[0x33; 12]);
    }

    #[test]
    fn invalid_appends_return_the_original_buffer_without_changing_the_log() {
        let (log, client) = setup(ENTRY_HEADER_SIZE + 16);
        for (buffer_len, length, expected) in [
            (16, 0, ErrorCode::INVAL),
            (16, 17, ErrorCode::INVAL),
            (17, 17, ErrorCode::SIZE),
        ] {
            let input = bytes(1, buffer_len);
            let pointer = input.as_ptr();
            let (error, input) = log.append(input, length).unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(input.as_ptr(), pointer);
            assert_eq!(log.log_end(), 0);
        }
        assert!(client.events.borrow().is_empty());
        let (tiny, _) = setup(ENTRY_HEADER_SIZE);
        assert_eq!(tiny.append(bytes(1, 1), 1).unwrap_err().0, ErrorCode::SIZE);
        let unconfigured = Log::new(bytes(0, 64), true);
        assert_eq!(
            unconfigured.append(bytes(1, 1), 1).unwrap_err().0,
            ErrorCode::RESERVE
        );
    }

    #[test]
    fn non_circular_full_log_preserves_records_until_clear() {
        let capacity = 2 * (ENTRY_HEADER_SIZE + 16);
        let (log, client) = setup_mode(capacity, false);
        append(log, 1, 16);
        append(log, 2, 16);
        assert_eq!(log.get_size(), capacity);
        let end = log.log_end();
        let events = client.events.borrow().len();
        let input = bytes(3, 1);
        let pointer = input.as_ptr();
        let (error, input) = log.append(input, 1).unwrap_err();
        assert_eq!(error, ErrorCode::FAIL);
        assert_eq!(input.as_ptr(), pointer);
        assert_eq!(log.log_end(), end);
        assert_eq!(log.log_start(), 0);
        assert_eq!(client.events.borrow().len(), events);
        read(log, client, &[1; 16]);
        read(log, client, &[2; 16]);
        assert_eq!(log.append(bytes(3, 1), 1).unwrap_err().0, ErrorCode::FAIL);
        log.seek(end).unwrap();
        log.handle_deferred_call();
        assert_eq!(log.seek(end + 1), Err(ErrorCode::INVAL));
        log.erase().unwrap();
        log.handle_deferred_call();
        append(log, 3, 16);
        read(log, client, &[3; 16]);
    }

    #[test]
    fn entry_id_rollover_preserves_retained_ids_and_deferred_completion() {
        let (log, client) = setup_near_rollover(3 * ENTRY_HEADER_SIZE + 17);
        let first = log.log_start();
        append(log, 1, 2);
        let second = log.log_end();
        assert_eq!(second, usize::MAX);

        let input = bytes(2, 3);
        let pointer = input.as_ptr();
        let events = client.events.borrow().len();
        log.append(input, 3).unwrap();
        assert_eq!(log.log_start(), first);
        assert_eq!(log.log_end(), ENTRY_HEADER_SIZE + 2);
        assert_eq!(log.next_read_entry_id(), first);
        assert_eq!(client.events.borrow().len(), events);
        assert_eq!(log.seek(first), Err(ErrorCode::BUSY));
        log.handle_deferred_call();
        assert_eq!(client.returned.take().unwrap().as_ptr(), pointer);
        assert_eq!(
            client.events.borrow().last(),
            Some(&Event::Append(3, false))
        );

        let third = log.log_end();
        append(log, 3, 4);
        log.seek(second).unwrap();
        log.handle_deferred_call();
        read(log, client, &[2; 3]);
        assert_eq!(log.next_read_entry_id(), third);
        log.seek(first).unwrap();
        log.handle_deferred_call();
        read(log, client, &[1; 2]);
        assert_eq!(log.next_read_entry_id(), second);
        read(log, client, &[2; 3]);
        read(log, client, &[3; 4]);
        let end = log.log_end();
        log.seek(end).unwrap();
        log.handle_deferred_call();
        assert_eq!(log.read(bytes(0, 4), 4).unwrap_err().0, ErrorCode::FAIL);

        append(log, 4, 5);
        assert_eq!(log.next_read_entry_id(), end);
        read(log, client, &[4; 5]);
    }

    #[test]
    fn rollover_evictions_advance_only_evicted_cursors_and_reject_stale_ids() {
        let capacity = 2 * ENTRY_HEADER_SIZE + 7;
        let (log, client) = setup_near_rollover(capacity);
        let first = log.log_start();
        append(log, 1, 2);
        let second = log.log_end();
        append(log, 2, 3);
        let third = log.log_end();
        append(log, 3, 4);
        assert_eq!(log.log_start(), second);
        assert_eq!(log.next_read_entry_id(), second);
        assert_eq!(client.events.borrow().last(), Some(&Event::Append(4, true)));
        assert_eq!(log.seek(first), Err(ErrorCode::INVAL));
        read(log, client, &[2; 3]);
        assert_eq!(log.next_read_entry_id(), third);

        let fourth = log.log_end();
        append(log, 4, 1);
        assert_eq!(log.log_start(), third);
        assert_eq!(log.next_read_entry_id(), third);
        assert_eq!(log.seek(second), Err(ErrorCode::INVAL));
        assert_eq!(log.seek(third + 1), Err(ErrorCode::INVAL));
        read(log, client, &[3; 4]);
        read(log, client, &[4]);

        log.seek(third).unwrap();
        log.handle_deferred_call();
        let fifth = log.log_end();
        append(log, 5, capacity - ENTRY_HEADER_SIZE);
        assert_eq!(log.log_start(), fifth);
        assert_eq!(log.next_read_entry_id(), fifth);
        assert_eq!(log.seek(third), Err(ErrorCode::INVAL));
        assert_eq!(log.seek(fourth), Err(ErrorCode::INVAL));
        read(log, client, &vec![5; capacity - ENTRY_HEADER_SIZE]);
        append(log, 6, 2);
        read(log, client, &[6; 2]);

        log.erase().unwrap();
        log.handle_deferred_call();
        append(log, 7, 3);
        read(log, client, &[7; 3]);
    }

    #[test]
    fn invalid_operations_across_rollover_leave_storage_and_cursors_unchanged() {
        let capacity = 2 * ENTRY_HEADER_SIZE + 7;
        let (log, client) = setup_near_rollover(capacity);
        append(log, 1, 2);
        append(log, 2, 3);
        let positions = (log.log_start(), log.log_end(), log.next_read_entry_id());
        let storage = log.storage.map(|storage| storage.to_vec()).unwrap();
        let events = client.events.borrow().len();
        for (buffer_len, length, expected) in [
            (1, 0, ErrorCode::INVAL),
            (1, 2, ErrorCode::INVAL),
            (capacity, capacity, ErrorCode::SIZE),
        ] {
            let input = bytes(3, buffer_len);
            let pointer = input.as_ptr();
            let (error, input) = log.append(input, length).unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(input.as_ptr(), pointer);
        }
        assert_eq!(log.seek(positions.0.wrapping_sub(1)), Err(ErrorCode::INVAL));
        assert_eq!(log.seek(positions.0 + 1), Err(ErrorCode::INVAL));
        assert_eq!(log.seek(0), Err(ErrorCode::INVAL));
        assert_eq!(log.seek(positions.1 + 1), Err(ErrorCode::INVAL));
        let output = bytes(0x55, 1);
        let pointer = output.as_ptr();
        let (error, output) = log.read(output, 1).unwrap_err();
        assert_eq!(error, ErrorCode::SIZE);
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(output, &[0x55]);
        assert_eq!(
            (log.log_start(), log.log_end(), log.next_read_entry_id()),
            positions
        );
        assert_eq!(
            log.storage.map(|storage| storage.to_vec()).unwrap(),
            storage
        );
        assert_eq!(log.state.get(), State::Idle);
        log.handle_deferred_call();
        assert_eq!(client.events.borrow().len(), events);
        read(log, client, &[1; 2]);
        read(log, client, &[2; 3]);
    }
}
