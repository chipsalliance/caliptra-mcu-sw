// Licensed under the Apache-2.0 license

use core::{marker::PhantomData, mem};

use caliptra_api::{
    calc_checksum,
    mailbox::{MailboxReqHeader, MailboxRespHeader},
    CaliptraApiError, SocManager,
};
use caliptra_mcu_registers_generated::{mbox, soc};
use caliptra_ureg::RealMmioMut;
use zerocopy::{FromBytes, IntoBytes};

const MAILBOX_SIZE: usize = 256 * 1024;
pub struct CaliptraSoC {
    _private: (), // ensure that this struct cannot be instantiated directly except through new
    soc_ifc_addr: *mut u32,
    soc_ifc_trng_addr: *mut u32,
    soc_mbox_addr: *mut u32,
}

/// Mailbox lock acquired, but no command has been programmed yet.
pub struct MailboxLocked;

/// Mailbox command and payload length have been programmed and data can be sent.
pub struct MailboxSending;

/// Mailbox command has been executed and is waiting for completion/response.
pub struct MailboxExecuting;

/// Typestate guard for a Caliptra mailbox transaction.
///
/// The guard holds a mutable borrow of [`CaliptraSoC`] for the whole mailbox
/// transaction, so a second transaction cannot be started while one is alive.
/// Dropping the guard clears the execute bit, releasing the hardware lock even
/// on early-return error paths.
pub struct MailboxSession<'a, State> {
    soc: Option<&'a mut CaliptraSoC>,
    _state: PhantomData<State>,
}

impl<'a, State> MailboxSession<'a, State> {
    fn new(soc: &'a mut CaliptraSoC) -> Self {
        Self {
            soc: Some(soc),
            _state: PhantomData,
        }
    }

    fn soc(&mut self) -> &mut CaliptraSoC {
        match self.soc.as_deref_mut() {
            Some(soc) => soc,
            None => unsafe {
                // SAFETY: `soc` is only taken when a session is consumed by
                // `detach`, `abort`, `transition`, or `finish_blocking_with`.
                // All methods that call this helper require ownership of an
                // active session value that has not been consumed.
                core::hint::unreachable_unchecked()
            },
        }
    }

    fn transition<Next>(mut self) -> MailboxSession<'a, Next> {
        MailboxSession {
            soc: self.soc.take(),
            _state: PhantomData,
        }
    }

    /// Stop managing the hardware lock with this guard.
    ///
    /// This is only used by the legacy split-phase API, where the command is
    /// started by one method and completed by a later [`CaliptraSoC::finish_mailbox_resp`]
    /// call. New code should keep the typestate guard alive instead.
    fn detach(mut self) {
        let _ = self.soc.take();
    }

    /// Abort the transaction and return the underlying SoC handle.
    pub fn abort(mut self) -> &'a mut CaliptraSoC {
        let soc = match self.soc.take() {
            Some(soc) => soc,
            None => unsafe {
                // SAFETY: `abort` consumes the session, and sessions expose no
                // API that can call `abort` after their SoC handle was already
                // taken.
                core::hint::unreachable_unchecked()
            },
        };
        soc.abort_request();
        soc
    }
}

impl<State> Drop for MailboxSession<'_, State> {
    fn drop(&mut self) {
        if let Some(soc) = self.soc.as_deref_mut() {
            soc.abort_request();
        }
    }
}

impl<'a> MailboxSession<'a, MailboxLocked> {
    /// Program the command and payload length, transitioning to the sending state.
    pub fn set_command(
        mut self,
        cmd: u32,
        payload_len_bytes: usize,
    ) -> core::result::Result<MailboxSession<'a, MailboxSending>, CaliptraApiError> {
        self.soc().set_command(cmd, payload_len_bytes)?;
        Ok(self.transition())
    }
}

impl<'a> MailboxSession<'a, MailboxSending> {
    /// Write one 32-bit payload word while the mailbox is in the sending state.
    pub fn write_data(&mut self, data: u32) -> core::result::Result<(), CaliptraApiError> {
        self.soc().write_data(data)
    }

    /// Write all payload words while the mailbox is in the sending state.
    pub fn write_data_iter(
        &mut self,
        buf: impl Iterator<Item = u32>,
    ) -> core::result::Result<(), CaliptraApiError> {
        for word in buf {
            self.write_data(word)?;
        }
        Ok(())
    }

    /// Ask Caliptra to execute the programmed command.
    pub fn execute(
        self,
    ) -> core::result::Result<MailboxSession<'a, MailboxExecuting>, CaliptraApiError> {
        self.try_execute().map_err(|(err, _session)| err)
    }

    /// Ask Caliptra to execute the programmed command, returning the sending
    /// session on failure so async owners can recover the underlying SoC handle.
    pub fn try_execute(
        mut self,
    ) -> core::result::Result<MailboxSession<'a, MailboxExecuting>, (CaliptraApiError, Self)> {
        match self.soc().execute_command() {
            Ok(()) => Ok(self.transition()),
            Err(err) => Err((err, self)),
        }
    }
}

impl<'a> MailboxSession<'a, MailboxExecuting> {
    /// Return true while Caliptra is still processing this mailbox command.
    pub fn is_busy(&mut self) -> bool {
        self.soc().is_mailbox_busy()
    }

    /// Finish a blocking mailbox request, validating the response shape before returning it.
    ///
    /// If a response is returned, the response object owns the lock-release responsibility.
    /// Otherwise this session releases the lock before returning.
    pub fn finish_blocking(
        mut self,
        resp_min_size: usize,
        resp_size: usize,
    ) -> core::result::Result<Option<CaliptraMailboxResponse<'a>>, CaliptraApiError> {
        let result = finish_mailbox_resp_locked(self.soc(), resp_min_size, resp_size);
        if matches!(result, Ok(Some(_))) {
            // The response now owns the mailbox register block and will release
            // the lock when dropped.
            self.detach();
        }
        result
    }

    /// Finish a blocking request and process the response before returning the
    /// SoC handle to the caller.
    ///
    /// This supports async owners, such as the runtime mailbox capsule, that
    /// store the typestate session across callbacks but must eventually recover
    /// the underlying [`CaliptraSoC`] handle for the next transaction.
    pub fn finish_blocking_with<R>(
        mut self,
        resp_min_size: usize,
        resp_size: usize,
        f: impl FnOnce(
            Option<CaliptraMailboxResponse<'static>>,
        ) -> core::result::Result<R, CaliptraApiError>,
    ) -> (
        &'a mut CaliptraSoC,
        core::result::Result<R, CaliptraApiError>,
    ) {
        let result = finish_mailbox_resp_locked(self.soc(), resp_min_size, resp_size).and_then(f);
        let soc = match self.soc.take() {
            Some(soc) => soc,
            None => unsafe {
                // SAFETY: this method consumes an active executing session and
                // takes the SoC handle exactly once before returning it.
                core::hint::unreachable_unchecked()
            },
        };
        (soc, result)
    }
}

impl SocManager for CaliptraSoC {
    // we override the methods that use these
    const SOC_MBOX_ADDR: u32 = 0;
    const SOC_IFC_ADDR: u32 = 0;
    const SOC_IFC_TRNG_ADDR: u32 = 0;

    /// Maximum number of wait cycles.
    const MAX_WAIT_CYCLES: u32 = 400_000;

    /// Type alias for mutable memory-mapped I/O.
    type TMmio<'a> = RealMmioMut<'a>;

    /// Returns a mutable reference to the memory-mapped I/O.
    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        caliptra_ureg::RealMmioMut::default()
    }

    /// Provides a delay function to be invoked when polling mailbox status.
    fn delay(&mut self) {
        core::hint::spin_loop();
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                self.soc_ifc_addr,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral TRNG registers
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc_trng(&mut self) -> caliptra_registers::soc_ifc_trng::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                self.soc_ifc_trng_addr,
                self.mmio_mut(),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<Self::TMmio<'_>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                self.soc_mbox_addr,
                self.mmio_mut(),
            )
        }
    }
}

impl CaliptraSoC {
    pub fn new(
        soc_ifc_addr: Option<u32>,
        soc_ifc_trng_addr: Option<u32>,
        soc_mbox_addr: Option<u32>,
    ) -> Self {
        CaliptraSoC {
            _private: (),
            soc_ifc_addr: soc_ifc_addr.unwrap_or(soc::SOC_IFC_REG_ADDR) as *mut u32,
            soc_ifc_trng_addr: soc_ifc_trng_addr.unwrap_or(soc::SOC_IFC_REG_ADDR) as *mut u32,
            soc_mbox_addr: soc_mbox_addr.unwrap_or(mbox::MBOX_CSR_ADDR) as *mut u32,
        }
    }

    pub fn is_mailbox_busy(&mut self) -> bool {
        self.soc_mbox().status().read().status().cmd_busy()
    }

    fn soc_mbox_response(
        &mut self,
    ) -> caliptra_registers::mbox::RegisterBlock<RealMmioMut<'static>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                self.soc_mbox_addr,
                RealMmioMut::default(),
            )
        }
    }

    /// Acquire the hardware mailbox lock and return a typestate session guard.
    ///
    /// The returned guard releases the mailbox lock on drop unless ownership is
    /// transferred to a response object.
    pub fn acquire_mailbox(
        &mut self,
    ) -> core::result::Result<MailboxSession<'_, MailboxLocked>, CaliptraApiError> {
        self.lock_mailbox()?;
        Ok(MailboxSession::new(self))
    }

    /// Acquire the mailbox and program a command, returning a sending session.
    pub fn start_mailbox_session(
        &mut self,
        cmd: u32,
        len_bytes: usize,
    ) -> core::result::Result<MailboxSession<'_, MailboxSending>, CaliptraApiError> {
        self.try_start_mailbox_session(cmd, len_bytes)
            .map_err(|(err, _soc)| err)
    }

    /// Acquire the mailbox and program a command, returning the SoC handle on
    /// failure so async owners can put it back into their idle storage.
    pub fn try_start_mailbox_session(
        &mut self,
        cmd: u32,
        len_bytes: usize,
    ) -> core::result::Result<MailboxSession<'_, MailboxSending>, (CaliptraApiError, &mut Self)>
    {
        if len_bytes > MAILBOX_SIZE {
            return Err((CaliptraApiError::BufferTooLargeForMailbox, self));
        }

        // Read a 0 to get the hardware lock. Do this before constructing the
        // session so the error path can still return the SoC handle.
        if self.soc_mbox().lock().read().lock() {
            return Err((CaliptraApiError::UnableToLockMailbox, self));
        }

        let mut session: MailboxSession<'_, MailboxLocked> = MailboxSession::new(self);
        match session.soc().set_command(cmd, len_bytes) {
            Ok(()) => Ok(session.transition()),
            Err(err) => Err((err, session.abort())),
        }
    }

    /// Send a command to the mailbox but don't wait for the response
    pub fn start_mailbox_req(
        &mut self,
        cmd: u32,
        len_bytes: usize,
        buf: impl Iterator<Item = u32>,
    ) -> core::result::Result<(), CaliptraApiError> {
        let mut session = self.start_mailbox_session(cmd, len_bytes)?;
        session.write_data_iter(buf)?;
        // This split-phase API intentionally returns before the response is
        // ready. Detach the executing session so the later finish_mailbox_resp()
        // call owns releasing the hardware lock.
        session.execute()?.detach();
        Ok(())
    }

    pub fn initiate_request(
        &mut self,
        cmd: u32,
        len_bytes: usize,
    ) -> core::result::Result<(), CaliptraApiError> {
        // The runtime capsule's chunked syscall flow writes data and executes
        // in later syscalls, so this method must keep the legacy split-phase
        // surface. Still acquire and program the mailbox through the typestate
        // API so the lock->command transition is checked in one place.
        self.start_mailbox_session(cmd, len_bytes)?.detach();
        Ok(())
    }

    pub fn lock_mailbox(&mut self) -> core::result::Result<(), CaliptraApiError> {
        // Read a 0 to get the lock
        if self.soc_mbox().lock().read().lock() {
            Err(CaliptraApiError::UnableToLockMailbox)
        } else {
            Ok(())
        }
    }

    pub fn set_command(
        &mut self,
        cmd: u32,
        payload_len_bytes: usize,
    ) -> core::result::Result<(), CaliptraApiError> {
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }

        self.soc_mbox().cmd().write(|_| cmd);

        self.soc_mbox().dlen().write(|_| payload_len_bytes as u32);
        Ok(())
    }

    pub fn write_data(&mut self, data: u32) -> core::result::Result<(), CaliptraApiError> {
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }
        self.soc_mbox().datain().write(|_| data);
        Ok(())
    }

    pub fn execute_command(&mut self) -> core::result::Result<(), CaliptraApiError> {
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(CaliptraApiError::UnableToLockMailbox);
        }
        self.soc_mbox().execute().write(|w| w.execute(true));
        Ok(())
    }

    /// Aborts a mailbox request by clearing the execute bit, releasing the HW lock.
    pub fn abort_request(&mut self) {
        self.soc_mbox().execute().write(|w| w.execute(false));
    }

    /// Finished a mailbox request, validating the checksum of the response.
    pub fn finish_mailbox_resp(
        &mut self,
        resp_min_size: usize,
        resp_size: usize,
    ) -> core::result::Result<Option<CaliptraMailboxResponse>, CaliptraApiError> {
        finish_mailbox_resp_locked(self, resp_min_size, resp_size)
    }

    /// Executes a mailbox request assembled from a mutable header and
    /// read-only `&[u32]` payload parts. The header's first word (the
    /// [`MailboxReqHeader`] checksum) is computed automatically. The payload
    /// parts are concatenated after the header in order.
    ///
    /// This avoids copying large buffers (e.g. MLDSA keys/signatures) onto the
    /// stack — the caller can pass references to wherever the data already
    /// lives (SRAM, flash, etc.).  All slices are `&[u32]` because the MCI
    /// mailbox SRAM may not be byte-addressable.
    pub fn exec_mailbox_req_u32_parts(
        &mut self,
        cmd: u32,
        hdr: &mut [u32],
        data_parts: &[&[u32]],
        resp: &mut [u32],
    ) -> core::result::Result<(), CaliptraApiError> {
        if hdr.is_empty() {
            return Err(CaliptraApiError::MailboxReqTypeTooSmall);
        }

        // Compute total length in bytes.
        let mut total_words: usize = hdr.len();
        let mut pi = 0;
        while pi < data_parts.len() {
            total_words += data_parts[pi].len();
            pi += 1;
        }
        let total_bytes = total_words * 4;

        // Compute checksum: sum every byte of cmd and all payload bytes
        // (everything after the 4-byte MailboxReqHeader checksum field).
        // We sum by decomposing u32 words into their LE bytes.
        fn sum_word_bytes(word: u32) -> u32 {
            let b = word.to_le_bytes();
            (b[0] as u32)
                .wrapping_add(b[1] as u32)
                .wrapping_add(b[2] as u32)
                .wrapping_add(b[3] as u32)
        }
        let mut chksum = sum_word_bytes(cmd);
        // Header: skip word 0 (the checksum slot)
        let mut wi = 1;
        while wi < hdr.len() {
            chksum = chksum.wrapping_add(sum_word_bytes(hdr[wi]));
            wi += 1;
        }
        // Data parts: sum all words
        pi = 0;
        while pi < data_parts.len() {
            wi = 0;
            while wi < data_parts[pi].len() {
                chksum = chksum.wrapping_add(sum_word_bytes(data_parts[pi][wi]));
                wi += 1;
            }
            pi += 1;
        }
        let chksum = 0u32.wrapping_sub(chksum);

        // Write checksum into the header (first u32).
        hdr[0] = chksum;

        // Stream header + all data parts to the mailbox through the typestate
        // session so this blocking helper is typed from lock through response.
        let mut session = self.start_mailbox_session(cmd, total_bytes)?;
        session.write_data_iter(
            hdr.iter()
                .copied()
                .chain(data_parts.iter().flat_map(|p| p.iter().copied())),
        )?;
        let session = session.execute()?;

        let resp_len_bytes = resp.len() * 4;
        match session.finish_blocking(resp_len_bytes, resp_len_bytes) {
            Ok(Some(mut resp_iter)) => {
                for (i, r) in resp_iter.by_ref().enumerate() {
                    if i < resp.len() {
                        resp[i] = r;
                    }
                }
                resp_iter.verify_checksum()?;
                Ok(())
            }
            Err(err) => Err(err),
            _ => Err(CaliptraApiError::MailboxNoResponseData),
        }
    }

    /// Executes a mailbox request that is represented as a u32 slice and
    /// writing the response to a u32 slice.
    /// This is useful for code size to avoid unaligned and byte-level access,
    /// when possible.
    pub fn exec_mailbox_req_u32(
        &mut self,
        cmd: u32,
        req: &mut [u32],
        resp: &mut [u32],
    ) -> core::result::Result<(), CaliptraApiError> {
        if req.len() * 4 < core::mem::size_of::<MailboxReqHeader>() {
            return Err(CaliptraApiError::MailboxReqTypeTooSmall);
        }

        let (header_bytes, payload_bytes) = req
            .as_mut_bytes()
            .split_at_mut(core::mem::size_of::<MailboxReqHeader>());

        let Ok(header) = MailboxReqHeader::mut_from_bytes(header_bytes as &mut [u8]) else {
            return Err(CaliptraApiError::MailboxReqTypeTooSmall);
        };
        header.chksum = calc_checksum(cmd, payload_bytes);

        let mut session = self.start_mailbox_session(cmd, req.len() * 4)?;
        session.write_data_iter(req.iter().copied())?;
        let session = session.execute()?;

        let resp_len_bytes = resp.len() * 4;
        match session.finish_blocking(resp_len_bytes, resp_len_bytes) {
            Ok(Some(mut resp_iter)) => {
                for (i, r) in resp_iter.by_ref().enumerate() {
                    if i < resp.len() {
                        resp[i] = r;
                    }
                }
                resp_iter.verify_checksum()?;
                Ok(())
            }
            Err(err) => Err(err),
            _ => Err(CaliptraApiError::MailboxNoResponseData),
        }
    }

    pub fn read_vendor_pk_hash(&mut self) -> [u32; 12] {
        self.soc_ifc().fuse_vendor_pk_hash().read()
    }
}

fn finish_mailbox_resp_locked(
    soc: &mut CaliptraSoC,
    resp_min_size: usize,
    resp_size: usize,
) -> core::result::Result<Option<CaliptraMailboxResponse<'static>>, CaliptraApiError> {
    if resp_size < mem::size_of::<MailboxRespHeader>() {
        return Err(CaliptraApiError::MailboxRespTypeTooSmall);
    }
    if resp_min_size < mem::size_of::<MailboxRespHeader>() {
        return Err(CaliptraApiError::MailboxRespTypeTooSmall);
    }

    // Wait for the microcontroller to finish executing
    let mut timeout_cycles = CaliptraSoC::MAX_WAIT_CYCLES; // 100ms @400MHz
    while soc.soc_mbox().status().read().status().cmd_busy() {
        soc.delay();
        timeout_cycles -= 1;
        if timeout_cycles == 0 {
            soc.abort_request();
            return Err(CaliptraApiError::MailboxTimeout);
        }
    }
    let status = soc.soc_mbox().status().read().status();
    if status.cmd_failure() {
        soc.abort_request();
        let soc_ifc = soc.soc_ifc();
        return Err(CaliptraApiError::MailboxCmdFailed(
            if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                soc_ifc.cptra_fw_error_fatal().read()
            } else {
                soc_ifc.cptra_fw_error_non_fatal().read()
            },
        ));
    }
    if status.cmd_complete() {
        soc.abort_request();
        return Ok(None);
    }
    if !status.data_ready() {
        soc.abort_request();
        return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
    }

    let dlen_bytes = soc.soc_mbox().dlen().read();

    let expected_checksum = soc.soc_mbox().dataout().read();

    Ok(Some(CaliptraMailboxResponse {
        soc_mbox: soc.soc_mbox_response(),
        idx: 0,
        dlen_bytes: dlen_bytes as usize,
        checksum: 0,
        expected_checksum,
    }))
}

pub struct CaliptraMailboxResponse<'a> {
    soc_mbox: caliptra_registers::mbox::RegisterBlock<RealMmioMut<'a>>,
    idx: usize,
    dlen_bytes: usize,
    checksum: u32,
    expected_checksum: u32,
}

impl CaliptraMailboxResponse<'_> {
    pub fn verify_checksum(&self) -> Result<(), CaliptraApiError> {
        let checksum = 0u32.wrapping_sub(self.checksum);
        if checksum == self.expected_checksum {
            Ok(())
        } else {
            Err(CaliptraApiError::MailboxRespInvalidChecksum {
                expected: self.expected_checksum,
                actual: checksum,
            })
        }
    }

    pub fn len(&self) -> usize {
        self.dlen_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.dlen_bytes == 0
    }
}

impl Iterator for CaliptraMailboxResponse<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.dlen_bytes.div_ceil(4) {
            None
        } else if self.idx == 0 {
            self.idx += 1;
            Some(self.expected_checksum)
        } else {
            self.idx += 1;
            let data = self.soc_mbox.dataout().read();

            // Calculate the remaining bytes to process
            let remaining_bytes = self.dlen_bytes.saturating_sub((self.idx - 1) * 4);

            // Mask invalid bytes if this is the last chunk and not a full 4 bytes
            let valid_data = if remaining_bytes < 4 {
                data & ((1 << (remaining_bytes * 8)) - 1) // Mask only the valid bytes
            } else {
                data
            };

            // Update the checksum with only the valid bytes
            for x in valid_data.to_le_bytes().iter().take(remaining_bytes) {
                self.checksum = self.checksum.wrapping_add(*x as u32);
            }

            Some(valid_data)
        }
    }
}

impl Drop for CaliptraMailboxResponse<'_> {
    fn drop(&mut self) {
        // Release the lock
        self.soc_mbox.execute().write(|w| w.execute(false));
    }
}
