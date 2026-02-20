// Licensed under the Apache-2.0 license

use core::mem;

use caliptra_api::{
    calc_checksum,
    mailbox::{MailboxReqHeader, MailboxRespHeader},
    CaliptraApiError, SocManager,
};
use registers_generated::{mbox, soc};
use ureg::RealMmioMut;
use zerocopy::{FromBytes, IntoBytes};

const MAILBOX_SIZE: usize = 256 * 1024;
pub struct CaliptraSoC {
    _private: (), // ensure that this struct cannot be instantiated directly except through new
    counter: u64,
    soc_ifc_addr: *mut u32,
    soc_ifc_trng_addr: *mut u32,
    soc_mbox_addr: *mut u32,
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
        ureg::RealMmioMut::default()
    }

    /// Provides a delay function to be invoked when polling mailbox status.
    fn delay(&mut self) {
        self.counter = core::hint::black_box(self.counter) + 1;
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
            counter: 0,
            soc_ifc_addr: soc_ifc_addr.unwrap_or(soc::SOC_IFC_REG_ADDR) as *mut u32,
            soc_ifc_trng_addr: soc_ifc_trng_addr.unwrap_or(soc::SOC_IFC_REG_ADDR) as *mut u32,
            soc_mbox_addr: soc_mbox_addr.unwrap_or(mbox::MBOX_CSR_ADDR) as *mut u32,
        }
    }

    pub fn is_mailbox_busy(&mut self) -> bool {
        self.soc_mbox().status().read().status().cmd_busy()
    }

    /// Send a command to the mailbox but don't wait for the response
    pub fn start_mailbox_req(
        &mut self,
        cmd: u32,
        len_bytes: usize,
        buf: impl Iterator<Item = u32>,
    ) -> core::result::Result<(), CaliptraApiError> {
        if len_bytes > MAILBOX_SIZE {
            return Err(CaliptraApiError::BufferTooLargeForMailbox);
        }

        self.lock_mailbox()?;

        self.set_command(cmd, len_bytes)?;

        for word in buf {
            self.soc_mbox().datain().write(|_| word);
        }

        // Ask Caliptra to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    pub fn initiate_request(
        &mut self,
        cmd: u32,
        len_bytes: usize,
    ) -> core::result::Result<(), CaliptraApiError> {
        if len_bytes > MAILBOX_SIZE {
            return Err(CaliptraApiError::BufferTooLargeForMailbox);
        }

        self.lock_mailbox()?;

        self.set_command(cmd, len_bytes)?;

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
        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the PAUSER check or some other issue
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

    /// Finished a mailbox request, validating the checksum of the response.
    pub fn finish_mailbox_resp(
        &mut self,
        resp_min_size: usize,
        resp_size: usize,
    ) -> core::result::Result<Option<CaliptraMailboxResponse>, CaliptraApiError> {
        if resp_size < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }
        if resp_min_size < mem::size_of::<MailboxRespHeader>() {
            return Err(CaliptraApiError::MailboxRespTypeTooSmall);
        }

        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = Self::MAX_WAIT_CYCLES; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.delay();
            timeout_cycles -= 1;
            if timeout_cycles == 0 {
                return Err(CaliptraApiError::MailboxTimeout);
            }
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            let soc_ifc = self.soc_ifc();
            return Err(CaliptraApiError::MailboxCmdFailed(
                if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                    soc_ifc.cptra_fw_error_fatal().read()
                } else {
                    soc_ifc.cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(CaliptraApiError::UnknownCommandStatus(status as u32));
        }

        let dlen_bytes = self.soc_mbox().dlen().read();

        let expected_checksum = self.soc_mbox().dataout().read();

        Ok(Some(CaliptraMailboxResponse {
            soc_mbox: self.soc_mbox(),
            idx: 0,
            dlen_bytes: dlen_bytes as usize,
            checksum: 0,
            expected_checksum,
        }))
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

        // Stream header + all data parts to the mailbox.
        let iter = hdr
            .iter()
            .copied()
            .chain(data_parts.iter().flat_map(|p| p.iter().copied()));
        self.start_mailbox_req(cmd, total_bytes, iter)?;
        let resp_len_bytes = resp.len() * 4;
        match self.finish_mailbox_resp(resp_len_bytes, resp_len_bytes) {
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

        let header = MailboxReqHeader::mut_from_bytes(header_bytes as &mut [u8]).unwrap();
        header.chksum = calc_checksum(cmd, payload_bytes);

        self.start_mailbox_req(cmd, req.len() * 4, req.iter().copied())?;
        let resp_len_bytes = resp.len() * 4;
        match self.finish_mailbox_resp(resp_len_bytes, resp_len_bytes) {
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
