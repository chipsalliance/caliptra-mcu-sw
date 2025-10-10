// Licensed under the Apache-2.0 license

// This is placeholder DMA driver that does not perform any real DMA operation.
// It simply copies data from source to destination in software when a transfer
// is started. This is useful for platforms that do not have a DMA controller
// or for testing purposes.

use core::cell::RefCell;

use crate::hil::{DMAClient, DMAError};
use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

pub struct NoDMA<'a, A: Alarm<'a>> {
    dma_client: OptionalCell<&'a dyn DMAClient>,
    src_addr: RefCell<u32>,
    dest_addr: RefCell<u32>,
    btt: RefCell<u32>,
    busy: RefCell<bool>,
    alarm: VirtualMuxAlarm<'a, A>,
}

impl<'a, A: Alarm<'a>> NoDMA<'a, A> {
    pub fn new(alarm: &'a MuxAlarm<'a, A>) -> NoDMA<'a, A> {
        NoDMA {
            dma_client: OptionalCell::empty(),
            src_addr: RefCell::new(0),
            dest_addr: RefCell::new(0),
            btt: RefCell::new(0),
            busy: RefCell::new(false),
            alarm: VirtualMuxAlarm::new(alarm),
        }
    }

    pub fn init(&'static self) {
        self.alarm.setup();
        self.alarm.set_alarm_client(self);
    }

    fn schedule_alarm(&self) {
        let now = self.alarm.now();
        let dt = A::Ticks::from(10000);
        self.alarm.set_alarm(now, dt);
    }
}

impl<'a, A: Alarm<'a>> crate::hil::DMA for NoDMA<'a, A> {
    fn configure_transfer(
        &self,
        byte_count: usize,
        block_size: usize,
        src_addr: Option<u64>,
        dest_addr: Option<u64>,
    ) -> Result<(), ErrorCode> {
        // Check if the parameters are valid
        if byte_count == 0 || block_size == 0 || block_size > byte_count {
            return Err(ErrorCode::INVAL);
        }

        // Check if the addresses are valid
        if src_addr.is_none() || dest_addr.is_none() {
            return Err(ErrorCode::INVAL);
        }
        if *self.busy.borrow() {
            return Err(ErrorCode::BUSY);
        }

        // Set the source and destination addresses
        self.src_addr.replace(src_addr.unwrap() as u32);
        self.dest_addr.replace(dest_addr.unwrap() as u32);

        // Set the transfer size
        *self.btt.borrow_mut() = byte_count as u32;

        Ok(())
    }

    fn start_transfer(
        &self,
        read_route: crate::hil::DmaRoute,
        write_route: crate::hil::DmaRoute,
        _fixed_addr: bool,
    ) -> Result<(), ErrorCode> {
        if read_route != crate::hil::DmaRoute::AxiToAxi {
            // Only AxiToAxi route is supported
            return Err(ErrorCode::INVAL);
        }
        if write_route != crate::hil::DmaRoute::AxiToAxi {
            // Only AxiToAxi route is supported
            return Err(ErrorCode::INVAL);
        }
        if *self.busy.borrow() {
            return Err(ErrorCode::BUSY);
        }

        self.busy.replace(true);
        self.schedule_alarm();

        Ok(())
    }

    fn poll_status(&self) -> Result<crate::hil::DMAStatus, DMAError> {
        // Not supported
        Err(DMAError::CommandError)
    }

    fn write_fifo(&self, _data: &[u8]) -> Result<(), DMAError> {
        Err(DMAError::CommandError)
    }

    fn read_fifo(&self, _buffer: &mut [u8]) -> Result<usize, DMAError> {
        Err(DMAError::CommandError)
    }

    fn set_client(&self, client: &'static dyn DMAClient) {
        self.dma_client.set(client);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for NoDMA<'a, A> {
    fn alarm(&self) {
        // Do the transfer
        if !*self.busy.borrow() {
            return;
        }

        let btt = *self.btt.borrow();
        let src_addr = *self.src_addr.borrow();
        let dest_addr = *self.dest_addr.borrow();
        if btt & 0x3 == 0 && src_addr & 0x3 == 0 && dest_addr & 0x3 == 0 {
            // If everything is word aligned, transfer in words
            for offset in (0..btt).step_by(4) {
                let src_ptr = (src_addr + offset) as *const u32;
                let dst_ptr = (dest_addr + offset) as *mut u32;
                unsafe {
                    let value = core::ptr::read_volatile(src_ptr);
                    core::ptr::write_volatile(dst_ptr, value);
                }
            }
            *self.busy.borrow_mut() = false;
            self.dma_client.map(move |client| {
                client.transfer_complete(crate::hil::DMAStatus::TxnDone);
            });
            return;
        } else {
            // Transfer in bytes since src or dest may not be word aligned
            for offset in 0..(*self.btt.borrow()) {
                let src_ptr = self.src_addr.borrow().wrapping_add(offset) as *const u8;
                let dst_ptr = self.dest_addr.borrow().wrapping_add(offset) as *mut u8;
                unsafe {
                    let value = core::ptr::read_volatile(src_ptr);
                    core::ptr::write_volatile(dst_ptr, value);
                }
            }
        }

        *self.busy.borrow_mut() = false;
        self.dma_client.map(move |client| {
            client.transfer_complete(crate::hil::DMAStatus::TxnDone);
        });
    }
}
