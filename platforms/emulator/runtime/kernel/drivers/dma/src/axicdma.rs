// Licensed under the Apache-2.0 license

// This is a driver for the  AMD LogiCORE IP AXI Central Direct Memory Access (CDMA) core.
// Reference: https://docs.amd.com/r/en-US/pg034-axi-cdma
// This driver only supports simple transfer mode.

use core::cell::RefCell;

use capsules_core::virtualizers::virtual_alarm::{MuxAlarm, VirtualMuxAlarm};
use capsules_runtime::dma::hil::{Dma, DmaClient, DmaError, DmaRoute, DmaStatus};
use kernel::hil::time::{Alarm, AlarmClient, Time};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;
use registers_generated::axicdma::{bits::*, regs::*, AXICDMA_ADDR};

pub const DMA_CTRL_BASE: StaticRef<Axicdma> =
    unsafe { StaticRef::new(AXICDMA_ADDR as *const Axicdma) };

pub struct AxiCDMA<'a, A: Alarm<'a>> {
    registers: StaticRef<Axicdma>,
    dma_client: OptionalCell<&'a dyn DmaClient>,
    btt: RefCell<u32>,
    use_interrupt: bool,
    alarm: Option<VirtualMuxAlarm<'a, A>>,
}

impl<'a, A: Alarm<'a>> AxiCDMA<'a, A> {
    pub fn new(
        base: StaticRef<Axicdma>,
        use_interrupt: bool,
        alarm: Option<&'a MuxAlarm<'a, A>>,
    ) -> AxiCDMA<'a, A> {
        AxiCDMA {
            registers: base,
            dma_client: OptionalCell::empty(),
            btt: RefCell::new(0),
            use_interrupt,
            alarm: alarm.map(|a| VirtualMuxAlarm::new(a)),
        }
    }

    pub fn init(&'static self) {
        self.reset();
        self.clear_error_interrupt();
        self.clear_event_interrupt();

        if let Some(alarm) = &self.alarm {
            alarm.setup();
            alarm.set_alarm_client(self);
        }
    }

    fn enable_interrupts(&self) {
        self.registers
            .axicdma_control
            .modify(AxicdmaControl::ErrIrqEn::SET + AxicdmaControl::IocIrqEn::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .axicdma_control
            .modify(AxicdmaControl::ErrIrqEn::CLEAR + AxicdmaControl::IocIrqEn::CLEAR);
    }

    fn reset(&self) {
        // Reset the DMA controller. Write 1 to reset
        self.registers
            .axicdma_control
            .modify(AxicdmaControl::Reset::SET);
        while self.registers.axicdma_control.is_set(AxicdmaControl::Reset) {}
    }

    fn clear_error_interrupt(&self) {
        // Clear the error interrupt. Write 1 to clear
        self.registers
            .axicdma_status
            .modify(AxicdmaStatus::IrqError::SET);
    }

    fn clear_event_interrupt(&self) {
        // Clear the event interrupt. Write 1 to clear
        self.registers
            .axicdma_status
            .modify(AxicdmaStatus::IrqIoc::SET);
    }

    pub fn handle_interrupt(&self) {
        let dmactrl_intr = self.registers.axicdma_status.extract();
        self.disable_interrupts();

        // Handling error interrupt
        if dmactrl_intr.is_set(AxicdmaStatus::IrqError) {
            self.clear_error_interrupt();
            self.dma_client.map(move |client| {
                client.transfer_error(DmaError::AxiWriteError);
            });
        }

        // Handling event interrupt (normal completion)
        if dmactrl_intr.is_set(AxicdmaStatus::IrqIoc) {
            self.clear_event_interrupt();
            self.dma_client.map(move |client| {
                client.transfer_complete(DmaStatus::TxnDone);
            });
        }
    }

    fn schedule_alarm(&self) {
        if let Some(alarm) = &self.alarm {
            let now = alarm.now();
            let dt = A::Ticks::from(20000);
            alarm.set_alarm(now, dt);
        }
    }
}

impl<'a, A: Alarm<'a>> Dma for AxiCDMA<'a, A> {
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
        if !self.registers.axicdma_status.is_set(AxicdmaStatus::Idle) {
            // DMA is not idle
            return Err(ErrorCode::BUSY);
        }

        if self.use_interrupt {
            self.enable_interrupts();
        }

        // Set the source and destination addresses
        self.registers
            .axicdma_src_addr
            .set(src_addr.unwrap() as u32);
        self.registers
            .axicdma_src_addr_msb
            .set((src_addr.unwrap() >> 32) as u32);
        self.registers
            .axicdma_dst_addr
            .set(dest_addr.unwrap() as u32);
        self.registers
            .axicdma_dst_addr_msb
            .set((dest_addr.unwrap() >> 32) as u32);

        // Set the transfer size
        *self.btt.borrow_mut() = byte_count as u32;

        Ok(())
    }

    fn start_transfer(
        &self,
        read_route: DmaRoute,
        write_route: DmaRoute,
        _fixed_addr: bool,
    ) -> Result<(), ErrorCode> {
        if read_route != DmaRoute::AxiToAxi {
            // Only AxiToAxi route is supported
            return Err(ErrorCode::INVAL);
        }
        if write_route != DmaRoute::AxiToAxi {
            // Only AxiToAxi route is supported
            return Err(ErrorCode::INVAL);
        }
        if !self.registers.axicdma_status.is_set(AxicdmaStatus::Idle) {
            // DMA is not idle
            return Err(ErrorCode::BUSY);
        }

        self.registers
            .axicdma_bytes_to_transfer
            .set(*self.btt.borrow());

        if !self.use_interrupt {
            self.schedule_alarm();
        }
        Ok(())
    }

    fn poll_status(&self) -> Result<DmaStatus, DmaError> {
        // Read the op_status register
        let op_status = self.registers.axicdma_status.extract();
        if op_status.is_set(AxicdmaStatus::Idle) {
            return Ok(DmaStatus::TxnDone);
        }
        if op_status.is_set(AxicdmaStatus::ErrInternal)
            || op_status.is_set(AxicdmaStatus::ErrSlave)
            || op_status.is_set(AxicdmaStatus::ErrDecode)
        {
            return Err(DmaError::CommandError);
        }
        Ok(DmaStatus::RdFifoNotEmpty)
    }

    fn write_fifo(&self, _data: &[u8]) -> Result<(), DmaError> {
        Err(DmaError::CommandError)
    }

    fn read_fifo(&self, _buffer: &mut [u8]) -> Result<usize, DmaError> {
        Err(DmaError::CommandError)
    }

    fn set_client(&self, client: &'static dyn DmaClient) {
        self.dma_client.set(client);
    }
}

impl<'a, A: Alarm<'a>> AlarmClient for AxiCDMA<'a, A> {
    fn alarm(&self) {
        match self.poll_status() {
            Ok(DmaStatus::TxnDone) => {
                self.dma_client.map(move |client| {
                    client.transfer_complete(DmaStatus::TxnDone);
                });
                self.disable_interrupts();
            }
            Ok(_) => {
                self.schedule_alarm();
            }
            Err(_e) => {
                self.dma_client.map(move |client| {
                    client.transfer_error(DmaError::AxiWriteError);
                });
                self.disable_interrupts();
            }
        }
    }
}
