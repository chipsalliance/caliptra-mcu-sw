// Licensed under the Apache-2.0 license

// Dma controller driver for the dummy dma controller in the emulator.

use crate::hil::{DMAClient, DMAError};
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::registers::interfaces::{ReadWriteable, Readable, Writeable};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;
use registers_generated::dma_ctrl::{bits::*, regs::*, DMA_CTRL_ADDR};

pub const DMA_CTRL_BASE: StaticRef<DmaCtrl> =
    unsafe { StaticRef::new(DMA_CTRL_ADDR as *const DmaCtrl) };

pub struct EmulatedDmaCtrl<'a> {
    registers: StaticRef<DmaCtrl>,
    dma_client: OptionalCell<&'a dyn DMAClient>,
}

impl<'a> EmulatedDmaCtrl<'a> {
    pub fn new(base: StaticRef<DmaCtrl>) -> EmulatedDmaCtrl<'a> {
        EmulatedDmaCtrl {
            registers: base,
            dma_client: OptionalCell::empty(),
        }
    }

    pub fn init(&self) {
        self.registers
            .dma_op_status
            .modify(DmaOpStatus::Err::CLEAR + DmaOpStatus::Done::CLEAR);

        self.clear_error_interrupt();
        self.clear_event_interrupt();
    }

    fn enable_interrupts(&self) {
        self.registers
            .dma_interrupt_enable
            .modify(DmaInterruptEnable::Error::SET + DmaInterruptEnable::Event::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .dma_interrupt_enable
            .modify(DmaInterruptEnable::Error::CLEAR + DmaInterruptEnable::Event::CLEAR);
    }

    fn clear_error_interrupt(&self) {
        // Clear the error interrupt. Write 1 to clear
        self.registers
            .dma_interrupt_state
            .modify(DmaInterruptState::Error::SET);
    }

    fn clear_event_interrupt(&self) {
        // Clear the event interrupt. Write 1 to clear
        self.registers
            .dma_interrupt_state
            .modify(DmaInterruptState::Event::SET);
    }

    pub fn handle_interrupt(&self) {
        let dmactrl_intr = self.registers.dma_interrupt_state.extract();
        self.disable_interrupts();

        // Handling error interrupt
        if dmactrl_intr.is_set(DmaInterruptState::Error) {
            // Read the op_status register
            let op_status = self.registers.dma_op_status.extract();

            // Clear the op_status register
            self.registers.dma_op_status.modify(DmaOpStatus::Err::CLEAR);

            self.clear_error_interrupt();

            if op_status.is_set(DmaOpStatus::Err) {
                self.dma_client.map(move |client| {
                    client.transfer_error(DMAError::AxiWriteError);
                });
            } else {
                self.dma_client.map(move |client| {
                    client.transfer_error(DMAError::AxiReadError);
                });
            }
        }

        // Handling event interrupt (normal completion)
        if dmactrl_intr.is_set(DmaInterruptState::Event) {
            // Clear the op_status register
            self.registers
                .dma_op_status
                .modify(DmaOpStatus::Done::CLEAR);

            // Clear the interrupt before callback as it is possible that the callback will start another operation.
            // Otherwise, emulated dma ctrl won't allow starting another operation if the previous one is not cleared.
            self.clear_event_interrupt();

            self.dma_client.map(move |client| {
                client.transfer_complete(crate::hil::DMAStatus::TxnDone);
            });
        }
    }
}

impl crate::hil::DMA for EmulatedDmaCtrl<'_> {
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

        // Set the source and destination addresses
        self.registers
            .source_addr_lower
            .set(src_addr.unwrap() as u32);
        self.registers
            .source_addr_high
            .set((src_addr.unwrap() >> 32) as u32);
        self.registers
            .dest_addr_lower
            .set(dest_addr.unwrap() as u32);
        self.registers
            .dest_addr_high
            .set((dest_addr.unwrap() >> 32) as u32);

        // Set the transfer size
        self.registers.xfer_size.set(byte_count as u32);

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
        self.enable_interrupts();
        self.registers.dma_control.modify(DmaControl::Start::SET);
        Ok(())
    }

    fn poll_status(&self) -> Result<crate::hil::DMAStatus, DMAError> {
        // Read the op_status register
        let op_status = self.registers.dma_op_status.extract();
        if op_status.is_set(DmaOpStatus::Done) {
            return Ok(crate::hil::DMAStatus::TxnDone);
        }
        if op_status.is_set(DmaOpStatus::Err) {
            return Err(DMAError::CommandError);
        }
        Ok(crate::hil::DMAStatus::RdFifoNotEmpty)
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
