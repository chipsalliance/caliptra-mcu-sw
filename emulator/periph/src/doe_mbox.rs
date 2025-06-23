// Licensed under the Apache-2.0 license
use caliptra_emu_bus::{Clock, ReadWriteRegister, Timer};
use caliptra_emu_cpu::Irq;
use emulator_registers_generated::doe_mbox::DoeMboxPeripheral;
use registers_generated::doe_mbox::bits::{DoeMboxEvent, DoeMboxStatus};
use std::sync::{Arc, Mutex};
use tock_registers::interfaces::{Readable, Writeable};

use std::thread;

pub struct DummyDoeMbox {
    timer: Timer,
    event_irq: Irq,
    last_irq_status: bool,
    periph: DoeMboxPeriph,
}

struct PollScheduler {
    timer: Timer,
}

impl IncomingDoeMboxWrite for PollScheduler {
    fn incoming(&self) {
        println!("Incoming write to DOE mailbox detected, scheduling poll.");
        // trigger interrupt check next tick
        self.timer.schedule_poll_in(1);
    }
}
pub trait IncomingDoeMboxWrite {
    fn incoming(&self);
}

impl DummyDoeMbox {
    const DOE_MBOX_TICKS: u64 = 1000; // Example value, adjust as needed
    pub fn new(clock: &Clock, event_irq: Irq, mut periph: DoeMboxPeriph) -> Self {
        let timer = Timer::new(clock);
        timer.schedule_poll_in(Self::DOE_MBOX_TICKS);
        let poll_scheduler = PollScheduler {
            timer: timer.clone(),
        };
        periph.set_incoming_write_client(Arc::new(poll_scheduler));

        DummyDoeMbox {
            timer,
            event_irq,
            last_irq_status: false,
            periph,
        }
    }
}

impl DoeMboxPeripheral for DummyDoeMbox {
    fn poll(&mut self) {
        let irq_status = self.periph.inner.lock().unwrap().check_interrupts();
        if self.last_irq_status != irq_status {
            // No change in IRQ status, no need to reschedule
            println!(
                "DOE mailbox interrupt triggered {}. thread id: {:?}",
                irq_status,
                thread::current().id()
            );
            self.last_irq_status = irq_status;
        }
        self.event_irq.set_level(irq_status);
        self.timer.schedule_poll_in(Self::DOE_MBOX_TICKS);
    }

    fn read_doe_mbox_dlen(&mut self) -> caliptra_emu_types::RvData {
        self.periph.inner.lock().unwrap().mbox_dlen.reg.get()
    }
    fn write_doe_mbox_dlen(&mut self, val: caliptra_emu_types::RvData) {
        self.periph.inner.lock().unwrap().mbox_dlen.reg.set(val);
    }

    fn read_doe_mbox_status(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::doe_mbox::bits::DoeMboxStatus::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.periph.inner.lock().unwrap().mbox_status.reg.get(),
        )
    }

    fn write_doe_mbox_status(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::doe_mbox::bits::DoeMboxStatus::Register,
        >,
    ) {
        println!(
            "DOE_MBOX_BUS: Bus Writing to status register: {:#x}",
            val.reg.get()
        );

        // Simple: STATUS register uses normal read/write semantics
        // MCU can set and clear bits explicitly by writing the desired value
        self.periph
            .inner
            .lock()
            .unwrap()
            .mbox_status
            .reg
            .set(val.reg.get());
    }

    fn read_doe_mbox_event(
        &mut self,
    ) -> caliptra_emu_bus::ReadWriteRegister<
        u32,
        registers_generated::doe_mbox::bits::DoeMboxEvent::Register,
    > {
        caliptra_emu_bus::ReadWriteRegister::new(
            self.periph.inner.lock().unwrap().mbox_event.reg.get(),
        )
    }

    fn write_doe_mbox_event(
        &mut self,
        val: caliptra_emu_bus::ReadWriteRegister<
            u32,
            registers_generated::doe_mbox::bits::DoeMboxEvent::Register,
        >,
    ) {
        println!(
            "DOE_MBOX_BUS: Bus Writing to event register: {:#x}",
            val.reg.get()
        );
        self.periph
            .inner
            .lock()
            .unwrap()
            .write_to_event_register(val);
        self.timer.schedule_poll_in(1);
    }

    fn read_doe_mbox_sram(&mut self, index: usize) -> caliptra_emu_types::RvData {
        self.periph.inner.lock().unwrap().read_doe_sram(index)
    }

    fn write_doe_mbox_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        self.periph.inner.lock().unwrap().write_doe_sram(val, index);
    }
}

#[derive(Default, Clone)]
pub struct DoeMboxPeriph {
    inner: Arc<Mutex<DoeMboxInner>>,
    incoming_write_client: Arc<Mutex<Option<Arc<dyn IncomingDoeMboxWrite + Send + Sync>>>>,
}

impl DoeMboxPeriph {
    pub fn set_incoming_write_client(
        &mut self,
        client: Arc<dyn IncomingDoeMboxWrite + Send + Sync>,
    ) {
        *self.incoming_write_client.lock().unwrap() = Some(client);
    }

    pub fn reset(&mut self) {
        self.inner.lock().unwrap().reset();
    }

    pub fn write_data(&mut self, data: Vec<u8>) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if data.len() > inner.max_sram_dword_size * 4 {
            return Err(format!(
                "invalida data length: {} bytes exceeds maximum allowed size: {} bytes",
                data.len(),
                inner.max_sram_dword_size * 4
            ));
        }
        // Write the data to SRAM as u32 words, chunking every 4 bytes
        for (word_idx, chunk) in data.chunks(4).enumerate() {
            let mut buf = [0u8; 4];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            let word = u32::from_le_bytes(buf);
            inner.write_doe_sram(word, word_idx);
        }
        let data_len = data.len() / 4;
        inner.mbox_dlen.reg.set(data_len as u32);
        inner.set_event_data_ready();

        if let Some(client) = self.incoming_write_client.lock().unwrap().clone() {
            client.incoming();
        }

        println!(
            "DOE_MBOX_FSM: Data written successfully, length: {} words",
            data_len
        );
        Ok(())
    }

    pub fn request_reset(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        // PERIPHERAL LOGIC: Set EVENT.RESET_REQ bit
        inner.set_event_reset_req();

        if let Some(client) = self.incoming_write_client.lock().unwrap().clone() {
            client.incoming();
        }

        println!("DOE_MBOX_FSM: Reset request sent.");
    }

    pub fn read_data(&self) -> Result<Option<Vec<u8>>, String> {
        let mut inner = self.inner.lock().unwrap();
        let status = inner.mbox_status.reg.get();

        if status == 0 {
            return Ok(None);
        }
        println!("DOE_MBOX_FSM: Checking status: {:#x}", status);

        if status & DoeMboxStatus::DataReady::SET.value != 0 {
            // Data is ready to be read
            // NOTE: SoC reads the data but MCU is responsible
            // for clearing STATUS.DATA_READY via explicit bus write.
            // SoC should NOT clear this bit directly.
            // So, use emulator peripheral logic to clear it
            inner.clear_status_data_ready();

            let data_len = inner.mbox_dlen.reg.get() as usize;
            println!("DOE_MBOX_FSM: Reading data of length: {} words", data_len);
            let data = (0..data_len)
                .flat_map(|i| inner.read_doe_sram(i).to_le_bytes())
                .collect::<Vec<u8>>();

            Ok(Some(data))
        } else if status & DoeMboxStatus::Error::SET.value != 0 {
            // NOTE: Similar to DATA_READY, ERROR should be cleared by MCU via bus write
            // The peripheral logic will clear the bits
            inner.clear_status_error();
            Err("Doe Mailbox error occurred".to_string())
        } else {
            Ok(None)
        }
    }

    pub fn check_reset_ack(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let status = inner.mbox_status.reg.get();
        if status & DoeMboxStatus::ResetAck::SET.value != 0 {
            // Clear the RESET_ACK bit
            inner.clear_status_reset_ack();
            println!("DOE_MBOX_PERIPH: Reset acknowledged.");
            inner.reset(); // Reset the mailbox state
            true
        } else {
            false
        }
    }
}

struct DoeMboxInner {
    mbox_sram: Vec<u32>,
    max_sram_dword_size: usize,
    mbox_dlen: ReadWriteRegister<u32>,
    mbox_event: ReadWriteRegister<u32, DoeMboxEvent::Register>,
    mbox_status: ReadWriteRegister<u32, DoeMboxStatus::Register>,
}

impl Default for DoeMboxInner {
    fn default() -> Self {
        Self::new()
    }
}

impl DoeMboxInner {
    fn new() -> Self {
        DoeMboxInner {
            mbox_sram: Vec::new(),
            max_sram_dword_size: (1 << 18), // Example size, adjust as needed
            mbox_dlen: ReadWriteRegister::new(0),
            mbox_event: ReadWriteRegister::new(0),
            mbox_status: ReadWriteRegister::new(0),
        }
    }

    fn reset(&mut self) {
        // Reset the mailbox registers to their initial state
        self.mbox_dlen.reg.set(0);
        self.mbox_event.reg.set(0);
        self.mbox_status.reg.set(0);
        self.mbox_sram.clear(); // Clear the SRAM
    }

    fn check_interrupts(&mut self) -> bool {
        // Check if any relevant bits (DataReady or ResetReq) are set in the event register
        let event_val = self.mbox_event.reg.get();
        // println!(
        //     "DOE_MBOX_PERIPH: Checking interrupts, event value: {:#x}",
        //     event_val
        // );
        (event_val & DoeMboxEvent::DataReady::SET.value != 0)
            || (event_val & DoeMboxEvent::ResetReq::SET.value != 0)
    }

    fn read_doe_sram(&self, index: usize) -> caliptra_emu_types::RvData {
        if index >= self.max_sram_dword_size {
            panic!("Index out of bounds for DOE mailbox SRAM");
        }

        if index < self.mbox_sram.len() {
            self.mbox_sram[index]
        } else {
            0 // Return 0 if the index is beyond the current size
        }
    }

    fn write_doe_sram(&mut self, val: caliptra_emu_types::RvData, index: usize) {
        if index >= self.max_sram_dword_size {
            panic!("Index out of bounds for DOE mailbox SRAM");
        }

        if index < self.mbox_sram.len() {
            self.mbox_sram[index] = val;
        } else {
            // Extend the SRAM vector if necessary
            self.mbox_sram.resize(index + 1, 0);
            self.mbox_sram[index] = val;
        }
    }

    // Bus write operations (w1c clearing) - only for EVENT register
    pub fn write_to_event_register(&mut self, val: ReadWriteRegister<u32, DoeMboxEvent::Register>) {
        let current = self.mbox_event.reg.get();
        let write_val = val.reg.get();
        let new_val = current & !write_val; // w1c: writing 1 clears the bit
        self.mbox_event.reg.set(new_val);
        println!(
            "Bus w1c EVENT: wrote {:#x}, {:#x} -> {:#x}",
            write_val, current, new_val
        );
    }

    // Internal peripheral logic for SETTING EVENT bits and clearing the STATUS bits (not bus operations)
    pub fn set_event_data_ready(&mut self) {
        let current = self.mbox_event.reg.get();
        self.mbox_event
            .reg
            .set(current | DoeMboxEvent::DataReady::SET.value);
        println!(
            "DOE_MBOX_PERIPH: Set EVENT.DATA_READY, new value: {:#x}",
            self.mbox_event.reg.get()
        );
    }

    pub fn set_event_reset_req(&mut self) {
        let current = self.mbox_event.reg.get();
        self.mbox_event
            .reg
            .set(current | DoeMboxEvent::ResetReq::SET.value);
        println!(
            "DOE_MBOX_PERIPH: Set EVENT.RESET_REQ, new value: {:#x}",
            self.mbox_event.reg.get()
        );
    }

    pub fn clear_status_data_ready(&mut self) {
        let current = self.mbox_status.reg.get();
        self.mbox_status
            .reg
            .set(current & !DoeMboxStatus::DataReady::SET.value);
        println!(
            "DOE_MBOX_PERIPH: Cleared STATUS.DATA_READY, new value: {:#x}",
            self.mbox_status.reg.get()
        );
    }

    pub fn clear_status_error(&mut self) {
        let current = self.mbox_status.reg.get();
        self.mbox_status
            .reg
            .set(current & !DoeMboxStatus::Error::SET.value);
        println!(
            "DOE_MBOX_PERIPH: Cleared STATUS.ERROR, new value: {:#x}",
            self.mbox_status.reg.get()
        );
    }

    pub fn clear_status_reset_ack(&mut self) {
        let current = self.mbox_status.reg.get();
        self.mbox_status
            .reg
            .set(current & !DoeMboxStatus::ResetAck::SET.value);
        println!(
            "DOE_MBOX_PERIPH: Cleared STATUS.RESET_ACK, new value: {:#x}",
            self.mbox_status.reg.get()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::McuRootBus;
    use caliptra_emu_bus::{Bus, Clock};
    use caliptra_emu_cpu::Pic;
    use caliptra_emu_types::RvSize;
    use emulator_registers_generated::root_bus::AutoRootBus;
    use registers_generated::doe_mbox::bits::{DoeMboxEvent, DoeMboxStatus};
    use registers_generated::doe_mbox::DOE_MBOX_ADDR;

    const DOE_MBOX_BASE_ADDR: u32 = DOE_MBOX_ADDR as u32;
    const DOE_MBOX_DLEN_REG_OFFSET: u32 = 0x04;
    const DOE_MBOX_STATUS_REG_OFFSET: u32 = 0x08;
    const DOE_MBOX_EVENT_REG_OFFSET: u32 = 0x0C;

    const DOE_MBOX_SRAM_BASE_ADDR: u32 = DOE_MBOX_BASE_ADDR + 0x1000;

    fn test_helper_setup_autobus(clock: &Clock) -> AutoRootBus {
        let pic = Pic::new();
        let doe_event_irq = pic.register_irq(McuRootBus::DOE_MBOX_EVENT_IRQ);

        let doe_periph = DoeMboxPeriph {
            inner: Arc::new(Mutex::new(DoeMboxInner::new())),
            incoming_write_client: Arc::new(Mutex::new(None)),
        };

        let doe_mbox = Box::new(DummyDoeMbox::new(clock, doe_event_irq, doe_periph));

        AutoRootBus::new(
            vec![],
            None,
            None,
            None,
            None,
            None,
            Some(doe_mbox),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_doe_mbox_data() {
        let dummy_clock = Clock::new();
        let mut autobus = test_helper_setup_autobus(&dummy_clock);
        let data_word_len = 100;
        // Write to the DOE SRAM
        let data: Vec<u32> = (0..data_word_len).collect();
        for (i, &word) in data.iter().enumerate() {
            autobus
                .write(
                    RvSize::Word,
                    DOE_MBOX_SRAM_BASE_ADDR + i as u32 * 4,
                    word as u32,
                )
                .unwrap();
        }

        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_DLEN_REG_OFFSET,
                data_word_len as u32,
            )
            .unwrap();

        let read_word_len = autobus
            .read(RvSize::Word, DOE_MBOX_BASE_ADDR + DOE_MBOX_DLEN_REG_OFFSET)
            .unwrap();
        assert_eq!(read_word_len, data_word_len as u32);

        // Read the DOE SRAM for read_word_len size and compare each word with the data
        for i in 0..read_word_len as usize {
            let read_word = autobus
                .read(RvSize::Word, DOE_MBOX_SRAM_BASE_ADDR + i as u32 * 4)
                .unwrap();
            assert_eq!(read_word, data[i]);
        }
    }

    #[test]
    fn test_doe_mbox_event() {
        let dummy_clock = Clock::new();
        let mut autobus = test_helper_setup_autobus(&dummy_clock);
        // DOE driver writes to the event register to clear data ready event
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,
                DoeMboxEvent::DataReady::SET.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(RvSize::Word, DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,)
                .unwrap(),
            DoeMboxEvent::DataReady::CLEAR.value
        );

        // Clear the event register
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,
                DoeMboxEvent::DataReady::CLEAR.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(RvSize::Word, DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,)
                .unwrap(),
            DoeMboxEvent::DataReady::CLEAR.value
        );

        // DOE Driver writes 1 to event register to clear the reset request event
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,
                DoeMboxEvent::ResetReq::SET.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(RvSize::Word, DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,)
                .unwrap(),
            DoeMboxEvent::ResetReq::CLEAR.value
        );
    }

    #[test]
    fn test_doe_mbox_status() {
        let dummy_clock = Clock::new();
        let mut autobus = test_helper_setup_autobus(&dummy_clock);

        // Doe driver writes the status register to indicate the response is ready
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::DataReady::SET.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::DataReady::SET.value
        );

        // Clear the data ready status
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::DataReady::CLEAR.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::DataReady::CLEAR.value
        );

        // Set the status register to indicate an reset ack
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::ResetAck::SET.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::ResetAck::SET.value
        );

        // Clear the reset ack status
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::ResetAck::CLEAR.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::ResetAck::CLEAR.value
        );

        // Set the status register to indicate an error
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::Error::SET.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::Error::SET.value
        );

        // Clear the error status
        autobus
            .write(
                RvSize::Word,
                DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                DoeMboxStatus::Error::CLEAR.value,
            )
            .unwrap();
        assert_eq!(
            autobus
                .read(
                    RvSize::Word,
                    DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET,
                )
                .unwrap(),
            DoeMboxStatus::Error::CLEAR.value
        );
    }

    // #[test]
    // // fn test_doe_mbox_req_resp_success() {
    // //     let dummy_clock = Clock::new();
    // //     let mut autobus = test_helper_setup_autobus(&dummy_clock);

    // //     // check to see if the status register is clear
    // //     assert_eq!(
    // //         autobus
    // //             .read(
    // //                 RvSize::Word,
    // //                 DOE_MBOX_BASE_ADDR + DOE_MBOX_STATUS_REG_OFFSET
    // //             )
    // //             .unwrap(),
    // //         0
    // //     );

    // //     // write to the DOE SRAM
    // //     let data: Vec<u32> = (0..100).collect();
    // //     for (i, &word) in data.iter().enumerate() {
    // //         autobus
    // //             .write(
    // //                 RvSize::Word,
    // //                 DOE_MBOX_SRAM_BASE_ADDR + i as u32 * 4,
    // //                 word as u32,
    // //             )
    // //             .unwrap();
    // //     }

    // //     // write the data length register
    // //     autobus
    // //         .write(
    // //             RvSize::Word,
    // //             DOE_MBOX_BASE_ADDR + DOE_MBOX_DLEN_REG_OFFSET,
    // //             data.len() as u32,
    // //         )
    // //         .unwrap();

    // //     // Set the event register to indicate data is ready
    // //     autobus
    // //         .write(
    // //             RvSize::Word,
    // //             DOE_MBOX_BASE_ADDR + DOE_MBOX_EVENT_REG_OFFSET,
    // //             DoeMboxEvent::DataReady::SET.value,
    // //         )
    // //         .unwrap();

    // //     // write the event register to indicate data is ready
    // // }
}
