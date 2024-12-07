/*++

Licensed under the Apache-2.0 license.

File Name:

    spi_host.rs

Abstract:

    File contains SPI host emulation

--*/

use std::collections::VecDeque;
use std::convert::TryInto;

use emulator_bus::ReadWriteRegisterArray;
use emulator_bus::{
    ActionHandle, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer, WriteOnlyRegister,
};
use emulator_derive::Bus;
use emulator_types::{RvData, RvSize};
use tock_registers::fields::FieldValue;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

use crate::spi_flash::{self, IoMode, SpiByte, SpiFlashOutReq};
use crate::spi_host::Command::LEN;
use crate::spi_host::Status::RXEMPTY;

use self::Command::{CSAAT, DIRECTION, SPEED};
use self::Status::{ACTIVE, CMDQD, RXQD, RXWM, TXFULL, TXQD, TXWM};
use crate::spi_flash::SpiFlash;

use self::Control::{OUTPUT_EN, RX_WATERMARK, SPIEN, TX_WATERMARK};

register_bitfields! [
    u32,

    /// Interrupt Status
    InterruptState [
        ERROR OFFSET(0) NUMBITS(1) [],
        SPI_EVENT OFFSET(1) NUMBITS(1) [],
    ],

    /// Interrupt Enable
    InterruptEnable [
        ERROR OFFSET(0) NUMBITS(1) [],
        SPI_EVENT OFFSET(1) NUMBITS(1) [],
    ],

    /// Interrupt Test
    InterruptTest [
        ERROR OFFSET(0) NUMBITS(1) [],
        SPI_EVENT OFFSET(1) NUMBITS(1) [],
    ],

    /// Alert Test
    AlertTest [
        FATAL_FAULT OFFSET(0) NUMBITS(1) [],
    ],

    /// Control
    Control [
        RX_WATERMARK OFFSET(0) NUMBITS(8) [],
        TX_WATERMARK OFFSET(8) NUMBITS(8) [],
        OUTPUT_EN OFFSET(29) NUMBITS(1) [],
        SW_RST OFFSET(30) NUMBITS(1) [],
        SPIEN OFFSET(31) NUMBITS(1) [],
    ],

    /// Status
    Status [
        TXQD OFFSET(0) NUMBITS(8) [],
        RXQD OFFSET(8) NUMBITS(8) [],
        CMDQD OFFSET(16) NUMBITS(4) [],
        RXWM OFFSET(20) NUMBITS(1) [],
        BYTEORDER OFFSET(22) NUMBITS(1) [],
        RXSTALL OFFSET(23) NUMBITS(1) [],
        RXEMPTY OFFSET(24) NUMBITS(1) [],
        RXFULL OFFSET(25) NUMBITS(1) [],
        TXWM OFFSET(26) NUMBITS(1) [],
        TXSTALL OFFSET(27) NUMBITS(1) [],
        TXEMPTY OFFSET(28) NUMBITS(1) [],
        TXFULL OFFSET(29) NUMBITS(1) [],
        ACTIVE OFFSET(30) NUMBITS(1) [],
        READY OFFSET(31) NUMBITS(1) [],
    ],

    /// Configopts
    Configopts [
        CLKDIV OFFSET(0) NUMBITS(16) [],
        CSNIDLE OFFSET(16) NUMBITS(4) [],
        CSNTRAIL OFFSET(20) NUMBITS(4) [],
        CSNLEAD OFFSET(24) NUMBITS(4) [],
        FULLCYC OFFSET(29) NUMBITS(1) [],
        CPHA OFFSET(30) NUMBITS(1) [],
        CPOL OFFSET(31) NUMBITS(1) [],
    ],

    /// Command
    Command [
        LEN OFFSET(0) NUMBITS(9) [],
        CSAAT OFFSET(9) NUMBITS(1) [],
        SPEED OFFSET(10) NUMBITS(2) [
            SINGLE_IO = 0x0,
            DUAL_IO = 0x1,
            QUAD_IO = 0x3,
        ],
        DIRECTION OFFSET(12) NUMBITS(2) [
            DUMMY = 0x0,
            RX = 0x1,
            TX = 0x2,
            RX_TX = 0x3,
        ],
    ],

    /// Error Enable
    ErrorEnable [
        CMDBUSY OFFSET(0) NUMBITS(1) [],
        OVERFLOW OFFSET(1) NUMBITS(1) [],
    ],

    /// Error Status
    ErrorStatus [
        CMDBUSY OFFSET(0) NUMBITS(1) [],
        OVERFLOW OFFSET(1) NUMBITS(1) [],
        UNDERFLOW OFFSET(2) NUMBITS(1) [],
        CMDINVAL OFFSET(3) NUMBITS(1) [],
        CSIDINVAL OFFSET(4) NUMBITS(1) [],
        ACCESSINVAL OFFSET(5) NUMBITS(1) [],
    ],

    /// Event Enable
    EventEnable [
        RXFULL OFFSET(0) NUMBITS(1) [],
        TXEMPTY OFFSET(1) NUMBITS(1) [],
        RXWM OFFSET(2) NUMBITS(1) [],
        TXWN OFFSET(3) NUMBITS(1) [],
        READY OFFSET(4) NUMBITS(1) [],
        IDLE OFFSET(5) NUMBITS(1) [],
    ],

];

/// SPI host peripheral
#[derive(Bus)]
#[poll_fn(bus_poll)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct SpiHost {
    /// Interrupt State
    #[register(offset = 0x00)]
    interrupt_state: ReadWriteRegister<u32, InterruptState::Register>,

    /// Interrupt Enable
    #[register(offset = 0x04)]
    interrupt_enable: ReadWriteRegister<u32, InterruptEnable::Register>,

    /// Interrupt Test
    #[register(offset = 0x08)]
    interrupt_test: WriteOnlyRegister<u32, InterruptTest::Register>,

    /// Alert Test
    #[register(offset = 0x0c)]
    alert_test: WriteOnlyRegister<u32, AlertTest::Register>,

    /// Control
    #[register(offset = 0x10, write_fn = on_write_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    /// Status
    #[register(offset = 0x14, read_fn = on_read_status)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// Configopts
    #[register_array(offset = 0x18)]
    configopts: ReadWriteRegisterArray<u32, 2, Configopts::Register>,

    /// CSID
    #[register(offset = 0x20)]
    csid: ReadWriteRegister<u32>,

    /// Command
    #[register(offset = 0x24, write_fn = on_write_command)]
    command: WriteOnlyRegister<u32, Command::Register>,

    /// RxData
    #[register(offset = 0x28, read_fn = on_read_rx_data)]
    rxdata: ReadOnlyRegister<u32>,

    /// TxData
    #[register(offset = 0x2c, write_fn = on_write_tx_data)]
    txdata: WriteOnlyRegister<u32>,

    /// Error Enable
    #[register(offset = 0x30)]
    error_enable: ReadWriteRegister<u32, ErrorEnable::Register>,

    #[register(offset = 0x34)]
    error_status: ReadWriteRegister<u32, ErrorStatus::Register>,

    #[register(offset = 0x38)]
    event_enable: ReadWriteRegister<u32, EventEnable::Register>,

    /// CS state
    cs_low: bool,

    /// TXFIFO
    tx_fifo: VecDeque<u8>,

    /// RXFIFO
    rx_fifo: VecDeque<u8>,

    /// Segments
    segments: VecDeque<u32>,

    /// Timer
    timer: Timer,

    ready: Option<ActionHandle>,

    command_complete: Option<ActionHandle>,

    time_pass: Option<ActionHandle>,

    /// Spi Flash 0
    flash0: SpiFlash,
}

impl SpiHost {
    const POLL_TIME: u64 = 1000;
    const TX_RX_FIFO_SIZE_BYTES: usize = 1024;
    const CMD_Q_SIZE: usize = 16;

    pub fn new(clock: &Clock) -> Self {
        Self {
            interrupt_state: ReadWriteRegister::new(0),
            interrupt_enable: ReadWriteRegister::new(0),
            interrupt_test: WriteOnlyRegister::new(0),
            alert_test: WriteOnlyRegister::new(0),
            control: ReadWriteRegister::new(0x7f),
            status: ReadOnlyRegister::new(0x400000),
            configopts: ReadWriteRegisterArray::new(0),
            csid: ReadWriteRegister::new(0),
            command: WriteOnlyRegister::new(0),
            rxdata: ReadOnlyRegister::new(0),
            txdata: WriteOnlyRegister::new(0),
            error_enable: ReadWriteRegister::new(0x1f),
            error_status: ReadWriteRegister::new(0),
            event_enable: ReadWriteRegister::new(0),
            cs_low: false,
            tx_fifo: VecDeque::with_capacity(Self::TX_RX_FIFO_SIZE_BYTES),
            rx_fifo: VecDeque::with_capacity(Self::TX_RX_FIFO_SIZE_BYTES),
            segments: VecDeque::with_capacity(Self::CMD_Q_SIZE),
            timer: clock.timer(),
            ready: None,
            command_complete: None,
            time_pass: None,
            flash0: Default::default(),
        }
    }

    fn spi_enabled(&self) -> bool {
        self.control.reg.is_set(SPIEN)
    }

    fn output_enable(&self) -> bool {
        self.control.reg.is_set(OUTPUT_EN)
    }

    fn reset(&mut self) {
        self.control.reg.modify(
            SPIEN::CLEAR
                + OUTPUT_EN::CLEAR
                + Control::TX_WATERMARK.val(0)
                + Control::RX_WATERMARK.val(0x7f),
        );
        self.tx_fifo.clear();
        self.rx_fifo.clear();
        // TODO CMD que not cleared according to docs??
        self.segments.clear();
        self.status.reg.set(0x8040_0000);
        self.configopts.iter_mut().for_each(|c| c.set(0));
        self.csid.reg.set(0);
        self.error_enable.reg.set(0x1f);
        self.event_enable.reg.set(0);
        self.ready = None;
        self.command_complete = None;
        self.time_pass = None;
    }

    /// On Write callback for `control` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_control(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the control register
        self.control.reg.set(val);

        if self.control.reg.is_set(Control::SW_RST) {
            self.reset();
            // Clear the control register
            self.control.reg.modify(Control::SW_RST::CLEAR)
        }

        if self.spi_enabled() {
            self.time_pass = Some(self.timer.schedule_poll_in(Self::POLL_TIME));
        } else {
            self.time_pass = None;
        }
        Ok(())
    }

    /// On Read callback for `status` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    ///
    /// # Error
    ///
    pub fn on_read_status(&mut self, size: RvSize) -> Result<u32, BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }
        let tx_fifo_len = self.tx_fifo.len() as u32;
        let txqd = tx_fifo_len / 4 + if tx_fifo_len % 4 == 0 { 0 } else { 1 };
        let txwm = self.control.reg.read(TX_WATERMARK);

        let rx_fifo_len = self.rx_fifo.len() as u32;
        let rxqd = rx_fifo_len / 4 + if rx_fifo_len % 4 == 0 { 0 } else { 1 };
        let rxwm = self.control.reg.read(RX_WATERMARK);

        let cmdqd = self.segments.len() as u32;
        self.status.reg.modify(
            TXQD.val(txqd)
                + RXQD.val(rxqd)
                + CMDQD.val(cmdqd)
                + RXWM.val((rxqd > rxwm).into())
                + RXEMPTY.val((rx_fifo_len == 0).into())
                + Status::RXFULL.val((rx_fifo_len == Self::TX_RX_FIFO_SIZE_BYTES as u32).into())
                + TXWM.val((txqd > txwm).into())
                + Status::TXEMPTY.val((tx_fifo_len == 0).into())
                + TXFULL.val((tx_fifo_len == Self::TX_RX_FIFO_SIZE_BYTES as u32).into())
                + ACTIVE.val((cmdqd > 0).into()),
        );

        Ok(self.status.reg.get())
    }

    fn scedule_next_command(&mut self, command: WriteOnlyRegister<u32, Command::Register>) {
        if self.command_complete.is_some() {
            return;
        }

        const READY_DELAY: u64 = 4;
        // TODO scedule interrupt if enabled
        self.ready = Some(self.timer.schedule_poll_in(READY_DELAY));
        // TODO make configurable based on actual speed?
        const CPU_CLOCK_PER_SPI_CLOCK: u64 = 8;
        let spi_clocks_per_len: u64 = if command.reg.read(DIRECTION)
            == <FieldValue<u32, Command::Register> as Into<u32>>::into(DIRECTION::DUMMY)
        {
            1
        } else {
            match command.reg.read_as_enum(SPEED).unwrap() {
                SPEED::Value::SINGLE_IO => 8,
                SPEED::Value::DUAL_IO => 4,
                SPEED::Value::QUAD_IO => 2,
            }
        };
        let len: u64 = (command.reg.read(LEN) + 1).into();
        self.command_complete = Some(
            self.timer
                .schedule_poll_in(CPU_CLOCK_PER_SPI_CLOCK * len * spi_clocks_per_len),
        );
    }

    /// On Write callback for `command` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_command(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        if !self.spi_enabled() {
            return Ok(());
        }

        let command: WriteOnlyRegister<u32, Command::Register> = WriteOnlyRegister::new(val);
        let speed: SPEED::Value = command.reg.read_as_enum(SPEED).unwrap();
        let direction: DIRECTION::Value = command.reg.read_as_enum(DIRECTION).unwrap();
        if speed == SPEED::Value::QUAD_IO && direction == DIRECTION::Value::RX_TX {
            todo!();
        }

        // Save command register
        self.segments.push_back(val);

        self.status.reg.modify(Status::READY::CLEAR);

        self.scedule_next_command(command);
        // TODO TX + RX WATERMARK

        Ok(())
    }

    /// On Write callback for `tx_data` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError`
    pub fn on_write_tx_data(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if !self.spi_enabled() {
            return Ok(());
        }

        let is_little_endian = self.status.reg.is_set(Status::BYTEORDER);

        if self.tx_fifo.len() + usize::from(size) > SpiHost::TX_RX_FIFO_SIZE_BYTES {
            self.error_status.reg.modify(ErrorStatus::OVERFLOW::SET);
            println!("Overflow TX Fifo");
            return Ok(());
        }

        let range = if is_little_endian {
            0..size.into()
        } else {
            size.into()..0
        };

        for i in range {
            let byte = (val >> (i * 8)) & 0xff;
            self.tx_fifo.push_back(byte.try_into().unwrap());
        }
        Ok(())
    }

    /// On Read callback for `rx_data` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    ///
    /// # Error
    ///
    /// * `BusError`
    pub fn on_read_rx_data(&mut self, size: RvSize) -> Result<u32, BusError> {
        if !self.spi_enabled() {
            return Ok(0);
        }

        let is_little_endian = self.status.reg.is_set(Status::BYTEORDER);

        if self.rx_fifo.len() < usize::from(size) {
            self.error_status.reg.modify(ErrorStatus::UNDERFLOW::SET);
            println!("Underflow RX Fifo");
            return Ok(0);
        }

        let range = if is_little_endian {
            0..size.into()
        } else {
            size.into()..0
        };

        Ok(range
            .into_iter()
            .map(|x| (x, self.rx_fifo.pop_front().unwrap())) // We checked for this earlier
            .fold(0u32, |acc, (x, byte)| acc | (u32::from(byte) << (8 * x))))
    }

    fn segment_handle(&mut self) {
        if !self.cs_low {
            self.cs_low = true;
            self.flash0.input(&spi_flash::SpiFlashInput::CsLow).unwrap();
        }
        let segment = self.segments.pop_front().unwrap();
        let command: WriteOnlyRegister<u32, Command::Register> = WriteOnlyRegister::new(segment);
        let mode = match command.reg.read_as_enum(SPEED).unwrap() {
            SPEED::Value::SINGLE_IO => IoMode::Single,
            SPEED::Value::DUAL_IO => IoMode::Dual,
            SPEED::Value::QUAD_IO => IoMode::Quad,
        };
        if !self.output_enable() {
            println!("Output not enabled");
            return;
        }
        if self.csid.reg.get() != 0 {
            println!("CS not set to 0 and only flash0 hooked up");
            return;
        }
        // bytes to be send is LEN + 1
        let size = usize::try_from(command.reg.read(LEN)).unwrap() + 1;
        match command.reg.read_as_enum(DIRECTION).unwrap() {
            DIRECTION::Value::DUMMY => self.flash0.input(&spi_flash::SpiFlashInput::DummyCycles(
                command.reg.read(LEN),
            )),
            DIRECTION::Value::RX_TX => panic!("No SPI flash implements full duplex operations"),
            DIRECTION::Value::RX => {
                let fifo_remaining_size = SpiHost::TX_RX_FIFO_SIZE_BYTES - self.rx_fifo.len();
                if size > fifo_remaining_size {
                    todo!(); // FIFO overflow
                }
                let len = size.min(fifo_remaining_size);

                let output_req = SpiFlashOutReq {
                    mode,
                    n_bytes: len.try_into().unwrap(),
                };
                match self.flash0.req_output(output_req) {
                    Ok(out) => {
                        self.rx_fifo.append(&mut out.into());
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            DIRECTION::Value::TX => {
                if size > self.tx_fifo.len() {
                    // TODO set TXSTALL
                    todo!();
                }
                let range = 0..size;
                let input: Vec<SpiByte> = range
                    .into_iter()
                    .map(|_| SpiByte {
                        byte: self.tx_fifo.pop_front().unwrap(),
                        mode,
                    })
                    .collect();
                self.flash0
                    .input(&spi_flash::SpiFlashInput::BytesSend(input))
            }
        }
        .unwrap_or_else(|e| {
            println!(
                "Spi flash reports error: {:?} on CMD {:x?}",
                e,
                command.reg.get()
            )
        });
        if !command.reg.is_set(CSAAT) {
            self.cs_low = false;
            self.flash0
                .input(&spi_flash::SpiFlashInput::CsHigh)
                .unwrap_or_else(|e| {
                    println!(
                        "Spi flash reports error: {:?} on CMD {:x?}",
                        e,
                        command.reg.get()
                    )
                });
        }
    }

    fn bus_poll(&mut self) {
        if self.timer.fired(&mut self.ready) {
            self.status.reg.modify(Status::READY::SET);
        }
        if self.timer.fired(&mut self.command_complete) {
            self.segment_handle();
            if let Some(segment) = self.segments.front() {
                let command: WriteOnlyRegister<u32, Command::Register> =
                    WriteOnlyRegister::new(*segment);
                self.scedule_next_command(command);
            }
        }
        if self.timer.fired(&mut self.time_pass) {
            // Let the SPI flash know if some time has passed
            if !self.cs_low {
                self.flash0
                    .time_pass(Self::POLL_TIME)
                    .unwrap_or_else(|e| println!("Spi flash reports error: {:?}", e));
            }
            self.time_pass = Some(self.timer.schedule_poll_in(Self::POLL_TIME));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitfield::Bit;
    use emulator_bus::Bus;
    use std::fmt::write;

    const CONTROL_REG_OFFSET: RvData = 0x10;
    const STATUS_REG_OFFSET: RvData = 0x14;
    const COMMAND_REG_OFFSET: RvData = 0x24;
    const RX_FIFO_OFFSET: RvData = 0x28;
    const TX_FIFO_OFFSET: RvData = 0x2c;
    const ERROR_STATUS_REG_OFFSET: RvData = 0x34;

    const DUMMY_CYCLES_CMD: u32 = 0 << 12;
    const RX_CMD: u32 = 1 << 12;
    const TX_CMD: u32 = 2 << 12;
    const SINGLE_CMD: u32 = 0 << 10;
    const DUAL_CMD: u32 = 1 << 10;
    const QUAD_CMD: u32 = 2 << 10;
    const CSAAT_BIT: u32 = 1 << 9;

    struct SpiXfer<'a> {
        cmd: u8,
        addr_mode: spi_flash::IoMode,
        addr: &'a [u8],
        mode_clocks: u8,
        dummy_clocks: u8,
        receive_mode: spi_flash::IoMode,
        receive_len: usize,
    }

    fn spi_xfer(clock: &Clock, spi_host: &mut SpiHost, xfer: &SpiXfer) -> Result<Vec<u8>, String> {
        let wait_for_ready = |clock: &Clock, spi_host: &mut SpiHost| {
            while !spi_host
                .read(RvSize::Word, STATUS_REG_OFFSET)
                .unwrap()
                .bit(31)
            {
                clock.increment_and_process_timer_actions(1, spi_host);
            }
        };

        let wait_for_done = |clock: &Clock, spi_host: &mut SpiHost| {
            while spi_host
                .read(RvSize::Word, STATUS_REG_OFFSET)
                .unwrap()
                .bit(30)
            {
                clock.increment_and_process_timer_actions(1, spi_host);
            }
        };

        let encode_speed = |mode| match mode {
            spi_flash::IoMode::Single => SINGLE_CMD,
            spi_flash::IoMode::Dual => DUAL_CMD,
            spi_flash::IoMode::Quad => QUAD_CMD,
        };

        // CMD
        spi_host
            .write(RvSize::Byte, TX_FIFO_OFFSET, xfer.cmd.into())
            .unwrap();
        let cs_high = xfer.addr.is_empty()
            && xfer.mode_clocks == 0
            && xfer.dummy_clocks == 0
            && xfer.receive_len == 0;
        spi_host
            .write(
                RvSize::Word,
                COMMAND_REG_OFFSET,
                TX_CMD | SINGLE_CMD | if cs_high { 0 } else { CSAAT_BIT },
            )
            .unwrap();
        wait_for_ready(clock, spi_host);

        // ADDR
        if !xfer.addr.is_empty() {
            xfer.addr.iter().for_each(|b| {
                spi_host
                    .write(RvSize::Byte, TX_FIFO_OFFSET, (*b).into())
                    .unwrap()
            });
            let cs_high = xfer.mode_clocks == 0 && xfer.dummy_clocks == 0 && xfer.receive_len == 0;
            let spi_len: u32 = (xfer.addr.len() - 1).try_into().unwrap();
            spi_host
                .write(
                    RvSize::Word,
                    COMMAND_REG_OFFSET,
                    TX_CMD
                        | encode_speed(xfer.addr_mode)
                        | if cs_high { 0 } else { CSAAT_BIT }
                        | spi_len,
                )
                .unwrap();
            wait_for_ready(clock, spi_host);
        }

        // Mode Clocks
        if xfer.mode_clocks != 0 {
            let divisor = match xfer.addr_mode {
                spi_flash::IoMode::Single => 8,
                spi_flash::IoMode::Dual => 4,
                spi_flash::IoMode::Quad => 2,
            };
            (0..(xfer.mode_clocks / divisor))
                .for_each(|_| spi_host.write(RvSize::Byte, TX_FIFO_OFFSET, 0xff).unwrap());

            let cs_high = xfer.dummy_clocks == 0 && xfer.receive_len == 0;
            let spi_len: u32 = (xfer.mode_clocks / divisor - 1).into();
            spi_host
                .write(
                    RvSize::Word,
                    COMMAND_REG_OFFSET,
                    TX_CMD
                        | encode_speed(xfer.addr_mode)
                        | if cs_high { 0 } else { CSAAT_BIT }
                        | spi_len,
                )
                .unwrap();
            wait_for_ready(clock, spi_host);
        }

        // DummyCycles
        if xfer.dummy_clocks != 0 {
            let cs_high = xfer.receive_len == 0;
            let spi_len: u32 = (xfer.dummy_clocks - 1).into();
            spi_host
                .write(
                    RvSize::Word,
                    COMMAND_REG_OFFSET,
                    DUMMY_CYCLES_CMD | SINGLE_CMD | if cs_high { 0 } else { CSAAT_BIT } | spi_len,
                )
                .unwrap();
            wait_for_ready(clock, spi_host);
        }

        // RX bytes
        let ret = if xfer.receive_len == 0 {
            Ok(Vec::new())
        } else {
            let spi_len: u32 = (xfer.receive_len - 1).try_into().unwrap();
            spi_host
                .write(
                    RvSize::Word,
                    COMMAND_REG_OFFSET,
                    RX_CMD | encode_speed(xfer.receive_mode) | spi_len,
                )
                .unwrap();
            wait_for_ready(clock, spi_host);
            wait_for_done(clock, spi_host);

            let resp: Vec<u8> = (0..xfer.receive_len)
                .map(|_| {
                    spi_host
                        .read(RvSize::Byte, RX_FIFO_OFFSET)
                        .unwrap()
                        .try_into()
                        .unwrap()
                })
                .collect();
            Ok(resp)
        };
        let error = spi_host
            .read(RvSize::Word, ERROR_STATUS_REG_OFFSET)
            .unwrap();
        if error != 0 {
            let mut string = String::new();
            write(&mut string, format_args!("Spi Host has an error {}", error)).unwrap();
            Err(string)
        } else {
            ret
        }
    }

    #[test]
    fn test_spi_rdid() {
        let clock = Clock::new();
        let mut spi_host = SpiHost::new(&clock);
        // Enable SPI, reset + output enable
        spi_host
            .write(RvSize::Word, CONTROL_REG_OFFSET, 0xa000_007f)
            .unwrap();

        let xfer = SpiXfer {
            cmd: 0x9f,
            addr: &[],
            addr_mode: IoMode::Single,
            mode_clocks: 0,
            dummy_clocks: 0,
            receive_len: 3,
            receive_mode: IoMode::Single,
        };

        let receive = spi_xfer(&clock, &mut spi_host, &xfer).unwrap();
        assert_eq!(receive.as_slice(), &[0xef, 0x40, 0x21]);

        // Do it twice
        let receive = spi_xfer(&clock, &mut spi_host, &xfer).unwrap();
        assert_eq!(receive.as_slice(), &[0xef, 0x40, 0x21]);
    }

    #[test]
    fn test_spi_read_program_erase() {
        let clock = Clock::new();
        let mut spi_host = SpiHost::new(&clock);
        // Enable SPI, reset + output enable
        spi_host
            .write(RvSize::Word, CONTROL_REG_OFFSET, 0xa000_007f)
            .unwrap();

        // Read 4ba at addr 5
        let read_xfer = SpiXfer {
            cmd: 0x13,
            addr: &[0x00, 0x00, 0x00, 0x05],
            addr_mode: IoMode::Single,
            mode_clocks: 0,
            dummy_clocks: 0,
            receive_len: 1,
            receive_mode: IoMode::Single,
        };
        let receive = spi_xfer(&clock, &mut spi_host, &read_xfer).unwrap();
        assert_eq!(receive.as_slice(), &[0xff]);

        let enable_write_xfer = SpiXfer {
            cmd: 0x06,
            addr: &[],
            addr_mode: IoMode::Single,
            mode_clocks: 0,
            dummy_clocks: 0,
            receive_len: 0,
            receive_mode: IoMode::Single,
        };
        spi_xfer(&clock, &mut spi_host, &enable_write_xfer).unwrap();

        // Page program 4ba: addr 5 set to 0xab
        let page_program_xfer = SpiXfer {
            cmd: 0x12,
            addr: &[0x00, 0x00, 0x00, 0x05, 0xab],
            addr_mode: IoMode::Single,
            mode_clocks: 0,
            dummy_clocks: 0,
            receive_len: 0,
            receive_mode: IoMode::Single,
        };
        spi_xfer(&clock, &mut spi_host, &page_program_xfer).unwrap();
        // Wait some time
        for _ in 0..10 {
            clock.increment_and_process_timer_actions(1000, &mut spi_host);
        }
        let receive = spi_xfer(&clock, &mut spi_host, &read_xfer).unwrap();
        assert_eq!(receive.as_slice(), &[0xab]);

        // Erase chip
        let chip_erase_xfer = SpiXfer {
            cmd: 0x60,
            addr: &[],
            addr_mode: IoMode::Single,
            mode_clocks: 0,
            dummy_clocks: 0,
            receive_len: 0,
            receive_mode: IoMode::Single,
        };
        spi_xfer(&clock, &mut spi_host, &enable_write_xfer).unwrap();
        spi_xfer(&clock, &mut spi_host, &chip_erase_xfer).unwrap();
        // Wait some time
        for _ in 0..1000 {
            clock.increment_and_process_timer_actions(1000, &mut spi_host);
        }
        let receive = spi_xfer(&clock, &mut spi_host, &read_xfer).unwrap();
        assert_eq!(receive.as_slice(), &[0xff]);
    }
}
