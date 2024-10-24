// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub const SPI_HOST_REG_ADDR: u32 = 0x2000_0000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub AlertTest [
                /// Write 1 to trigger one alert event of this kind.
                FatalFault OFFSET(0) NUMBITS(1) [],
            ],
            pub Command [
                /// Segment Length.
                ///
                /// For read or write segments, this field controls the
                /// number of 1-byte bursts to transmit and or receive in
                /// this command segment.  The number of cyles required
                /// to send or received a byte will depend on !!COMMAND.SPEED.
                /// For dummy segments, (!!COMMAND.DIRECTION == 0), this register
                /// controls the number of dummy cycles to issue.
                /// The number of bytes (or dummy cycles) in the segment will be
                /// equal to !!COMMAND.LEN + 1.
                Len OFFSET(0) NUMBITS(9) [],
                /// Chip select active after transaction.  If CSAAT = 0, the
                /// chip select line is raised immediately at the end of the
                /// command segment.   If !!COMMAND.CSAAT = 1, the chip select
                /// line is left low at the end of the current transaction
                /// segment.  This allows the creation longer, more
                /// complete SPI transactions, consisting of several separate
                /// segments for issuing instructions, pausing for dummy cycles,
                /// and transmitting or receiving data from the device.
                Csaat OFFSET(9) NUMBITS(1) [],
                /// The speed for this command segment: "0" = Standard SPI. "1" = Dual SPI.
                /// "2"=Quad SPI,  "3": RESERVED.
                Speed OFFSET(10) NUMBITS(2) [],
                /// The direction for the following command: "0" = Dummy cycles
                /// (no TX/RX). "1" = Rx only, "2" = Tx only, "3" = Bidirectional
                /// Tx/Rx (Standard SPI mode only).
                Direction OFFSET(12) NUMBITS(2) [],
            ],
            pub Configopts [
                /// Core clock divider.  Slows down subsequent SPI transactions by a
                /// factor of (CLKDIV+1) relative to the core clock frequency.  The
                /// period of sck, T(sck) then becomes `2*(CLK_DIV+1)*T(core)`
                Clkdiv OFFSET(0) NUMBITS(16) [],
                /// Minimum idle time between commands. Indicates the minimum
                /// number of sck half-cycles to hold cs_n high between commands.
                /// Setting this register to zero creates a minimally-wide CS_N-high
                /// pulse of one-half sck cycle.
                Csnidle OFFSET(16) NUMBITS(4) [],
                /// CS_N Trailing Time.  Indicates the number of half sck cycles,
                /// CSNTRAIL+1, to leave between last edge of sck and the rising
                /// edge of cs_n. Setting this register to zero corresponds
                /// to the minimum delay of one-half sck cycle.
                Csntrail OFFSET(20) NUMBITS(4) [],
                /// CS_N Leading Time.  Indicates the number of half sck cycles,
                /// CSNLEAD+1, to leave between the falling edge of cs_n and
                /// the first edge of sck.  Setting this register to zero
                /// corresponds to the minimum delay of one-half sck cycle
                Csnlead OFFSET(24) NUMBITS(4) [],
                /// Full cycle.  Modifies the CPHA sampling behaviour to allow
                /// for longer device logic setup times.  Rather than sampling the SD
                /// bus a half cycle after shifting out data, the data is sampled
                /// a full cycle after shifting data out.  This means that if
                /// CPHA = 0, data is shifted out on the trailing edge, and
                /// sampled a full cycle later.  If CPHA = 1, data is shifted and
                /// sampled with the trailing edge, also separated by a
                /// full cycle.
                Fullcyc OFFSET(29) NUMBITS(1) [],
                /// The phase of the sck clock signal relative to the data. When
                /// CPHA = 0, the data changes on the trailing edge of sck
                /// and is typically sampled on the leading edge.  Conversely
                /// if CPHA = 1 high, data lines change on the leading edge of
                /// sck and are typically sampled on the trailing edge.
                /// CPHA should be chosen to match the phase of the selected
                /// device.  The sampling behavior is modified by the
                /// !!CONFIGOPTS.FULLCYC bit.
                Cpha OFFSET(30) NUMBITS(1) [],
                /// The polarity of the sck clock signal.  When CPOL is 0,
                /// sck is low when idle, and emits high pulses.   When CPOL
                /// is low, sck is high when idle, and emits a series of low
                /// pulses.
                Cpol OFFSET(31) NUMBITS(1) [],
            ],
            pub Control [
                /// If !!EVENT_ENABLE.RXWM is set, the IP will send
                /// an interrupt when the depth of the RX FIFO reaches
                /// RX_WATERMARK words (32b each).
                RxWatermark OFFSET(0) NUMBITS(8) [],
                /// If !!EVENT_ENABLE.TXWM is set, the IP will send
                /// an interrupt when the depth of the TX FIFO drops below
                /// TX_WATERMARK words (32b each).
                TxWatermark OFFSET(8) NUMBITS(8) [],
                /// Enable the SPI host output buffers for the sck, csb, and sd lines.  This allows
                /// the SPI_HOST IP to connect to the same bus as other SPI controllers without
                /// interference.
                OutputEn OFFSET(29) NUMBITS(1) [],
                /// Clears the entire IP to the reset state when set to 1, including
                /// the FIFOs, the CDC's, the core state machine and the shift register.
                /// In the current implementation, the CDC FIFOs are drained not reset.
                /// Therefore software must confirm that both FIFO's empty before releasing
                /// the IP from reset.
                SwRst OFFSET(30) NUMBITS(1) [],
                /// Enables the SPI host.  On reset, this field is 0, meaning
                /// that no transactions can proceed.
                Spien OFFSET(31) NUMBITS(1) [],
            ],
            pub ErrorEnable [
                /// Command Error: If this bit is set, the block sends an error
                /// interrupt whenever a command is issued while busy (i.e. a 1 is
                /// when !!STATUS.READY is not asserted.)
                Cmdbusy OFFSET(0) NUMBITS(1) [],
                /// Overflow Errors: If this bit is set, the block sends an
                /// error interrupt whenever the TX FIFO overflows.
                Overflow OFFSET(1) NUMBITS(1) [],
                /// Underflow Errors: If this bit is set, the block sends an
                /// error interrupt whenever there is a read from !!RXDATA
                /// but the RX FIFO is empty.
                Underflow OFFSET(2) NUMBITS(1) [],
                /// Invalid Command Errors: If this bit is set, the block sends an
                /// error interrupt whenever a command is sent with invalid values for
                /// !!COMMAND.SPEED or !!COMMAND.DIRECTION.
                Cmdinval OFFSET(3) NUMBITS(1) [],
                /// Invalid CSID: If this bit is set, the block sends an error interrupt whenever
                /// a command is submitted, but CSID exceeds NumCS.
                Csidinval OFFSET(4) NUMBITS(1) [],
            ],
            pub ErrorStatus [
                /// Indicates a write to !!COMMAND when !!STATUS.READY = 0.
                Cmdbusy OFFSET(0) NUMBITS(1) [],
                /// Indicates that firmware has overflowed the TX FIFO
                Overflow OFFSET(1) NUMBITS(1) [],
                /// Indicates that firmware has attempted to read from
                /// !!RXDATA when the RX FIFO is empty.
                Underflow OFFSET(2) NUMBITS(1) [],
                /// Indicates an invalid command segment, meaning either an invalid value of
                /// !!COMMAND.SPEED or a request for bidirectional data transfer at dual or quad
                /// speed
                Cmdinval OFFSET(3) NUMBITS(1) [],
                /// Indicates a command was attempted with an invalid value for !!CSID.
                Csidinval OFFSET(4) NUMBITS(1) [],
                /// Indicates that TLUL attempted to write to TXDATA with no bytes enabled. Such
                /// 'zero byte' writes are not supported.
                Accessinval OFFSET(5) NUMBITS(1) [],
            ],
            pub EventEnable [
                /// Assert to send a spi_event interrupt whenever !!STATUS.RXFULL
                /// goes high
                Rxfull OFFSET(0) NUMBITS(1) [],
                /// Assert to send a spi_event interrupt whenever !!STATUS.TXEMPTY
                /// goes high
                Txempty OFFSET(1) NUMBITS(1) [],
                /// Assert to send a spi_event interrupt whenever the number of 32-bit words in
                /// the RX FIFO is greater than !!CONTROL.RX_WATERMARK. To prevent the
                /// reassertion of this interrupt, read more data from the RX FIFO, or
                /// increase !!CONTROL.RX_WATERMARK.
                Rxwm OFFSET(2) NUMBITS(1) [],
                /// Assert to send a spi_event interrupt whenever the number of 32-bit words in
                /// the TX FIFO is less than !!CONTROL.TX_WATERMARK.  To prevent the
                /// reassertion of this interrupt add more data to the TX FIFO, or
                /// reduce !!CONTROL.TX_WATERMARK.
                Txwm OFFSET(3) NUMBITS(1) [],
                /// Assert to send a spi_event interrupt whenever !!STATUS.READY
                /// goes high
                Ready OFFSET(4) NUMBITS(1) [],
                /// Assert to send a spi_event interrupt whenever !!STATUS.ACTIVE
                /// goes low
                Idle OFFSET(5) NUMBITS(1) [],
            ],
            pub InterruptEnable [
                /// Enable interrupt when error is set.
                Error OFFSET(0) NUMBITS(1) [],
                /// Enable interrupt when spi_event is set.
                SpiEvent OFFSET(1) NUMBITS(1) [],
            ],
            pub InterruptState [
                /// Error-related interrupts, see !!ERROR_ENABLE register for more
                /// information.
                Error OFFSET(0) NUMBITS(1) [],
                /// Event-related interrupts, see !!EVENT_ENABLE register for more
                /// information.
                SpiEvent OFFSET(1) NUMBITS(1) [],
            ],
            pub InterruptTest [
                /// Write 1 to force error to 1.
                Error OFFSET(0) NUMBITS(1) [],
                /// Write 1 to force spi_event to 1.
                SpiEvent OFFSET(1) NUMBITS(1) [],
            ],
            pub Status [
                /// Transmit queue depth. Indicates how many unsent 32-bit words
                /// are currently in the TX FIFO.  When active, this result may
                /// be an overestimate due to synchronization delays,
                Txqd OFFSET(0) NUMBITS(8) [],
                /// Receive queue depth. Indicates how many unread 32-bit words are
                /// currently in the RX FIFO.  When active, this result may an
                /// underestimate due to synchronization delays.
                Rxqd OFFSET(8) NUMBITS(8) [],
                /// Command queue depth. Indicates how many unread 32-bit words are
                /// currently in the command segment queue.
                Cmdqd OFFSET(16) NUMBITS(4) [],
                /// If high, the number of 32-bits in the RX FIFO now exceeds the
                /// !!CONTROL.RX_WATERMARK entries (32b each).
                Rxwm OFFSET(20) NUMBITS(1) [],
                /// The value of the ByteOrder parameter, provided so that firmware
                /// can confirm proper IP configuration.
                Byteorder OFFSET(22) NUMBITS(1) [],
                /// If high, signifies that an ongoing transaction has stalled
                /// due to lack of available space in the RX FIFO
                Rxstall OFFSET(23) NUMBITS(1) [],
                /// When high, indicates that the receive fifo is empty.
                /// Any reads from RX FIFO will cause an error interrupt.
                Rxempty OFFSET(24) NUMBITS(1) [],
                /// When high, indicates that the receive fifo is full.  Any
                /// ongoing transactions will stall until firmware reads some
                /// data from !!RXDATA.
                Rxfull OFFSET(25) NUMBITS(1) [],
                /// If high, the amount of data in the TX FIFO has fallen below the
                /// level of !!CONTROL.TX_WATERMARK words (32b each).
                Txwm OFFSET(26) NUMBITS(1) [],
                /// If high, signifies that an ongoing transaction has stalled
                /// due to lack of data in the TX FIFO
                Txstall OFFSET(27) NUMBITS(1) [],
                /// When high, indicates that the transmit data fifo is empty.
                Txempty OFFSET(28) NUMBITS(1) [],
                /// When high, indicates that the transmit data fifo is full.
                /// Any further writes to !!RXDATA will create an error interrupt.
                Txfull OFFSET(29) NUMBITS(1) [],
                /// When high, indicates the SPI host is processing a previously
                /// issued command.
                Active OFFSET(30) NUMBITS(1) [],
                /// When high, indicates the SPI host is ready to receive
                /// commands. Writing to COMMAND when READY is low is
                /// an error, and will trigger an interrupt.
                Ready OFFSET(31) NUMBITS(1) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub SpiHost {
            (0x0 => pub interrupt_state: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::InterruptState::Register>),
            (0x4 => pub interrupt_enable: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::InterruptEnable::Register>),
            (0x8 => pub interrupt_test: tock_registers::registers::WriteOnly<u32, crate::spi_host::bits::InterruptTest::Register>),
            (0xc => pub alert_test: tock_registers::registers::WriteOnly<u32, crate::spi_host::bits::AlertTest::Register>),
            (0x10 => pub control: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::Control::Register>),
            (0x14 => pub status: tock_registers::registers::ReadOnly<u32, crate::spi_host::bits::Status::Register>),
            (0x18 => pub configopts: [tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::Configopts::Register>; 2]),
            (0x20 => pub csid: tock_registers::registers::ReadWrite<u32>),
            (0x24 => pub command: tock_registers::registers::WriteOnly<u32, crate::spi_host::bits::Command::Register>),
            (0x28 => pub rxdata: tock_registers::registers::ReadOnly<u32>),
            (0x2c => pub txdata: tock_registers::registers::WriteOnly<u32>),
            (0x30 => pub error_enable: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::ErrorEnable::Register>),
            (0x34 => pub error_status: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::ErrorStatus::Register>),
            (0x38 => pub event_enable: tock_registers::registers::ReadWrite<u32, crate::spi_host::bits::EventEnable::Register>),
            (0x3c => @END),
        }
    }
}