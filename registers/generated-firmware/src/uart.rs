// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub const UART_ADDR: u32 = 0x2000_1000;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub AlertTest [
                /// Write 1 to trigger one alert event of this kind.
                FatalFault OFFSET(0) NUMBITS(1) [],
            ],
            pub Ctrl [
                /// TX enable
                Tx OFFSET(0) NUMBITS(1) [],
                /// RX enable
                Rx OFFSET(1) NUMBITS(1) [],
                /// RX noise filter enable.
                /// If the noise filter is enabled, RX line goes through the 3-tap
                /// repetition code. It ignores single IP clock period noise.
                Nf OFFSET(2) NUMBITS(1) [],
                /// System loopback enable.
                ///
                /// If this bit is turned on, any outgoing bits to TX are received through RX.
                /// See Block Diagram. Note that the TX line goes 1 if System loopback is enabled.
                Slpbk OFFSET(4) NUMBITS(1) [],
                /// Line loopback enable.
                ///
                /// If this bit is turned on, incoming bits are forwarded to TX for testing purpose.
                /// See Block Diagram. Note that the internal design sees RX value as 1 always if line
                /// loopback is enabled.
                Llpbk OFFSET(5) NUMBITS(1) [],
                /// If true, parity is enabled in both RX and TX directions.
                ParityEn OFFSET(6) NUMBITS(1) [],
                /// If PARITY_EN is true, this determines the type, 1 for odd parity, 0 for even.
                ParityOdd OFFSET(7) NUMBITS(1) [],
                /// Trigger level for RX break detection. Sets the number of character
                /// times the line must be low to detect a break.
                Rxblvl OFFSET(8) NUMBITS(2) [],
                /// BAUD clock rate control.
                Nco OFFSET(16) NUMBITS(16) [],
            ],
            pub FifoCtrl [
                /// RX fifo reset. Write 1 to the register resets RX_FIFO. Read returns 0
                Rxrst OFFSET(0) NUMBITS(1) [],
                /// TX fifo reset. Write 1 to the register resets TX_FIFO. Read returns 0
                Txrst OFFSET(1) NUMBITS(1) [],
                /// Trigger level for RX interrupts. If the FIFO depth is greater than or equal to
                /// the setting, it raises rx_watermark interrupt.
                Rxilvl OFFSET(2) NUMBITS(3) [],
                /// Trigger level for TX interrupts. If the FIFO depth is less than the setting, it
                /// raises tx_watermark interrupt.
                Txilvl OFFSET(5) NUMBITS(2) [],
            ],
            pub FifoStatus [
                /// Current fill level of TX fifo
                Txlvl OFFSET(0) NUMBITS(6) [],
                /// Current fill level of RX fifo
                Rxlvl OFFSET(16) NUMBITS(6) [],
            ],
            pub InterruptEnable [
                /// Enable interrupt when tx_watermark is set.
                TxWatermark OFFSET(0) NUMBITS(1) [],
                /// Enable interrupt when rx_watermark is set.
                RxWatermark OFFSET(1) NUMBITS(1) [],
                /// Enable interrupt when tx_empty is set.
                TxEmpty OFFSET(2) NUMBITS(1) [],
                /// Enable interrupt when rx_overflow is set.
                RxOverflow OFFSET(3) NUMBITS(1) [],
                /// Enable interrupt when rx_frame_err is set.
                RxFrameErr OFFSET(4) NUMBITS(1) [],
                /// Enable interrupt when rx_break_err is set.
                RxBreakErr OFFSET(5) NUMBITS(1) [],
                /// Enable interrupt when rx_timeout is set.
                RxTimeout OFFSET(6) NUMBITS(1) [],
                /// Enable interrupt when rx_parity_err is set.
                RxParityErr OFFSET(7) NUMBITS(1) [],
            ],
            pub InterruptState [
                /// raised if the transmit FIFO is past the high-water mark.
                TxWatermark OFFSET(0) NUMBITS(1) [],
                /// raised if the receive FIFO is past the high-water mark.
                RxWatermark OFFSET(1) NUMBITS(1) [],
                /// raised if the transmit FIFO has emptied and no transmit is ongoing.
                TxEmpty OFFSET(2) NUMBITS(1) [],
                /// raised if the receive FIFO has overflowed.
                RxOverflow OFFSET(3) NUMBITS(1) [],
                /// raised if a framing error has been detected on receive.
                RxFrameErr OFFSET(4) NUMBITS(1) [],
                /// raised if break condition has been detected on receive.
                RxBreakErr OFFSET(5) NUMBITS(1) [],
                /// raised if RX FIFO has characters remaining in the FIFO without being
                /// retrieved for the programmed time period.
                RxTimeout OFFSET(6) NUMBITS(1) [],
                /// raised if the receiver has detected a parity error.
                RxParityErr OFFSET(7) NUMBITS(1) [],
            ],
            pub InterruptTest [
                /// Write 1 to force tx_watermark to 1.
                TxWatermark OFFSET(0) NUMBITS(1) [],
                /// Write 1 to force rx_watermark to 1.
                RxWatermark OFFSET(1) NUMBITS(1) [],
                /// Write 1 to force tx_empty to 1.
                TxEmpty OFFSET(2) NUMBITS(1) [],
                /// Write 1 to force rx_overflow to 1.
                RxOverflow OFFSET(3) NUMBITS(1) [],
                /// Write 1 to force rx_frame_err to 1.
                RxFrameErr OFFSET(4) NUMBITS(1) [],
                /// Write 1 to force rx_break_err to 1.
                RxBreakErr OFFSET(5) NUMBITS(1) [],
                /// Write 1 to force rx_timeout to 1.
                RxTimeout OFFSET(6) NUMBITS(1) [],
                /// Write 1 to force rx_parity_err to 1.
                RxParityErr OFFSET(7) NUMBITS(1) [],
            ],
            pub Ovrd [
                /// Enable TX pin override control
                Txen OFFSET(0) NUMBITS(1) [],
                /// Write to set the value of the TX pin
                Txval OFFSET(1) NUMBITS(1) [],
            ],
            pub Rdata [
                /// UART read data
                Rdata OFFSET(0) NUMBITS(8) [],
            ],
            pub Status [
                /// TX buffer is full
                Txfull OFFSET(0) NUMBITS(1) [],
                /// RX buffer is full
                Rxfull OFFSET(1) NUMBITS(1) [],
                /// TX FIFO is empty
                Txempty OFFSET(2) NUMBITS(1) [],
                /// TX FIFO is empty and all bits have been transmitted
                Txidle OFFSET(3) NUMBITS(1) [],
                /// RX is idle
                Rxidle OFFSET(4) NUMBITS(1) [],
                /// RX FIFO is empty
                Rxempty OFFSET(5) NUMBITS(1) [],
            ],
            pub TimeoutCtrl [
                /// RX timeout value in UART bit times
                Val OFFSET(0) NUMBITS(24) [],
                /// Enable RX timeout feature
                En OFFSET(31) NUMBITS(1) [],
            ],
            pub Val [
                /// Last 16 oversampled values of RX. Most recent bit is bit 0, oldest 15.
                Rx OFFSET(0) NUMBITS(16) [],
            ],
            pub Wdata [
                /// UART write data
                Wdata OFFSET(0) NUMBITS(8) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub Uart {
            (0x0 => pub interrupt_state: tock_registers::registers::ReadWrite<u32, crate::uart::bits::InterruptState::Register>),
            (0x4 => pub interrupt_enable: tock_registers::registers::ReadWrite<u32, crate::uart::bits::InterruptEnable::Register>),
            (0x8 => pub interrupt_test: tock_registers::registers::WriteOnly<u32, crate::uart::bits::InterruptTest::Register>),
            (0xc => pub alert_test: tock_registers::registers::WriteOnly<u32, crate::uart::bits::AlertTest::Register>),
            (0x10 => pub ctrl: tock_registers::registers::ReadWrite<u32, crate::uart::bits::Ctrl::Register>),
            (0x14 => pub status: tock_registers::registers::ReadOnly<u32, crate::uart::bits::Status::Register>),
            (0x18 => pub rdata: tock_registers::registers::ReadOnly<u32, crate::uart::bits::Rdata::Register>),
            (0x1c => pub wdata: tock_registers::registers::WriteOnly<u32, crate::uart::bits::Wdata::Register>),
            (0x20 => pub fifo_ctrl: tock_registers::registers::ReadWrite<u32, crate::uart::bits::FifoCtrl::Register>),
            (0x24 => pub fifo_status: tock_registers::registers::ReadOnly<u32, crate::uart::bits::FifoStatus::Register>),
            (0x28 => pub ovrd: tock_registers::registers::ReadWrite<u32, crate::uart::bits::Ovrd::Register>),
            (0x2c => pub val: tock_registers::registers::ReadOnly<u32, crate::uart::bits::Val::Register>),
            (0x30 => pub timeout_ctrl: tock_registers::registers::ReadWrite<u32, crate::uart::bits::TimeoutCtrl::Register>),
            (0x34 => @END),
        }
    }
}