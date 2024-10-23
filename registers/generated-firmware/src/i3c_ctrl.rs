// Licensed under the Apache-2.0 license.
//
// generated by registers_generator with caliptra-rtl repo at 0e43b8e7011c1c8761e114bc949fcad6cf30538e
// , caliptra-ss repo at 9911c2b0e4bac9e4b48f6c2155c86cb116159734
// , and i3c-core repo at d5c715103f529ade0e5d375a53c5692daaa9c54b
//
pub const I3C_CTRL_ADDR: u32 = 0x1003_8100;
pub mod bits {
    //! Types that represent individual registers (bitfields).
    use tock_registers::register_bitfields;
    register_bitfields! {
        u32,
            pub AltQueueSize [
                /// 1 indicates that IBI queue size is equal to 8*IBI_STATUS_SIZE
                ExtIbiQueueEn OFFSET(28) NUMBITS(1) [],
                /// If set, response and command queues are not equal lengths, then
                /// ALT_RESP_QUEUE_SIZE contains response queue size
                AltRespQueueEn OFFSET(24) NUMBITS(1) [],
                /// Valid only if ALT_RESP_QUEUE_EN is set. Contains response queue size
                AltRespQueueSize OFFSET(0) NUMBITS(8) [],
            ],
            pub ControllerDeviceAddr [
                /// Dynamic Address is Valid:
                ///
                /// 0 - dynamic address is invalid
                ///
                /// 1 - dynamic address is valid
                DynamicAddrValid OFFSET(31) NUMBITS(1) [],
                /// Device Dynamic Address
                DynamicAddr OFFSET(16) NUMBITS(7) [],
            ],
            pub DataBufferThldCtrl [
                /// Postpone read command until RX queue has 2^(N+1) free entries
                RxStartThld OFFSET(24) NUMBITS(3) [],
                /// Postpone write command until TX queue has 2^(N+1) entries
                TxStartThld OFFSET(16) NUMBITS(3) [],
                /// Trigger RX_THLD_STAT interrupt when RX queue has 2^(N+1) or more entries
                RxBufThld OFFSET(8) NUMBITS(3) [],
                /// Trigger TX_THLD_STAT interrupt when TX queue has 2^(N+1) or more free entries
                TxBufThld OFFSET(0) NUMBITS(3) [],
            ],
            pub DatSectionOffset [
                /// Individual DAT entry size.
                /// 0 - 2 DWRODs,
                /// 1:15 - reserved.
                EntrySize OFFSET(28) NUMBITS(4) [],
                /// Max number of DAT entries.
                TableSize OFFSET(12) NUMBITS(7) [],
                /// DAT entry offset in respect to BASE address.
                TableOffset OFFSET(0) NUMBITS(12) [],
            ],
            pub DctSectionOffset [
                /// Individual DCT entry size.
                ///
                /// 0 - 4 DWORDs,
                ///
                /// 1:15 - Reserved.
                EntrySize OFFSET(28) NUMBITS(4) [],
                /// Index to DCT used during ENTDAA.
                TableIndex OFFSET(19) NUMBITS(5) [],
                /// Max number of DCT entries.
                TableSize OFFSET(12) NUMBITS(7) [],
                /// DCT entry offset in respect to BASE address.
                TableOffset OFFSET(0) NUMBITS(12) [],
            ],
            pub DevCtxBaseHi [
                BaseHi OFFSET(0) NUMBITS(1) [],
            ],
            pub DevCtxBaseLo [
                BaseLo OFFSET(0) NUMBITS(1) [],
            ],
            pub DevCtxSg [
                /// Buffer vs list pointer in device context:
                ///
                /// 0 - continuous physical memory region,
                ///
                /// 1 - pointer to SG descriptor list.
                Blp OFFSET(31) NUMBITS(1) [],
                /// Number of SG entries.
                ListSize OFFSET(0) NUMBITS(16) [],
            ],
            pub ExtcapHeader [
                /// Capability Structure Length in DWORDs
                CapLength OFFSET(8) NUMBITS(16) [],
                /// Extended Capability ID
                CapId OFFSET(0) NUMBITS(8) [],
            ],
            pub ExtCapsSectionOffset [
                /// Extended Capabilities section offset. Invalid if 0.
                SectionOffset OFFSET(0) NUMBITS(16) [],
            ],
            pub HcCapabilities [
                /// Device context memory:
                ///
                /// 0 - must be physically continuous
                ///
                /// 1 - controller supports scatter-gather
                SgCapabilityDcEn OFFSET(30) NUMBITS(1) [],
                /// DMA only: IBI status and IBI Data rings memory:
                ///
                /// 0 - must be physically continuous
                ///
                /// 1 - controller supports scatter-gather
                SgCapabilityIbiEn OFFSET(29) NUMBITS(1) [],
                /// DMA only: Command and Response rings memory:
                ///
                /// 0 - must be physically continuous
                ///
                /// 1 - controller supports scatter-gather
                SgCapabilityCrEn OFFSET(28) NUMBITS(1) [],
                /// Size and structure of the Command Descriptor:
                ///
                /// 2'b0: 2 DWORDs,
                ///
                /// all other reserved.
                CmdSize OFFSET(20) NUMBITS(2) [],
                /// Controller command scheduling:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                ScheduledCommandsEn OFFSET(13) NUMBITS(1) [],
                /// Controller IBI credit count:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                IbiCreditCountEn OFFSET(12) NUMBITS(1) [],
                /// Controller IBI data abort:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                IbiDataAbortEn OFFSET(11) NUMBITS(1) [],
                /// CCC with defining byte:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                CmdCccDefbyte OFFSET(10) NUMBITS(1) [],
                /// HDR-Ternary transfers:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                HdrTsEn OFFSET(7) NUMBITS(1) [],
                /// HDR-DDR transfers:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                HdrDdrEn OFFSET(6) NUMBITS(1) [],
                /// Switching from active to standby mode:
                ///
                /// 0 - not supported, this controller is always active on I3C
                ///
                /// 1- supported, this controller can hand off I3C to secondary controller
                StandbyCrCap OFFSET(5) NUMBITS(1) [],
                /// Automatic read command on IBI:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                AutoCommand OFFSET(3) NUMBITS(1) [],
                /// Controller combined command:
                ///
                /// 0 - not supported
                ///
                /// 1 - supported
                ComboCommand OFFSET(2) NUMBITS(1) [],
            ],
            pub HcControl [
                /// Host Controller Bus Enable
                BusEnable OFFSET(31) NUMBITS(1) [],
                /// Host Controller Resume:
                ///
                /// 0 - Controller is running
                ///
                /// 1 - Controller is suspended
                ///
                /// Write 1 to resume Controller operations.
                Resume OFFSET(30) NUMBITS(1) [],
                /// Host Controller Abort when set to 1
                Abort OFFSET(29) NUMBITS(1) [],
                /// Halt on Command Sequence Timeout when set to 1
                HaltOnCmdSeqTimeout OFFSET(12) NUMBITS(1) [],
                /// Hot-Join ACK/NACK Control:
                ///
                /// 0 - ACK Hot-Join request
                ///
                /// 1 - NACK Hot-Join request and send Broadcast CCC to disable Hot-Join
                HotJoinCtrl OFFSET(8) NUMBITS(1) [],
                /// I2C Device Present on Bus:
                ///
                /// 0 - pure I3C bus
                ///
                /// 1 - legacy I2C devices on the bus
                I2cDevPresent OFFSET(7) NUMBITS(1) [],
                /// DMA/PIO Mode Selector:
                ///
                /// 0 - DMA
                ///
                /// 1 - PIO
                ModeSelector OFFSET(6) NUMBITS(1) [],
                /// Data Byte Ordering Mode:
                ///
                /// 0 - Little Endian
                ///
                /// 1 - Big Endian
                DataByteOrderMode OFFSET(4) NUMBITS(1) [],
                /// Auto-Command Data Report:
                ///
                /// 0 - coalesced reporting
                ///
                /// 1 - separated reporting
                AutocmdDataRpt OFFSET(3) NUMBITS(1) [],
                /// Include I3C Broadcast Address:
                ///
                /// 0 - skips I3C Broadcast Address for private transfers
                ///
                /// 1 - includes I3C Broadcast Address for private transfers
                IbaInclude OFFSET(0) NUMBITS(1) [],
            ],
            pub IbiDataAbortCtrl [
                /// Enable/disable IBI monitoring logic.
                IbiDataAbortMon OFFSET(31) NUMBITS(1) [],
                /// Define which IBI should be aborted:
                ///
                /// 3'b000 - Regular IBI,
                ///
                /// 3'b100 - Autocmd IBI,
                ///
                /// other values - not supported.
                MatchStatusType OFFSET(18) NUMBITS(3) [],
                /// Number of data chunks to be allowed before forced termination:
                ///
                /// 0 - immediate,
                ///
                /// 1:3 - delay by 1-3 data chunks.
                AfterNChunks OFFSET(16) NUMBITS(2) [],
                /// IBI target address:
                ///
                /// [15:9] - device address,
                ///
                /// [8] - must always be set to 1'b1
                MatchIbiId OFFSET(8) NUMBITS(8) [],
            ],
            pub IbiNotifyCtrl [
                /// Notify about rejected IBI:
                ///
                /// 0 - do not enqueue rejected IBI,
                ///
                /// 1 = enqueue rejected IBI on IBI queue/ring.
                NotifyIbiRejected OFFSET(3) NUMBITS(1) [],
                /// Notify about rejected controller role request:
                ///
                /// 0 - do not enqueue rejected CRR,
                ///
                /// 1 = enqueue rejected CRR on IBI queue/ring.
                NotifyCrrRejected OFFSET(1) NUMBITS(1) [],
                /// Notify about rejected hot-join:
                ///
                /// 0 - do not enqueue rejected HJ,
                ///
                /// 1 = enqueue rejected HJ on IBI queue/ring.
                NotifyHjRejected OFFSET(0) NUMBITS(1) [],
            ],
            pub IbiPort [
                IbiData OFFSET(0) NUMBITS(1) [],
            ],
            pub IntrForce [
                /// Force SCHED_CMD_MISSED_TICK_STAT interrupt.
                SchedCmdMissedTickForce OFFSET(14) NUMBITS(1) [],
                /// Force HC_ERR_CMD_SEQ_TIMEOUT_STAT interrupt.
                HcErrCmdSeqTimeoutForce OFFSET(13) NUMBITS(1) [],
                /// Force HC_WARN_CMD_SEQ_STALL_STAT interrupt.
                HcWarnCmdSeqStallForce OFFSET(12) NUMBITS(1) [],
                /// Force HC_SEQ_CANCEL_STAT interrupt.
                HcSeqCancelForce OFFSET(11) NUMBITS(1) [],
                /// Force HC_INTERNAL_ERR_STAT interrupt.
                HcInternalErrForce OFFSET(10) NUMBITS(1) [],
            ],
            pub IntrSignalEnable [
                /// Enable SCHED_CMD_MISSED_TICK_STAT interrupt.
                SchedCmdMissedTickSignalEn OFFSET(14) NUMBITS(1) [],
                /// Enable HC_ERR_CMD_SEQ_TIMEOUT_STAT interrupt.
                HcErrCmdSeqTimeoutSignalEn OFFSET(13) NUMBITS(1) [],
                /// Enable HC_WARN_CMD_SEQ_STALL_STAT interrupt.
                HcWarnCmdSeqStallSignalEn OFFSET(12) NUMBITS(1) [],
                /// Enable HC_SEQ_CANCEL_STAT interrupt.
                HcSeqCancelSignalEn OFFSET(11) NUMBITS(1) [],
                /// Enable HC_INTERNAL_ERR_STAT interrupt.
                HcInternalErrSignalEn OFFSET(10) NUMBITS(1) [],
            ],
            pub IntrStatus [
                /// Scheduled commands could be executed due to controller being busy.
                SchedCmdMissedTickStat OFFSET(14) NUMBITS(1) [],
                /// Command timeout after prolonged stall.
                HcErrCmdSeqTimeoutStat OFFSET(13) NUMBITS(1) [],
                /// Clock stalled due to lack of commands.
                HcWarnCmdSeqStallStat OFFSET(12) NUMBITS(1) [],
                /// Controller had to cancel command sequence.
                HcSeqCancelStat OFFSET(11) NUMBITS(1) [],
                /// Controller internal unrecoverable error.
                HcInternalErrStat OFFSET(10) NUMBITS(1) [],
            ],
            pub IntrStatusEnable [
                /// Enable SCHED_CMD_MISSED_TICK_STAT monitoring.
                SchedCmdMissedTickStatEn OFFSET(14) NUMBITS(1) [],
                /// Enable HC_ERR_CMD_SEQ_TIMEOUT_STAT monitoring.
                HcErrCmdSeqTimeoutStatEn OFFSET(13) NUMBITS(1) [],
                /// Enable HC_WARN_CMD_SEQ_STALL_STAT monitoring.
                HcWarnCmdSeqStallStatEn OFFSET(12) NUMBITS(1) [],
                /// Enable HC_SEQ_CANCEL_STAT monitoring.
                HcSeqCancelStatEn OFFSET(11) NUMBITS(1) [],
                /// Enable HC_INTERNAL_ERR_STAT monitoring.
                HcInternalErrStatEn OFFSET(10) NUMBITS(1) [],
            ],
            pub IntCtrlCmdsEn [
                /// Bitmask of supported MIPI commands.
                MipiCmdsSupported OFFSET(1) NUMBITS(15) [],
                /// Internal Control Commands:
                ///
                /// 1 - some or all internals commands sub-commands are supported,
                ///
                /// 0 - illegal.
                IccSupport OFFSET(0) NUMBITS(1) [],
            ],
            pub PioControl [
                /// Stop current command descriptor execution forcefully and hold remaining commands.
                /// 1 - Request PIO Abort,
                /// 0 - Resume PIO execution
                Abort OFFSET(2) NUMBITS(1) [],
                /// Run/Stop execution of enqueued commands.
                /// When set to 0, it holds execution of enqueued commands and runs current command to completion.
                /// 1 - PIO Queue start request,
                /// 0 - PIO Queue stop request.
                Rs OFFSET(1) NUMBITS(1) [],
                /// Enables PIO queues. When disabled, SW may not read from/write to PIO queues.
                /// 1 - PIO queue enable request,
                /// 0 - PIO queue disable request
                Enable OFFSET(0) NUMBITS(1) [],
            ],
            pub PioIntrForce [
                /// Force transfer error
                TransferErrForce OFFSET(9) NUMBITS(1) [],
                /// Force transfer aborted
                TransferAbortForce OFFSET(5) NUMBITS(1) [],
                /// Force response queue interrupt
                RespReadyForce OFFSET(4) NUMBITS(1) [],
                /// Force command queue interrupt
                CmdQueueReadyForce OFFSET(3) NUMBITS(1) [],
                /// Force IBI queue interrupt
                IbiThldForce OFFSET(2) NUMBITS(1) [],
                /// Force RX queue interrupt
                RxThldForce OFFSET(1) NUMBITS(1) [],
                /// Force TX queue interrupt
                TxThldForce OFFSET(0) NUMBITS(1) [],
            ],
            pub PioIntrSignalEnable [
                /// Enable transfer error interrupt
                TransferErrSignalEn OFFSET(9) NUMBITS(1) [],
                /// Enable transfer abort interrupt
                TransferAbortSignalEn OFFSET(5) NUMBITS(1) [],
                /// Enable response ready interrupt
                RespReadySignalEn OFFSET(4) NUMBITS(1) [],
                /// Enable command queue interrupt
                CmdQueueReadySignalEn OFFSET(3) NUMBITS(1) [],
                /// Enable IBI queue interrupt
                IbiStatusThldSignalEn OFFSET(2) NUMBITS(1) [],
                /// Enable RX queue interrupt
                RxThldSignalEn OFFSET(1) NUMBITS(1) [],
                /// Enable TX queue interrupt
                TxThldSignalEn OFFSET(0) NUMBITS(1) [],
            ],
            pub PioIntrStatus [
                /// Transfer error
                TransferErrStat OFFSET(9) NUMBITS(1) [],
                /// Transfer aborted
                TransferAbortStat OFFSET(5) NUMBITS(1) [],
                /// Response queue fulfils RESP_BUF_THLD
                RespReadyStat OFFSET(4) NUMBITS(1) [],
                /// Command queue fulfils CMD_EMPTY_BUF_THLD
                CmdQueueReadyStat OFFSET(3) NUMBITS(1) [],
                /// IBI queue fulfils IBI_STATUS_THLD
                IbiStatusThldStat OFFSET(2) NUMBITS(1) [],
                /// RX queue fulfils RX_BUF_THLD
                RxThldStat OFFSET(1) NUMBITS(1) [],
                /// TX queue fulfils TX_BUF_THLD
                TxThldStat OFFSET(0) NUMBITS(1) [],
            ],
            pub PioIntrStatusEnable [
                /// Enable transfer error monitoring
                TransferErrStatEn OFFSET(9) NUMBITS(1) [],
                /// Enable transfer abort monitoring
                TransferAbortStatEn OFFSET(5) NUMBITS(1) [],
                /// Enable response queue monitoring
                RespReadyStatEn OFFSET(4) NUMBITS(1) [],
                /// Enable command queue monitoring
                CmdQueueReadyStatEn OFFSET(3) NUMBITS(1) [],
                /// Enable IBI queue monitoring
                IbiStatusThldStatEn OFFSET(2) NUMBITS(1) [],
                /// Enable RX queue monitoring
                RxThldStatEn OFFSET(1) NUMBITS(1) [],
                /// Enable TX queue monitoring
                TxThldStatEn OFFSET(0) NUMBITS(1) [],
            ],
            pub PioSectionOffset [
                /// PIO section offset. Invalid if 0.
                SectionOffset OFFSET(0) NUMBITS(16) [],
            ],
            pub PresentState [
                /// Controller I3C state:
                ///
                /// 0 - not bus owner
                ///
                /// 1 - bus owner
                AcCurrentOwn OFFSET(2) NUMBITS(1) [],
            ],
            pub QueueSize [
                /// TX queue size is equal to 2^(N+1), where N is this field value
                TxDataBufferSize OFFSET(24) NUMBITS(8) [],
                /// RX queue size is equal to 2^(N+1), where N is this field value
                RxDataBufferSize OFFSET(16) NUMBITS(8) [],
                /// IBI Queue size is equal to N
                IbiStatusSize OFFSET(8) NUMBITS(8) [],
                /// Command/Response queue size is equal to N
                CrQueueSize OFFSET(0) NUMBITS(8) [],
            ],
            pub QueueThldCtrl [
                /// Triggers IBI_STATUS_THLD_STAT interrupt when IBI queue has N or more entries. Accepted values are 1:255
                IbiStatusThld OFFSET(24) NUMBITS(8) [],
                /// IBI Queue data segment size. Valida values are 1:63
                IbiDataSegmentSize OFFSET(16) NUMBITS(8) [],
                /// Triggers RESP_READY_STAT interrupt when RESP queue has N or more entries. Accepted values are 1:255
                RespBufThld OFFSET(8) NUMBITS(8) [],
                /// Triggers CMD_QUEUE_READY_STAT interrupt when CMD queue has N or more free entries. Accepted values are 1:255
                CmdEmptyBufThld OFFSET(0) NUMBITS(8) [],
            ],
            pub ResetControl [
                /// Clear IBI queue from software. Valid only in PIO mode.
                IbiQueueRst OFFSET(5) NUMBITS(1) [],
                /// Clear RX FIFO from software. Valid only in PIO mode.
                RxFifoRst OFFSET(4) NUMBITS(1) [],
                /// Clear TX FIFO from software. Valid only in PIO mode.
                TxFifoRst OFFSET(3) NUMBITS(1) [],
                /// Clear response queue from software. Valid only in PIO mode.
                RespQueueRst OFFSET(2) NUMBITS(1) [],
                /// Clear command queue from software. Valid only in PIO mode.
                CmdQueueRst OFFSET(1) NUMBITS(1) [],
                /// Reset controller from software.
                SoftRst OFFSET(0) NUMBITS(1) [],
            ],
            pub RingHeadersSectionOffset [
                /// DMA ring headers section offset. Invalid if 0.
                SectionOffset OFFSET(0) NUMBITS(16) [],
            ],
    }
}
pub mod regs {
    //! Types that represent registers.
    use tock_registers::register_structs;
    register_structs! {
        pub I3cCtrl {
            (0x0 => pub hci_version: tock_registers::registers::ReadOnly<u32>),
            (0x4 => pub hc_control: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::HcControl::Register>),
            (0x8 => pub controller_device_addr: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ControllerDeviceAddr::Register>),
            (0xc => pub hc_capabilities: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::HcCapabilities::Register>),
            (0x10 => pub reset_control: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ResetControl::Register>),
            (0x14 => pub present_state: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PresentState::Register>),
            (0x18 => _reserved0),
            (0x20 => pub intr_status: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IntrStatus::Register>),
            (0x24 => pub intr_status_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IntrStatusEnable::Register>),
            (0x28 => pub intr_signal_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IntrSignalEnable::Register>),
            (0x2c => pub intr_force: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IntrForce::Register>),
            (0x30 => pub dat_section_offset: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DatSectionOffset::Register>),
            (0x34 => pub dct_section_offset: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DctSectionOffset::Register>),
            (0x38 => pub ring_headers_section_offset: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::RingHeadersSectionOffset::Register>),
            (0x3c => pub pio_section_offset: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioSectionOffset::Register>),
            (0x40 => pub ext_caps_section_offset: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtCapsSectionOffset::Register>),
            (0x44 => _reserved1),
            (0x4c => pub int_ctrl_cmds_en: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IntCtrlCmdsEn::Register>),
            (0x50 => _reserved2),
            (0x58 => pub ibi_notify_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IbiNotifyCtrl::Register>),
            (0x5c => pub ibi_data_abort_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IbiDataAbortCtrl::Register>),
            (0x60 => pub dev_ctx_base_lo: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DevCtxBaseLo::Register>),
            (0x64 => pub dev_ctx_base_hi: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DevCtxBaseHi::Register>),
            (0x68 => pub dev_ctx_sg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DevCtxSg::Register>),
            (0x6c => _reserved3),
            (0x80 => pub command_port: tock_registers::registers::ReadOnly<u32>),
            (0x84 => pub response_port: tock_registers::registers::ReadOnly<u32>),
            (0x88 => pub tx_data_port: tock_registers::registers::ReadOnly<u32>),
            (0x8c => pub ibi_port: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IbiPort::Register>),
            (0x90 => pub queue_thld_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::QueueThldCtrl::Register>),
            (0x94 => pub data_buffer_thld_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::DataBufferThldCtrl::Register>),
            (0x98 => pub queue_size: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::QueueSize::Register>),
            (0x9c => pub alt_queue_size: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::AltQueueSize::Register>),
            (0xa0 => pub pio_intr_status: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioIntrStatus::Register>),
            (0xa4 => pub pio_intr_status_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioIntrStatusEnable::Register>),
            (0xa8 => pub pio_intr_signal_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioIntrSignalEnable::Register>),
            (0xac => pub pio_intr_force: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioIntrForce::Register>),
            (0xb0 => pub pio_control: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::PioControl::Register>),
            (0xb4 => _reserved4),
            (0x100 => pub termination_extcap_header: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtcapHeader::Register>),
            (0x104 => pub prot_cap_0: tock_registers::registers::ReadOnly<u32>),
            (0x108 => pub prot_cap_1: tock_registers::registers::ReadOnly<u32>),
            (0x10c => pub prot_cap_2: tock_registers::registers::ReadOnly<u32>),
            (0x110 => pub prot_cap_3: tock_registers::registers::ReadOnly<u32>),
            (0x114 => pub device_id_0: tock_registers::registers::ReadOnly<u32>),
            (0x118 => pub device_id_1: tock_registers::registers::ReadOnly<u32>),
            (0x11c => pub device_id_2: tock_registers::registers::ReadOnly<u32>),
            (0x120 => pub device_id_3: tock_registers::registers::ReadOnly<u32>),
            (0x124 => pub device_id_4: tock_registers::registers::ReadOnly<u32>),
            (0x128 => pub device_id_5: tock_registers::registers::ReadOnly<u32>),
            (0x12c => pub device_id_6: tock_registers::registers::ReadOnly<u32>),
            (0x130 => pub device_status_0: tock_registers::registers::ReadOnly<u32>),
            (0x134 => pub device_status_1: tock_registers::registers::ReadOnly<u32>),
            (0x138 => pub device_reset: tock_registers::registers::ReadOnly<u32>),
            (0x13c => pub recovery_ctrl: tock_registers::registers::ReadOnly<u32>),
            (0x140 => pub recovery_status: tock_registers::registers::ReadOnly<u32>),
            (0x144 => pub hw_status: tock_registers::registers::ReadOnly<u32>),
            (0x148 => pub indirect_fifo_ctrl_0: tock_registers::registers::ReadOnly<u32>),
            (0x14c => pub indirect_fifo_ctrl_1: tock_registers::registers::ReadOnly<u32>),
            (0x150 => pub indirect_fifo_status_0: tock_registers::registers::ReadOnly<u32>),
            (0x154 => pub indirect_fifo_status_1: tock_registers::registers::ReadOnly<u32>),
            (0x158 => pub indirect_fifo_status_2: tock_registers::registers::ReadOnly<u32>),
            (0x15c => pub indirect_fifo_status_3: tock_registers::registers::ReadOnly<u32>),
            (0x160 => pub indirect_fifo_status_4: tock_registers::registers::ReadOnly<u32>),
            (0x164 => pub indirect_fifo_status_5: tock_registers::registers::ReadOnly<u32>),
            (0x168 => pub indirect_fifo_data: tock_registers::registers::ReadOnly<u32>),
            (0x16c => _reserved5),
            (0x180 => pub extcap_header0: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtcapHeader::Register>),
            (0x184 => pub stby_cr_control: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrControl::Register>),
            (0x188 => pub stby_cr_device_addr: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrDeviceAddr::Register>),
            (0x18c => pub stby_cr_capabilities: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrCapabilities::Register>),
            (0x190 => pub _rsvd_0: tock_registers::registers::ReadOnly<u32>),
            (0x194 => pub stby_cr_status: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrStatus::Register>),
            (0x198 => pub stby_cr_device_char: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrDeviceChar::Register>),
            (0x19c => pub stby_cr_device_pid_lo: tock_registers::registers::ReadOnly<u32>),
            (0x1a0 => pub stby_cr_intr_status: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrIntrStatus::Register>),
            (0x1a4 => pub _rsvd_1: tock_registers::registers::ReadOnly<u32>),
            (0x1a8 => pub stby_cr_intr_signal_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrIntrSignalEnable::Register>),
            (0x1ac => pub stby_cr_intr_force: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrIntrForce::Register>),
            (0x1b0 => pub stby_cr_ccc_config_getcaps: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrCccConfigGetcaps::Register>),
            (0x1b4 => pub stby_cr_ccc_config_rstact_params: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::StbyCrCccConfigRstactParams::Register>),
            (0x1b8 => pub _rsvd_2: tock_registers::registers::ReadOnly<u32>),
            (0x1bc => pub _rsvd_3: tock_registers::registers::ReadOnly<u32>),
            (0x1c0 => pub extcap_header1: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtcapHeader::Register>),
            (0x1c4 => pub control: tock_registers::registers::ReadOnly<u32>),
            (0x1c8 => pub status: tock_registers::registers::ReadOnly<u32>),
            (0x1cc => pub tti_reset_control: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TtiResetControl::Register>),
            (0x1d0 => pub interrupt_status: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::InterruptStatus::Register>),
            (0x1d4 => pub interrupt_enable: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::InterruptEnable::Register>),
            (0x1d8 => pub interrupt_force: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::InterruptForce::Register>),
            (0x1dc => pub rx_desc_queue_port: tock_registers::registers::ReadOnly<u32>),
            (0x1e0 => pub rx_data_port0: tock_registers::registers::ReadOnly<u32>),
            (0x1e4 => pub tx_desc_queue_port: tock_registers::registers::ReadOnly<u32>),
            (0x1e8 => pub tx_data_port0: tock_registers::registers::ReadOnly<u32>),
            (0x1ec => pub tti_ibi_port: tock_registers::registers::ReadOnly<u32>),
            (0x1f0 => pub tti_queue_size: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TtiQueueSize::Register>),
            (0x1f4 => pub ibi_tti_queue_size: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::IbiTtiQueueSize::Register>),
            (0x1f8 => pub tti_queue_thld_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TtiQueueThldCtrl::Register>),
            (0x1fc => pub tti_data_buffer_thld_ctrl: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TtiDataBufferThldCtrl::Register>),
            (0x200 => pub extcap_header2: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtcapHeader::Register>),
            (0x204 => pub soc_mgmt_control: tock_registers::registers::ReadOnly<u32>),
            (0x208 => pub soc_mgmt_status: tock_registers::registers::ReadOnly<u32>),
            (0x20c => pub soc_mgmt_rsvd_0: tock_registers::registers::ReadOnly<u32>),
            (0x210 => pub soc_mgmt_rsvd_1: tock_registers::registers::ReadOnly<u32>),
            (0x214 => pub soc_mgmt_rsvd_2: tock_registers::registers::ReadOnly<u32>),
            (0x218 => pub soc_mgmt_rsvd_3: tock_registers::registers::ReadOnly<u32>),
            (0x21c => pub soc_pad_conf: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::SocPadConf::Register>),
            (0x220 => pub soc_pad_attr: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::SocPadAttr::Register>),
            (0x224 => pub soc_mgmt_feature_2: tock_registers::registers::ReadOnly<u32>),
            (0x228 => pub soc_mgmt_feature_3: tock_registers::registers::ReadOnly<u32>),
            (0x22c => pub t_r_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TRReg::Register>),
            (0x230 => pub t_f_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TFReg::Register>),
            (0x234 => pub t_su_dat_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TSuDatReg::Register>),
            (0x238 => pub t_hd_dat_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::THdDatReg::Register>),
            (0x23c => pub t_high_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::THighReg::Register>),
            (0x240 => pub t_low_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TLowReg::Register>),
            (0x244 => pub t_hd_sta_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::THdStaReg::Register>),
            (0x248 => pub t_su_sta_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TSuStaReg::Register>),
            (0x24c => pub t_su_sto_reg: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::TSuStoReg::Register>),
            (0x250 => pub t_free_reg: tock_registers::registers::ReadOnly<u32>),
            (0x254 => pub t_aval_reg: tock_registers::registers::ReadOnly<u32>),
            (0x258 => pub t_idle_reg: tock_registers::registers::ReadOnly<u32>),
            (0x25c => _reserved6),
            (0x260 => pub extcap_header3: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ExtcapHeader::Register>),
            (0x264 => pub controller_config: tock_registers::registers::ReadOnly<u32, crate::i3c_ctrl::bits::ControllerConfig::Register>),
            (0x268 => @END),
        }
    }
}
