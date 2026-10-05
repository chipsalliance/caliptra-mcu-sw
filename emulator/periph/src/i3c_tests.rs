// Licensed under the Apache-2.0 license

use super::*;
use caliptra_emu_cpu::Pic;
use caliptra_mcu_testing_common::i3c::{I3cTcriCommandXfer, ReguDataTransferCommand};
use std::sync::mpsc::channel;

struct Fixture {
    _clock: Clock,
    i3c: I3c,
    controller: I3cController,
    target: I3cTarget,
    responses: mpsc::Receiver<caliptra_mcu_testing_common::i3c::I3cBusResponse>,
}

impl Fixture {
    fn new() -> Self {
        let clock = Clock::new();
        let pic = Pic::new();
        let (_, rx) = channel();
        let (tx, responses) = channel();
        let mut controller = I3cController::new(rx, tx);
        let i3c = I3c::new(
            &clock,
            &mut controller,
            pic.register_irq(2),
            Version::new(2, 1, 0),
            Arc::new(Mutex::new(())),
        );
        let target = controller
            .target(i3c.get_dynamic_address().unwrap())
            .unwrap();
        Self {
            _clock: clock,
            i3c,
            controller,
            target,
            responses,
        }
    }

    fn command(&mut self, read: bool, len: u16, data: Vec<u8>) {
        let mut cmd = ReguDataTransferCommand(0);
        cmd.set_rnw(read as u8);
        cmd.set_data_length(len);
        self.target.send_command(I3cTcriCommandXfer {
            cmd: I3cTcriCommand::Regular(cmd),
            data,
        });
        self.i3c.poll();
        self.controller.run_once();
    }

    fn tx(&mut self, bytes: &[u8]) {
        self.i3c
            .write_i3c_ec_tti_tx_desc_queue_port(bytes.len() as u32);
        for chunk in bytes.chunks(4) {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.i3c
                .write_i3c_ec_tti_tx_data_port(u32::from_le_bytes(word));
        }
    }

    fn ibi(&mut self, data: &[u8]) {
        self.i3c
            .write_i3c_ec_tti_tti_ibi_port(0xae000000 | data.len() as u32);
        for chunk in data.chunks(4) {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.i3c
                .write_i3c_ec_tti_tti_ibi_port(u32::from_le_bytes(word));
        }
    }

    fn poll(&mut self) {
        self.i3c.poll();
        self.controller.run_once();
    }

    fn consume_ibi_status(&mut self) -> u32 {
        let status = self
            .i3c
            .read_i3c_ec_tti_status()
            .reg
            .read(Status::LastIbiStatus);
        self.i3c
            .write_i3c_ec_tti_interrupt_status(ReadWriteRegister::new(
                InterruptStatus::IbiDone::SET.value,
            ));
        status
    }
}

#[test]
fn tx_waits_for_explicit_read_and_strips_word_padding() {
    let mut f = Fixture::new();
    f.tx(&[1, 2, 3, 4, 5]);
    f.poll();
    assert!(f.responses.try_recv().is_err());
    f.command(true, 0, vec![]);
    let response = f.responses.try_recv().unwrap();
    assert_eq!(response.ibi, None);
    assert_eq!(response.resp.resp.data_length(), 5);
    assert_eq!(response.resp.data, [1, 2, 3, 4, 5]);
    assert!(f.i3c.tti_rx_desc_queue_raw.is_empty());
    assert!(f.i3c.tti_rx_data_raw.is_empty());
    assert!(!f
        .i3c
        .interrupt_status
        .reg
        .is_set(InterruptStatus::RxDescStat));
    f.poll();
    assert!(f.responses.try_recv().is_err());
}

#[test]
fn early_and_short_reads_are_bounded_and_consume_one_packet() {
    let mut f = Fixture::new();
    f.command(true, 3, vec![]);
    assert!(f.responses.try_recv().is_err());
    assert!(f.i3c.tti_rx_desc_queue_raw.is_empty());
    f.tx(&[1, 2, 3, 4, 5]);
    f.tx(&[6, 7]);
    f.poll();
    assert_eq!(f.responses.try_recv().unwrap().resp.data, [1, 2, 3]);
    assert!(f.responses.try_recv().is_err());
    f.command(true, 250, vec![]);
    assert_eq!(f.responses.try_recv().unwrap().resp.data, [6, 7]);
    assert!(f.i3c.tti_rx_desc_queue_raw.is_empty());
}

#[test]
fn ibi_completion_is_separate_and_preserves_payload() {
    let mut f = Fixture::new();
    f.ibi(&[0x12, 0x34, 0x56, 0x78, 0x9a]);
    assert!(f.i3c.ibi_status.is_none());
    assert!(!f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
    assert!(f.responses.try_recv().is_err());
    f.poll();
    assert!(f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
    let ibi = f.responses.try_recv().unwrap();
    assert_eq!(ibi.ibi, Some(0xae));
    assert_eq!(ibi.resp.resp.data_length(), 5);
    assert_eq!(ibi.resp.data, [0x12, 0x34, 0x56, 0x78, 0x9a]);
    assert_eq!(f.consume_ibi_status(), 0);
    assert!(!f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
}

#[test]
fn failed_then_successful_ibi_does_not_consume_queued_tx() {
    let mut f = Fixture::new();
    f.target.queue_ibi_outcome(I3cIbiOutcome::Complete {
        status: I3cIbiStatus::Nack,
        after_polls: 1,
    });
    f.tx(&[1, 2, 3, 4, 5]);
    f.ibi(&[0, 5]);
    f.poll();
    assert_eq!(f.consume_ibi_status(), I3cIbiStatus::Nack as u32);
    assert!(f.responses.try_recv().is_err());
    f.ibi(&[0, 5]);
    f.poll();
    assert_eq!(f.consume_ibi_status(), 0);
    assert_eq!(f.responses.try_recv().unwrap().resp.data, [0, 5]);
    assert!(f.responses.try_recv().is_err());
    assert_eq!(f.target.ibi_attempts(), 2);
    f.command(true, 5, vec![]);
    assert_eq!(f.responses.try_recv().unwrap().resp.data, [1, 2, 3, 4, 5]);
}

#[test]
fn delayed_and_missing_ibi_do_not_signal_early_completion() {
    let mut f = Fixture::new();
    f.target.queue_ibi_outcome(I3cIbiOutcome::Complete {
        status: I3cIbiStatus::PartialData,
        after_polls: 3,
    });
    f.ibi(&[0, 5]);
    for _ in 0..2 {
        f.poll();
        assert!(!f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
        assert!(f.responses.try_recv().is_err());
    }
    f.poll();
    assert!(f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
    assert_eq!(f.consume_ibi_status(), I3cIbiStatus::PartialData as u32);
    f.target.queue_ibi_outcome(I3cIbiOutcome::Missing);
    f.ibi(&[0, 5]);
    for _ in 0..10 {
        f.poll();
        assert!(!f.i3c.interrupt_status.reg.is_set(InterruptStatus::IbiDone));
        assert!(f.responses.try_recv().is_err());
    }
    assert!(f.i3c.pending_ibi.is_some());
}

#[test]
fn rx_descriptor_pop_does_not_flush_unread_data() {
    let mut f = Fixture::new();
    f.command(false, 5, vec![1, 2, 3, 4, 5]);
    f.command(false, 4, vec![6, 7, 8, 9]);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_desc_queue_port(), 5);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_desc_queue_port(), 4);
    // Data is an independent FIFO. Popping the second descriptor must leave
    // the first packet's unread bytes (and final-word padding) at its head.
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x04030201);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 5);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x09080706);
}

#[test]
fn rx_error_then_oversized_then_valid_write_preserves_fifo_boundaries() {
    let mut f = Fixture::new();
    f.target.queue_rx_error(1);
    // A controller read must not consume a fault meant for an RX write.
    f.command(true, 0, vec![]);
    assert!(f.i3c.tti_rx_desc_queue_raw.is_empty());
    f.command(false, 5, vec![1, 2, 3, 4, 5]);
    f.command(false, 251, vec![0x55; 251]);
    f.command(false, 3, vec![7, 8, 9]);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_desc_queue_port(), 0x10000005);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x04030201);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 5);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_desc_queue_port(), 251);
    for _ in 0..62 {
        assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x55555555);
    }
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x00555555);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_desc_queue_port(), 3);
    assert_eq!(f.i3c.read_i3c_ec_tti_rx_data_port(), 0x00090807);
    assert!(!f
        .i3c
        .interrupt_status
        .reg
        .is_set(InterruptStatus::RxDescStat));
}
