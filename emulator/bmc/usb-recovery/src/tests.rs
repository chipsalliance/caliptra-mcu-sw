// Licensed under the Apache-2.0 license

use super::*;
use std::collections::VecDeque;

enum Event {
    Read(RecoveryCommand, Vec<u8>),
    ReadLength(RecoveryCommand, usize),
    Write(RecoveryCommand, Vec<u8>),
    FailedWrite(RecoveryCommand),
}

struct Script {
    events: VecDeque<Event>,
    now: Instant,
    writes: usize,
}

impl Script {
    fn new(events: Vec<Event>) -> Self {
        Self {
            events: events.into(),
            now: Instant::now(),
            writes: 0,
        }
    }
}

impl RecoveryTransport for Script {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        timeout: Duration,
    ) -> Result<usize> {
        assert!(!timeout.is_zero());
        self.now += Duration::from_millis(1);
        match self.events.pop_front().expect("unexpected read") {
            Event::Read(expected, bytes) => {
                assert_eq!(command, expected);
                response[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Event::ReadLength(expected, length) => {
                assert_eq!(command, expected);
                Ok(length)
            }
            _ => panic!("read instead of write: {command:?}"),
        }
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()> {
        assert!(!timeout.is_zero());
        self.now += Duration::from_millis(1);
        self.writes += 1;
        match self.events.pop_front().expect("unexpected write") {
            Event::Write(expected, bytes) => {
                assert_eq!(command, expected);
                assert_eq!(data, bytes);
                Ok(())
            }
            Event::FailedWrite(expected) => {
                assert_eq!(command, expected);
                bail!("peer disconnected after possible acceptance")
            }
            _ => panic!("write instead of read: {command:?}"),
        }
    }

    fn now(&self) -> Instant {
        self.now
    }

    fn wait(&mut self, duration: Duration) -> Result<()> {
        self.now += duration;
        Ok(())
    }
}

fn capabilities() -> Vec<u8> {
    let mut bytes = prot_cap::MAGIC.to_vec();
    bytes.extend([1, 1, 0x9a, 0x1a, 1, 0, 0]);
    bytes
}

fn device(status: u8) -> Event {
    Event::Read(
        RecoveryCommand::DeviceStatus,
        vec![status, 0, 0, 0, 0, 0, 0],
    )
}

fn fifo(full: bool, write: u32, read: u32, maximum: u32) -> Vec<u8> {
    let mut bytes = vec![
        if full {
            2
        } else if write == read {
            1
        } else {
            0
        },
        0,
        0,
        0,
    ];
    for word in [write, read, 64, maximum] {
        bytes.extend(word.to_le_bytes());
    }
    bytes
}

fn initial() -> Vec<Event> {
    vec![
        Event::Read(RecoveryCommand::ProtCap, capabilities()),
        device(0),
        device(3),
        Event::Write(RecoveryCommand::RecoveryCtrl, vec![0, 0, 0]),
    ]
}

fn complete_script(images: &RecoveryImages<'_>, maximum: u32) -> Vec<Event> {
    let mut events = initial();
    for index in [2, 0, 1] {
        let image = images.get(index).unwrap();
        events.push(device(3));
        events.push(Event::Read(
            RecoveryCommand::RecoveryStatus,
            vec![(index << 4) | 1, 0],
        ));
        let mut control = vec![0, 0];
        control.extend(image_words(image.len()).unwrap().to_le_bytes());
        events.push(Event::Write(RecoveryCommand::IndirectFifoCtrl, control));
        events.push(Event::Read(
            RecoveryCommand::IndirectFifoStatus,
            fifo(true, 0, 0, maximum),
        ));
        let mut padded = image.to_vec();
        padded.resize(padded.len().next_multiple_of(4), 0);
        for bytes in padded.chunks((maximum.min(16) * 4) as usize) {
            events.push(Event::Read(
                RecoveryCommand::IndirectFifoStatus,
                fifo(false, 0, 0, maximum),
            ));
            events.push(Event::Write(
                RecoveryCommand::IndirectFifoData,
                bytes.to_vec(),
            ));
        }
        events.push(device(3));
        events.push(device(4));
        events.push(Event::Write(RecoveryCommand::RecoveryCtrl, vec![0, 0, 15]));
    }
    events.push(device(5));
    events
}

#[test]
fn requested_image_order_exact_bytes_chunk_limits_padding_and_completion() {
    for size in [1, 3, 4, 63, 64, 65, 257, 601] {
        let bytes: Vec<_> = (0..size).map(|index| (index % 251) as u8).collect();
        let images = RecoveryImages {
            caliptra_fmc_rt: &bytes,
            soc_manifest: &bytes,
            mcu_runtime: &bytes,
        };
        for maximum in [2, 16, 64, u32::MAX] {
            let script = Script::new(complete_script(&images, maximum));
            let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
            assert_eq!(agent.run(&images).unwrap(), RecoveryOutcome::Confirmed);
            assert!(agent.into_transport().events.is_empty());
        }
    }
}

#[test]
fn fifo_space_and_wrapped_indices_bound_each_chunk() {
    let mut events = vec![
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(false, 62, 1, 64)),
        Event::Write(RecoveryCommand::IndirectFifoData, vec![1; 12]),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(false, 2, 1, 64)),
        Event::Write(RecoveryCommand::IndirectFifoData, vec![1; 8]),
    ];
    let mut control = vec![0, 0];
    control.extend(5u32.to_le_bytes());
    events.insert(0, Event::Write(RecoveryCommand::IndirectFifoCtrl, control));
    let mut agent = RecoveryAgent::new(Script::new(events), RecoveryOptions::default()).unwrap();
    agent.send_image(&[1; 20]).unwrap();
    assert!(agent.into_transport().events.is_empty());
}

#[test]
fn invalid_sizes_and_options_fail_before_transport_io() {
    assert!(image_words(0).is_err());
    assert!(image_words(usize::MAX).is_err());
    if usize::BITS > 32 {
        assert!(image_words(u32::MAX as usize * 4 + 1).is_err());
    }
    let mut agent = RecoveryAgent::new(Script::new(vec![]), RecoveryOptions::default()).unwrap();
    let error = agent
        .run(&RecoveryImages {
            caliptra_fmc_rt: &[],
            soc_manifest: &[1],
            mcu_runtime: &[1],
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("empty recovery image"));
    let options = RecoveryOptions {
        poll_interval: Duration::ZERO,
        ..Default::default()
    };
    assert!(RecoveryAgent::new(Script::new(vec![]), options).is_err());
}

#[test]
fn rejects_malformed_and_unsupported_capabilities() {
    let mut invalid = vec![vec![], vec![0; 15], capabilities()[..14].to_vec()];
    for index in [8, 9, 10, 11, 12] {
        let mut bytes = capabilities();
        bytes[index] = 0;
        invalid.push(bytes);
    }
    for bytes in invalid {
        let script = Script::new(vec![Event::Read(RecoveryCommand::ProtCap, bytes)]);
        let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
        assert!(agent.probe().is_err());
    }
}

#[test]
fn transport_must_not_silently_truncate_an_oversized_response() {
    let script = Script::new(vec![Event::ReadLength(RecoveryCommand::ProtCap, 65)]);
    let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
    assert!(format!("{:#}", agent.probe().unwrap_err()).contains("oversized response: 65"));
}

#[test]
fn probe_never_writes_or_activates() {
    let script = Script::new(vec![
        Event::Read(RecoveryCommand::ProtCap, capabilities()),
        device(0),
    ]);
    let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
    let result = agent.probe().unwrap();
    assert_eq!(result.device_status, DeviceStatusValue::StatusPending);
    assert_eq!(agent.into_transport().writes, 0);
}

#[test]
fn rejects_invalid_lengths_device_errors_and_unknown_image_requests() {
    for response in [
        vec![],
        vec![3; 6],
        vec![3, 0, 0, 0, 0, 0, 1],
        vec![3, 1, 0, 0, 0, 0, 0],
        vec![255, 0, 0, 0, 0, 0, 0],
    ] {
        let script = Script::new(vec![Event::Read(RecoveryCommand::DeviceStatus, response)]);
        let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
        assert!(agent.device_status().is_err());
    }
    for response in [vec![], vec![1], vec![4, 0], vec![1, 0, 0]] {
        let script = Script::new(vec![Event::Read(RecoveryCommand::RecoveryStatus, response)]);
        let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
        assert!(agent.recovery_status().is_err());
    }
    let mut events = initial();
    events.extend([
        device(3),
        Event::Read(RecoveryCommand::RecoveryStatus, vec![0x31, 0]),
    ]);
    let mut agent = RecoveryAgent::new(Script::new(events), RecoveryOptions::default()).unwrap();
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    assert!(format!("{:#}", agent.run(&images).unwrap_err()).contains("unsupported image index 3"));
}

#[test]
fn validates_fifo_flags_limits_indices_and_response_length() {
    let mut responses = vec![
        vec![],
        vec![0; 19],
        vec![0; 21],
        fifo(false, 0, 0, 0),
        fifo(false, 64, 0, 64),
    ];
    for index in [0, 1, 2, 3] {
        let mut response = fifo(false, 0, 0, 64);
        response[index] = 255;
        responses.push(response);
    }
    let mut no_capacity = fifo(false, 0, 0, 64);
    no_capacity[12..16].fill(0);
    responses.push(no_capacity);
    for response in responses {
        let mut control = vec![0, 0];
        control.extend(1u32.to_le_bytes());
        let script = Script::new(vec![
            Event::Write(RecoveryCommand::IndirectFifoCtrl, control),
            Event::Read(RecoveryCommand::IndirectFifoStatus, response),
        ]);
        let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
        assert!(agent.send_image(&[1]).is_err());
    }
}

#[test]
fn ambiguous_image_write_is_not_replayed_and_reports_offset() {
    let script = Script::new(vec![
        Event::Write(RecoveryCommand::IndirectFifoCtrl, vec![0, 0, 1, 0, 0, 0]),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(false, 0, 0, 64)),
        Event::FailedWrite(RecoveryCommand::IndirectFifoData),
    ]);
    let mut agent = RecoveryAgent::new(script, RecoveryOptions::default()).unwrap();
    let error = format!("{:#}", agent.send_image(&[1]).unwrap_err());
    assert!(error.contains("byte offset 0/4") && error.contains("not retried"));
    assert_eq!(agent.into_transport().writes, 2);
}

#[test]
fn fifo_that_never_drains_has_a_bounded_contextual_failure() {
    let mut events = vec![Event::Write(
        RecoveryCommand::IndirectFifoCtrl,
        vec![0, 0, 1, 0, 0, 0],
    )];
    for _ in 0..10 {
        events.push(Event::Read(
            RecoveryCommand::IndirectFifoStatus,
            fifo(true, 0, 0, 64),
        ));
    }
    let options = RecoveryOptions {
        progress_timeout: Duration::from_millis(25),
        ..Default::default()
    };
    let mut agent = RecoveryAgent::new(Script::new(events), options).unwrap();
    let error = format!("{:#}", agent.send_image(&[1]).unwrap_err());
    assert!(error.contains("byte offset 0/4") && error.contains("progress timeout"));
    assert_eq!(agent.into_transport().writes, 1);
}

struct Pending {
    now: Instant,
}

impl RecoveryTransport for Pending {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        _: Duration,
    ) -> Result<usize> {
        self.now += Duration::from_millis(1);
        let data = if command == RecoveryCommand::ProtCap {
            capabilities()
        } else {
            vec![0; 7]
        };
        response[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
    fn write(&mut self, _: RecoveryCommand, _: &[u8], _: Duration) -> Result<()> {
        panic!("pending peer must not receive writes");
    }
    fn now(&self) -> Instant {
        self.now
    }
    fn wait(&mut self, duration: Duration) -> Result<()> {
        self.now += duration;
        Ok(())
    }
}

#[test]
fn stalled_peer_and_overall_budget_are_bounded_by_virtual_time() {
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    let options = RecoveryOptions {
        progress_timeout: Duration::from_millis(25),
        ..Default::default()
    };
    let mut agent = RecoveryAgent::new(
        Pending {
            now: Instant::now(),
        },
        options,
    )
    .unwrap();
    assert!(format!("{:#}", agent.run(&images).unwrap_err()).contains("progress timeout"));
    let bytes = [1; 2048];
    let images = RecoveryImages {
        caliptra_fmc_rt: &bytes,
        soc_manifest: &bytes,
        mcu_runtime: &bytes,
    };
    let options = RecoveryOptions {
        overall_timeout: Duration::from_millis(40),
        ..Default::default()
    };
    let mut agent = RecoveryAgent::new(Script::new(complete_script(&images, 16)), options).unwrap();
    assert!(format!("{:#}", agent.run(&images).unwrap_err()).contains("overall recovery timeout"));
}

#[test]
fn activation_is_not_success_and_premature_completion_is_rejected() {
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    let mut events = initial();
    events.push(device(5));
    let mut agent = RecoveryAgent::new(Script::new(events), RecoveryOptions::default()).unwrap();
    assert!(format!("{:#}", agent.run(&images).unwrap_err()).contains("before all images"));

    let mut events = complete_script(&images, 16);
    events.pop();
    for _ in 0..10 {
        events.push(device(4));
        events.push(Event::Read(RecoveryCommand::RecoveryStatus, vec![0x22, 0]));
    }
    let options = RecoveryOptions {
        progress_timeout: Duration::from_millis(30),
        ..Default::default()
    };
    let mut agent = RecoveryAgent::new(Script::new(events), options).unwrap();
    assert!(format!("{:#}", agent.run(&images).unwrap_err()).contains("timeout"));
}
