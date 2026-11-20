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
    writes: usize,
}

impl Script {
    fn new(events: Vec<Event>) -> Self {
        Self {
            events: events.into(),
            writes: 0,
        }
    }
}

impl RecoveryTransport for Script {
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
    ) -> Result<usize> {
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

    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
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
}

fn drive<T: RecoveryTransport>(
    agent: &mut RecoveryAgent<T>,
    images: &RecoveryImages<'_>,
) -> Result<(RecoveryOutcome, usize)> {
    let mut pending = 0;
    loop {
        match agent.poll(images)? {
            Poll::Ready(outcome) => return Ok((outcome, pending)),
            Poll::Pending => pending += 1,
        }
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
            let mut agent = RecoveryAgent::new(script);
            let (outcome, pending) = drive(&mut agent, &images).unwrap();
            assert_eq!(outcome, RecoveryOutcome::Confirmed);
            assert_eq!(pending, 10);
            assert!(agent.poll(&images).is_err());
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
    let mut agent = RecoveryAgent::new(Script::new(events));
    let total = agent.begin_image(&[1; 20]).unwrap();
    let mut offset = 0;
    assert_eq!(
        agent
            .poll_image_chunks(&[1; 20], &mut offset, total)
            .unwrap(),
        Poll::Ready(())
    );
    assert_eq!(offset, 20);
    assert!(agent.into_transport().events.is_empty());
}

#[test]
fn invalid_image_sizes_fail_before_transport_io() {
    assert!(image_words(0).is_err());
    assert!(image_words(usize::MAX).is_err());
    if usize::BITS > 32 {
        assert!(image_words(u32::MAX as usize * 4 + 1).is_err());
    }
    let mut agent = RecoveryAgent::new(Script::new(vec![]));
    let error = agent
        .poll(&RecoveryImages {
            caliptra_fmc_rt: &[],
            soc_manifest: &[1],
            mcu_runtime: &[1],
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("empty recovery image"));

    let script = Script::new(vec![
        Event::Read(RecoveryCommand::ProtCap, capabilities()),
        device(0),
    ]);
    let mut agent = RecoveryAgent::new(script);
    assert_eq!(
        agent
            .poll(&RecoveryImages {
                caliptra_fmc_rt: &[1],
                soc_manifest: &[2],
                mcu_runtime: &[3],
            })
            .unwrap(),
        Poll::Pending
    );
    let error = agent
        .poll(&RecoveryImages {
            caliptra_fmc_rt: &[1, 2],
            soc_manifest: &[2],
            mcu_runtime: &[3],
        })
        .unwrap_err();
    assert!(format!("{error:#}").contains("length changed"));
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
        let mut agent = RecoveryAgent::new(script);
        assert!(agent.probe().is_err());
    }
    let script = Script::new(vec![Event::Read(RecoveryCommand::ProtCap, capabilities())]);
    let mut agent = RecoveryAgent::with_cms(script, 1);
    assert!(agent.probe().is_err());
}

#[test]
fn transport_must_not_silently_truncate_an_oversized_response() {
    let script = Script::new(vec![Event::ReadLength(RecoveryCommand::ProtCap, 65)]);
    let mut agent = RecoveryAgent::new(script);
    assert!(format!("{:#}", agent.probe().unwrap_err()).contains("oversized response: 65"));
}

#[test]
fn probe_never_writes_or_activates() {
    let script = Script::new(vec![
        Event::Read(RecoveryCommand::ProtCap, capabilities()),
        device(0),
    ]);
    let mut agent = RecoveryAgent::new(script);
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
        let mut agent = RecoveryAgent::new(script);
        assert!(agent.device_status().is_err());
    }
    for response in [vec![], vec![1], vec![4, 0], vec![1, 0, 0]] {
        let script = Script::new(vec![Event::Read(RecoveryCommand::RecoveryStatus, response)]);
        let mut agent = RecoveryAgent::new(script);
        assert!(agent.recovery_status().is_err());
    }
    let mut events = initial();
    events.extend([
        device(3),
        Event::Read(RecoveryCommand::RecoveryStatus, vec![0x31, 0]),
    ]);
    let mut agent = RecoveryAgent::new(Script::new(events));
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    assert!(format!("{:#}", drive(&mut agent, &images).unwrap_err())
        .contains("unsupported image index 3"));
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
        let mut agent = RecoveryAgent::new(script);
        let total = agent.begin_image(&[1]).unwrap();
        let mut offset = 0;
        assert!(agent.poll_image_chunks(&[1], &mut offset, total).is_err());
    }
}

#[test]
fn ambiguous_image_write_is_not_replayed_and_reports_offset() {
    let mut events = initial();
    events.extend([
        device(3),
        Event::Read(RecoveryCommand::RecoveryStatus, vec![0x01, 0]),
        Event::Write(RecoveryCommand::IndirectFifoCtrl, vec![0, 0, 1, 0, 0, 0]),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(false, 0, 0, 64)),
        Event::FailedWrite(RecoveryCommand::IndirectFifoData),
    ]);
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    let mut agent = RecoveryAgent::new(Script::new(events));
    let error = format!("{:#}", drive(&mut agent, &images).unwrap_err());
    assert!(error.contains("byte offset 0/4") && error.contains("not retried"));
    assert!(agent.poll(&images).is_err());
    assert_eq!(agent.into_transport().writes, 3);
}

#[test]
fn full_fifo_yields_pending_without_replaying_fifo_ctrl() {
    let mut events = initial();
    events.extend([
        device(3),
        Event::Read(RecoveryCommand::RecoveryStatus, vec![0x01, 0]),
        Event::Write(RecoveryCommand::IndirectFifoCtrl, vec![0, 0, 1, 0, 0, 0]),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(true, 0, 0, 64)),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(true, 0, 0, 64)),
        Event::Read(RecoveryCommand::IndirectFifoStatus, fifo(false, 0, 0, 64)),
        Event::Write(RecoveryCommand::IndirectFifoData, vec![1, 0, 0, 0]),
        device(3),
    ]);
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    let mut agent = RecoveryAgent::new(Script::new(events));
    // Initial `StatusPending` poll.
    assert_eq!(agent.poll(&images).unwrap(), Poll::Pending);
    // Enters recovery, writes `IndirectFifoCtrl`, then sees full FIFO twice.
    assert_eq!(agent.poll(&images).unwrap(), Poll::Pending);
    assert_eq!(agent.poll(&images).unwrap(), Poll::Pending);
    // FIFO drains, writes data chunk once, then waits for `RecoveryPending`.
    assert_eq!(agent.poll(&images).unwrap(), Poll::Pending);
    let script = agent.into_transport();
    assert_eq!(script.writes, 3);
    assert!(script.events.is_empty());
}

#[test]
fn pending_peer_yields_pending_without_writes() {
    let script = Script::new(vec![
        Event::Read(RecoveryCommand::ProtCap, capabilities()),
        device(0),
        device(0),
        device(0),
    ]);
    let images = RecoveryImages {
        caliptra_fmc_rt: &[1],
        soc_manifest: &[2],
        mcu_runtime: &[3],
    };
    let mut agent = RecoveryAgent::new(script);
    for _ in 0..3 {
        assert_eq!(agent.poll(&images).unwrap(), Poll::Pending);
    }
    let script = agent.into_transport();
    assert_eq!(script.writes, 0);
    assert!(script.events.is_empty());
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
    let mut agent = RecoveryAgent::new(Script::new(events));
    assert!(format!("{:#}", drive(&mut agent, &images).unwrap_err()).contains("before all images"));

    let mut events = complete_script(&images, 16);
    let final_status = events.pop().unwrap();
    events.push(device(4));
    events.push(Event::Read(RecoveryCommand::RecoveryStatus, vec![0x22, 0]));
    events.push(final_status);
    let mut agent = RecoveryAgent::new(Script::new(events));
    let (outcome, pending) = drive(&mut agent, &images).unwrap();
    assert_eq!(outcome, RecoveryOutcome::Confirmed);
    assert_eq!(pending, 11);
    assert!(agent.into_transport().events.is_empty());
}
