// Licensed under the Apache-2.0 license

use caliptra_mcu_emulator_periph::TapDevice;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    DhcpV4,
    DhcpV6,
    Tftp,
}

impl PacketKind {
    const fn index(self) -> usize {
        match self {
            Self::DhcpV4 => 0,
            Self::DhcpV6 => 1,
            Self::Tftp => 2,
        }
    }
}

#[derive(Debug, Default)]
pub struct FaultStats {
    dropped: [AtomicUsize; 3],
    delayed: [AtomicUsize; 3],
}

impl FaultStats {
    pub fn dropped(&self, kind: PacketKind) -> usize {
        self.dropped[kind.index()].load(Ordering::Relaxed)
    }

    pub fn delayed(&self, kind: PacketKind) -> usize {
        self.delayed[kind.index()].load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, Debug)]
enum FaultAction {
    Drop,
    Delay(Duration),
}

#[derive(Clone, Copy, Debug)]
struct FaultRule {
    kind: PacketKind,
    tftp_transfer: Option<usize>,
    drop_outbound: bool,
    action: FaultAction,
    remaining: usize,
}

#[derive(Clone, Debug, Default)]
pub struct FaultPlan {
    rules: Vec<FaultRule>,
}

impl FaultPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drop_packets(mut self, kind: PacketKind, count: usize) -> Self {
        self.rules.push(FaultRule {
            kind,
            tftp_transfer: None,
            drop_outbound: false,
            action: FaultAction::Drop,
            remaining: count,
        });
        self
    }

    pub fn delay_packets(mut self, kind: PacketKind, count: usize, delay: Duration) -> Self {
        self.rules.push(FaultRule {
            kind,
            tftp_transfer: None,
            drop_outbound: false,
            action: FaultAction::Delay(delay),
            remaining: count,
        });
        self
    }

    pub fn drop_all(mut self, kind: PacketKind) -> Self {
        self.rules.push(FaultRule {
            kind,
            tftp_transfer: None,
            drop_outbound: true,
            action: FaultAction::Drop,
            remaining: usize::MAX,
        });
        self
    }

    pub fn drop_tftp_transfer(mut self, transfer: usize) -> Self {
        self.rules.push(FaultRule {
            kind: PacketKind::Tftp,
            tftp_transfer: Some(transfer),
            drop_outbound: false,
            action: FaultAction::Drop,
            remaining: usize::MAX,
        });
        self
    }
}

pub struct FaultInjectingTapDevice {
    inner: Box<dyn TapDevice>,
    rules: Vec<FaultRule>,
    delayed_frames: VecDeque<(Instant, Vec<u8>)>,
    tftp_client_ports: HashMap<u16, usize>,
    tftp_transfer_count: usize,
    last_tftp_filename: Vec<u8>,
    stats: Arc<FaultStats>,
}

impl FaultInjectingTapDevice {
    pub fn new(inner: Box<dyn TapDevice>, plan: FaultPlan, stats: Arc<FaultStats>) -> Self {
        Self {
            inner,
            rules: plan.rules,
            delayed_frames: VecDeque::new(),
            tftp_client_ports: HashMap::new(),
            tftp_transfer_count: 0,
            last_tftp_filename: Vec::new(),
            stats,
        }
    }

    fn classify(&self, frame: &[u8]) -> Option<(PacketKind, Option<usize>)> {
        let (ip_version, udp_offset) = udp_offset(frame)?;
        let src_port = u16::from_be_bytes(frame.get(udp_offset..udp_offset + 2)?.try_into().ok()?);
        let dst_port =
            u16::from_be_bytes(frame.get(udp_offset + 2..udp_offset + 4)?.try_into().ok()?);

        match (ip_version, src_port, dst_port) {
            (4, 67 | 68, 67 | 68) => Some((PacketKind::DhcpV4, None)),
            (6, 546 | 547, 546 | 547) => Some((PacketKind::DhcpV6, None)),
            _ if self.tftp_client_ports.contains_key(&dst_port) => Some((
                PacketKind::Tftp,
                self.tftp_client_ports.get(&dst_port).copied(),
            )),
            _ => return None,
        }
    }

    fn take_ready_delayed_frame(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let now = Instant::now();
        let position = self
            .delayed_frames
            .iter()
            .position(|(release_at, _)| *release_at <= now)?;
        let (_, frame) = self.delayed_frames.remove(position)?;
        let len = frame.len().min(buffer.len());
        buffer[..len].copy_from_slice(&frame[..len]);
        Some(len)
    }
}

impl TapDevice for FaultInjectingTapDevice {
    fn send(&mut self, frame: &[u8]) -> io::Result<usize> {
        if let Some((kind, tftp_transfer)) = self.classify(frame) {
            if let Some(rule) = self.rules.iter().find(|rule| {
                rule.kind == kind
                    && rule.drop_outbound
                    && matches!(rule.action, FaultAction::Drop)
                    && rule
                        .tftp_transfer
                        .map_or(true, |expected| tftp_transfer == Some(expected))
            }) {
                let _ = rule;
                self.stats.dropped[kind.index()].fetch_add(1, Ordering::Relaxed);
                return Ok(frame.len());
            }
        }

        if let Some((_, src_port, dst_port)) = udp_ports(frame) {
            if dst_port == 69 {
                if let Some(filename) = tftp_request_filename(frame) {
                    if filename != self.last_tftp_filename {
                        self.last_tftp_filename.clear();
                        self.last_tftp_filename.extend_from_slice(filename);
                        self.tftp_transfer_count += 1;
                    }
                    self.tftp_client_ports
                        .insert(src_port, self.tftp_transfer_count);
                } else if !self.tftp_client_ports.contains_key(&src_port) {
                    self.tftp_transfer_count += 1;
                    self.tftp_client_ports
                        .insert(src_port, self.tftp_transfer_count);
                }
            }
        }
        self.inner.send(frame)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if let Some(len) = self.take_ready_delayed_frame(buffer) {
            return Ok(len);
        }

        let len = self.inner.recv(buffer)?;
        if len == 0 {
            return Ok(0);
        }

        let Some((kind, tftp_transfer)) = self.classify(&buffer[..len]) else {
            return Ok(len);
        };
        let Some(rule) = self.rules.iter_mut().find(|rule| {
            rule.kind == kind
                && rule.remaining > 0
                && rule
                    .tftp_transfer
                    .map_or(true, |expected| tftp_transfer == Some(expected))
        }) else {
            return Ok(len);
        };

        rule.remaining -= 1;
        match rule.action {
            FaultAction::Drop => {
                self.stats.dropped[kind.index()].fetch_add(1, Ordering::Relaxed);
                Ok(0)
            }
            FaultAction::Delay(delay) => {
                self.stats.delayed[kind.index()].fetch_add(1, Ordering::Relaxed);
                self.delayed_frames
                    .push_back((Instant::now() + delay, buffer[..len].to_vec()));
                Ok(0)
            }
        }
    }

    fn poll_readable(&self) -> bool {
        self.inner.poll_readable()
            || self
                .delayed_frames
                .iter()
                .any(|(release_at, _)| *release_at <= Instant::now())
    }
}

fn udp_ports(frame: &[u8]) -> Option<(u8, u16, u16)> {
    let (ip_version, udp_offset) = udp_offset(frame)?;
    let src_port = u16::from_be_bytes(frame.get(udp_offset..udp_offset + 2)?.try_into().ok()?);
    let dst_port = u16::from_be_bytes(frame.get(udp_offset + 2..udp_offset + 4)?.try_into().ok()?);
    Some((ip_version, src_port, dst_port))
}

fn tftp_request_filename(frame: &[u8]) -> Option<&[u8]> {
    let (_, udp_offset) = udp_offset(frame)?;
    let payload = frame.get(udp_offset + 8..)?;
    if payload.get(..2)? != [0, 1] {
        return None;
    }
    let filename = payload.get(2..)?;
    let end = filename.iter().position(|byte| *byte == 0)?;
    filename.get(..end)
}

fn udp_offset(frame: &[u8]) -> Option<(u8, usize)> {
    const ETHERNET_HEADER_LEN: usize = 14;
    let ether_type = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    match ether_type {
        0x0800 => {
            let version_ihl = *frame.get(ETHERNET_HEADER_LEN)?;
            if version_ihl >> 4 != 4 || *frame.get(ETHERNET_HEADER_LEN + 9)? != 17 {
                return None;
            }
            let ip_header_len = ((version_ihl & 0x0f) as usize) * 4;
            if ip_header_len < 20 {
                return None;
            }
            Some((4, ETHERNET_HEADER_LEN + ip_header_len))
        }
        0x86dd => {
            if *frame.get(ETHERNET_HEADER_LEN)? >> 4 != 6
                || *frame.get(ETHERNET_HEADER_LEN + 6)? != 17
            {
                return None;
            }
            Some((6, ETHERNET_HEADER_LEN + 40))
        }
        _ => None,
    }
}
