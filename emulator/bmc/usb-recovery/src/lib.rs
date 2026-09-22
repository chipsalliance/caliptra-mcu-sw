// Licensed under the Apache-2.0 license

use anyhow::{bail, ensure, Context, Result};
use caliptra_mcu_ocp::protocol::device_status::DeviceStatusValue;
use caliptra_mcu_ocp::protocol::prot_cap;
use caliptra_mcu_ocp::protocol::recovery_status::DeviceRecoveryStatus;
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use rusb::{DeviceHandle, GlobalContext};
use std::thread;
use std::time::{Duration, Instant};

const REQUEST_TYPE_IN: u8 = 0xa1;
const REQUEST_TYPE_OUT: u8 = 0x21;
const REQUEST: u8 = 0;
const INTERFACE: u16 = 0;
const USB_CONTROL_MAX_BYTES: usize = 64;

pub const DEFAULT_VENDOR_ID: u16 = 0x1209;
pub const DEFAULT_PRODUCT_ID: u16 = 0x0001;

pub trait RecoveryTransport {
    fn read(&mut self, command: RecoveryCommand, response: &mut [u8]) -> Result<usize>;
    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()>;
}

pub struct LibusbTransport {
    handle: DeviceHandle<GlobalContext>,
    timeout: Duration,
}

impl LibusbTransport {
    pub fn open(vendor_id: u16, product_id: u16, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;
        let handle = loop {
            if let Some(handle) = rusb::open_device_with_vid_pid(vendor_id, product_id) {
                break handle;
            }
            ensure!(
                Instant::now() < deadline,
                "USB recovery device {vendor_id:04x}:{product_id:04x} was not found"
            );
            thread::sleep(Duration::from_millis(20));
        };
        handle
            .claim_interface(INTERFACE as u8)
            .context("failed to claim OCP Recovery USB interface")?;
        Ok(Self { handle, timeout })
    }
}

impl RecoveryTransport for LibusbTransport {
    fn read(&mut self, command: RecoveryCommand, response: &mut [u8]) -> Result<usize> {
        self.handle
            .read_control(
                REQUEST_TYPE_IN,
                REQUEST,
                command as u16,
                INTERFACE,
                response,
                self.timeout,
            )
            .with_context(|| format!("OCP {command:?} read failed"))
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
        let written = self
            .handle
            .write_control(
                REQUEST_TYPE_OUT,
                REQUEST,
                command as u16,
                INTERFACE,
                data,
                self.timeout,
            )
            .with_context(|| format!("OCP {command:?} write failed"))?;
        ensure!(written == data.len(), "short OCP {command:?} write");
        Ok(())
    }
}

pub struct RecoveryImages<'a> {
    pub caliptra_fmc_rt: &'a [u8],
    pub soc_manifest: &'a [u8],
    pub mcu_runtime: &'a [u8],
}

impl RecoveryImages<'_> {
    fn get(&self, index: u8) -> Result<&[u8]> {
        match index {
            0 => Ok(self.caliptra_fmc_rt),
            1 => Ok(self.soc_manifest),
            2 => Ok(self.mcu_runtime),
            _ => bail!("device requested unsupported recovery image index {index}"),
        }
    }
}

pub struct RecoveryAgent<T> {
    transport: T,
    cms: u8,
    poll_interval: Duration,
    state_timeout: Duration,
}

impl<T: RecoveryTransport> RecoveryAgent<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            cms: 0,
            poll_interval: Duration::from_millis(10),
            state_timeout: Duration::from_secs(30),
        }
    }

    pub fn run(&mut self, images: &RecoveryImages<'_>) -> Result<()> {
        self.check_capabilities()?;
        let startup_deadline = Instant::now() + self.state_timeout;
        loop {
            match self.device_status()? {
                DeviceStatusValue::RecoveryMode => break,
                DeviceStatusValue::RunningRecoveryImage => return Ok(()),
                DeviceStatusValue::StatusPending | DeviceStatusValue::DeviceHealthy => {
                    ensure!(
                        Instant::now() < startup_deadline,
                        "timed out waiting for the device to enter recovery mode"
                    );
                    thread::sleep(self.poll_interval);
                }
                status => bail!("device is not ready for recovery: {status:?}"),
            }
        }

        self.transport
            .write(RecoveryCommand::RecoveryCtrl, &[0, 0, 0])?;

        let mut sent = [false; 3];
        let mut progress_deadline = Instant::now() + self.state_timeout;
        loop {
            ensure!(
                Instant::now() < progress_deadline,
                "timed out waiting for recovery state progress"
            );
            match self.device_status()? {
                DeviceStatusValue::DeviceHealthy | DeviceStatusValue::RunningRecoveryImage => {
                    return Ok(())
                }
                DeviceStatusValue::RecoveryMode | DeviceStatusValue::RecoveryPending => {}
                status => bail!("recovery failed with device status {status:?}"),
            }

            let (status, image_index) = self.recovery_status()?;
            match status {
                DeviceRecoveryStatus::AwaitingImage => {
                    let image = images.get(image_index)?;
                    if sent[image_index as usize] {
                        thread::sleep(self.poll_interval);
                        continue;
                    }
                    self.send_fifo_image(image)?;
                    sent[image_index as usize] = true;
                    self.wait_for_recovery_pending()?;
                    self.transport
                        .write(RecoveryCommand::RecoveryCtrl, &[self.cms, 0, 0x0f])?;
                    if sent.iter().all(|sent| *sent) {
                        return Ok(());
                    }
                    progress_deadline = Instant::now() + self.state_timeout;
                }
                DeviceRecoveryStatus::BootingImage | DeviceRecoveryStatus::Success => {
                    thread::sleep(self.poll_interval);
                }
                status => bail!("device reported recovery failure {status:?}"),
            }
        }
    }

    fn check_capabilities(&mut self) -> Result<()> {
        let mut response = [0; prot_cap::RESPONSE_LEN];
        let len = self
            .transport
            .read(RecoveryCommand::ProtCap, &mut response)?;
        ensure!(
            len == response.len(),
            "invalid PROT_CAP response length {len}"
        );
        ensure!(&response[..8] == prot_cap::MAGIC, "invalid PROT_CAP magic");
        let capabilities = u16::from_le_bytes([response[10], response[11]]);
        ensure!(
            capabilities & (1 << 4) != 0,
            "DEVICE_STATUS is not supported"
        );
        ensure!(capabilities & (1 << 12) != 0, "FIFO CMS is not supported");
        Ok(())
    }

    fn device_status(&mut self) -> Result<DeviceStatusValue> {
        let mut response = [0; 7];
        let len = self
            .transport
            .read(RecoveryCommand::DeviceStatus, &mut response)?;
        ensure!(
            len == response.len(),
            "invalid DEVICE_STATUS response length {len}"
        );
        match response[0] {
            0x0 => Ok(DeviceStatusValue::StatusPending),
            0x1 => Ok(DeviceStatusValue::DeviceHealthy),
            0x2 => Ok(DeviceStatusValue::DeviceError),
            0x3 => Ok(DeviceStatusValue::RecoveryMode),
            0x4 => Ok(DeviceStatusValue::RecoveryPending),
            0x5 => Ok(DeviceStatusValue::RunningRecoveryImage),
            0xe => Ok(DeviceStatusValue::BootFailure),
            0xf => Ok(DeviceStatusValue::FatalError),
            status => bail!("invalid device status {status:#04x}"),
        }
    }

    fn recovery_status(&mut self) -> Result<(DeviceRecoveryStatus, u8)> {
        let mut response = [0; 2];
        let len = self
            .transport
            .read(RecoveryCommand::RecoveryStatus, &mut response)?;
        ensure!(
            len == response.len(),
            "invalid RECOVERY_STATUS response length {len}"
        );
        let status = DeviceRecoveryStatus::try_from(response[0] & 0x0f)
            .map_err(|_| anyhow::anyhow!("invalid recovery status {:#04x}", response[0] & 0x0f))?;
        Ok((status, response[0] >> 4))
    }

    fn wait_for_recovery_pending(&mut self) -> Result<()> {
        let deadline = Instant::now() + self.state_timeout;
        loop {
            if self.device_status()? == DeviceStatusValue::RecoveryPending {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "timed out waiting for the device to process the recovery image"
            );
            thread::sleep(self.poll_interval);
        }
    }

    fn send_fifo_image(&mut self, image: &[u8]) -> Result<()> {
        let mut image = image.to_vec();
        image.resize(image.len().next_multiple_of(4), 0);
        let image_size_dwords = u32::try_from(image.len() / 4)?;
        let size = image_size_dwords.to_le_bytes();
        self.transport.write(
            RecoveryCommand::IndirectFifoCtrl,
            &[self.cms, 0, size[0], size[1], size[2], size[3]],
        )?;

        let mut offset = 0;
        let deadline = Instant::now() + self.state_timeout;
        while offset < image.len() {
            let status = self.fifo_status()?;
            let available_dwords = status.available_dwords();
            if available_dwords == 0 {
                ensure!(
                    Instant::now() < deadline,
                    "timed out waiting for FIFO space"
                );
                thread::sleep(self.poll_interval);
                continue;
            }
            let max_bytes = usize::try_from(status.max_transfer_dwords)?
                .saturating_mul(4)
                .min(USB_CONTROL_MAX_BYTES);
            let chunk_len = (available_dwords as usize * 4)
                .min(max_bytes)
                .min(image.len() - offset);
            ensure!(
                chunk_len > 0,
                "device reported an invalid FIFO transfer size"
            );
            self.transport.write(
                RecoveryCommand::IndirectFifoData,
                &image[offset..offset + chunk_len],
            )?;
            offset += chunk_len;
        }
        Ok(())
    }

    fn fifo_status(&mut self) -> Result<FifoStatus> {
        let mut response = [0; 20];
        let len = self
            .transport
            .read(RecoveryCommand::IndirectFifoStatus, &mut response)?;
        ensure!(
            len == response.len(),
            "invalid FIFO status response length {len}"
        );
        Ok(FifoStatus {
            full: response[0] & 2 != 0,
            write_index: u32::from_le_bytes(response[4..8].try_into()?),
            read_index: u32::from_le_bytes(response[8..12].try_into()?),
            size_dwords: u32::from_le_bytes(response[12..16].try_into()?),
            max_transfer_dwords: u32::from_le_bytes(response[16..20].try_into()?),
        })
    }
}

struct FifoStatus {
    full: bool,
    write_index: u32,
    read_index: u32,
    size_dwords: u32,
    max_transfer_dwords: u32,
}

impl FifoStatus {
    fn available_dwords(&self) -> u32 {
        if self.full || self.size_dwords == 0 {
            return 0;
        }
        let used = if self.write_index >= self.read_index {
            self.write_index - self.read_index
        } else {
            self.size_dwords - (self.read_index - self.write_index)
        };
        self.size_dwords.saturating_sub(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct MockTransport {
        reads: VecDeque<(RecoveryCommand, Vec<u8>)>,
        writes: Vec<(RecoveryCommand, Vec<u8>)>,
    }

    impl RecoveryTransport for MockTransport {
        fn read(&mut self, command: RecoveryCommand, response: &mut [u8]) -> Result<usize> {
            let (expected, data) = self.reads.pop_front().unwrap();
            assert_eq!(command, expected);
            response[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        }

        fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
            self.writes.push((command, data.to_vec()));
            Ok(())
        }
    }

    fn prot_cap() -> Vec<u8> {
        let mut response = vec![0; 15];
        response[..8].copy_from_slice(b"OCP RECV");
        response[10..12].copy_from_slice(&((1_u16 << 4) | (1_u16 << 12)).to_le_bytes());
        response
    }

    fn fifo_status() -> Vec<u8> {
        let mut response = vec![0; 20];
        response[12..16].copy_from_slice(&64_u32.to_le_bytes());
        response[16..20].copy_from_slice(&64_u32.to_le_bytes());
        response
    }

    #[test]
    fn sends_requested_images_in_fifo_chunks() {
        let mut reads = VecDeque::from([
            (RecoveryCommand::ProtCap, prot_cap()),
            (RecoveryCommand::DeviceStatus, vec![1, 0, 0, 0, 0, 0, 0]),
            (RecoveryCommand::DeviceStatus, vec![3, 0, 0, 0, 0, 0, 0]),
        ]);
        for index in 0..3_u8 {
            if index == 1 {
                reads.extend([
                    (RecoveryCommand::DeviceStatus, vec![3, 0, 0, 0, 0, 0, 0]),
                    (RecoveryCommand::RecoveryStatus, vec![1, 0]),
                ]);
            }
            reads.extend([
                (RecoveryCommand::DeviceStatus, vec![3, 0, 0, 0, 0, 0, 0]),
                (RecoveryCommand::RecoveryStatus, vec![(index << 4) | 1, 0]),
                (RecoveryCommand::IndirectFifoStatus, fifo_status()),
            ]);
            if index == 0 {
                reads.push_back((RecoveryCommand::IndirectFifoStatus, fifo_status()));
            }
            reads.push_back((RecoveryCommand::DeviceStatus, vec![4, 0, 0, 0, 0, 0, 0]));
        }
        reads.push_back((
            RecoveryCommand::DeviceStatus,
            vec![
                DeviceStatusValue::RunningRecoveryImage as u8,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        ));
        let transport = MockTransport {
            reads,
            writes: Vec::new(),
        };
        let images = RecoveryImages {
            caliptra_fmc_rt: &[0x11; 68],
            soc_manifest: &[0x22; 4],
            mcu_runtime: &[0x33; 4],
        };
        let mut agent = RecoveryAgent::new(transport);
        agent.run(&images).unwrap();

        let fifo_writes: Vec<_> = agent
            .transport
            .writes
            .iter()
            .filter(|(command, _)| *command == RecoveryCommand::IndirectFifoData)
            .map(|(_, data)| data.len())
            .collect();
        assert_eq!(fifo_writes, [64, 4, 4, 4]);
        assert_eq!(
            agent
                .transport
                .writes
                .iter()
                .filter(|(command, data)| {
                    *command == RecoveryCommand::RecoveryCtrl && data == &[0, 0, 0x0f]
                })
                .count(),
            3
        );
    }
}
