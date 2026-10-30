// Licensed under the Apache-2.0 license

//! Host recovery sequencing, independent of libusb and USB/IP.
//!
//! Transports complete one OCP control transfer per call, respect the supplied
//! timeout, and never retry an ambiguously completed write. Linux enumeration
//! belongs to the libusb adapter's OS, not this protocol driver.

use anyhow::{bail, ensure, Context, Result};
use caliptra_mcu_ocp::protocol::device_status::DeviceStatusValue;
use caliptra_mcu_ocp::protocol::indirect_fifo_ctrl::IndirectFifoCtrl;
use caliptra_mcu_ocp::protocol::indirect_fifo_status::{FifoCmsRegionType, IndirectFifoStatus};
use caliptra_mcu_ocp::protocol::prot_cap::{self, RecoveryProtocolCapabilities};
use caliptra_mcu_ocp::protocol::recovery_ctrl::{
    ActivateRecoveryImage, ImageSelection, RecoveryCtrl,
};
use caliptra_mcu_ocp::protocol::recovery_status::DeviceRecoveryStatus;
use caliptra_mcu_ocp::protocol::RecoveryCommand;
use std::time::{Duration, Instant};
use zerocopy::TryFromBytes;

#[cfg(feature = "libusb")]
pub mod libusb;

pub const CONTROL_MAX_BYTES: usize = 64;

pub trait RecoveryTransport {
    /// OCP reads request 64 bytes on this LPCIP implementation, even when the
    /// command's response is shorter. Return the actual length, without truncation.
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
        timeout: Duration,
    ) -> Result<usize>;
    fn write(&mut self, command: RecoveryCommand, data: &[u8], timeout: Duration) -> Result<()>;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wait(&mut self, duration: Duration) -> Result<()> {
        std::thread::sleep(duration);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryOptions {
    pub cms: u8,
    pub transfer_timeout: Duration,
    pub progress_timeout: Duration,
    pub overall_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            cms: 0,
            transfer_timeout: Duration::from_secs(2),
            progress_timeout: Duration::from_secs(30),
            overall_timeout: Duration::from_secs(180),
            poll_interval: Duration::from_millis(10),
        }
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
            _ => bail!("device requested unsupported image index {index}"),
        }
    }
}

fn image_words(bytes: usize) -> Result<u32> {
    ensure!(bytes != 0, "empty recovery image");
    let words = bytes.checked_add(3).context("image size overflow")? / 4;
    u32::try_from(words).context("image size exceeds the DWORD-count field")
}

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub major: u8,
    pub minor: u8,
    pub cms_regions: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct Discovery {
    pub capabilities: Capabilities,
    pub device_status: DeviceStatusValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// All supplied images were activated and the device reported healthy/running.
    Confirmed,
    /// No transfer was performed because the device was already running recovery.
    AlreadyRunning,
}

pub struct RecoveryAgent<T> {
    transport: T,
    options: RecoveryOptions,
    started: Instant,
    progressed: Instant,
}

impl<T: RecoveryTransport> RecoveryAgent<T> {
    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn new(transport: T, options: RecoveryOptions) -> Result<Self> {
        ensure!(
            !options.transfer_timeout.is_zero()
                && !options.progress_timeout.is_zero()
                && !options.overall_timeout.is_zero()
                && !options.poll_interval.is_zero(),
            "recovery timeouts and poll interval must be nonzero"
        );
        let started = transport.now();
        Ok(Self {
            transport,
            options,
            started,
            progressed: started,
        })
    }

    fn start(&mut self) {
        self.started = self.transport.now();
        self.progressed = self.started;
    }

    fn progress(&mut self) {
        self.progressed = self.transport.now();
    }

    fn budget(&self) -> Result<Duration> {
        let now = self.transport.now();
        let elapsed = now
            .checked_duration_since(self.started)
            .context("transport clock moved backwards")?;
        let idle = now
            .checked_duration_since(self.progressed)
            .context("transport clock moved backwards")?;
        let overall = self
            .options
            .overall_timeout
            .checked_sub(elapsed)
            .filter(|value| !value.is_zero())
            .context("overall recovery timeout")?;
        let progress = self
            .options
            .progress_timeout
            .checked_sub(idle)
            .filter(|value| !value.is_zero())
            .context("recovery progress timeout")?;
        Ok(overall.min(progress).min(self.options.transfer_timeout))
    }

    fn pause(&mut self) -> Result<()> {
        let duration = self.budget()?.min(self.options.poll_interval);
        self.transport
            .wait(duration)
            .context("recovery polling wait")
    }

    fn read(&mut self, command: RecoveryCommand) -> Result<([u8; CONTROL_MAX_BYTES], usize)> {
        let timeout = self.budget().with_context(|| format!("{command:?} read"))?;
        let mut response = [0; CONTROL_MAX_BYTES];
        let length = self
            .transport
            .read(command, &mut response, timeout)
            .with_context(|| format!("{command:?} control IN"))?;
        ensure!(
            length <= response.len(),
            "{command:?} oversized response: {length}"
        );
        self.budget()
            .with_context(|| format!("{command:?} read completed too late"))?;
        Ok((response, length))
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
        ensure!(
            !data.is_empty() && data.len() <= CONTROL_MAX_BYTES,
            "{command:?} invalid control OUT length {}",
            data.len()
        );
        let timeout = self
            .budget()
            .with_context(|| format!("{command:?} write"))?;
        self.transport
            .write(command, data, timeout)
            .with_context(|| format!("{command:?} control OUT (not retried)"))?;
        self.budget()
            .with_context(|| format!("{command:?} write completed too late"))?;
        Ok(())
    }

    fn capabilities(&mut self) -> Result<Capabilities> {
        let (response, length) = self.read(RecoveryCommand::ProtCap)?;
        ensure!(
            length == prot_cap::RESPONSE_LEN,
            "invalid PROT_CAP length {length}"
        );
        ensure!(&response[..8] == prot_cap::MAGIC, "invalid PROT_CAP magic");
        ensure!(
            response[8..10] == [1, 1],
            "unsupported recovery protocol {}.{}",
            response[8],
            response[9]
        );
        let flags = RecoveryProtocolCapabilities(u16::from_le_bytes([response[10], response[11]]));
        ensure!(
            flags.device_status() && flags.push_c_image_support() && flags.fifo_cms_support(),
            "device must support DEVICE_STATUS, push C-image and FIFO CMS"
        );
        ensure!(
            self.options.cms < response[12],
            "unsupported CMS index {}",
            self.options.cms
        );
        Ok(Capabilities {
            major: response[8],
            minor: response[9],
            cms_regions: response[12],
        })
    }

    fn device_status(&mut self) -> Result<DeviceStatusValue> {
        let (response, length) = self.read(RecoveryCommand::DeviceStatus)?;
        ensure!(
            length >= 7 && length == 7 + usize::from(response[6]),
            "invalid DEVICE_STATUS length {length}"
        );
        ensure!(
            response[1] == 0,
            "DEVICE_STATUS protocol error {:#04x}",
            response[1]
        );
        match response[0] {
            0 => Ok(DeviceStatusValue::StatusPending),
            1 => Ok(DeviceStatusValue::DeviceHealthy),
            2 => Ok(DeviceStatusValue::DeviceError),
            3 => Ok(DeviceStatusValue::RecoveryMode),
            4 => Ok(DeviceStatusValue::RecoveryPending),
            5 => Ok(DeviceStatusValue::RunningRecoveryImage),
            14 => Ok(DeviceStatusValue::BootFailure),
            15 => Ok(DeviceStatusValue::FatalError),
            value => bail!("invalid DEVICE_STATUS {value:#04x}"),
        }
    }

    fn recovery_status(&mut self) -> Result<(DeviceRecoveryStatus, u8)> {
        let (response, length) = self.read(RecoveryCommand::RecoveryStatus)?;
        ensure!(length == 2, "invalid RECOVERY_STATUS length {length}");
        let status = DeviceRecoveryStatus::try_from(response[0] & 15)
            .map_err(|error| anyhow::anyhow!("invalid RECOVERY_STATUS: {error:?}"))?;
        Ok((status, response[0] >> 4))
    }

    /// Probe capabilities/status without changing recovery state or sending images.
    pub fn probe(&mut self) -> Result<Discovery> {
        self.start();
        Ok(Discovery {
            capabilities: self.capabilities()?,
            device_status: self.device_status()?,
        })
    }

    pub fn run(&mut self, images: &RecoveryImages<'_>) -> Result<RecoveryOutcome> {
        for index in 0..3 {
            image_words(images.get(index)?.len())
                .with_context(|| format!("invalid image {index}"))?;
        }
        self.start();
        self.capabilities()?;
        loop {
            match self.device_status()? {
                DeviceStatusValue::RecoveryMode => break,
                DeviceStatusValue::RunningRecoveryImage => {
                    return Ok(RecoveryOutcome::AlreadyRunning)
                }
                DeviceStatusValue::StatusPending | DeviceStatusValue::DeviceHealthy => {
                    self.pause()?
                }
                status => bail!("device cannot enter recovery: {status:?}"),
            }
        }
        self.progress();
        self.write(RecoveryCommand::RecoveryCtrl, &[self.options.cms, 0, 0])?;
        let mut sent = [false; 3];
        let mut last_status = None;
        loop {
            let device = self
                .device_status()
                .context("waiting for recovery progress (activation alone is not success)")?;
            if matches!(
                device,
                DeviceStatusValue::DeviceHealthy | DeviceStatusValue::RunningRecoveryImage
            ) {
                ensure!(
                    sent.iter().all(|sent| *sent),
                    "device ended recovery before all images were activated"
                );
                return Ok(RecoveryOutcome::Confirmed);
            }
            ensure!(
                matches!(
                    device,
                    DeviceStatusValue::RecoveryMode | DeviceStatusValue::RecoveryPending
                ),
                "recovery failed: device status {device:?}"
            );
            let (status, index) = self.recovery_status()?;
            if last_status != Some((device, status, index)) {
                self.progress();
                last_status = Some((device, status, index));
            }
            match status {
                DeviceRecoveryStatus::AwaitingImage => {
                    let image = images.get(index)?;
                    if !sent[usize::from(index)] {
                        self.send_image(image)
                            .with_context(|| format!("image {index} ({} bytes)", image.len()))?;
                        self.wait_pending()
                            .with_context(|| format!("image {index} processing"))?;
                        let control = RecoveryCtrl::new(
                            self.options.cms,
                            ImageSelection::NoOperation,
                            ActivateRecoveryImage::Activate,
                        );
                        let mut data = [0; 3];
                        control
                            .to_message(&mut data)
                            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
                        self.write(RecoveryCommand::RecoveryCtrl, &data)
                            .with_context(|| format!("image {index} activation"))?;
                        sent[usize::from(index)] = true;
                        self.progress();
                    }
                }
                DeviceRecoveryStatus::BootingImage | DeviceRecoveryStatus::Success => {}
                status => bail!("recovery failed: status {status:?}, image {index}"),
            }
            self.pause()?;
        }
    }

    fn wait_pending(&mut self) -> Result<()> {
        loop {
            match self.device_status()? {
                DeviceStatusValue::RecoveryPending => return Ok(()),
                DeviceStatusValue::RecoveryMode => self.pause()?,
                status => bail!("image processing failed: {status:?}"),
            }
        }
    }

    fn send_image(&mut self, image: &[u8]) -> Result<()> {
        let words = image_words(image.len())?;
        let mut control = [0; 6];
        IndirectFifoCtrl::new(self.options.cms, false, words.to_le())
            .to_message(&mut control)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        self.write(RecoveryCommand::IndirectFifoCtrl, &control)?;
        let total = usize::try_from(words)?
            .checked_mul(4)
            .context("image size overflow")?;
        let mut offset = 0;
        while offset < total {
            let chunk = (|| -> Result<usize> {
                let (response, length) = self.read(RecoveryCommand::IndirectFifoStatus)?;
                let status = IndirectFifoStatus::try_read_from_bytes(&response[..length])
                    .map_err(|error| anyhow::anyhow!("invalid FIFO status: {error:?}"))?;
                let size = u32::from_le(status.fifo_size());
                let maximum = u32::from_le(status.max_transfer_size());
                let write = u32::from_le(status.write_index);
                let read = u32::from_le(status.read_index);
                ensure!(size > 0 && maximum > 0, "zero FIFO capacity/transfer limit");
                ensure!(write < size && read < size, "FIFO indices exceed capacity");
                ensure!(
                    status.region_type() == FifoCmsRegionType::CodeSpace,
                    "FIFO CMS is not writable code space"
                );
                ensure!(
                    response[0] & !3 == 0 && response[2..4] == [0, 0],
                    "reserved FIFO status bits"
                );
                ensure!(
                    !(status.full() && status.empty()),
                    "FIFO is both full and empty"
                );
                ensure!(
                    (write == read) == (status.full() || status.empty()),
                    "inconsistent FIFO indices/flags"
                );
                let used = if write >= read {
                    write - read
                } else {
                    size - (read - write)
                };
                let available = if status.full() { 0 } else { size - used };
                Ok(usize::try_from(available.min(maximum).min(16))? * 4)
            })()
            .with_context(|| format!("FIFO status at image byte offset {offset}/{total}"))?;
            if chunk == 0 {
                self.pause()
                    .with_context(|| format!("FIFO full at image byte offset {offset}/{total}"))?;
                continue;
            }
            let count = chunk.min(total - offset);
            let mut data = [0; CONTROL_MAX_BYTES];
            let actual = count.min(image.len().saturating_sub(offset));
            data[..actual]
                .copy_from_slice(&image[offset.min(image.len())..offset.min(image.len()) + actual]);
            self.write(RecoveryCommand::IndirectFifoData, &data[..count])
                .with_context(|| format!("image byte offset {offset}/{total}"))?;
            offset += count;
            self.progress();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
