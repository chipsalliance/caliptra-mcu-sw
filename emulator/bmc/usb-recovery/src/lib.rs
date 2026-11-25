// Licensed under the Apache-2.0 license

//! Host-side OCP Recovery v1.1 protocol driver (`RecoveryAgent`) and
//! transport trait (`RecoveryTransport`).

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
use std::task::Poll;
use zerocopy::TryFromBytes;

#[cfg(feature = "libusb")]
pub mod libusb;

/// Maximum payload size (in bytes) of a single OCP USB control transfer.
pub const CONTROL_MAX_BYTES: usize = 64;

/// Transport interface for issuing OCP Recovery class control transfers.
pub trait RecoveryTransport {
    /// Issue an OCP class control IN transfer for `command`, writing the
    /// payload into `response` and returning the number of bytes received.
    ///
    /// Full 64-byte buffers are supplied because LPCIP hardware expects 64-byte
    /// class IN requests even when a command's response is shorter.
    fn read(
        &mut self,
        command: RecoveryCommand,
        response: &mut [u8; CONTROL_MAX_BYTES],
    ) -> Result<usize>;

    /// Issue an OCP class control OUT transfer for `command` with `data`.
    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()>;
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

#[derive(Clone, Copy, Debug)]
enum Phase {
    Idle,
    EnteringRecovery,
    PollingRecovery,
    StreamingImage {
        index: u8,
        offset: usize,
        total: usize,
    },
    WaitingImagePending {
        index: u8,
    },
    Finished,
}

pub struct RecoveryAgent<T> {
    transport: T,
    cms: u8,
    phase: Phase,
    image_lengths: [usize; 3],
    sent: [bool; 3],
}

impl<T: RecoveryTransport> RecoveryAgent<T> {
    /// Construct a `RecoveryAgent` targeting CMS region `0` over `transport`.
    pub fn new(transport: T) -> Self {
        Self::with_cms(transport, 0)
    }

    /// Construct a `RecoveryAgent` targeting `cms` over `transport`.
    pub fn with_cms(transport: T, cms: u8) -> Self {
        Self {
            transport,
            cms,
            phase: Phase::Idle,
            image_lengths: [0; 3],
            sent: [false; 3],
        }
    }

    /// Consume the agent and return the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }

    fn read(&mut self, command: RecoveryCommand) -> Result<([u8; CONTROL_MAX_BYTES], usize)> {
        let mut response = [0; CONTROL_MAX_BYTES];
        let length = self
            .transport
            .read(command, &mut response)
            .with_context(|| format!("{command:?} control IN"))?;
        ensure!(
            length <= response.len(),
            "{command:?} oversized response: {length}"
        );
        Ok((response, length))
    }

    fn write(&mut self, command: RecoveryCommand, data: &[u8]) -> Result<()> {
        ensure!(
            !data.is_empty() && data.len() <= CONTROL_MAX_BYTES,
            "{command:?} invalid control OUT length {}",
            data.len()
        );
        self.transport
            .write(command, data)
            .with_context(|| format!("{command:?} control OUT (not retried)"))
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
            self.cms < response[12],
            "unsupported CMS index {}",
            self.cms
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

    /// Read `PROT_CAP` and `DEVICE_STATUS` from the target before recovery has
    /// started and return its reported capabilities and current status.
    pub fn probe(&mut self) -> Result<Discovery> {
        ensure!(
            matches!(self.phase, Phase::Idle),
            "cannot probe after recovery has started"
        );
        Ok(Discovery {
            capabilities: self.capabilities()?,
            device_status: self.device_status()?,
        })
    }

    /// Advance the recovery state machine without sleeping.
    ///
    /// Streams immediately available recovery chunks and returns
    /// `Ok(Poll::Pending)` whenever the device is still entering recovery,
    /// draining its indirect FIFO, processing a transferred image, or booting
    /// an activated image so the caller can perform its own wait between polls.
    /// Returns `Ok(Poll::Ready(_))` once recovery completes.
    pub fn poll(&mut self, images: &RecoveryImages<'_>) -> Result<Poll<RecoveryOutcome>> {
        let result = self.poll_step(images);
        if result.is_err() {
            self.phase = Phase::Finished;
        }
        result
    }

    fn poll_step(&mut self, images: &RecoveryImages<'_>) -> Result<Poll<RecoveryOutcome>> {
        if !matches!(self.phase, Phase::Idle | Phase::Finished) {
            for index in 0..3 {
                ensure!(
                    images.get(index)?.len() == self.image_lengths[usize::from(index)],
                    "image {index} length changed during recovery"
                );
            }
        }

        loop {
            match self.phase {
                Phase::Idle => {
                    for index in 0..3 {
                        let len = images.get(index)?.len();
                        image_words(len).with_context(|| format!("invalid image {index}"))?;
                        self.image_lengths[usize::from(index)] = len;
                    }
                    self.capabilities()?;
                    self.phase = Phase::EnteringRecovery;
                }
                Phase::EnteringRecovery => match self.device_status()? {
                    DeviceStatusValue::RecoveryMode => {
                        self.write(RecoveryCommand::RecoveryCtrl, &[self.cms, 0, 0])?;
                        self.phase = Phase::PollingRecovery;
                    }
                    DeviceStatusValue::RunningRecoveryImage => {
                        self.phase = Phase::Finished;
                        return Ok(Poll::Ready(RecoveryOutcome::AlreadyRunning));
                    }
                    DeviceStatusValue::StatusPending | DeviceStatusValue::DeviceHealthy => {
                        return Ok(Poll::Pending);
                    }
                    status => bail!("device cannot enter recovery: {status:?}"),
                },
                Phase::PollingRecovery => {
                    let device = self
                        .device_status()
                        .context("polling DEVICE_STATUS during recovery")?;
                    if matches!(
                        device,
                        DeviceStatusValue::DeviceHealthy | DeviceStatusValue::RunningRecoveryImage
                    ) {
                        ensure!(
                            self.sent.iter().all(|sent| *sent),
                            "device ended recovery before all images were activated"
                        );
                        self.phase = Phase::Finished;
                        return Ok(Poll::Ready(RecoveryOutcome::Confirmed));
                    }
                    ensure!(
                        matches!(
                            device,
                            DeviceStatusValue::RecoveryMode | DeviceStatusValue::RecoveryPending
                        ),
                        "recovery failed: device status {device:?}"
                    );
                    let (status, index) = self.recovery_status()?;
                    match status {
                        DeviceRecoveryStatus::AwaitingImage => {
                            let image = images.get(index)?;
                            if self.sent[usize::from(index)] {
                                return Ok(Poll::Pending);
                            }
                            let total = self.begin_image(image).with_context(|| {
                                format!("image {index} ({} bytes)", image.len())
                            })?;
                            self.phase = Phase::StreamingImage {
                                index,
                                offset: 0,
                                total,
                            };
                        }
                        DeviceRecoveryStatus::BootingImage | DeviceRecoveryStatus::Success => {
                            return Ok(Poll::Pending);
                        }
                        status => bail!("recovery failed: status {status:?}, image {index}"),
                    }
                }
                Phase::StreamingImage {
                    index,
                    mut offset,
                    total,
                } => {
                    let image = images.get(index)?;
                    match self
                        .poll_image_chunks(image, &mut offset, total)
                        .with_context(|| format!("image {index} ({} bytes)", image.len()))?
                    {
                        Poll::Pending => {
                            self.phase = Phase::StreamingImage {
                                index,
                                offset,
                                total,
                            };
                            return Ok(Poll::Pending);
                        }
                        Poll::Ready(()) => {
                            self.phase = Phase::WaitingImagePending { index };
                        }
                    }
                }
                Phase::WaitingImagePending { index } => {
                    match self
                        .poll_image_pending()
                        .with_context(|| format!("image {index} processing"))?
                    {
                        Poll::Pending => return Ok(Poll::Pending),
                        Poll::Ready(()) => {
                            let control = RecoveryCtrl::new(
                                self.cms,
                                ImageSelection::NoOperation,
                                ActivateRecoveryImage::Activate,
                            );
                            let mut data = [0; 3];
                            control
                                .to_message(&mut data)
                                .map_err(|error| anyhow::anyhow!("{error:?}"))?;
                            self.write(RecoveryCommand::RecoveryCtrl, &data)
                                .with_context(|| format!("image {index} activation"))?;
                            self.sent[usize::from(index)] = true;
                            self.phase = Phase::PollingRecovery;
                            return Ok(Poll::Pending);
                        }
                    }
                }
                Phase::Finished => bail!("recovery session has already completed"),
            }
        }
    }

    fn poll_image_pending(&mut self) -> Result<Poll<()>> {
        match self.device_status()? {
            DeviceStatusValue::RecoveryPending => Ok(Poll::Ready(())),
            DeviceStatusValue::RecoveryMode => Ok(Poll::Pending),
            status => bail!("image processing failed: {status:?}"),
        }
    }

    fn begin_image(&mut self, image: &[u8]) -> Result<usize> {
        let words = image_words(image.len())?;
        let mut control = [0; 6];
        IndirectFifoCtrl::new(self.cms, false, words.to_le())
            .to_message(&mut control)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        self.write(RecoveryCommand::IndirectFifoCtrl, &control)?;
        usize::try_from(words)?
            .checked_mul(4)
            .context("image size overflow")
    }

    fn next_fifo_chunk(&mut self) -> Result<usize> {
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
    }

    fn poll_image_chunks(
        &mut self,
        image: &[u8],
        offset: &mut usize,
        total: usize,
    ) -> Result<Poll<()>> {
        while *offset < total {
            let chunk = self
                .next_fifo_chunk()
                .with_context(|| format!("FIFO status at image byte offset {}/{total}", *offset))?;
            if chunk == 0 {
                return Ok(Poll::Pending);
            }
            let count = chunk.min(total - *offset);
            let mut data = [0; CONTROL_MAX_BYTES];
            let actual = count.min(image.len().saturating_sub(*offset));
            let start = (*offset).min(image.len());
            data[..actual].copy_from_slice(&image[start..start + actual]);
            self.write(RecoveryCommand::IndirectFifoData, &data[..count])
                .with_context(|| format!("image byte offset {}/{total}", *offset))?;
            *offset += count;
        }
        Ok(Poll::Ready(()))
    }
}

#[cfg(test)]
mod tests;
