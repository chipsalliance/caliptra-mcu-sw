// Licensed under the Apache-2.0 license

//! OCP Recovery Interface state machine.
//!
//! This module defines the `RecoveryStateMachine` that implements the OCP
//! Secure Firmware Recovery v1.1 command processing loop, along with the
//! `RecoveryDeviceConfig` and `RecoveryAction` types used by integrators.

use crate::cms::{FifoCmsRegion, IndirectCmsRegion};
use crate::error::{CmsError, OcpError};
use crate::protocol::device_id::DeviceId;
use crate::protocol::device_reset::{
    DeviceReset, ForcedRecoveryMode, InterfaceControl, ResetControl,
};
use crate::protocol::device_status;
use crate::protocol::device_status::{
    DeviceStatus, DeviceStatusValue, ProtocolError, RecoveryReasonCode,
};
use crate::protocol::indirect_ctrl::IndirectCtrl;
use crate::protocol::indirect_fifo_ctrl::IndirectFifoCtrl;
use crate::protocol::indirect_fifo_status::{
    FifoCmsRegionType, FifoStatusFlags, IndirectFifoStatus,
};
use crate::protocol::indirect_status::{CmsRegionType, IndirectStatus, StatusFlags};
use crate::protocol::prot_cap::{ProtCap, RecoveryProtocolCapabilities};
use crate::protocol::recovery_ctrl::{ActivateRecoveryImage, ImageSelection, RecoveryCtrl};
use crate::protocol::recovery_status::{DeviceRecoveryStatus, RecoveryStatus};
use crate::protocol::RecoveryCommand;
use crate::usb::driver::{RecoveryRequest, UsbDeviceDriver};
use crate::vendor::VendorHandler;

/// Static device configuration provided at state machine construction time.
///
/// These fields are immutable for the lifetime of the state machine and are
/// used to populate PROT_CAP and DEVICE_ID responses.
pub struct RecoveryDeviceConfig<'a> {
    /// DEVICE_ID response payload.
    pub device_id: DeviceId<'a>,

    /// PROT_CAP major version (byte 8).
    pub major_version: u8,

    /// PROT_CAP minor version (byte 9).
    pub minor_version: u8,

    /// PROT_CAP max response time exponent (byte 13).
    /// Actual time = 2^max_response_time microseconds.
    pub max_response_time: u8,

    /// PROT_CAP heartbeat period exponent (byte 14).
    /// 0 means heartbeat is not supported.
    pub heartbeat_period: u8,

    /// Whether the device supports local c-image recovery (PROT_CAP bit 6).
    /// Set to `true` if the device can recover from a locally stored image.
    pub local_c_image_support: bool,
}

/// Actions the integrator must handle after `process_command` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// No integrator action required. The command was fully handled.
    None,

    /// The integrator should activate the recovery image.
    /// After performing activation, the integrator calls
    /// `complete_activation()` to report the result.
    ActivateRecoveryImage,
}

/// Protocol state and configuration, separated from the transport to allow
/// disjoint borrowing in `process_command`.
#[allow(dead_code)]
pub struct RecoveryState<'a, V: VendorHandler> {
    // Protocol structs stored directly (no borrowed data).
    pub(crate) recovery_status: RecoveryStatus,
    pub(crate) recovery_ctrl: RecoveryCtrl,
    pub(crate) device_reset: DeviceReset,
    pub(crate) indirect_ctrl: IndirectCtrl,
    pub(crate) indirect_fifo_ctrl_cms: u8,
    pub(crate) indirect_fifo_ctrl_image_size: u32,

    // DEVICE_STATUS fields stored individually. DeviceStatus<'a> cannot be
    // stored because its vendor_status slice comes from VendorHandler at
    // read time.
    pub(crate) device_status_value: DeviceStatusValue,
    pub(crate) protocol_error: ProtocolError,
    pub(crate) recovery_reason: RecoveryReasonCode,

    pub(crate) config: RecoveryDeviceConfig<'a>,

    pub(crate) indirect_regions: &'a mut [(u8, &'a mut dyn IndirectCmsRegion)],
    pub(crate) fifo_regions: &'a mut [(u8, &'a mut dyn FifoCmsRegion)],
    pub(crate) cms_count: u8,

    pub(crate) vendor: V,
}

/// OCP Recovery Interface state machine.
///
/// Implements the recovery lifecycle defined in the OCP Secure Firmware
/// Recovery spec v1.1. The state machine owns the transport and handles
/// receive/send internally, exposing `process_command()` as the single
/// entry point for the integrator's main loop.
#[allow(dead_code)]
pub struct RecoveryStateMachine<'a, U: UsbDeviceDriver, V: VendorHandler> {
    pub(crate) transport: &'a mut U,
    pub(crate) state: RecoveryState<'a, V>,
}

impl<'a, U: UsbDeviceDriver, V: VendorHandler> RecoveryStateMachine<'a, U, V> {
    /// Construct a new state machine with spec-defined defaults.
    ///
    /// All protocol state is initialized to power-on defaults:
    /// device status is `StatusPending`, no protocol errors, no boot failure,
    /// recovery status is `NotInRecovery`, and all control registers are zeroed.
    pub fn new(
        config: RecoveryDeviceConfig<'a>,
        transport: &'a mut U,
        indirect_regions: &'a mut [(u8, &'a mut dyn IndirectCmsRegion)],
        fifo_regions: &'a mut [(u8, &'a mut dyn FifoCmsRegion)],
        vendor: V,
    ) -> Result<Self, OcpError> {
        let recovery_status = RecoveryStatus::new(DeviceRecoveryStatus::NotInRecovery, 0, 0)?;

        if !indirect_regions.is_empty() {
            let has_cms0_code = indirect_regions.iter().any(|(idx, r)| {
                *idx == 0 && r.status().cms_region_type() == Ok(CmsRegionType::CodeSpace)
            });
            if !has_cms0_code {
                return Err(OcpError::IndirectCms0NotCodeSpace);
            }
        }

        // Verify no CMS index appears more than once across both slices.
        // Note: CMS regions are likely to be few, so this operation is not prohibetively expensive.
        for (i, (idx_a, _)) in indirect_regions.iter().enumerate() {
            for (idx_b, _) in indirect_regions[i + 1..].iter() {
                if idx_a == idx_b {
                    return Err(OcpError::DuplicateCmsIndex);
                }
            }
            for (idx_b, _) in fifo_regions.iter() {
                if idx_a == idx_b {
                    return Err(OcpError::DuplicateCmsIndex);
                }
            }
        }
        for (i, (idx_a, _)) in fifo_regions.iter().enumerate() {
            for (idx_b, _) in fifo_regions[i + 1..].iter() {
                if idx_a == idx_b {
                    return Err(OcpError::DuplicateCmsIndex);
                }
            }
        }

        let indirect_count = indirect_regions.len();
        let fifo_count = fifo_regions.len();
        let cms_count: u8 = (indirect_count + fifo_count)
            .try_into()
            .map_err(|_| OcpError::InvalidCmdBufferCount)?;

        Ok(Self {
            transport,
            state: RecoveryState {
                recovery_status,
                recovery_ctrl: RecoveryCtrl::new(
                    0,
                    ImageSelection::NoOperation,
                    ActivateRecoveryImage::DoNotActivate,
                ),
                device_reset: DeviceReset::new(
                    ResetControl::NoReset,
                    ForcedRecoveryMode::None,
                    InterfaceControl::DisableMastering,
                ),
                indirect_ctrl: IndirectCtrl::new(0, 0)?,
                indirect_fifo_ctrl_cms: 0,
                indirect_fifo_ctrl_image_size: 0,
                cms_count,
                device_status_value: DeviceStatusValue::StatusPending,
                protocol_error: ProtocolError::NoError,
                recovery_reason: RecoveryReasonCode::NoBootFailure,
                config,
                indirect_regions,
                fifo_regions,
                vendor,
            },
        })
    }

    /// Block for the next command on the transport, process it, send any
    /// response, and return an action for the integrator to handle.
    ///
    /// Returns an error only if the transport itself fails. Protocol-level
    /// errors are recorded in DEVICE_STATUS and do not cause this method
    /// to return Err.
    pub fn process_command(&mut self) -> Result<RecoveryAction, OcpError> {
        let (cmd, req) = self.transport.recv()?;
        match req {
            RecoveryRequest::Read { .. } => {
                let state = &mut self.state;
                self.transport.send(&mut |buf| match cmd {
                    RecoveryCommand::ProtCap => state.handle_prot_cap_read(buf),
                    RecoveryCommand::DeviceId => state.handle_device_id_read(buf),
                    RecoveryCommand::DeviceStatus => state.handle_device_status_read(buf),
                    RecoveryCommand::RecoveryStatus => state.handle_recovery_status_read(buf),
                    RecoveryCommand::HwStatus => state.handle_hw_status_read(buf),
                    RecoveryCommand::IndirectStatus => state.handle_indirect_status_read(buf),
                    RecoveryCommand::IndirectFifoStatus => {
                        state.handle_indirect_fifo_status_read(buf)
                    }
                    RecoveryCommand::DeviceReset => state.handle_device_reset_read(buf),
                    RecoveryCommand::IndirectCtrl => state.handle_indirect_ctrl_read(buf),
                    RecoveryCommand::IndirectFifoCtrl => state.handle_indirect_fifo_ctrl_read(buf),
                    RecoveryCommand::IndirectData => state.handle_indirect_data_read(buf),
                    RecoveryCommand::Vendor => state.handle_vendor_read(buf),
                    RecoveryCommand::IndirectFifoData => state.handle_indirect_fifo_data_read(buf),
                    _ => {
                        state.set_protocol_error(ProtocolError::UnsupportedCommand);
                        Ok(0)
                    }
                })?;
            }
            RecoveryRequest::Write { data } => match cmd {
                RecoveryCommand::DeviceReset => self.state.handle_device_reset_write(data),
                RecoveryCommand::IndirectCtrl => self.state.handle_indirect_ctrl_write(data),
                RecoveryCommand::IndirectFifoCtrl => {
                    self.state.handle_indirect_fifo_ctrl_write(data)
                }
                RecoveryCommand::IndirectData => self.state.handle_indirect_data_write(data),
                RecoveryCommand::Vendor => self.state.handle_vendor_write(data),
                RecoveryCommand::IndirectFifoData => {
                    self.state.handle_indirect_fifo_data_write(data);
                }
                _ => self
                    .state
                    .set_protocol_error(ProtocolError::UnsupportedCommand),
            },
        }

        Ok(RecoveryAction::None)
    }
}

impl<V: VendorHandler> RecoveryState<'_, V> {
    /// Look up a memory-window CMS region by index.
    fn lookup_indirect_region(&mut self, cms: u8) -> Option<&mut dyn IndirectCmsRegion> {
        for (idx, region) in self.indirect_regions.iter_mut() {
            if *idx == cms {
                return Some(*region);
            }
        }
        None
    }

    /// Look up a FIFO CMS region by index.
    fn lookup_fifo_region(&mut self, cms: u8) -> Option<&mut dyn FifoCmsRegion> {
        for (idx, region) in self.fifo_regions.iter_mut() {
            if *idx == cms {
                return Some(*region);
            }
        }
        None
    }

    /// Record a protocol error for the next DEVICE_STATUS read.
    fn set_protocol_error(&mut self, err: ProtocolError) {
        self.protocol_error = err;
    }

    /// Build the PROT_CAP capabilities bitfield from the current region
    /// configuration and vendor-reported capabilities.
    ///
    /// Identification and device_status are always set. CMS 0 is guaranteed
    /// to be CodeSpace when indirect regions are present (enforced by `new()`),
    /// so push_c_image_support and recovery_memory_access are set together
    /// whenever indirect regions exist. Bits 1-3 and 8-10 are populated from
    /// `VendorHandler::capabilities()`.
    fn build_capabilities(&self) -> RecoveryProtocolCapabilities {
        let mut caps = RecoveryProtocolCapabilities(0);
        let vendor_caps = self.vendor.capabilities();

        caps.set_identification(true);
        caps.set_device_status(true);
        caps.set_local_c_image_support(self.config.local_c_image_support);

        caps.set_forced_recovery(vendor_caps.forced_recovery());
        caps.set_mgmt_reset(vendor_caps.mgmt_reset());
        caps.set_device_reset(vendor_caps.device_reset());
        caps.set_interface_isolation(vendor_caps.interface_isolation());
        caps.set_hardware_status(vendor_caps.hardware_status());
        caps.set_vendor_command(vendor_caps.vendor_command());

        if !self.indirect_regions.is_empty() {
            caps.set_push_c_image_support(true);
            caps.set_recovery_memory_access(true);
        }

        if !self.fifo_regions.is_empty() {
            caps.set_fifo_cms_support(true);
        }

        caps
    }

    /// Handle a PROT_CAP (cmd=0x22) read: build and serialize the response.
    fn handle_prot_cap_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let caps = self.build_capabilities();
        let prot_cap = ProtCap::new(
            self.config.major_version,
            self.config.minor_version,
            caps,
            self.cms_count,
            self.config.max_response_time,
            self.config.heartbeat_period,
        );
        prot_cap.to_message(buf)
    }

    /// Handle a DEVICE_ID (cmd=0x23) read: serialize the device identity.
    fn handle_device_id_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        self.config.device_id.to_message(buf)
    }

    /// Handle a DEVICE_STATUS (cmd=0x24) read: assemble dynamic fields and serialize.
    ///
    /// Protocol error is clear-on-read: the current value is included in the
    /// response, then reset to `NoError`.
    fn handle_device_status_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let heartbeat = self.vendor.heartbeat();
        let mut vendor_buf = [0u8; device_status::MAX_VENDOR_STATUS_LEN];
        let vendor_len = self.vendor.vendor_device_status(&mut vendor_buf);

        let status = DeviceStatus::new(
            self.device_status_value,
            self.protocol_error,
            self.recovery_reason,
            heartbeat,
            &vendor_buf[..vendor_len],
        )?;

        let len = status.to_message(buf)?;
        self.protocol_error = ProtocolError::NoError;
        Ok(len)
    }

    /// Handle a RECOVERY_STATUS (cmd=0x27) read: serialize stored recovery status.
    fn handle_recovery_status_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        self.recovery_status.to_message(buf)
    }

    /// Handle a HW_STATUS (cmd=0x28) read: delegate to vendor and serialize.
    fn handle_hw_status_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let hw = self.vendor.hw_status()?;
        hw.to_message(buf)
    }

    /// Handle an INDIRECT_STATUS (cmd=0x2A) read.
    ///
    /// Looks up the memory-window CMS region selected by `indirect_ctrl.cms`.
    /// If found, returns its status and clears accumulated flags (clear-on-read).
    /// If the index doesn't match any indirect region (including FIFO-only
    /// indices), returns `CmsRegionType::Unsupported`.
    fn handle_indirect_status_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let cms = self.indirect_ctrl.cms;
        match self.lookup_indirect_region(cms) {
            Some(region) => {
                let status = region.status();
                region.clear_status();
                status.to_message(buf)
            }
            None => IndirectStatus::new(StatusFlags(0), CmsRegionType::Unsupported, false, 0)
                .to_message(buf),
        }
    }

    /// Handle an INDIRECT_FIFO_STATUS (cmd=0x2E) read.
    ///
    /// Looks up the FIFO CMS region selected by `indirect_fifo_ctrl_cms`.
    /// If found, returns its status metadata. If the index doesn't match any
    /// FIFO region (including indirect-only indices), returns
    /// `FifoCmsRegionType::Unsupported`.
    fn handle_indirect_fifo_status_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let cms = self.indirect_fifo_ctrl_cms;
        match self.lookup_fifo_region(cms) {
            Some(region) => region.status().to_message(buf),
            None => IndirectFifoStatus::new(
                FifoStatusFlags(0),
                FifoCmsRegionType::Unsupported,
                0,
                0,
                0,
                0,
            )
            .to_message(buf),
        }
    }

    /// Handle a DEVICE_RESET (cmd=0x25) read: serialize stored reset state.
    fn handle_device_reset_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        self.device_reset.to_message(buf)
    }

    /// Handle a DEVICE_RESET (cmd=0x25) write: parse, validate, store, and
    /// return action.
    ///
    /// Before accepting the command, verifies that the vendor advertises the
    /// capabilities required by the requested operations (device_reset,
    /// mgmt_reset, forced_recovery). On success the parsed `DeviceReset` is
    /// stored and `vendor.execute_reset()` is called. Length errors map to
    /// `LengthWriteError`, reserved or unsupported values map to
    /// `UnsupportedParameter`.
    fn handle_device_reset_write(&mut self, data: &[u8]) {
        let parsed = match DeviceReset::from_message(data) {
            Ok(p) => p,
            Err(OcpError::MessageTooShort | OcpError::MessageTooLong) => {
                self.set_protocol_error(ProtocolError::LengthWriteError);
                return;
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::UnsupportedParameter);
                return;
            }
        };

        let caps = self.vendor.capabilities();

        if parsed.reset_control == ResetControl::ResetDevice && !caps.device_reset() {
            self.set_protocol_error(ProtocolError::UnsupportedParameter);
            return;
        }
        if parsed.reset_control == ResetControl::ResetManagement && !caps.mgmt_reset() {
            self.set_protocol_error(ProtocolError::UnsupportedParameter);
            return;
        }
        if parsed.forced_recovery != ForcedRecoveryMode::None && !caps.forced_recovery() {
            self.set_protocol_error(ProtocolError::UnsupportedParameter);
            return;
        }

        self.device_reset = parsed;
        self.vendor.execute_reset(&self.device_reset);
    }

    fn handle_indirect_ctrl_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let cms = self.indirect_ctrl.cms;
        let imo = match self.lookup_indirect_region(cms) {
            Some(region) => region.imo(),
            None => 0,
        };
        IndirectCtrl::new(cms, imo)?.to_message(buf)
    }

    fn handle_indirect_ctrl_write(&mut self, data: &[u8]) {
        let parsed = match IndirectCtrl::from_message(data) {
            Ok(p) => p,
            Err(OcpError::MessageTooShort | OcpError::MessageTooLong) => {
                self.set_protocol_error(ProtocolError::LengthWriteError);
                return;
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::UnsupportedParameter);
                return;
            }
        };

        let cms_changed = parsed.cms != self.indirect_ctrl.cms;
        self.indirect_ctrl = parsed;

        if let Some(region) = self.lookup_indirect_region(parsed.cms) {
            // According to the spec changing the CMS resets the IMO. As such do not set
            // the imo value inside the write command if the CMS has changed.
            if cms_changed {
                region.reset();
            } else {
                region.set_imo(parsed.imo());
            }
        }
    }

    /// Handle an INDIRECT_FIFO_CTRL (cmd=0x2D) read: serialize stored state
    /// with the reset byte read from the region ("Write 1, Device Clears").
    fn handle_indirect_fifo_ctrl_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let reset = match self.lookup_fifo_region(self.indirect_fifo_ctrl_cms) {
            Some(region) => region.is_reset_pending(),
            None => false,
        };
        IndirectFifoCtrl::new(
            self.indirect_fifo_ctrl_cms,
            reset,
            self.indirect_fifo_ctrl_image_size,
        )
        .to_message(buf)
    }

    /// Handle an INDIRECT_FIFO_CTRL (cmd=0x2D) write: parse, optionally
    /// reset FIFO, and store.
    fn handle_indirect_fifo_ctrl_write(&mut self, data: &[u8]) {
        let parsed = match IndirectFifoCtrl::from_message(data) {
            Ok(p) => p,
            Err(OcpError::MessageTooShort | OcpError::MessageTooLong) => {
                self.set_protocol_error(ProtocolError::LengthWriteError);
                return;
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::UnsupportedParameter);
                return;
            }
        };

        if parsed.reset {
            if let Some(region) = self.lookup_fifo_region(parsed.cms) {
                region.request_reset();
            }
        }

        self.indirect_fifo_ctrl_cms = parsed.cms;
        self.indirect_fifo_ctrl_image_size = parsed.image_size;
    }

    /// Handle an INDIRECT_DATA (cmd=0x2B) read: read from the currently
    /// selected indirect CMS region at the current IMO.
    ///
    /// The region auto-increments the IMO after the read. Returns the
    /// number of bytes read. If the CMS index doesn't match any indirect
    /// region, returns 0 bytes. Access errors (write-only) set
    /// `UnsupportedCommand`; any other CMS error sets
    /// `GeneralProtocolError`.
    fn handle_indirect_data_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let region = match self.lookup_indirect_region(self.indirect_ctrl.cms) {
            Some(r) => r,
            None => return Ok(0),
        };
        match region.read(buf) {
            Ok(n) => Ok(n),
            Err(CmsError::WriteOnly) => {
                self.set_protocol_error(ProtocolError::UnsupportedCommand);
                Ok(0)
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::GeneralProtocolError);
                Ok(0)
            }
        }
    }

    /// Handle an INDIRECT_DATA (cmd=0x2B) write: write to the currently
    /// selected indirect CMS region at the current IMO.
    ///
    /// The region auto-increments the IMO after the write. If the CMS
    /// index doesn't match any indirect region, the write is silently
    /// dropped. Access errors (read-only) set `UnsupportedCommand`;
    /// any other CMS error sets `GeneralProtocolError`.
    fn handle_indirect_data_write(&mut self, data: &[u8]) {
        let region = match self.lookup_indirect_region(self.indirect_ctrl.cms) {
            Some(r) => r,
            None => return,
        };
        match region.write(data) {
            Ok(()) => {}
            Err(CmsError::ReadOnly) => {
                self.set_protocol_error(ProtocolError::UnsupportedCommand);
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::GeneralProtocolError);
            }
        }
    }

    /// Handle a VENDOR (cmd=0x2C) read: delegate to VendorHandler.
    ///
    /// If the vendor_command capability is not advertised, sets
    /// `UnsupportedCommand` and returns 0 bytes.
    fn handle_vendor_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        if !self.vendor.capabilities().vendor_command() {
            self.set_protocol_error(ProtocolError::UnsupportedCommand);
            return Ok(0);
        }
        match self.vendor.handle_vendor_read(buf) {
            Ok(n) => Ok(n),
            Err(_) => {
                self.set_protocol_error(ProtocolError::GeneralProtocolError);
                Ok(0)
            }
        }
    }

    /// Handle a VENDOR (cmd=0x2C) write: delegate to VendorHandler.
    ///
    /// If the vendor_command capability is not advertised, sets
    /// `UnsupportedCommand`.
    fn handle_vendor_write(&mut self, data: &[u8]) {
        if !self.vendor.capabilities().vendor_command() {
            self.set_protocol_error(ProtocolError::UnsupportedCommand);
            return;
        }
        if self.vendor.handle_vendor_write(data).is_err() {
            self.set_protocol_error(ProtocolError::GeneralProtocolError);
        }
    }

    /// Handle an INDIRECT_FIFO_DATA (cmd=0x2F) read: pop data from the
    /// currently selected FIFO CMS region.
    ///
    /// Returns the number of bytes read. If the FIFO is empty, returns 0.
    /// If the CMS index doesn't match any FIFO region, returns 0.
    /// Access errors (write-only) set `UnsupportedCommand`; any other
    /// CMS error sets `GeneralProtocolError`.
    fn handle_indirect_fifo_data_read(&mut self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let region = match self.lookup_fifo_region(self.indirect_fifo_ctrl_cms) {
            Some(r) => r,
            None => return Ok(0),
        };
        match region.pop(buf) {
            Ok(n) => Ok(n),
            Err(CmsError::FifoEmpty) => Ok(0),
            Err(CmsError::WriteOnly) => {
                self.set_protocol_error(ProtocolError::UnsupportedCommand);
                Ok(0)
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::GeneralProtocolError);
                Ok(0)
            }
        }
    }

    /// Handle an INDIRECT_FIFO_DATA (cmd=0x2F) write: push data into the
    /// currently selected FIFO CMS region.
    ///
    /// Returns `true` if the data was accepted, `false` if the write must
    /// be NACKed (FIFO full or no matching region). Access errors
    /// (read-only) set `UnsupportedCommand`; any other CMS error sets
    /// `GeneralProtocolError` and returns `false`.
    fn handle_indirect_fifo_data_write(&mut self, data: &[u8]) -> bool {
        let region = match self.lookup_fifo_region(self.indirect_fifo_ctrl_cms) {
            Some(r) => r,
            None => return false,
        };
        match region.push(data) {
            Ok(()) => true,
            Err(CmsError::FifoFull) => false,
            Err(CmsError::ReadOnly) => {
                self.set_protocol_error(ProtocolError::UnsupportedCommand);
                false
            }
            Err(_) => {
                self.set_protocol_error(ProtocolError::GeneralProtocolError);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;
    use crate::cms::slice_fifo::SliceFifoRegion;
    use crate::cms::slice_indirect::SliceIndirectRegion;
    use crate::protocol::device_id::{self, DeviceDescriptor, PciVendorDescriptor};
    use crate::protocol::device_reset::{self, DeviceReset};
    use crate::protocol::device_status;
    use crate::protocol::hw_status::{self, CompositeTemperature, HwStatus, HwStatusFlags};
    use crate::protocol::indirect_ctrl;
    use crate::protocol::indirect_fifo_ctrl;
    use crate::protocol::indirect_fifo_status::{self, FifoCmsRegionType};
    use crate::protocol::indirect_status::{self, CmsRegionType, IndirectStatus, StatusFlags};
    use crate::protocol::prot_cap::{self, RESPONSE_LEN};
    use crate::protocol::recovery_status;
    use crate::protocol::RecoveryCommand;
    use crate::usb::driver::{RecoveryRequest, UsbDriverError};
    use crate::vendor::VendorCapabilities;

    struct MockVendorHandler {
        caps: VendorCapabilities,
        heartbeat_val: u16,
        vendor_status_data: Vec<u8>,
        hw_flags: HwStatusFlags,
        hw_vendor_status_byte: u8,
        hw_composite_temp: CompositeTemperature,
        hw_vendor_specific: Vec<u8>,
        last_reset: Option<DeviceReset>,
        last_vendor_write: Option<Vec<u8>>,
        vendor_read_data: Vec<u8>,
    }

    impl MockVendorHandler {
        fn new() -> Self {
            Self {
                caps: VendorCapabilities(0),
                heartbeat_val: 0,
                vendor_status_data: Vec::new(),
                hw_flags: HwStatusFlags(0),
                hw_vendor_status_byte: 0,
                hw_composite_temp: CompositeTemperature::NoData,
                hw_vendor_specific: Vec::new(),
                last_reset: None,
                last_vendor_write: None,
                vendor_read_data: Vec::new(),
            }
        }

        fn with_all_caps() -> Self {
            Self {
                caps: VendorCapabilities(0b0011_1111),
                ..Self::new()
            }
        }
    }

    impl crate::vendor::VendorHandler for MockVendorHandler {
        fn capabilities(&self) -> VendorCapabilities {
            self.caps
        }

        fn execute_reset(&mut self, reset: &DeviceReset) {
            self.last_reset = Some(*reset);
        }

        fn handle_vendor_write(&mut self, data: &[u8]) -> Result<(), OcpError> {
            self.last_vendor_write = Some(data.to_vec());
            Ok(())
        }

        fn handle_vendor_read(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
            let len = self.vendor_read_data.len().min(buf.len());
            buf[..len].copy_from_slice(&self.vendor_read_data[..len]);
            Ok(len)
        }

        fn vendor_device_status(&self, buf: &mut [u8]) -> usize {
            let len = self.vendor_status_data.len();
            buf[..len].copy_from_slice(&self.vendor_status_data);
            len
        }

        fn heartbeat(&self) -> u16 {
            self.heartbeat_val
        }

        fn hw_status(&self) -> Result<HwStatus<'_>, OcpError> {
            HwStatus::new(
                self.hw_flags,
                self.hw_vendor_status_byte,
                self.hw_composite_temp,
                &self.hw_vendor_specific,
            )
        }
    }

    enum MockRequest {
        Read { len: u16 },
        Write { data: Vec<u8> },
    }

    struct MockUsbDeviceDriver {
        recv_queue: Vec<(RecoveryCommand, MockRequest)>,
        recv_idx: usize,
        send_buf: [u8; 256],
        sent: Vec<Vec<u8>>,
    }

    impl MockUsbDeviceDriver {
        fn new() -> Self {
            Self {
                recv_queue: Vec::new(),
                recv_idx: 0,
                send_buf: [0u8; 256],
                sent: Vec::new(),
            }
        }

        fn enqueue_read(&mut self, cmd: RecoveryCommand, len: u16) {
            self.recv_queue.push((cmd, MockRequest::Read { len }));
        }

        fn enqueue_write(&mut self, cmd: RecoveryCommand, data: Vec<u8>) {
            self.recv_queue.push((cmd, MockRequest::Write { data }));
        }
    }

    impl UsbDeviceDriver for MockUsbDeviceDriver {
        fn init(&mut self) -> Result<(), UsbDriverError> {
            Ok(())
        }

        fn recv(&mut self) -> Result<(RecoveryCommand, RecoveryRequest<'_>), UsbDriverError> {
            if self.recv_idx >= self.recv_queue.len() {
                return Err(UsbDriverError::NoPendingCommand);
            }
            let idx = self.recv_idx;
            self.recv_idx += 1;
            match &self.recv_queue[idx] {
                (cmd, MockRequest::Read { len }) => Ok((*cmd, RecoveryRequest::Read { len: *len })),
                (cmd, MockRequest::Write { data }) => Ok((*cmd, RecoveryRequest::Write { data })),
            }
        }

        fn send(
            &mut self,
            populate_buffer: &mut dyn FnMut(&mut [u8]) -> Result<usize, OcpError>,
        ) -> Result<(), UsbDriverError> {
            let len = populate_buffer(&mut self.send_buf).map_err(UsbDriverError::OcpError)?;
            self.sent.push(self.send_buf[..len].to_vec());
            Ok(())
        }

        fn stall_endpoint(&mut self) -> Result<(), UsbDriverError> {
            Ok(())
        }
    }

    fn test_config() -> RecoveryDeviceConfig<'static> {
        let desc = DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0x1234, 0x5678, 0, 0, 0));
        RecoveryDeviceConfig {
            device_id: DeviceId::new(desc, &[]).unwrap(),
            major_version: 1,
            minor_version: 1,
            max_response_time: 17,
            heartbeat_period: 0,
            local_c_image_support: true,
        }
    }

    #[test]
    fn default_state_after_construction() {
        let mut transport = MockUsbDeviceDriver::new();
        let sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        assert_eq!(
            sm.state.device_status_value,
            DeviceStatusValue::StatusPending
        );
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
        assert_eq!(sm.state.recovery_reason, RecoveryReasonCode::NoBootFailure);

        assert_eq!(
            sm.state.recovery_status.status().unwrap(),
            DeviceRecoveryStatus::NotInRecovery
        );
        assert_eq!(sm.state.recovery_status.image_index(), 0);

        assert_eq!(sm.state.recovery_ctrl.cms, 0);
        assert_eq!(
            sm.state.recovery_ctrl.image_selection,
            ImageSelection::NoOperation
        );
        assert_eq!(
            sm.state.recovery_ctrl.activate,
            ActivateRecoveryImage::DoNotActivate
        );

        assert_eq!(sm.state.device_reset.reset_control, ResetControl::NoReset);
        assert_eq!(
            sm.state.device_reset.forced_recovery,
            ForcedRecoveryMode::None
        );
        assert_eq!(
            sm.state.device_reset.interface_control,
            InterfaceControl::DisableMastering
        );

        assert_eq!(sm.state.indirect_ctrl.cms, 0);
        assert_eq!(sm.state.indirect_ctrl.imo(), 0);

        assert_eq!(sm.state.indirect_fifo_ctrl_cms, 0);
        assert_eq!(sm.state.indirect_fifo_ctrl_image_size, 0);

        assert_eq!(sm.state.cms_count, 0);
    }

    #[test]
    fn process_command_stub_returns_none() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, 15);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
    }

    #[test]
    fn process_command_propagates_transport_error() {
        let mut transport = MockUsbDeviceDriver::new();
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let err = sm.process_command().unwrap_err();
        assert_eq!(err, OcpError::TransportError(0));
    }

    #[test]
    fn lookup_indirect_region_finds_match() {
        let mut buf0 = [0u8; 64];
        let mut buf3 = [0u8; 64];
        let mut r0 = SliceIndirectRegion::new(&mut buf0, CmsRegionType::CodeSpace).unwrap();
        let mut r3 = SliceIndirectRegion::new(&mut buf3, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] = [(0, &mut r0), (3, &mut r3)];

        let mut transport = MockUsbDeviceDriver::new();
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        assert!(sm.state.lookup_indirect_region(0).is_some());
        assert!(sm.state.lookup_indirect_region(3).is_some());
        assert!(sm.state.lookup_indirect_region(1).is_none());
        assert!(sm.state.lookup_indirect_region(255).is_none());
    }

    #[test]
    fn lookup_fifo_region_finds_match() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(5, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        assert!(sm.state.lookup_fifo_region(5).is_some());
        assert!(sm.state.lookup_fifo_region(0).is_none());
        assert!(sm.state.lookup_fifo_region(3).is_none());
    }

    #[test]
    fn set_protocol_error_updates_state() {
        let mut transport = MockUsbDeviceDriver::new();
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
        sm.state
            .set_protocol_error(ProtocolError::UnsupportedCommand);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- PROT_CAP handler tests --

    #[test]
    fn prot_cap_read_returns_magic_version_and_config() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(&msg[0..8], prot_cap::MAGIC.as_slice());
        assert_eq!(msg[8], 1); // major
        assert_eq!(msg[9], 1); // minor
        assert_eq!(msg[13], 17); // max_response_time
        assert_eq!(msg[14], 0); // heartbeat_period
    }

    #[test]
    fn prot_cap_read_no_regions_reports_local_c_image() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let caps_raw = u16::from_le_bytes([msg[10], msg[11]]);
        let caps = RecoveryProtocolCapabilities(caps_raw);

        assert!(caps.identification());
        assert!(caps.device_status());
        assert!(caps.local_c_image_support());
        assert!(!caps.push_c_image_support());
        assert!(!caps.recovery_memory_access());
        assert!(!caps.fifo_cms_support());
        assert_eq!(msg[12], 0);
    }

    #[test]
    fn prot_cap_read_with_indirect_code_sets_push_and_memory_access() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let caps_raw = u16::from_le_bytes([msg[10], msg[11]]);
        let caps = RecoveryProtocolCapabilities(caps_raw);

        assert!(caps.push_c_image_support());
        assert!(caps.recovery_memory_access());
        assert!(!caps.fifo_cms_support());
        assert_eq!(msg[12], 1);
    }

    #[test]
    fn prot_cap_read_cms_count_is_total_regions() {
        let mut buf0 = [0u8; 64];
        let mut buf1 = [0u8; 64];
        let mut r0 = SliceIndirectRegion::new(&mut buf0, CmsRegionType::CodeSpace).unwrap();
        let mut r1 = SliceIndirectRegion::new(&mut buf1, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] = [(0, &mut r0), (7, &mut r1)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.transport.sent[0][12], 2); // 2 regions total (indices are not contiguous)
    }

    #[test]
    fn prot_cap_read_cms_count_spans_indirect_and_fifo() {
        let mut ibuf = [0u8; 64];
        let mut fbuf = [0u8; 64];
        let mut ir = SliceIndirectRegion::new(&mut ibuf, CmsRegionType::CodeSpace).unwrap();
        let mut fr = SliceFifoRegion::new(&mut fbuf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut indirect: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut ir)];
        let mut fifo: [(u8, &mut dyn FifoCmsRegion); 1] = [(1, &mut fr)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut indirect,
            &mut fifo,
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.transport.sent[0][12], 2); // 1 indirect + 1 fifo = 2
    }

    #[test]
    fn new_rejects_indirect_without_cms0_code() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        let result = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        );

        assert!(matches!(result, Err(OcpError::IndirectCms0NotCodeSpace)));
    }

    #[test]
    fn new_rejects_indirect_missing_cms0() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(1, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        let result = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        );

        assert!(matches!(result, Err(OcpError::IndirectCms0NotCodeSpace)));
    }

    #[test]
    fn prot_cap_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::ProtCap, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    #[test]
    fn prot_cap_read_vendor_caps_all_set() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let caps_raw = u16::from_le_bytes([msg[10], msg[11]]);
        let caps = RecoveryProtocolCapabilities(caps_raw);

        assert!(caps.forced_recovery());
        assert!(caps.mgmt_reset());
        assert!(caps.device_reset());
        assert!(caps.interface_isolation());
        assert!(caps.hardware_status());
        assert!(caps.vendor_command());
    }

    #[test]
    fn prot_cap_read_vendor_caps_none_set() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::ProtCap, RESPONSE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let caps_raw = u16::from_le_bytes([msg[10], msg[11]]);
        let caps = RecoveryProtocolCapabilities(caps_raw);

        assert!(!caps.forced_recovery());
        assert!(!caps.mgmt_reset());
        assert!(!caps.device_reset());
        assert!(!caps.interface_isolation());
        assert!(!caps.hardware_status());
        assert!(!caps.vendor_command());
    }

    // -- Duplicate CMS index tests --

    #[test]
    fn new_rejects_duplicate_indirect_indices() {
        let mut buf0 = [0u8; 64];
        let mut buf1 = [0u8; 64];
        let mut r0 = SliceIndirectRegion::new(&mut buf0, CmsRegionType::CodeSpace).unwrap();
        let mut r1 = SliceIndirectRegion::new(&mut buf1, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] = [(0, &mut r0), (0, &mut r1)];

        let mut transport = MockUsbDeviceDriver::new();
        let result = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        );

        assert!(matches!(result, Err(OcpError::DuplicateCmsIndex)));
    }

    #[test]
    fn new_rejects_duplicate_fifo_indices() {
        let mut buf0 = [0u8; 64];
        let mut buf1 = [0u8; 64];
        let mut r0 = SliceFifoRegion::new(&mut buf0, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut r1 = SliceFifoRegion::new(&mut buf1, FifoCmsRegionType::Log, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 2] = [(2, &mut r0), (2, &mut r1)];

        let mut transport = MockUsbDeviceDriver::new();
        let result = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        );

        assert!(matches!(result, Err(OcpError::DuplicateCmsIndex)));
    }

    #[test]
    fn new_rejects_overlapping_indirect_and_fifo_index() {
        let mut ibuf = [0u8; 64];
        let mut fbuf = [0u8; 64];
        let mut ir = SliceIndirectRegion::new(&mut ibuf, CmsRegionType::CodeSpace).unwrap();
        let mut fr = SliceFifoRegion::new(&mut fbuf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut indirect: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut ir)];
        let mut fifo: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut fr)];

        let mut transport = MockUsbDeviceDriver::new();
        let result = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut indirect,
            &mut fifo,
            MockVendorHandler::new(),
        );

        assert!(matches!(result, Err(OcpError::DuplicateCmsIndex)));
    }

    // -- DEVICE_ID handler tests --

    #[test]
    fn device_id_read_returns_serialized_id() {
        let config = test_config();
        let mut expected_buf = [0u8; device_id::MAX_MESSAGE_LEN];
        let expected_len = config.device_id.to_message(&mut expected_buf).unwrap();

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::DeviceId, device_id::MAX_MESSAGE_LEN as u16);
        let mut sm = RecoveryStateMachine::new(
            config,
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.len(), expected_len);
        assert_eq!(msg.as_slice(), &expected_buf[..expected_len]);
    }

    #[test]
    fn device_id_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceId, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- DEVICE_STATUS handler tests --

    #[test]
    fn device_status_read_returns_default_status() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::DeviceStatus,
            device_status::MAX_MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.len(), 7);
        assert_eq!(msg[0], DeviceStatusValue::StatusPending as u8);
        assert_eq!(msg[1], ProtocolError::NoError as u8);
        assert_eq!(u16::from_le_bytes([msg[2], msg[3]]), 0x00);
        assert_eq!(u16::from_le_bytes([msg[4], msg[5]]), 0);
        assert_eq!(msg[6], 0);
    }

    #[test]
    fn device_status_read_clears_protocol_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::DeviceStatus,
            device_status::MAX_MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.state
            .set_protocol_error(ProtocolError::UnsupportedCommand);

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[1], ProtocolError::UnsupportedCommand as u8);
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    #[test]
    fn device_status_read_includes_vendor_status() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::DeviceStatus,
            device_status::MAX_MESSAGE_LEN as u16,
        );
        let mut vendor = MockVendorHandler::new();
        vendor.vendor_status_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut sm =
            RecoveryStateMachine::new(test_config(), &mut transport, &mut [], &mut [], vendor)
                .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.len(), 11);
        assert_eq!(msg[6], 4);
        assert_eq!(&msg[7..11], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn device_status_read_heartbeat_from_vendor() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::DeviceStatus,
            device_status::MAX_MESSAGE_LEN as u16,
        );
        let mut vendor = MockVendorHandler::new();
        vendor.heartbeat_val = 42;
        let mut sm =
            RecoveryStateMachine::new(test_config(), &mut transport, &mut [], &mut [], vendor)
                .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(u16::from_le_bytes([msg[4], msg[5]]), 42);
    }

    #[test]
    fn device_status_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceStatus, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- RECOVERY_STATUS handler tests --

    #[test]
    fn recovery_status_read_returns_default() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::RecoveryStatus,
            recovery_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.len(), 2);
        let byte0 = recovery_status::RecoveryStatusByte0(msg[0]);
        assert_eq!(byte0.status(), DeviceRecoveryStatus::NotInRecovery as u8);
        assert_eq!(byte0.image_index(), 0);
        assert_eq!(msg[1], 0);
    }

    #[test]
    fn recovery_status_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::RecoveryStatus, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- HW_STATUS handler tests --

    #[test]
    fn hw_status_read_returns_vendor_hw_status() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::HwStatus, hw_status::MAX_MESSAGE_LEN as u16);
        let mut vendor = MockVendorHandler::new();
        let mut flags = HwStatusFlags(0);
        flags.set_temp_critical(true);
        vendor.hw_flags = flags;
        vendor.hw_vendor_status_byte = 0xAB;
        vendor.hw_composite_temp = CompositeTemperature::Celsius(42);
        vendor.hw_vendor_specific = vec![0x01, 0x02, 0x03];

        let mut sm =
            RecoveryStateMachine::new(test_config(), &mut transport, &mut [], &mut [], vendor)
                .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.len(), 7);
        assert_eq!(msg[0], 0x01);
        assert_eq!(msg[1], 0xAB);
        assert_eq!(msg[2], 42);
        assert_eq!(msg[3], 3);
        assert_eq!(&msg[4..7], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn hw_status_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::HwStatus, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- INDIRECT_STATUS handler tests --

    #[test]
    fn indirect_status_read_returns_region_type_and_size() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let mut expected = [0u8; indirect_status::MESSAGE_LEN];
        IndirectStatus::new(StatusFlags(0), CmsRegionType::CodeSpace, false, 64)
            .to_message(&mut expected)
            .unwrap();
        assert_eq!(msg.as_slice(), &expected);
    }

    #[test]
    fn indirect_status_read_unsupported_for_invalid_index() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.state.indirect_ctrl.cms = 99;
        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let mut expected = [0u8; indirect_status::MESSAGE_LEN];
        IndirectStatus::new(StatusFlags(0), CmsRegionType::Unsupported, false, 0)
            .to_message(&mut expected)
            .unwrap();
        assert_eq!(msg.as_slice(), &expected);
    }

    #[test]
    fn indirect_status_read_unsupported_for_fifo_index() {
        let mut ibuf = [0u8; 64];
        let mut fbuf = [0u8; 64];
        let mut ir = SliceIndirectRegion::new(&mut ibuf, CmsRegionType::CodeSpace).unwrap();
        let mut fr = SliceFifoRegion::new(&mut fbuf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut indirect: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut ir)];
        let mut fifo: [(u8, &mut dyn FifoCmsRegion); 1] = [(1, &mut fr)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut indirect,
            &mut fifo,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.state.indirect_ctrl.cms = 1;
        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        let mut expected = [0u8; indirect_status::MESSAGE_LEN];
        IndirectStatus::new(StatusFlags(0), CmsRegionType::Unsupported, false, 0)
            .to_message(&mut expected)
            .unwrap();
        assert_eq!(msg.as_slice(), &expected);
    }

    #[test]
    fn indirect_status_read_overflow_reported_and_cleared() {
        let mut buf = [0u8; 4];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        region.write(&[0xAA; 4]).unwrap();

        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[0] & 0x01, 0x01, "overflow flag should be set");

        sm.process_command().unwrap();
        let msg2 = &sm.transport.sent[1];
        assert_eq!(msg2[0] & 0x01, 0x00, "overflow flag should be cleared");
    }

    #[test]
    fn indirect_status_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectStatus, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- INDIRECT_FIFO_STATUS handler tests --

    #[test]
    fn indirect_fifo_status_read_returns_fifo_metadata() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoStatus,
            indirect_fifo_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert!(msg[0] & 0x01 != 0, "FIFO should start empty");
        assert_eq!(msg[1], FifoCmsRegionType::CodeSpace as u8);
        let fifo_size = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert!(fifo_size > 0);
        let max_xfer = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]);
        assert_eq!(max_xfer, 16);
    }

    #[test]
    fn indirect_fifo_status_read_unsupported_for_invalid_index() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoStatus,
            indirect_fifo_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.state.indirect_fifo_ctrl_cms = 99;
        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[1], FifoCmsRegionType::Unsupported as u8);
    }

    #[test]
    fn indirect_fifo_status_read_unsupported_for_indirect_index() {
        let mut ibuf = [0u8; 64];
        let mut fbuf = [0u8; 64];
        let mut ir = SliceIndirectRegion::new(&mut ibuf, CmsRegionType::CodeSpace).unwrap();
        let mut fr = SliceFifoRegion::new(&mut fbuf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut indirect: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut ir)];
        let mut fifo: [(u8, &mut dyn FifoCmsRegion); 1] = [(1, &mut fr)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoStatus,
            indirect_fifo_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut indirect,
            &mut fifo,
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[1], FifoCmsRegionType::Unsupported as u8);
    }

    #[test]
    fn indirect_fifo_status_read_empty_and_full_flags() {
        let mut buf = [0u8; 8];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 4).unwrap();

        region.push(&[0xAA; 4]).unwrap();

        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoStatus,
            indirect_fifo_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[0] & 0x01, 0x00, "should not be empty after push");
        assert_eq!(msg[0] & 0x02, 0x02, "should be full");
    }

    #[test]
    fn indirect_fifo_status_write_sets_unsupported_command_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectFifoStatus, Vec::new());
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    // -- DEVICE_RESET handler tests --

    #[test]
    fn device_reset_write_device_reset_stores_and_invokes_vendor() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x01, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(
            sm.state.device_reset.reset_control,
            ResetControl::ResetDevice
        );
        assert!(sm.state.vendor.last_reset.is_some());
    }

    #[test]
    fn device_reset_write_management_reset_stores_and_invokes_vendor() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x02, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(
            sm.state.device_reset.reset_control,
            ResetControl::ResetManagement
        );
        assert!(sm.state.vendor.last_reset.is_some());
    }

    #[test]
    fn device_reset_write_no_reset_stores_and_invokes_vendor() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x00, 0x0F, 0x01]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(
            sm.state.device_reset.forced_recovery,
            ForcedRecoveryMode::EnterRecovery
        );
        assert_eq!(
            sm.state.device_reset.interface_control,
            InterfaceControl::EnableMastering
        );
        let last = sm.state.vendor.last_reset.unwrap();
        assert_eq!(last.reset_control, ResetControl::NoReset);
        assert_eq!(last.forced_recovery, ForcedRecoveryMode::EnterRecovery);
    }

    #[test]
    fn device_reset_write_records_forced_recovery() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x01, 0x0E, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(
            sm.state.device_reset.forced_recovery,
            ForcedRecoveryMode::FlashlessBoot
        );
    }

    #[test]
    fn device_reset_write_invalid_parameter_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x03, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
    }

    #[test]
    fn device_reset_write_wrong_length_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x00]);
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x00, 0x00, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::LengthWriteError);

        sm.state.protocol_error = ProtocolError::NoError;
        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::LengthWriteError);
    }

    #[test]
    fn device_reset_write_unsupported_device_reset_cap() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x01, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
        assert!(sm.state.vendor.last_reset.is_none());
    }

    #[test]
    fn device_reset_write_unsupported_mgmt_reset_cap() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x02, 0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
    }

    #[test]
    fn device_reset_write_unsupported_forced_recovery_cap() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x00, 0x0F, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
    }

    #[test]
    fn device_reset_read_returns_current_state() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::DeviceReset, vec![0x01, 0x0F, 0x01]);
        transport.enqueue_read(
            RecoveryCommand::DeviceReset,
            device_reset::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::with_all_caps(),
        )
        .unwrap();

        sm.process_command().unwrap();
        let action = sm.process_command().unwrap();
        assert_eq!(action, RecoveryAction::None);
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.as_slice(), &[0x01, 0x0F, 0x01]);
    }

    // -- INDIRECT_CTRL handler tests --

    #[test]
    fn indirect_ctrl_write_selects_cms_and_sets_imo() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x10, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectCtrl,
            indirect_ctrl::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.indirect_ctrl.cms, 0);
        assert_eq!(sm.state.indirect_ctrl.imo(), 0x10);

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[0], 0);
        assert_eq!(u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]), 0x10);
    }

    #[test]
    fn indirect_ctrl_write_cms_change_resets_region() {
        let mut buf0 = [0u8; 64];
        let mut buf1 = [0u8; 64];
        let mut r0 = SliceIndirectRegion::new(&mut buf0, CmsRegionType::CodeSpace).unwrap();
        let mut r1 = SliceIndirectRegion::new(&mut buf1, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] = [(0, &mut r0), (3, &mut r1)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x20, 0x00, 0x00, 0x00],
        );
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x03, 0x00, 0x04, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectCtrl,
            indirect_ctrl::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.indirect_ctrl.cms, 0);

        sm.state
            .lookup_indirect_region(0)
            .unwrap()
            .write(&[0xAA; 64])
            .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.indirect_ctrl.cms, 3);

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[0], 3);
        // According to spec IMO is reset on CMS change, not set to the CMS value.
        assert_eq!(u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]), 0);
    }

    #[test]
    fn indirect_ctrl_read_returns_live_imo() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectCtrl,
            indirect_ctrl::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();

        sm.state
            .lookup_indirect_region(0)
            .unwrap()
            .write(&[0xBB; 4])
            .unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]), 4);
    }

    #[test]
    fn indirect_ctrl_write_wrong_length_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectCtrl, vec![0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::LengthWriteError);
    }

    #[test]
    fn indirect_ctrl_write_misaligned_imo_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
    }

    // -- INDIRECT_FIFO_CTRL handler tests --

    #[test]
    fn indirect_fifo_ctrl_write_selects_cms_and_image_size() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(2, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x02, 0x00, 0x00, 0x01, 0x00, 0x00],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.indirect_fifo_ctrl_cms, 2);
        assert_eq!(sm.state.indirect_fifo_ctrl_image_size, 0x100);
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    #[test]
    fn indirect_fifo_ctrl_write_reset_triggers_fifo_reset() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();

        region.push(&[0xAA; 4]).unwrap();
        assert!(!region.is_empty());

        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoStatus,
            indirect_fifo_status::MESSAGE_LEN as u16,
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoCtrl,
            indirect_fifo_ctrl::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();

        sm.process_command().unwrap();
        let status_msg = &sm.transport.sent[0];
        assert_eq!(
            status_msg[0] & 0x01,
            0x01,
            "FIFO should be empty after reset"
        );

        sm.process_command().unwrap();
        let ctrl_msg = &sm.transport.sent[1];
        assert_eq!(ctrl_msg[1], 0x00, "reset byte should be cleared by device");
    }

    #[test]
    fn indirect_fifo_ctrl_read_returns_current_state() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(5, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x05, 0x00, 0x10, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(
            RecoveryCommand::IndirectFifoCtrl,
            indirect_fifo_ctrl::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(msg[0], 5);
        assert_eq!(msg[1], 0x00);
        assert_eq!(u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]), 0x10);
    }

    #[test]
    fn indirect_fifo_ctrl_write_wrong_length_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectFifoCtrl, vec![0x00, 0x00]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::LengthWriteError);
    }

    #[test]
    fn indirect_fifo_ctrl_write_invalid_reset_sets_error() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedParameter);
    }

    // -- INDIRECT_DATA handler tests --

    #[test]
    fn indirect_data_write_and_read_back() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectData, 4);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);

        sm.process_command().unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(&msg[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn indirect_data_sequential_writes_auto_increment() {
        let mut buf = [0u8; 64];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x01, 0x02, 0x03, 0x04]);
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x05, 0x06, 0x07, 0x08]);
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectData, 8);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        sm.process_command().unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(&msg[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn indirect_data_overflow_wraps_imo() {
        let mut buf = [0u8; 8];
        let mut region = SliceIndirectRegion::new(&mut buf, CmsRegionType::CodeSpace).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x01, 0x02, 0x03, 0x04]);
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x05, 0x06, 0x07, 0x08]);
        transport.enqueue_read(
            RecoveryCommand::IndirectStatus,
            indirect_status::MESSAGE_LEN as u16,
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();

        sm.process_command().unwrap();
        let status_msg = &sm.transport.sent[0];
        assert_ne!(status_msg[0] & 0x01, 0, "overflow flag should be set");
    }

    #[test]
    fn indirect_data_write_to_read_only_sets_error() {
        let mut code_buf = [0u8; 64];
        let mut log_buf = [0u8; 64];
        let mut code_r = SliceIndirectRegion::new(&mut code_buf, CmsRegionType::CodeSpace).unwrap();
        let mut log_r = SliceIndirectRegion::new(&mut log_buf, CmsRegionType::Log).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] =
            [(0, &mut code_r), (1, &mut log_r)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x01, 0x02, 0x03, 0x04]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    #[test]
    fn indirect_data_read_from_write_only_sets_error() {
        let mut code_buf = [0u8; 64];
        let mut wo_buf = [0u8; 64];
        let mut code_r = SliceIndirectRegion::new(&mut code_buf, CmsRegionType::CodeSpace).unwrap();
        let mut wo_r = SliceIndirectRegion::new(&mut wo_buf, CmsRegionType::VendorWo).unwrap();
        let mut regions: [(u8, &mut dyn IndirectCmsRegion); 2] = [(0, &mut code_r), (2, &mut wo_r)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectCtrl,
            vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectData, 4);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut regions,
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert!(msg.is_empty());
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    #[test]
    fn indirect_data_no_region_returns_zero() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::IndirectData, 4);
        transport.enqueue_write(RecoveryCommand::IndirectData, vec![0x01, 0x02]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert!(msg.is_empty());
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    // -- INDIRECT_FIFO_DATA handler tests --

    #[test]
    fn indirect_fifo_data_write_accepted() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoData,
            vec![0xAA, 0xBB, 0xCC, 0xDD],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    #[test]
    fn indirect_fifo_data_read_returns_data() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::Log, 16).unwrap();

        region.push_data(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();

        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectFifoData, 4);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert_eq!(msg.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn indirect_fifo_data_push_until_full_no_error() {
        let mut buf = [0u8; 8];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 4).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoData,
            vec![0x01, 0x02, 0x03, 0x04],
        );
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoData,
            vec![0x05, 0x06, 0x07, 0x08],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    #[test]
    fn indirect_fifo_data_pop_from_empty_returns_zero() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::Log, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectFifoData, 4);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert!(msg.is_empty());
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    #[test]
    fn indirect_fifo_data_write_to_read_only_sets_error() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::Log, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoData,
            vec![0x01, 0x02, 0x03, 0x04],
        );
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    #[test]
    fn indirect_fifo_data_read_from_write_only_sets_error() {
        let mut buf = [0u8; 64];
        let mut region = SliceFifoRegion::new(&mut buf, FifoCmsRegionType::CodeSpace, 16).unwrap();
        let mut regions: [(u8, &mut dyn FifoCmsRegion); 1] = [(0, &mut region)];

        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(
            RecoveryCommand::IndirectFifoCtrl,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        transport.enqueue_read(RecoveryCommand::IndirectFifoData, 4);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut regions,
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert!(msg.is_empty());
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
    }

    #[test]
    fn indirect_fifo_data_no_region_returns_zero() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::IndirectFifoData, 4);
        transport.enqueue_write(RecoveryCommand::IndirectFifoData, vec![0x01, 0x02]);
        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        let msg = &sm.transport.sent[0];
        assert!(msg.is_empty());
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
    }

    // -- VENDOR command handler tests --

    #[test]
    fn vendor_write_forwards_data_to_handler() {
        let mut transport = MockUsbDeviceDriver::new();
        let mut vendor = MockVendorHandler::with_all_caps();
        vendor.vendor_read_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        transport.enqueue_write(RecoveryCommand::Vendor, vec![0x01, 0x02, 0x03]);

        let mut sm =
            RecoveryStateMachine::new(test_config(), &mut transport, &mut [], &mut [], vendor)
                .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
        assert_eq!(
            sm.state.vendor.last_vendor_write.as_deref(),
            Some([0x01, 0x02, 0x03].as_slice())
        );
    }

    #[test]
    fn vendor_read_returns_handler_data() {
        let mut transport = MockUsbDeviceDriver::new();
        let mut vendor = MockVendorHandler::with_all_caps();
        vendor.vendor_read_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        transport.enqueue_read(RecoveryCommand::Vendor, 8);

        let mut sm =
            RecoveryStateMachine::new(test_config(), &mut transport, &mut [], &mut [], vendor)
                .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::NoError);
        let msg = &sm.transport.sent[0];
        assert_eq!(&msg[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn vendor_write_unsupported_when_capability_not_set() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_write(RecoveryCommand::Vendor, vec![0x01, 0x02]);

        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
        assert!(sm.state.vendor.last_vendor_write.is_none());
    }

    #[test]
    fn vendor_read_unsupported_when_capability_not_set() {
        let mut transport = MockUsbDeviceDriver::new();
        transport.enqueue_read(RecoveryCommand::Vendor, 8);

        let mut sm = RecoveryStateMachine::new(
            test_config(),
            &mut transport,
            &mut [],
            &mut [],
            MockVendorHandler::new(),
        )
        .unwrap();

        sm.process_command().unwrap();
        assert_eq!(sm.state.protocol_error, ProtocolError::UnsupportedCommand);
        assert!(sm.transport.sent[0].iter().all(|&b| b == 0));
    }
}
