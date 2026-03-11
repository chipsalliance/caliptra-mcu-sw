// Licensed under the Apache-2.0 license

//! PROT_CAP (cmd=0x22) response structure.
//!
//! Spec reference: Section 9.2, "Recovery Capabilities Command".
//! The response is a fixed 15-byte read-only structure describing the
//! Device's recovery protocol version, capabilities, and timing parameters.

use bitfield::bitfield;
use zerocopy::{Immutable, IntoBytes};

use crate::error::OcpError;

/// Expected magic string in bytes 0-7: "OCP RECV" in ASCII.
pub const MAGIC: &[u8; 8] = b"OCP RECV";

/// Wire size of a PROT_CAP response in bytes, according to the Spec.
pub const RESPONSE_LEN: usize = 15;

// Assure the spec size matches the size of the structure.
const _: () = assert!(RESPONSE_LEN == size_of::<ProtCap>());

bitfield! {
    /// Recovery protocol capabilities (bytes 10-11 of PROT_CAP response).
    ///
    /// Mandatory capabilities per spec: identification (bit 0),
    /// device_status (bit 4), and at least one of local_c_image_support (bit 6)
    /// or push_c_image_support (bit 7). If push_c_image_support is set,
    /// recovery_memory_access (bit 5) MUST also be set.
    #[derive(Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
    pub struct RecoveryProtocolCapabilities(u16);
    impl Debug;

    pub identification, set_identification: 0;
    pub forced_recovery, set_forced_recovery: 1;
    pub mgmt_reset, set_mgmt_reset: 2;
    pub device_reset, set_device_reset: 3;
    pub device_status, set_device_status: 4;
    pub recovery_memory_access, set_recovery_memory_access: 5;
    pub local_c_image_support, set_local_c_image_support: 6;
    pub push_c_image_support, set_push_c_image_support: 7;
    pub interface_isolation, set_interface_isolation: 8;
    pub hardware_status, set_hardware_status: 9;
    pub vendor_command, set_vendor_command: 10;
    pub flashless_boot, set_flashless_boot: 11;
    pub fifo_cms_support, set_fifo_cms_support: 12;
}

/// PROT_CAP response (15 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ProtCap {
    /// Bytes 0-7: MUST be "OCP RECV" (see [`MAGIC`]).
    magic: [u8; 8],
    /// Byte 8: Protocol major version.
    pub major_version: u8,
    /// Byte 9: Protocol minor version.
    pub minor_version: u8,
    /// Bytes 10-11: Agent capabilities bitfield.
    pub capabilities: RecoveryProtocolCapabilities,
    /// Byte 12: Total number of CMS regions the Device supports (0-255).
    pub cms_regions: u8,
    /// Byte 13: Maximum response time as 2^x microseconds.
    pub max_response_time: u8,
    /// Byte 14: Heartbeat period as 2^x microseconds. 0 = not supported.
    pub heartbeat_period: u8,
}

impl ProtCap {
    pub fn new(
        major_version: u8,
        minor_version: u8,
        capabilities: RecoveryProtocolCapabilities,
        cms_regions: u8,
        max_response_time: u8,
        heartbeat_period: u8,
    ) -> Self {
        Self {
            magic: *MAGIC,
            major_version,
            minor_version,
            capabilities,
            cms_regions,
            max_response_time,
            heartbeat_period,
        }
    }

    /// Validate mandatory capability invariants from Section 9.2.
    pub fn validate_capabilities(&self) -> Result<(), OcpError> {
        let caps = self.capabilities;

        if !caps.identification() {
            return Err(OcpError::ProtCapIdentificationRequired);
        }
        if !caps.device_status() {
            return Err(OcpError::ProtCapDeviceStatusRequired);
        }
        if !caps.local_c_image_support() && !caps.push_c_image_support() {
            return Err(OcpError::ProtCapCImageSupportRequired);
        }
        if caps.push_c_image_support() && !caps.recovery_memory_access() {
            return Err(OcpError::ProtCapRecoveryMemoryAccessRequired);
        }

        Ok(())
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small or the mandatory
    /// capability invariants from Section 9.2 are not satisfied.
    /// On success, returns the number of bytes written ([`RESPONSE_LEN`]).
    pub fn to_message(self, buf: &mut [u8]) -> Result<usize, OcpError> {
        self.validate_capabilities()?;
        self.write_to_prefix(buf)
            .map_err(|_| OcpError::BufferTooSmall)?;
        Ok(RESPONSE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a capabilities value with all mandatory bits set.
    fn mandatory_caps() -> RecoveryProtocolCapabilities {
        let mut caps = RecoveryProtocolCapabilities(0);
        caps.set_identification(true);
        caps.set_device_status(true);
        caps.set_push_c_image_support(true);
        caps.set_recovery_memory_access(true);
        caps
    }

    #[test]
    fn valid_prot_cap_to_message() {
        let caps = mandatory_caps();
        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 10);
        let mut buf = [0u8; RESPONSE_LEN];
        let len = prot_cap
            .to_message(&mut buf)
            .expect("valid capabilities should succeed");

        assert_eq!(len, RESPONSE_LEN);
        assert_eq!(&buf[0..8], MAGIC);
        assert_eq!(buf[8], 0x01);
        assert_eq!(buf[9], 0x01);
        assert_eq!(buf[10..12], caps.0.to_le_bytes());
        assert_eq!(buf[12], 1);
        assert_eq!(buf[13], 17);
        assert_eq!(buf[14], 10);
    }

    #[test]
    fn missing_identification_rejected() {
        let mut caps = mandatory_caps();
        caps.set_identification(false);

        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert_eq!(
            prot_cap.to_message(&mut [0u8; RESPONSE_LEN]),
            Err(OcpError::ProtCapIdentificationRequired)
        );
    }

    #[test]
    fn missing_device_status_rejected() {
        let mut caps = mandatory_caps();
        caps.set_device_status(false);

        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert_eq!(
            prot_cap.to_message(&mut [0u8; RESPONSE_LEN]),
            Err(OcpError::ProtCapDeviceStatusRequired)
        );
    }

    #[test]
    fn missing_c_image_support_rejected() {
        let mut caps = mandatory_caps();
        caps.set_push_c_image_support(false);
        caps.set_local_c_image_support(false);

        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert_eq!(
            prot_cap.to_message(&mut [0u8; RESPONSE_LEN]),
            Err(OcpError::ProtCapCImageSupportRequired)
        );
    }

    #[test]
    fn push_c_image_without_recovery_memory_access_rejected() {
        let mut caps = mandatory_caps();
        caps.set_recovery_memory_access(false);

        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert_eq!(
            prot_cap.to_message(&mut [0u8; RESPONSE_LEN]),
            Err(OcpError::ProtCapRecoveryMemoryAccessRequired)
        );
    }

    #[test]
    fn local_c_image_without_recovery_memory_access_accepted() {
        let mut caps = mandatory_caps();
        caps.set_push_c_image_support(false);
        caps.set_local_c_image_support(true);
        caps.set_recovery_memory_access(false);

        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert!(prot_cap.to_message(&mut [0u8; RESPONSE_LEN]).is_ok());
    }

    #[test]
    fn to_message_buffer_too_small() {
        let caps = mandatory_caps();
        let prot_cap = ProtCap::new(0x01, 0x01, caps, 1, 17, 0);
        assert_eq!(
            prot_cap.to_message(&mut [0u8; RESPONSE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
