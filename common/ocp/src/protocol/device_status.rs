// Licensed under the Apache-2.0 license

//! DEVICE_STATUS (cmd=0x24) response structure.
//!
//! Spec reference: Section 9.2, Table 3.
//! A variable-length RO command (7-255 bytes) reporting device health,
//! protocol errors, recovery reason, heartbeat, and optional vendor status.
//! This command is required (scope A -- available anytime).

use core::convert::TryFrom;

use crate::error::OcpError;

/// Minimum wire size of a DEVICE_STATUS message (no vendor status).
pub const MIN_MESSAGE_LEN: usize = 7;

/// Maximum wire size of a DEVICE_STATUS message (full vendor status).
pub const MAX_MESSAGE_LEN: usize = 255;

/// Maximum length of the vendor status payload in bytes.
pub const MAX_VENDOR_STATUS_LEN: usize = 248;

/// Maximum heartbeat value (12-bit counter, wraps at 4095).
pub const MAX_HEARTBEAT: u16 = 4095;

/// Byte 0: Device status value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceStatusValue {
    StatusPending = 0x0,
    DeviceHealthy = 0x1,
    DeviceError = 0x2,
    RecoveryMode = 0x3,
    RecoveryPending = 0x4,
    RunningRecoveryImage = 0x5,
    BootFailure = 0xE,
    FatalError = 0xF,
}

impl TryFrom<u8> for DeviceStatusValue {
    type Error = OcpError;

    fn try_from(value: u8) -> Result<Self, OcpError> {
        match value {
            0x0 => Ok(Self::StatusPending),
            0x1 => Ok(Self::DeviceHealthy),
            0x2 => Ok(Self::DeviceError),
            0x3 => Ok(Self::RecoveryMode),
            0x4 => Ok(Self::RecoveryPending),
            0x5 => Ok(Self::RunningRecoveryImage),
            0xE => Ok(Self::BootFailure),
            0xF => Ok(Self::FatalError),
            _ => Err(OcpError::DeviceStatusInvalidStatus),
        }
    }
}

/// Byte 1: Protocol error code (clear on read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolError {
    NoError = 0x0,
    UnsupportedCommand = 0x1,
    UnsupportedParameter = 0x2,
    LengthWriteError = 0x3,
    CrcError = 0x4,
    GeneralProtocolError = 0xFF,
}

impl TryFrom<u8> for ProtocolError {
    type Error = OcpError;

    fn try_from(value: u8) -> Result<Self, OcpError> {
        match value {
            0x0 => Ok(Self::NoError),
            0x1 => Ok(Self::UnsupportedCommand),
            0x2 => Ok(Self::UnsupportedParameter),
            0x3 => Ok(Self::LengthWriteError),
            0x4 => Ok(Self::CrcError),
            0xFF => Ok(Self::GeneralProtocolError),
            _ => Err(OcpError::DeviceStatusInvalidProtocolError),
        }
    }
}

/// Bytes 2-3: Recovery reason code (Table 3).
///
/// Defined codes 0x00-0x12 are named variants. Vendor-unique codes
/// 0x80-0xFF are represented by [`VendorSpecific`](Self::VendorSpecific).
/// Reserved ranges (0x13-0x7F, 0x0100-0xFFFF) are not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReasonCode {
    /// 0x00: No boot failure detected.
    NoBootFailure,
    /// 0x01: Generic hardware error.
    GenericHardwareError,
    /// 0x02: Generic hardware soft error (may be recoverable).
    GenericHardwareSoftError,
    /// 0x03: Self-test failure (e.g. RSA/FIPS self-test).
    SelfTestFailure,
    /// 0x04: Corrupted/missing critical data.
    CorruptedMissingCriticalData,
    /// 0x05: Missing/corrupt key manifest.
    MissingCorruptKeyManifest,
    /// 0x06: Authentication failure on key manifest.
    AuthFailureKeyManifest,
    /// 0x07: Anti-rollback failure on key manifest.
    AntiRollbackFailureKeyManifest,
    /// 0x08: Missing/corrupt boot loader (first mutable code) firmware image.
    MissingCorruptBootLoader,
    /// 0x09: Authentication failure on boot loader firmware image.
    AuthFailureBootLoader,
    /// 0x0A: Anti-rollback failure on boot loader firmware image.
    AntiRollbackFailureBootLoader,
    /// 0x0B: Missing/corrupt main/management firmware image.
    MissingCorruptMainFirmware,
    /// 0x0C: Authentication failure on main/management firmware image.
    AuthFailureMainFirmware,
    /// 0x0D: Anti-rollback failure on main/management firmware image.
    AntiRollbackFailureMainFirmware,
    /// 0x0E: Missing/corrupt recovery firmware.
    MissingCorruptRecoveryFirmware,
    /// 0x0F: Authentication failure on recovery firmware.
    AuthFailureRecoveryFirmware,
    /// 0x10: Anti-rollback failure on recovery firmware.
    AntiRollbackFailureRecoveryFirmware,
    /// 0x11: Forced recovery.
    ForcedRecovery,
    /// 0x12: Flashless/streaming boot.
    FlashlessStreamingBoot,
    /// 0x80-0xFF: Vendor-unique boot failure code. The `u8` is the raw code value.
    VendorSpecific(u8),
}

impl RecoveryReasonCode {
    /// Convert to the 2-byte little-endian wire representation (u16 LE).
    pub fn to_bytes(self) -> [u8; 2] {
        let code: u16 = match self {
            Self::NoBootFailure => 0x00,
            Self::GenericHardwareError => 0x01,
            Self::GenericHardwareSoftError => 0x02,
            Self::SelfTestFailure => 0x03,
            Self::CorruptedMissingCriticalData => 0x04,
            Self::MissingCorruptKeyManifest => 0x05,
            Self::AuthFailureKeyManifest => 0x06,
            Self::AntiRollbackFailureKeyManifest => 0x07,
            Self::MissingCorruptBootLoader => 0x08,
            Self::AuthFailureBootLoader => 0x09,
            Self::AntiRollbackFailureBootLoader => 0x0A,
            Self::MissingCorruptMainFirmware => 0x0B,
            Self::AuthFailureMainFirmware => 0x0C,
            Self::AntiRollbackFailureMainFirmware => 0x0D,
            Self::MissingCorruptRecoveryFirmware => 0x0E,
            Self::AuthFailureRecoveryFirmware => 0x0F,
            Self::AntiRollbackFailureRecoveryFirmware => 0x10,
            Self::ForcedRecovery => 0x11,
            Self::FlashlessStreamingBoot => 0x12,
            Self::VendorSpecific(v) => v.into(),
        };
        code.to_le_bytes()
    }
}

/// DEVICE_STATUS response (7-255 bytes on the wire).
///
/// | Byte  | Field                |
/// |-------|----------------------|
/// | 0     | Device Status        |
/// | 1     | Protocol Error (CoR) |
/// | 2-3   | Recovery Reason (LE) |
/// | 4-5   | Heartbeat (LE)       |
/// | 6     | Vendor Status Length  |
/// | 7-254 | Vendor Status        |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStatus<'a> {
    device_status: DeviceStatusValue,
    protocol_error: ProtocolError,
    recovery_reason: RecoveryReasonCode,
    heartbeat: u16,
    vendor_status: &'a [u8],
}

impl<'a> DeviceStatus<'a> {
    /// Create a new DEVICE_STATUS response.
    ///
    /// Returns an error if:
    /// - `vendor_status` exceeds 248 bytes
    /// - `heartbeat` exceeds 4095 (12-bit counter)
    /// - `recovery_reason` is `VendorSpecific(v)` with `v < 0x80`
    pub fn new(
        device_status: DeviceStatusValue,
        protocol_error: ProtocolError,
        recovery_reason: RecoveryReasonCode,
        heartbeat: u16,
        vendor_status: &'a [u8],
    ) -> Result<Self, OcpError> {
        if vendor_status.len() > MAX_VENDOR_STATUS_LEN {
            return Err(OcpError::DeviceStatusVendorStatusTooLong);
        }
        if heartbeat > MAX_HEARTBEAT {
            return Err(OcpError::DeviceStatusHeartbeatOutOfRange);
        }
        if let RecoveryReasonCode::VendorSpecific(v) = recovery_reason {
            if v < 0x80 {
                return Err(OcpError::DeviceStatusInvalidVendorReasonCode);
            }
        }
        Ok(Self {
            device_status,
            protocol_error,
            recovery_reason,
            heartbeat,
            vendor_status,
        })
    }

    /// Byte 0: Device status value.
    pub fn device_status(&self) -> DeviceStatusValue {
        self.device_status
    }

    /// Byte 1: Protocol error code (clear on read).
    pub fn protocol_error(&self) -> ProtocolError {
        self.protocol_error
    }

    /// Bytes 2-3: Recovery reason code.
    pub fn recovery_reason(&self) -> RecoveryReasonCode {
        self.recovery_reason
    }

    /// Bytes 4-5: Heartbeat counter (0-4095).
    pub fn heartbeat(&self) -> u16 {
        self.heartbeat
    }

    /// Bytes 7-254: Vendor status payload (may be empty).
    pub fn vendor_status(&self) -> &[u8] {
        self.vendor_status
    }

    /// Logical length of the serialized message.
    pub fn message_len(&self) -> usize {
        MIN_MESSAGE_LEN + self.vendor_status.len()
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small.
    /// On success, returns the number of bytes written
    /// (7 + vendor_status length).
    pub fn to_message(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let len = self.message_len();
        if buf.len() < len {
            return Err(OcpError::BufferTooSmall);
        }
        let reason = self.recovery_reason.to_bytes();
        let heartbeat = self.heartbeat.to_le_bytes();

        buf[0] = self.device_status as u8;
        buf[1] = self.protocol_error as u8;
        buf[2] = reason[0];
        buf[3] = reason[1];
        buf[4] = heartbeat[0];
        buf[5] = heartbeat[1];
        buf[6] = self.vendor_status.len() as u8;

        buf[MIN_MESSAGE_LEN..len].copy_from_slice(self.vendor_status);

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DeviceStatusValue ---

    #[test]
    fn device_status_value_all_valid() {
        let cases = [
            (0x0, DeviceStatusValue::StatusPending),
            (0x1, DeviceStatusValue::DeviceHealthy),
            (0x2, DeviceStatusValue::DeviceError),
            (0x3, DeviceStatusValue::RecoveryMode),
            (0x4, DeviceStatusValue::RecoveryPending),
            (0x5, DeviceStatusValue::RunningRecoveryImage),
            (0xE, DeviceStatusValue::BootFailure),
            (0xF, DeviceStatusValue::FatalError),
        ];
        for (raw, expected) in cases {
            assert_eq!(DeviceStatusValue::try_from(raw), Ok(expected));
        }
    }

    #[test]
    fn device_status_value_reserved_rejected() {
        for raw in [0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0x10, 0xFF] {
            assert_eq!(
                DeviceStatusValue::try_from(raw),
                Err(OcpError::DeviceStatusInvalidStatus),
            );
        }
    }

    // --- ProtocolError ---

    #[test]
    fn protocol_error_all_valid() {
        let cases = [
            (0x0, ProtocolError::NoError),
            (0x1, ProtocolError::UnsupportedCommand),
            (0x2, ProtocolError::UnsupportedParameter),
            (0x3, ProtocolError::LengthWriteError),
            (0x4, ProtocolError::CrcError),
            (0xFF, ProtocolError::GeneralProtocolError),
        ];
        for (raw, expected) in cases {
            assert_eq!(ProtocolError::try_from(raw), Ok(expected));
        }
    }

    #[test]
    fn protocol_error_reserved_rejected() {
        for raw in [0x5, 0x6, 0x80, 0xFE] {
            assert_eq!(
                ProtocolError::try_from(raw),
                Err(OcpError::DeviceStatusInvalidProtocolError),
            );
        }
    }

    // --- RecoveryReasonCode ---

    #[test]
    fn recovery_reason_defined_codes_to_bytes() {
        let cases: [(RecoveryReasonCode, u16); 19] = [
            (RecoveryReasonCode::NoBootFailure, 0x00),
            (RecoveryReasonCode::GenericHardwareError, 0x01),
            (RecoveryReasonCode::GenericHardwareSoftError, 0x02),
            (RecoveryReasonCode::SelfTestFailure, 0x03),
            (RecoveryReasonCode::CorruptedMissingCriticalData, 0x04),
            (RecoveryReasonCode::MissingCorruptKeyManifest, 0x05),
            (RecoveryReasonCode::AuthFailureKeyManifest, 0x06),
            (RecoveryReasonCode::AntiRollbackFailureKeyManifest, 0x07),
            (RecoveryReasonCode::MissingCorruptBootLoader, 0x08),
            (RecoveryReasonCode::AuthFailureBootLoader, 0x09),
            (RecoveryReasonCode::AntiRollbackFailureBootLoader, 0x0A),
            (RecoveryReasonCode::MissingCorruptMainFirmware, 0x0B),
            (RecoveryReasonCode::AuthFailureMainFirmware, 0x0C),
            (RecoveryReasonCode::AntiRollbackFailureMainFirmware, 0x0D),
            (RecoveryReasonCode::MissingCorruptRecoveryFirmware, 0x0E),
            (RecoveryReasonCode::AuthFailureRecoveryFirmware, 0x0F),
            (
                RecoveryReasonCode::AntiRollbackFailureRecoveryFirmware,
                0x10,
            ),
            (RecoveryReasonCode::ForcedRecovery, 0x11),
            (RecoveryReasonCode::FlashlessStreamingBoot, 0x12),
        ];
        for (reason, expected_code) in cases {
            let bytes = reason.to_bytes();
            assert_eq!(
                u16::from_le_bytes(bytes),
                expected_code,
                "mismatch for {:?}",
                reason,
            );
        }
    }

    #[test]
    fn recovery_reason_vendor_specific_to_bytes() {
        let reason = RecoveryReasonCode::VendorSpecific(0x80);
        assert_eq!(reason.to_bytes(), [0x80, 0x00]);

        let reason = RecoveryReasonCode::VendorSpecific(0xFF);
        assert_eq!(reason.to_bytes(), [0xFF, 0x00]);

        let reason = RecoveryReasonCode::VendorSpecific(0xA5);
        assert_eq!(reason.to_bytes(), [0xA5, 0x00]);
    }

    // --- DeviceStatus construction validation ---

    #[test]
    fn vendor_status_empty_accepted() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0,
            &[],
        )
        .unwrap();
        assert_eq!(ds.vendor_status().len(), 0);
        assert_eq!(ds.message_len(), MIN_MESSAGE_LEN);
    }

    #[test]
    fn vendor_status_max_accepted() {
        let data = [0xAB; MAX_VENDOR_STATUS_LEN];
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0,
            &data,
        )
        .unwrap();
        assert_eq!(ds.vendor_status().len(), MAX_VENDOR_STATUS_LEN);
        assert_eq!(ds.message_len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn vendor_status_too_long_rejected() {
        let data = [0x00; MAX_VENDOR_STATUS_LEN + 1];
        assert_eq!(
            DeviceStatus::new(
                DeviceStatusValue::DeviceHealthy,
                ProtocolError::NoError,
                RecoveryReasonCode::NoBootFailure,
                0,
                &data,
            ),
            Err(OcpError::DeviceStatusVendorStatusTooLong),
        );
    }

    #[test]
    fn heartbeat_max_accepted() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            MAX_HEARTBEAT,
            &[],
        )
        .unwrap();
        assert_eq!(ds.heartbeat(), MAX_HEARTBEAT);
    }

    #[test]
    fn heartbeat_out_of_range_rejected() {
        assert_eq!(
            DeviceStatus::new(
                DeviceStatusValue::DeviceHealthy,
                ProtocolError::NoError,
                RecoveryReasonCode::NoBootFailure,
                MAX_HEARTBEAT + 1,
                &[],
            ),
            Err(OcpError::DeviceStatusHeartbeatOutOfRange),
        );
    }

    #[test]
    fn vendor_reason_code_valid_accepted() {
        DeviceStatus::new(
            DeviceStatusValue::RecoveryMode,
            ProtocolError::NoError,
            RecoveryReasonCode::VendorSpecific(0x80),
            0,
            &[],
        )
        .unwrap();
        DeviceStatus::new(
            DeviceStatusValue::RecoveryMode,
            ProtocolError::NoError,
            RecoveryReasonCode::VendorSpecific(0xFF),
            0,
            &[],
        )
        .unwrap();
    }

    #[test]
    fn vendor_reason_code_below_range_rejected() {
        assert_eq!(
            DeviceStatus::new(
                DeviceStatusValue::RecoveryMode,
                ProtocolError::NoError,
                RecoveryReasonCode::VendorSpecific(0x7F),
                0,
                &[],
            ),
            Err(OcpError::DeviceStatusInvalidVendorReasonCode),
        );
        assert_eq!(
            DeviceStatus::new(
                DeviceStatusValue::RecoveryMode,
                ProtocolError::NoError,
                RecoveryReasonCode::VendorSpecific(0x00),
                0,
                &[],
            ),
            Err(OcpError::DeviceStatusInvalidVendorReasonCode),
        );
    }

    // --- to_message ---

    #[test]
    fn to_message_no_vendor_status() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0,
            &[],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = ds.to_message(&mut buf).unwrap();

        assert_eq!(len, 7);
        assert_eq!(buf[0], 0x01); // DeviceHealthy
        assert_eq!(buf[1], 0x00); // NoError
        assert_eq!(buf[2], 0x00); // reason low
        assert_eq!(buf[3], 0x00); // reason high
        assert_eq!(buf[4], 0x00); // heartbeat low
        assert_eq!(buf[5], 0x00); // heartbeat high
        assert_eq!(buf[6], 0x00); // vendor status length
    }

    #[test]
    fn to_message_with_vendor_status() {
        let vendor = [0xDE, 0xAD, 0xBE, 0xEF];
        let ds = DeviceStatus::new(
            DeviceStatusValue::RecoveryMode,
            ProtocolError::UnsupportedCommand,
            RecoveryReasonCode::ForcedRecovery,
            100,
            &vendor,
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = ds.to_message(&mut buf).unwrap();

        assert_eq!(len, 11);
        assert_eq!(buf[0], 0x03); // RecoveryMode
        assert_eq!(buf[1], 0x01); // UnsupportedCommand
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x11); // ForcedRecovery
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 100); // heartbeat
        assert_eq!(buf[6], 4); // vendor status length
        assert_eq!(&buf[7..11], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn to_message_heartbeat_little_endian() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0x0A0B,
            &[],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        ds.to_message(&mut buf).unwrap();

        assert_eq!(buf[4], 0x0B);
        assert_eq!(buf[5], 0x0A);
    }

    #[test]
    fn to_message_recovery_reason_little_endian() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::RecoveryMode,
            ProtocolError::NoError,
            RecoveryReasonCode::VendorSpecific(0xAB),
            0,
            &[],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        ds.to_message(&mut buf).unwrap();

        assert_eq!(buf[2], 0xAB);
        assert_eq!(buf[3], 0x00);
    }

    #[test]
    fn to_message_bytes_beyond_len_are_zero() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0,
            &[0xFF, 0xFF],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = ds.to_message(&mut buf).unwrap();

        assert_eq!(len, 9);
        for &b in &buf[len..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn to_message_max_vendor_status() {
        let data = [0x42; MAX_VENDOR_STATUS_LEN];
        let ds = DeviceStatus::new(
            DeviceStatusValue::BootFailure,
            ProtocolError::GeneralProtocolError,
            RecoveryReasonCode::MissingCorruptBootLoader,
            4095,
            &data,
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = ds.to_message(&mut buf).unwrap();

        assert_eq!(len, MAX_MESSAGE_LEN);
        assert_eq!(buf[0], 0x0E); // BootFailure
        assert_eq!(buf[1], 0xFF); // GeneralProtocolError
        assert_eq!(buf[6], MAX_VENDOR_STATUS_LEN as u8);
        assert_eq!(&buf[7..MAX_MESSAGE_LEN], &data[..]);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let ds = DeviceStatus::new(
            DeviceStatusValue::DeviceHealthy,
            ProtocolError::NoError,
            RecoveryReasonCode::NoBootFailure,
            0,
            &[],
        )
        .unwrap();
        assert_eq!(
            ds.to_message(&mut [0u8; MIN_MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
