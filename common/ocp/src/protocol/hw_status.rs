// Licensed under the Apache-2.0 license

//! HW_STATUS (cmd=0x28) response structure.
//!
//! Spec reference: Section 9.2.
//! A variable-length RO command (4-255 bytes) reporting hardware status,
//! composite temperature, and optional vendor-specific hardware status.
//! This command is optional (scope R -- recovery interface must be active).

use bitfield::bitfield;
use core::convert::TryFrom;

use crate::error::OcpError;

/// Minimum wire size of an HW_STATUS message (no vendor-specific status).
pub const MIN_MESSAGE_LEN: usize = 4;

/// Maximum wire size of an HW_STATUS message (full vendor-specific status).
pub const MAX_MESSAGE_LEN: usize = 255;

/// Maximum length of the vendor-specific HW status payload in bytes.
pub const MAX_VENDOR_SPECIFIC_STATUS_LEN: usize = 251;

/// Minimum valid composite temperature in degrees Celsius.
pub const MIN_COMPOSITE_TEMP_CELSIUS: i8 = -60;

bitfield! {
    /// Byte 0 of HW_STATUS — hardware status flags (active high).
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct HwStatusFlags(u8);
    impl Debug;

    /// Bit 0: Device temperature is critical (may need reset to clear).
    pub bool, temp_critical, set_temp_critical: 0;
    /// Bit 1: Hardware soft error (may need reset to clear).
    pub bool, hw_soft_error, set_hw_soft_error: 1;
    /// Bit 2: Hardware fatal error.
    pub bool, hw_fatal_error, set_hw_fatal_error: 2;
}

/// Byte 2: Composite temperature (CTemp).
///
/// Compatible with NVMe-MI command code 0 offset 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeTemperature {
    /// Temperature in degrees Celsius (-60 to 127).
    /// 127 means 127°C or higher (clamped).
    /// -60 means -60°C or lower (clamped).
    Celsius(i8),
    /// No temperature data, or data is older than 5 seconds.
    NoData,
    /// Temperature sensor failure.
    SensorFailure,
}

impl CompositeTemperature {
    /// Convert to the single-byte wire representation.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Celsius(v) => v as u8,
            Self::NoData => 0x80,
            Self::SensorFailure => 0x81,
        }
    }
}

impl TryFrom<u8> for CompositeTemperature {
    type Error = OcpError;

    fn try_from(value: u8) -> Result<Self, OcpError> {
        match value {
            0x00..=0x7F => Ok(Self::Celsius(value as i8)),
            0x80 => Ok(Self::NoData),
            0x81 => Ok(Self::SensorFailure),
            0xC4..=0xFF => Ok(Self::Celsius(value as i8)),
            0x82..=0xC3 => Err(OcpError::HwStatusInvalidCompositeTemp),
        }
    }
}

/// HW_STATUS response (4-255 bytes on the wire).
///
/// | Byte  | Field                        |
/// |-------|------------------------------|
/// | 0     | HW Status flags              |
/// | 1     | Vendor HW Status             |
/// | 2     | Composite Temperature        |
/// | 3     | Vendor Specific Status Length |
/// | 4-254 | Vendor Specific HW Status    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwStatus<'a> {
    hw_status: HwStatusFlags,
    vendor_hw_status: u8,
    composite_temp: CompositeTemperature,
    vendor_specific_status: &'a [u8],
}

impl<'a> HwStatus<'a> {
    /// Create a new HW_STATUS response.
    ///
    /// Returns an error if:
    /// - `vendor_specific_status` exceeds 251 bytes
    /// - `composite_temp` is `Celsius(v)` with `v < -60`
    pub fn new(
        hw_status: HwStatusFlags,
        vendor_hw_status: u8,
        composite_temp: CompositeTemperature,
        vendor_specific_status: &'a [u8],
    ) -> Result<Self, OcpError> {
        if vendor_specific_status.len() > MAX_VENDOR_SPECIFIC_STATUS_LEN {
            return Err(OcpError::HwStatusVendorStatusTooLong);
        }
        if let CompositeTemperature::Celsius(v) = composite_temp {
            if v < MIN_COMPOSITE_TEMP_CELSIUS {
                return Err(OcpError::HwStatusInvalidCompositeTemp);
            }
        }
        Ok(Self {
            hw_status,
            vendor_hw_status,
            composite_temp,
            vendor_specific_status,
        })
    }

    /// Bit 0: Device temperature is critical.
    pub fn temp_critical(&self) -> bool {
        self.hw_status.temp_critical()
    }

    /// Bit 1: Hardware soft error.
    pub fn hw_soft_error(&self) -> bool {
        self.hw_status.hw_soft_error()
    }

    /// Bit 2: Hardware fatal error.
    pub fn hw_fatal_error(&self) -> bool {
        self.hw_status.hw_fatal_error()
    }

    /// Byte 1: Vendor HW status (vendor-specific bitmask).
    pub fn vendor_hw_status(&self) -> u8 {
        self.vendor_hw_status
    }

    /// Byte 2: Composite temperature.
    pub fn composite_temp(&self) -> CompositeTemperature {
        self.composite_temp
    }

    /// Bytes 4-254: Vendor-specific HW status payload (may be empty).
    pub fn vendor_specific_status(&self) -> &[u8] {
        self.vendor_specific_status
    }

    /// Logical length of the serialized message.
    pub fn message_len(&self) -> usize {
        MIN_MESSAGE_LEN + self.vendor_specific_status.len()
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small.
    /// On success, returns the number of bytes written
    /// (4 + vendor-specific status length).
    pub fn to_message(self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let len = self.message_len();
        if buf.len() < len {
            return Err(OcpError::BufferTooSmall);
        }

        buf[0] = self.hw_status.0;
        buf[1] = self.vendor_hw_status;
        buf[2] = self.composite_temp.to_byte();
        buf[3] = self.vendor_specific_status.len() as u8;

        buf[MIN_MESSAGE_LEN..len].copy_from_slice(self.vendor_specific_status);

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw_flags(temp_critical: bool, soft_error: bool, fatal_error: bool) -> HwStatusFlags {
        let mut f = HwStatusFlags(0);
        f.set_temp_critical(temp_critical);
        f.set_hw_soft_error(soft_error);
        f.set_hw_fatal_error(fatal_error);
        f
    }

    // --- HwStatusFlags ---

    #[test]
    fn flags_all_clear() {
        let status = HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &[]).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn flag_temp_critical() {
        let status = HwStatus::new(
            hw_flags(true, false, false),
            0,
            CompositeTemperature::NoData,
            &[],
        )
        .unwrap();
        assert!(status.temp_critical());
        assert!(!status.hw_soft_error());
        assert!(!status.hw_fatal_error());
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x01);
    }

    #[test]
    fn flag_hw_soft_error() {
        let status = HwStatus::new(
            hw_flags(false, true, false),
            0,
            CompositeTemperature::NoData,
            &[],
        )
        .unwrap();
        assert!(status.hw_soft_error());
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x02);
    }

    #[test]
    fn flag_hw_fatal_error() {
        let status = HwStatus::new(
            hw_flags(false, false, true),
            0,
            CompositeTemperature::NoData,
            &[],
        )
        .unwrap();
        assert!(status.hw_fatal_error());
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x04);
    }

    #[test]
    fn flags_all_set() {
        let status = HwStatus::new(
            hw_flags(true, true, true),
            0,
            CompositeTemperature::NoData,
            &[],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        status.to_message(&mut buf).unwrap();
        assert_eq!(buf[0], 0x07);
    }

    // --- CompositeTemperature ---

    #[test]
    fn ctemp_zero_celsius() {
        let ct = CompositeTemperature::Celsius(0);
        assert_eq!(ct.to_byte(), 0x00);
    }

    #[test]
    fn ctemp_positive_max() {
        let ct = CompositeTemperature::Celsius(127);
        assert_eq!(ct.to_byte(), 0x7F);
    }

    #[test]
    fn ctemp_negative_min() {
        let ct = CompositeTemperature::Celsius(-60);
        assert_eq!(ct.to_byte(), 0xC4);
    }

    #[test]
    fn ctemp_negative_one() {
        let ct = CompositeTemperature::Celsius(-1);
        assert_eq!(ct.to_byte(), 0xFF);
    }

    #[test]
    fn ctemp_no_data() {
        assert_eq!(CompositeTemperature::NoData.to_byte(), 0x80);
    }

    #[test]
    fn ctemp_sensor_failure() {
        assert_eq!(CompositeTemperature::SensorFailure.to_byte(), 0x81);
    }

    #[test]
    fn ctemp_try_from_positive() {
        assert_eq!(
            CompositeTemperature::try_from(0x00),
            Ok(CompositeTemperature::Celsius(0)),
        );
        assert_eq!(
            CompositeTemperature::try_from(0x7E),
            Ok(CompositeTemperature::Celsius(126)),
        );
        assert_eq!(
            CompositeTemperature::try_from(0x7F),
            Ok(CompositeTemperature::Celsius(127)),
        );
    }

    #[test]
    fn ctemp_try_from_special() {
        assert_eq!(
            CompositeTemperature::try_from(0x80),
            Ok(CompositeTemperature::NoData),
        );
        assert_eq!(
            CompositeTemperature::try_from(0x81),
            Ok(CompositeTemperature::SensorFailure),
        );
    }

    #[test]
    fn ctemp_try_from_negative() {
        assert_eq!(
            CompositeTemperature::try_from(0xC4),
            Ok(CompositeTemperature::Celsius(-60)),
        );
        assert_eq!(
            CompositeTemperature::try_from(0xFF),
            Ok(CompositeTemperature::Celsius(-1)),
        );
    }

    #[test]
    fn ctemp_try_from_reserved_rejected() {
        for raw in [0x82, 0x83, 0x90, 0xA0, 0xC3] {
            assert_eq!(
                CompositeTemperature::try_from(raw),
                Err(OcpError::HwStatusInvalidCompositeTemp),
            );
        }
    }

    #[test]
    fn ctemp_below_minus_60_rejected() {
        assert_eq!(
            HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::Celsius(-61), &[],),
            Err(OcpError::HwStatusInvalidCompositeTemp),
        );
        assert_eq!(
            HwStatus::new(
                HwStatusFlags(0),
                0,
                CompositeTemperature::Celsius(-128),
                &[],
            ),
            Err(OcpError::HwStatusInvalidCompositeTemp),
        );
    }

    #[test]
    fn ctemp_minus_60_accepted() {
        HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::Celsius(-60), &[]).unwrap();
    }

    // --- Vendor-specific status length ---

    #[test]
    fn vendor_status_empty_accepted() {
        let hs = HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &[]).unwrap();
        assert_eq!(hs.vendor_specific_status().len(), 0);
        assert_eq!(hs.message_len(), MIN_MESSAGE_LEN);
    }

    #[test]
    fn vendor_status_max_accepted() {
        let data = [0xAB; MAX_VENDOR_SPECIFIC_STATUS_LEN];
        let hs = HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &data).unwrap();
        assert_eq!(
            hs.vendor_specific_status().len(),
            MAX_VENDOR_SPECIFIC_STATUS_LEN
        );
        assert_eq!(hs.message_len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn vendor_status_too_long_rejected() {
        let data = [0x00; MAX_VENDOR_SPECIFIC_STATUS_LEN + 1];
        assert_eq!(
            HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &data,),
            Err(OcpError::HwStatusVendorStatusTooLong),
        );
    }

    // --- to_message ---

    #[test]
    fn to_message_no_vendor_status() {
        let hs = HwStatus::new(
            HwStatusFlags(0),
            0x00,
            CompositeTemperature::Celsius(25),
            &[],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = hs.to_message(&mut buf).unwrap();

        assert_eq!(len, 4);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 25);
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn to_message_with_vendor_status() {
        let vendor = [0xDE, 0xAD, 0xBE];
        let hs = HwStatus::new(
            hw_flags(true, false, true),
            0xF0,
            CompositeTemperature::Celsius(-10),
            &vendor,
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = hs.to_message(&mut buf).unwrap();

        assert_eq!(len, 7);
        assert_eq!(buf[0], 0x05); // bits 0 and 2
        assert_eq!(buf[1], 0xF0);
        assert_eq!(buf[2], (-10i8) as u8); // 0xF6
        assert_eq!(buf[3], 3);
        assert_eq!(&buf[4..7], &[0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn to_message_vendor_hw_status_preserved() {
        let hs = HwStatus::new(HwStatusFlags(0), 0xFF, CompositeTemperature::NoData, &[]).unwrap();
        assert_eq!(hs.vendor_hw_status(), 0xFF);
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        hs.to_message(&mut buf).unwrap();
        assert_eq!(buf[1], 0xFF);
    }

    #[test]
    fn to_message_bytes_beyond_len_are_zero() {
        let hs = HwStatus::new(
            HwStatusFlags(0),
            0,
            CompositeTemperature::NoData,
            &[0xFF, 0xFF],
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = hs.to_message(&mut buf).unwrap();

        assert_eq!(len, 6);
        for &b in &buf[len..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn to_message_max_vendor_status() {
        let data = [0x42; MAX_VENDOR_SPECIFIC_STATUS_LEN];
        let hs = HwStatus::new(
            hw_flags(false, true, false),
            0xAA,
            CompositeTemperature::SensorFailure,
            &data,
        )
        .unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = hs.to_message(&mut buf).unwrap();

        assert_eq!(len, MAX_MESSAGE_LEN);
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[1], 0xAA);
        assert_eq!(buf[2], 0x81);
        assert_eq!(buf[3], MAX_VENDOR_SPECIFIC_STATUS_LEN as u8);
        assert_eq!(&buf[4..MAX_MESSAGE_LEN], &data[..]);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let hs = HwStatus::new(HwStatusFlags(0), 0, CompositeTemperature::NoData, &[]).unwrap();
        assert_eq!(
            hs.to_message(&mut [0u8; MIN_MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
