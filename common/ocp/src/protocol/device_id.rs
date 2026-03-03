// Licensed under the Apache-2.0 license

//! DEVICE_ID (cmd=0x23) response structure.
//!
//! Spec reference: Section 9.2, DMTF PLDM FM Table 8.
//! A variable-length RO command (24-255 bytes) reporting device identity
//! information via a typed descriptor and optional vendor-specific string.
//! This command is required (scope A -- available anytime).

use core::convert::TryFrom;

use crate::error::OcpError;

/// Size of the descriptor data region in bytes (bytes 2-23).
pub const DESCRIPTOR_DATA_LEN: usize = 22;

/// Minimum wire size of a DEVICE_ID message (no vendor string).
pub const MIN_MESSAGE_LEN: usize = 24;

/// Maximum wire size of a DEVICE_ID message (full vendor string).
pub const MAX_MESSAGE_LEN: usize = 255;

/// Maximum length of the vendor-specific string in bytes.
pub const MAX_VENDOR_STRING_LEN: usize = 231;

// ---------------------------------------------------------------------------
// Descriptor type byte
// ---------------------------------------------------------------------------

/// Byte 0: Initial Descriptor Type (per DMTF PLDM FM Table 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DescriptorType {
    PciVendor = 0x00,
    Iana = 0x01,
    Uuid = 0x02,
    PnpVendor = 0x03,
    AcpiVendor = 0x04,
    IanaEnterprise = 0x05,
    NvmeMi = 0xFF,
}

impl TryFrom<u8> for DescriptorType {
    type Error = OcpError;

    fn try_from(value: u8) -> Result<Self, OcpError> {
        match value {
            0x00 => Ok(Self::PciVendor),
            0x01 => Ok(Self::Iana),
            0x02 => Ok(Self::Uuid),
            0x03 => Ok(Self::PnpVendor),
            0x04 => Ok(Self::AcpiVendor),
            0x05 => Ok(Self::IanaEnterprise),
            0xFF => Ok(Self::NvmeMi),
            _ => Err(OcpError::DeviceIdInvalidDescriptorType),
        }
    }
}

// ---------------------------------------------------------------------------
// Individual descriptor structs
// ---------------------------------------------------------------------------

/// PCI Vendor descriptor (type 0x00).
///
/// | Offset | Field                  |
/// |--------|------------------------|
/// | 0-1    | PCI Vendor ID (LE)     |
/// | 2-3    | PCI Device ID (LE)     |
/// | 4-5    | Subsystem Vendor ID (LE)|
/// | 6-7    | Subsystem ID (LE)      |
/// | 8      | Revision ID            |
/// | 9-21   | PAD (zeros)            |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciVendorDescriptor {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub revision_id: u8,
}

impl PciVendorDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        let vid = self.vendor_id.to_le_bytes();
        let did = self.device_id.to_le_bytes();
        let svid = self.subsystem_vendor_id.to_le_bytes();
        let sid = self.subsystem_id.to_le_bytes();
        buf[0] = vid[0];
        buf[1] = vid[1];
        buf[2] = did[0];
        buf[3] = did[1];
        buf[4] = svid[0];
        buf[5] = svid[1];
        buf[6] = sid[0];
        buf[7] = sid[1];
        buf[8] = self.revision_id;
        buf
    }
}

/// IANA descriptor (type 0x01) and IANA Enterprise descriptor (type 0x05).
///
/// Both types share the same field layout.
///
/// | Offset | Field                       |
/// |--------|-----------------------------|
/// | 0-3    | IANA Enterprise ID (LE)     |
/// | 4-15   | ACPI Product Identifier     |
/// | 16-21  | PAD (zeros)                 |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IanaDescriptor {
    pub enterprise_id: u32,
    pub product_identifier: [u8; 12],
}

impl IanaDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        let eid = self.enterprise_id.to_le_bytes();
        buf[0] = eid[0];
        buf[1] = eid[1];
        buf[2] = eid[2];
        buf[3] = eid[3];
        buf[4..16].copy_from_slice(&self.product_identifier);
        buf
    }
}

/// UUID descriptor (type 0x02).
///
/// | Offset | Field       |
/// |--------|-------------|
/// | 0-15   | UUID        |
/// | 16-21  | PAD (zeros) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UuidDescriptor {
    pub uuid: [u8; 16],
}

impl UuidDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        buf[0..16].copy_from_slice(&self.uuid);
        buf
    }
}

/// PnP Vendor descriptor (type 0x03).
///
/// | Offset | Field                  |
/// |--------|------------------------|
/// | 0-2    | PnP Vendor Identifier  |
/// | 3-6    | PnP Product Identifier |
/// | 7-21   | PAD (zeros)            |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PnpVendorDescriptor {
    pub vendor_identifier: [u8; 3],
    pub product_identifier: [u8; 4],
}

impl PnpVendorDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        buf[0..3].copy_from_slice(&self.vendor_identifier);
        buf[3..7].copy_from_slice(&self.product_identifier);
        buf
    }
}

/// ACPI Vendor descriptor (type 0x04).
///
/// | Offset | Field                     |
/// |--------|---------------------------|
/// | 0-3    | ACPI Vendor Identifier    |
/// | 4-6    | Vendor Product Identifier |
/// | 7-21   | PAD (zeros)               |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiVendorDescriptor {
    pub vendor_identifier: [u8; 4],
    pub product_identifier: [u8; 3],
}

impl AcpiVendorDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        buf[0..4].copy_from_slice(&self.vendor_identifier);
        buf[4..7].copy_from_slice(&self.product_identifier);
        buf
    }
}

/// NVMe-MI descriptor (type 0xFF).
///
/// | Offset | Field                |
/// |--------|----------------------|
/// | 0-1    | Vendor ID (LE)       |
/// | 2-21   | Device Serial Number |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeMiDescriptor {
    pub vendor_id: u16,
    pub serial_number: [u8; 20],
}

impl NvmeMiDescriptor {
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        let mut buf = [0u8; DESCRIPTOR_DATA_LEN];
        let vid = self.vendor_id.to_le_bytes();
        buf[0] = vid[0];
        buf[1] = vid[1];
        buf[2..22].copy_from_slice(&self.serial_number);
        buf
    }
}

// ---------------------------------------------------------------------------
// DeviceDescriptor enum
// ---------------------------------------------------------------------------

/// Descriptor data for bytes 2-23, typed by descriptor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDescriptor {
    PciVendor(PciVendorDescriptor),
    Iana(IanaDescriptor),
    Uuid(UuidDescriptor),
    PnpVendor(PnpVendorDescriptor),
    AcpiVendor(AcpiVendorDescriptor),
    IanaEnterprise(IanaDescriptor),
    NvmeMi(NvmeMiDescriptor),
}

impl DeviceDescriptor {
    /// Returns the descriptor type byte (byte 0) for the wire format.
    pub fn descriptor_type_byte(&self) -> u8 {
        match self {
            Self::PciVendor(_) => DescriptorType::PciVendor as u8,
            Self::Iana(_) => DescriptorType::Iana as u8,
            Self::Uuid(_) => DescriptorType::Uuid as u8,
            Self::PnpVendor(_) => DescriptorType::PnpVendor as u8,
            Self::AcpiVendor(_) => DescriptorType::AcpiVendor as u8,
            Self::IanaEnterprise(_) => DescriptorType::IanaEnterprise as u8,
            Self::NvmeMi(_) => DescriptorType::NvmeMi as u8,
        }
    }

    /// Returns the descriptor type enum value.
    pub fn descriptor_type(&self) -> DescriptorType {
        match self {
            Self::PciVendor(_) => DescriptorType::PciVendor,
            Self::Iana(_) => DescriptorType::Iana,
            Self::Uuid(_) => DescriptorType::Uuid,
            Self::PnpVendor(_) => DescriptorType::PnpVendor,
            Self::AcpiVendor(_) => DescriptorType::AcpiVendor,
            Self::IanaEnterprise(_) => DescriptorType::IanaEnterprise,
            Self::NvmeMi(_) => DescriptorType::NvmeMi,
        }
    }

    /// Serialize the descriptor data into the 22-byte region (bytes 2-23).
    pub fn to_descriptor_bytes(&self) -> [u8; DESCRIPTOR_DATA_LEN] {
        match self {
            Self::PciVendor(d) => d.to_descriptor_bytes(),
            Self::Iana(d) | Self::IanaEnterprise(d) => d.to_descriptor_bytes(),
            Self::Uuid(d) => d.to_descriptor_bytes(),
            Self::PnpVendor(d) => d.to_descriptor_bytes(),
            Self::AcpiVendor(d) => d.to_descriptor_bytes(),
            Self::NvmeMi(d) => d.to_descriptor_bytes(),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

/// DEVICE_ID response (24-255 bytes on the wire).
///
/// | Byte  | Field                    |
/// |-------|--------------------------|
/// | 0     | Descriptor Type          |
/// | 1     | Vendor String Length      |
/// | 2-23  | Descriptor Data (22B)    |
/// | 24-254| Vendor Specific String   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId<'a> {
    descriptor: DeviceDescriptor,
    vendor_string: &'a [u8],
}

impl<'a> DeviceId<'a> {
    /// Create a new DEVICE_ID response.
    ///
    /// Returns an error if `vendor_string` exceeds 231 bytes.
    pub fn new(descriptor: DeviceDescriptor, vendor_string: &'a [u8]) -> Result<Self, OcpError> {
        if vendor_string.len() > MAX_VENDOR_STRING_LEN {
            return Err(OcpError::DeviceIdVendorStringTooLong);
        }
        Ok(Self {
            descriptor,
            vendor_string,
        })
    }

    /// The device descriptor (typed).
    pub fn descriptor(&self) -> &DeviceDescriptor {
        &self.descriptor
    }

    /// The vendor-specific string (may be empty).
    pub fn vendor_string(&self) -> &[u8] {
        self.vendor_string
    }

    /// Logical length of the serialized message.
    pub fn message_len(&self) -> usize {
        MIN_MESSAGE_LEN + self.vendor_string.len()
    }

    /// Serialize into the wire representation.
    ///
    /// Returns an error if the buffer is too small.
    /// On success, returns the number of bytes written
    /// (24 + vendor string length).
    pub fn to_message(&self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let len = self.message_len();
        if buf.len() < len {
            return Err(OcpError::BufferTooSmall);
        }
        let desc_bytes = self.descriptor.to_descriptor_bytes();

        buf[0] = self.descriptor.descriptor_type_byte();
        buf[1] = self.vendor_string.len() as u8;
        buf[2..MIN_MESSAGE_LEN].copy_from_slice(&desc_bytes);

        buf[MIN_MESSAGE_LEN..len].copy_from_slice(self.vendor_string);

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DescriptorType TryFrom ---

    #[test]
    fn descriptor_type_all_valid() {
        let cases = [
            (0x00, DescriptorType::PciVendor),
            (0x01, DescriptorType::Iana),
            (0x02, DescriptorType::Uuid),
            (0x03, DescriptorType::PnpVendor),
            (0x04, DescriptorType::AcpiVendor),
            (0x05, DescriptorType::IanaEnterprise),
            (0xFF, DescriptorType::NvmeMi),
        ];
        for (raw, expected) in cases {
            assert_eq!(DescriptorType::try_from(raw), Ok(expected));
        }
    }

    #[test]
    fn descriptor_type_reserved_rejected() {
        for raw in [0x06, 0x07, 0x10, 0x80, 0xFE] {
            assert_eq!(
                DescriptorType::try_from(raw),
                Err(OcpError::DeviceIdInvalidDescriptorType),
            );
        }
    }

    // --- PciVendorDescriptor ---

    #[test]
    fn pci_vendor_serializes() {
        let d = PciVendorDescriptor {
            vendor_id: 0x8086,
            device_id: 0x1234,
            subsystem_vendor_id: 0xABCD,
            subsystem_id: 0x5678,
            revision_id: 0x01,
        };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x8086);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x1234);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 0xABCD);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 0x5678);
        assert_eq!(bytes[8], 0x01);
        assert_eq!(&bytes[9..], &[0u8; 13]);
    }

    // --- IanaDescriptor ---

    #[test]
    fn iana_serializes() {
        let d = IanaDescriptor {
            enterprise_id: 0x0000_1234,
            product_identifier: *b"HELLO_WORLD!",
        };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0x1234,
        );
        assert_eq!(&bytes[4..16], b"HELLO_WORLD!");
        assert_eq!(&bytes[16..], &[0u8; 6]);
    }

    // --- UuidDescriptor ---

    #[test]
    fn uuid_serializes() {
        let uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let d = UuidDescriptor { uuid };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(&bytes[0..16], &uuid);
        assert_eq!(&bytes[16..], &[0u8; 6]);
    }

    // --- PnpVendorDescriptor ---

    #[test]
    fn pnp_vendor_serializes() {
        let d = PnpVendorDescriptor {
            vendor_identifier: [0xAA, 0xBB, 0xCC],
            product_identifier: [0x01, 0x02, 0x03, 0x04],
        };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(&bytes[0..3], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&bytes[3..7], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[7..], &[0u8; 15]);
    }

    // --- AcpiVendorDescriptor ---

    #[test]
    fn acpi_vendor_serializes() {
        let d = AcpiVendorDescriptor {
            vendor_identifier: [0x41, 0x42, 0x43, 0x44],
            product_identifier: [0x01, 0x02, 0x03],
        };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(&bytes[0..4], &[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(&bytes[4..7], &[0x01, 0x02, 0x03]);
        assert_eq!(&bytes[7..], &[0u8; 15]);
    }

    // --- NvmeMiDescriptor ---

    #[test]
    fn nvme_mi_serializes() {
        let mut sn = [0u8; 20];
        sn[0] = 0xDE;
        sn[19] = 0xAD;
        let d = NvmeMiDescriptor {
            vendor_id: 0x1D1D,
            serial_number: sn,
        };
        let bytes = d.to_descriptor_bytes();

        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x1D1D);
        assert_eq!(bytes[2], 0xDE);
        assert_eq!(bytes[21], 0xAD);
        assert_eq!(&bytes[2..22], &sn);
    }

    // --- DeviceDescriptor type bytes ---

    #[test]
    fn descriptor_type_bytes() {
        let pci = DeviceDescriptor::PciVendor(PciVendorDescriptor {
            vendor_id: 0,
            device_id: 0,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            revision_id: 0,
        });
        assert_eq!(pci.descriptor_type_byte(), 0x00);
        assert_eq!(pci.descriptor_type(), DescriptorType::PciVendor);

        let iana = DeviceDescriptor::Iana(IanaDescriptor {
            enterprise_id: 0,
            product_identifier: [0; 12],
        });
        assert_eq!(iana.descriptor_type_byte(), 0x01);

        let iana_ent = DeviceDescriptor::IanaEnterprise(IanaDescriptor {
            enterprise_id: 0,
            product_identifier: [0; 12],
        });
        assert_eq!(iana_ent.descriptor_type_byte(), 0x05);

        let uuid = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0; 16] });
        assert_eq!(uuid.descriptor_type_byte(), 0x02);

        let pnp = DeviceDescriptor::PnpVendor(PnpVendorDescriptor {
            vendor_identifier: [0; 3],
            product_identifier: [0; 4],
        });
        assert_eq!(pnp.descriptor_type_byte(), 0x03);

        let acpi = DeviceDescriptor::AcpiVendor(AcpiVendorDescriptor {
            vendor_identifier: [0; 4],
            product_identifier: [0; 3],
        });
        assert_eq!(acpi.descriptor_type_byte(), 0x04);

        let nvme = DeviceDescriptor::NvmeMi(NvmeMiDescriptor {
            vendor_id: 0,
            serial_number: [0; 20],
        });
        assert_eq!(nvme.descriptor_type_byte(), 0xFF);
    }

    // --- IANA and IanaEnterprise share serialization ---

    #[test]
    fn iana_and_iana_enterprise_same_serialization() {
        let d = IanaDescriptor {
            enterprise_id: 0xDEAD_BEEF,
            product_identifier: *b"PRODUCT_ID__",
        };
        let as_iana = DeviceDescriptor::Iana(d);
        let as_enterprise = DeviceDescriptor::IanaEnterprise(d);

        assert_eq!(
            as_iana.to_descriptor_bytes(),
            as_enterprise.to_descriptor_bytes(),
        );
        assert_eq!(as_iana.descriptor_type_byte(), 0x01);
        assert_eq!(as_enterprise.descriptor_type_byte(), 0x05);
    }

    // --- DeviceId vendor string validation ---

    #[test]
    fn vendor_string_empty_accepted() {
        let desc = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0; 16] });
        let did = DeviceId::new(desc, &[]).unwrap();
        assert_eq!(did.vendor_string().len(), 0);
        assert_eq!(did.message_len(), MIN_MESSAGE_LEN);
    }

    #[test]
    fn vendor_string_max_accepted() {
        let data = [0x41; MAX_VENDOR_STRING_LEN];
        let desc = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0; 16] });
        let did = DeviceId::new(desc, &data).unwrap();
        assert_eq!(did.vendor_string().len(), MAX_VENDOR_STRING_LEN);
        assert_eq!(did.message_len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn vendor_string_too_long_rejected() {
        let data = [0x00; MAX_VENDOR_STRING_LEN + 1];
        let desc = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0; 16] });
        assert_eq!(
            DeviceId::new(desc, &data),
            Err(OcpError::DeviceIdVendorStringTooLong),
        );
    }

    // --- to_message ---

    #[test]
    fn to_message_no_vendor_string() {
        let desc = DeviceDescriptor::PciVendor(PciVendorDescriptor {
            vendor_id: 0x8086,
            device_id: 0x1234,
            subsystem_vendor_id: 0,
            subsystem_id: 0,
            revision_id: 0x0A,
        });
        let did = DeviceId::new(desc, &[]).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = did.to_message(&mut buf).unwrap();

        assert_eq!(len, 24);
        assert_eq!(buf[0], 0x00); // PciVendor type
        assert_eq!(buf[1], 0x00); // vendor string length
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0x8086);
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 0x1234);
        assert_eq!(buf[10], 0x0A); // revision_id at descriptor offset 8 → msg byte 10
    }

    #[test]
    fn to_message_with_vendor_string() {
        let desc = DeviceDescriptor::NvmeMi(NvmeMiDescriptor {
            vendor_id: 0xBEEF,
            serial_number: [0x42; 20],
        });
        let vendor_str = b"TestDevice-v1.0";
        let did = DeviceId::new(desc, vendor_str).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = did.to_message(&mut buf).unwrap();

        assert_eq!(len, 24 + vendor_str.len());
        assert_eq!(buf[0], 0xFF); // NvmeMi type
        assert_eq!(buf[1], vendor_str.len() as u8);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 0xBEEF);
        assert_eq!(&buf[4..24], &[0x42; 20]);
        assert_eq!(&buf[24..len], vendor_str);
    }

    #[test]
    fn to_message_descriptor_data_padded() {
        let desc = DeviceDescriptor::PnpVendor(PnpVendorDescriptor {
            vendor_identifier: [0xAA, 0xBB, 0xCC],
            product_identifier: [0x01, 0x02, 0x03, 0x04],
        });
        let did = DeviceId::new(desc, &[]).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        did.to_message(&mut buf).unwrap();

        assert_eq!(buf[0], 0x03); // PnpVendor type
        assert_eq!(&buf[2..5], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&buf[5..9], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&buf[9..24], &[0u8; 15]); // padding
    }

    #[test]
    fn to_message_bytes_beyond_len_are_zero() {
        let desc = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0xFF; 16] });
        let did = DeviceId::new(desc, b"hi").unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = did.to_message(&mut buf).unwrap();

        assert_eq!(len, 26);
        for &b in &buf[len..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn to_message_max_vendor_string() {
        let data = [0x58; MAX_VENDOR_STRING_LEN];
        let desc = DeviceDescriptor::AcpiVendor(AcpiVendorDescriptor {
            vendor_identifier: *b"ACPI",
            product_identifier: [0x01, 0x02, 0x03],
        });
        let did = DeviceId::new(desc, &data).unwrap();
        let mut buf = [0u8; MAX_MESSAGE_LEN];
        let len = did.to_message(&mut buf).unwrap();

        assert_eq!(len, MAX_MESSAGE_LEN);
        assert_eq!(buf[0], 0x04);
        assert_eq!(buf[1], MAX_VENDOR_STRING_LEN as u8);
        assert_eq!(&buf[24..MAX_MESSAGE_LEN], &data[..]);
    }

    #[test]
    fn to_message_buffer_too_small() {
        let desc = DeviceDescriptor::Uuid(UuidDescriptor { uuid: [0; 16] });
        let did = DeviceId::new(desc, &[]).unwrap();
        assert_eq!(
            did.to_message(&mut [0u8; MIN_MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
