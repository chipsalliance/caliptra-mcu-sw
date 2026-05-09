// Licensed under the Apache-2.0 license

//! DEVICE_ID (cmd=0x23) response structure.
//!
//! Spec reference: Section 9.2, DMTF PLDM FM Table 8.
//! A variable-length RO command (24-255 bytes) reporting device identity
//! information via a typed descriptor and optional vendor-specific string.
//! This command is required (scope A -- available anytime).

use zerocopy::{Immutable, IntoBytes};

use crate::error::OcpError;

/// Size of the descriptor data region in bytes (bytes 2-23).
pub const DESCRIPTOR_DATA_LEN: usize = 22;

/// Minimum wire size of a DEVICE_ID message (no vendor string), as specified by Spec.
pub const MIN_MESSAGE_LEN: usize = 24;

// Assure the spec size matches the size of the structure.
const _: () = assert!(MIN_MESSAGE_LEN == size_of::<DeviceIdInner>());

/// Maximum wire size of a DEVICE_ID message (full vendor string).
pub const MAX_MESSAGE_LEN: usize = 255;

/// Maximum length of the vendor-specific string in bytes.
pub const MAX_VENDOR_STRING_LEN: usize = MAX_MESSAGE_LEN - MIN_MESSAGE_LEN;

// ---------------------------------------------------------------------------
// Descriptor type byte
// ---------------------------------------------------------------------------

/// Byte 0: Initial Descriptor Type (per DMTF PLDM FM Table 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct PciVendorDescriptor {
    pub vendor_id: u16,
    pub device_id: u16,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub revision_id: u8,
    pad: [u8; 13],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<PciVendorDescriptor>());

impl PciVendorDescriptor {
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        revision_id: u8,
    ) -> Self {
        Self {
            vendor_id,
            device_id,
            subsystem_vendor_id,
            subsystem_id,
            revision_id,
            pad: [0; 13],
        }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct IanaDescriptor {
    pub enterprise_id: u32,
    pub product_identifier: [u8; 12],
    pad: [u8; 6],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<IanaDescriptor>());

impl IanaDescriptor {
    pub fn new(enterprise_id: u32, product_identifier: [u8; 12]) -> Self {
        Self {
            enterprise_id,
            product_identifier,
            pad: [0; 6],
        }
    }
}

/// UUID descriptor (type 0x02).
///
/// | Offset | Field       |
/// |--------|-------------|
/// | 0-15   | UUID        |
/// | 16-21  | PAD (zeros) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct UuidDescriptor {
    pub uuid: [u8; 16],
    pad: [u8; 6],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<UuidDescriptor>());

impl UuidDescriptor {
    pub fn new(uuid: [u8; 16]) -> Self {
        Self { uuid, pad: [0; 6] }
    }
}

/// PnP Vendor descriptor (type 0x03).
///
/// | Offset | Field                  |
/// |--------|------------------------|
/// | 0-2    | PnP Vendor Identifier  |
/// | 3-6    | PnP Product Identifier |
/// | 7-21   | PAD (zeros)            |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct PnpVendorDescriptor {
    pub vendor_identifier: [u8; 3],
    pub product_identifier: [u8; 4],
    pad: [u8; 15],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<PnpVendorDescriptor>());

impl PnpVendorDescriptor {
    pub fn new(vendor_identifier: [u8; 3], product_identifier: [u8; 4]) -> Self {
        Self {
            vendor_identifier,
            product_identifier,
            pad: [0; 15],
        }
    }
}

/// ACPI Vendor descriptor (type 0x04).
///
/// | Offset | Field                     |
/// |--------|---------------------------|
/// | 0-3    | ACPI Vendor Identifier    |
/// | 4-6    | Vendor Product Identifier |
/// | 7-21   | PAD (zeros)               |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct AcpiVendorDescriptor {
    pub vendor_identifier: [u8; 4],
    pub product_identifier: [u8; 3],
    pad: [u8; 15],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<AcpiVendorDescriptor>());

impl AcpiVendorDescriptor {
    pub fn new(vendor_identifier: [u8; 4], product_identifier: [u8; 3]) -> Self {
        Self {
            vendor_identifier,
            product_identifier,
            pad: [0; 15],
        }
    }
}

/// NVMe-MI descriptor (type 0xFF).
///
/// | Offset | Field                |
/// |--------|----------------------|
/// | 0-1    | Vendor ID (LE)       |
/// | 2-21   | Device Serial Number |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct NvmeMiDescriptor {
    pub vendor_id: u16,
    pub serial_number: [u8; 20],
}

// Assure the spec size matches the size of the structure.
const _: () = assert!(DESCRIPTOR_DATA_LEN == size_of::<NvmeMiDescriptor>());

// ---------------------------------------------------------------------------
// DeviceDescriptor enum
// ---------------------------------------------------------------------------

/// Descriptor data for bytes 2-23, typed by descriptor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
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
    pub fn to_descriptor_bytes(&self, buf: &mut [u8]) -> Result<(), OcpError> {
        match self {
            Self::PciVendor(d) => d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall),
            Self::Iana(d) | Self::IanaEnterprise(d) => {
                d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall)
            }
            Self::Uuid(d) => d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall),
            Self::PnpVendor(d) => d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall),
            Self::AcpiVendor(d) => d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall),
            Self::NvmeMi(d) => d.write_to_prefix(buf).map_err(|_| OcpError::BufferTooSmall),
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

/// A Zerobytes compatible representation of the non-variable layout of bytes within the
/// DeviceId memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Immutable, IntoBytes)]
#[repr(C, packed)]
pub struct DeviceIdInner {
    pub descriptor: DescriptorType,
    pub vendor_string_len: u8,
    pub descriptor_id: [u8; DESCRIPTOR_DATA_LEN],
}

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
    pub inner: DeviceIdInner,
    vendor_string: &'a [u8],
}

impl<'a> DeviceId<'a> {
    /// Create a new DEVICE_ID response.
    ///
    /// Returns an error if `vendor_string` exceeds 231 bytes.
    pub fn new(descriptor: DeviceDescriptor, vendor_string: &'a [u8]) -> Result<Self, OcpError> {
        // SAFETY: MAX_VENDOR_STRING_LEN is less than max u8, so if they length is less than that,
        // it will not overflow a u8.
        let vendor_length = if vendor_string.len() <= MAX_VENDOR_STRING_LEN {
            vendor_string.len() as u8
        } else {
            return Err(OcpError::DeviceIdVendorStringTooLong);
        };

        let mut descriptor_id = [0; DESCRIPTOR_DATA_LEN];
        let descriptor_type = descriptor.descriptor_type();
        descriptor.to_descriptor_bytes(&mut descriptor_id)?;

        Ok(Self {
            inner: DeviceIdInner {
                descriptor: descriptor_type,
                vendor_string_len: vendor_length,
                descriptor_id,
            },
            vendor_string,
        })
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
    pub fn to_message(self, buf: &mut [u8]) -> Result<usize, OcpError> {
        let len = self.message_len();
        if buf.len() < len {
            return Err(OcpError::BufferTooSmall);
        }

        self.inner
            .write_to_prefix(buf)
            .map_err(|_| OcpError::BufferTooSmall)?;
        buf[MIN_MESSAGE_LEN..len].copy_from_slice(self.vendor_string);

        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PciVendorDescriptor ---

    #[test]
    fn pci_vendor_serializes() {
        let d = PciVendorDescriptor::new(0x8086, 0x1234, 0xABCD, 0x5678, 0x01);
        let bytes = d.as_bytes();

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
        let d = IanaDescriptor::new(0x0000_1234, *b"HELLO_WORLD!");
        let bytes = d.as_bytes();

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
        let d = UuidDescriptor::new(uuid);
        let bytes = d.as_bytes();

        assert_eq!(&bytes[0..16], &uuid);
        assert_eq!(&bytes[16..], &[0u8; 6]);
    }

    // --- PnpVendorDescriptor ---

    #[test]
    fn pnp_vendor_serializes() {
        let d = PnpVendorDescriptor::new([0xAA, 0xBB, 0xCC], [0x01, 0x02, 0x03, 0x04]);
        let bytes = d.as_bytes();

        assert_eq!(&bytes[0..3], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(&bytes[3..7], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&bytes[7..], &[0u8; 15]);
    }

    // --- AcpiVendorDescriptor ---

    #[test]
    fn acpi_vendor_serializes() {
        let d = AcpiVendorDescriptor::new([0x41, 0x42, 0x43, 0x44], [0x01, 0x02, 0x03]);
        let bytes = d.as_bytes();

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
        let bytes = d.as_bytes();

        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0x1D1D);
        assert_eq!(bytes[2], 0xDE);
        assert_eq!(bytes[21], 0xAD);
        assert_eq!(&bytes[2..22], &sn);
    }

    // --- DeviceDescriptor type bytes ---

    #[test]
    fn descriptor_type_bytes() {
        let pci = DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0, 0, 0, 0, 0));
        assert_eq!(pci.descriptor_type() as u8, 0x00);
        assert_eq!(pci.descriptor_type(), DescriptorType::PciVendor);

        let iana = DeviceDescriptor::Iana(IanaDescriptor::new(0, [0; 12]));
        assert_eq!(iana.descriptor_type() as u8, 0x01);

        let iana_ent = DeviceDescriptor::IanaEnterprise(IanaDescriptor::new(0, [0; 12]));
        assert_eq!(iana_ent.descriptor_type() as u8, 0x05);

        let uuid = DeviceDescriptor::Uuid(UuidDescriptor::new([0; 16]));
        assert_eq!(uuid.descriptor_type() as u8, 0x02);

        let pnp = DeviceDescriptor::PnpVendor(PnpVendorDescriptor::new([0; 3], [0; 4]));
        assert_eq!(pnp.descriptor_type() as u8, 0x03);

        let acpi = DeviceDescriptor::AcpiVendor(AcpiVendorDescriptor::new([0; 4], [0; 3]));
        assert_eq!(acpi.descriptor_type() as u8, 0x04);

        let nvme = DeviceDescriptor::NvmeMi(NvmeMiDescriptor {
            vendor_id: 0,
            serial_number: [0; 20],
        });
        assert_eq!(nvme.descriptor_type() as u8, 0xFF);
    }

    // --- IANA and IanaEnterprise share serialization ---

    #[test]
    fn iana_and_iana_enterprise_same_serialization() {
        let d = IanaDescriptor::new(0xDEAD_BEEF, *b"PRODUCT_ID__");
        let as_iana = DeviceDescriptor::Iana(d);
        let as_enterprise = DeviceDescriptor::IanaEnterprise(d);

        let mut buf_iana = [0u8; DESCRIPTOR_DATA_LEN];
        let mut buf_ent = [0u8; DESCRIPTOR_DATA_LEN];
        as_iana.to_descriptor_bytes(&mut buf_iana).unwrap();
        as_enterprise.to_descriptor_bytes(&mut buf_ent).unwrap();
        assert_eq!(buf_iana, buf_ent);
        assert_eq!(as_iana.descriptor_type() as u8, 0x01);
        assert_eq!(as_enterprise.descriptor_type() as u8, 0x05);
    }

    // --- DeviceId vendor string validation ---

    #[test]
    fn vendor_string_empty_accepted() {
        let desc = DeviceDescriptor::Uuid(UuidDescriptor::new([0; 16]));
        let did = DeviceId::new(desc, &[]).unwrap();
        assert_eq!(did.vendor_string().len(), 0);
        assert_eq!(did.message_len(), MIN_MESSAGE_LEN);
    }

    #[test]
    fn vendor_string_max_accepted() {
        let data = [0x41; MAX_VENDOR_STRING_LEN];
        let desc = DeviceDescriptor::Uuid(UuidDescriptor::new([0; 16]));
        let did = DeviceId::new(desc, &data).unwrap();
        assert_eq!(did.vendor_string().len(), MAX_VENDOR_STRING_LEN);
        assert_eq!(did.message_len(), MAX_MESSAGE_LEN);
    }

    #[test]
    fn vendor_string_too_long_rejected() {
        let data = [0x00; MAX_VENDOR_STRING_LEN + 1];
        let desc = DeviceDescriptor::Uuid(UuidDescriptor::new([0; 16]));
        assert_eq!(
            DeviceId::new(desc, &data),
            Err(OcpError::DeviceIdVendorStringTooLong),
        );
    }

    // --- to_message ---

    #[test]
    fn to_message_no_vendor_string() {
        let desc =
            DeviceDescriptor::PciVendor(PciVendorDescriptor::new(0x8086, 0x1234, 0, 0, 0x0A));
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
        let desc = DeviceDescriptor::PnpVendor(PnpVendorDescriptor::new(
            [0xAA, 0xBB, 0xCC],
            [0x01, 0x02, 0x03, 0x04],
        ));
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
        let desc = DeviceDescriptor::Uuid(UuidDescriptor::new([0xFF; 16]));
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
        let desc =
            DeviceDescriptor::AcpiVendor(AcpiVendorDescriptor::new(*b"ACPI", [0x01, 0x02, 0x03]));
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
        let desc = DeviceDescriptor::Uuid(UuidDescriptor::new([0; 16]));
        let did = DeviceId::new(desc, &[]).unwrap();
        assert_eq!(
            did.to_message(&mut [0u8; MIN_MESSAGE_LEN - 1]),
            Err(OcpError::BufferTooSmall)
        );
    }
}
