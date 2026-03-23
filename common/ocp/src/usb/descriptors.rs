// Licensed under the Apache-2.0 license

//! USB descriptor structures for OCP Recovery device enumeration.
//!
//! Defines the minimal set of USB 2.0 descriptors required to enumerate
//! a composite device exposing the OCP Secure Firmware Recovery interface
//! on EP0 (OCP spec Section 8.5).
//!
//! All structures are `#[repr(C, packed)]` with zerocopy `IntoBytes` for
//! serialization into packet buffers. Field ordering and sizes match the
//! USB 2.0 specification tables exactly.

use core::num::NonZeroU8;

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::error::OcpError;

/// USB Descriptor Type codes (USB 2.0 Table 9-5, plus CS_INTERFACE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(u8)]
pub enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    Endpoint = 5,
    DeviceQualifier = 6,
    /// Class-specific interface descriptor (used by OCP Functional Descriptor).
    CsInterface = 0x24,
}

impl TryFrom<u8> for DescriptorType {
    type Error = OcpError;

    fn try_from(val: u8) -> Result<Self, OcpError> {
        match val {
            1 => Ok(Self::Device),
            2 => Ok(Self::Configuration),
            3 => Ok(Self::String),
            4 => Ok(Self::Interface),
            5 => Ok(Self::Endpoint),
            6 => Ok(Self::DeviceQualifier),
            0x24 => Ok(Self::CsInterface),
            _ => Err(OcpError::InvalidDescriptorType),
        }
    }
}

/// USB Device Descriptor (18 bytes, USB 2.0 Table 9-8).
///
/// For OCP Recovery, the spec (Section 8.5.4) requires:
///   - `b_device_class = 0`, `b_device_sub_class = 0`, `b_device_protocol = 0`
///     (composite device; classes defined per-interface).
///   - `b_max_packet_size0 = 64` (OpenTitan hardware constraint).
pub const DEVICE_DESCRIPTOR_LEN: usize = 18;

const _: () = assert!(DEVICE_DESCRIPTOR_LEN == size_of::<DeviceDescriptor>());

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct DeviceDescriptor {
    /// Size of this descriptor in bytes (18).
    pub b_length: u8,
    /// Descriptor type (DEVICE).
    pub b_descriptor_type: DescriptorType,
    /// USB specification release number in BCD (e.g. 0x0200 for USB 2.0).
    pub bcd_usb: u16,
    /// Device class code. 0 for composite devices.
    pub b_device_class: u8,
    /// Device subclass code.
    pub b_device_sub_class: u8,
    /// Device protocol code.
    pub b_device_protocol: u8,
    /// Maximum packet size for EP0 (8, 16, 32, or 64).
    pub b_max_packet_size0: u8,
    /// Vendor ID (USB-IF assigned).
    pub id_vendor: u16,
    /// Product ID (manufacturer assigned).
    pub id_product: u16,
    /// Device release number in BCD.
    pub bcd_device: u16,
    /// Index of manufacturer string descriptor, or 0.
    pub i_manufacturer: u8,
    /// Index of product string descriptor, or 0.
    pub i_product: u8,
    /// Index of serial number string descriptor, or 0.
    pub i_serial_number: u8,
    /// Number of possible configurations.
    pub b_num_configurations: u8,
}

impl DeviceDescriptor {
    /// Construct a Device Descriptor with OCP Recovery defaults.
    ///
    /// Fixed by the OCP spec and OpenTitan hardware:
    ///   class/subclass/protocol = 0 (composite),
    ///   bMaxPacketSize0 = 64, bNumConfigurations = 1.
    pub const fn ocp(
        bcd_usb: u16,
        id_vendor: u16,
        id_product: u16,
        bcd_device: u16,
        i_manufacturer: u8,
        i_product: u8,
        i_serial_number: u8,
    ) -> Self {
        Self {
            b_length: DEVICE_DESCRIPTOR_LEN as u8,
            b_descriptor_type: DescriptorType::Device,
            bcd_usb: bcd_usb.to_le(),
            b_device_class: 0x00,
            b_device_sub_class: 0x00,
            b_device_protocol: 0x00,
            b_max_packet_size0: 64,
            id_vendor: id_vendor.to_le(),
            id_product: id_product.to_le(),
            bcd_device: bcd_device.to_le(),
            i_manufacturer,
            i_product,
            i_serial_number,
            b_num_configurations: 1,
        }
    }
}

bitfield! {
    /// USB Configuration Descriptor `bmAttributes` byte (USB 2.0 Table 9-10).
    ///
    /// - Bit 7: Reserved (must be set to 1)
    /// - Bit 6: Self-powered
    /// - Bit 5: Remote Wakeup
    /// - Bits 4:0: Reserved (reset to 0)
    #[derive(Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct BmAttributes(u8);
    impl Debug;

    /// Bit 7 — Reserved, must be set to 1.
    u8, reserved_one, set_reserved_one: 7, 7;
    /// Bit 6 — Self-powered.
    pub u8, self_powered, set_self_powered: 6, 6;
    /// Bit 5 — Remote Wakeup.
    pub u8, remote_wakeup, set_remote_wakeup: 5, 5;
}

impl BmAttributes {
    /// Create a new `BmAttributes` with the given flags. Bit 7 is always set to 1.
    pub fn new(self_powered: bool, remote_wakeup: bool) -> Self {
        let mut val = BmAttributes(0);
        val.set_reserved_one(1);
        val.set_self_powered(self_powered as u8);
        val.set_remote_wakeup(remote_wakeup as u8);
        val
    }
}

/// Maximum power consumption expressed in 2 mA units (USB 2.0 Table 9-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(transparent)]
pub struct MaxPower2mA(pub u8);

/// USB Configuration Descriptor (9 bytes, USB 2.0 Table 9-10).
///
/// This is the header only. The host retrieves the full configuration blob
/// (config + interface + class-specific descriptors) as a single contiguous
/// transfer whose length is `w_total_length`.
pub const CONFIGURATION_DESCRIPTOR_LEN: usize = 9;

const _: () = assert!(CONFIGURATION_DESCRIPTOR_LEN == size_of::<ConfigurationDescriptor>());

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ConfigurationDescriptor {
    /// Size of this descriptor in bytes (9).
    pub b_length: u8,
    /// Descriptor type (CONFIGURATION).
    pub b_descriptor_type: DescriptorType,
    /// Total length of all descriptors in this configuration.
    pub w_total_length: u16,
    /// Number of interfaces in this configuration.
    pub b_num_interfaces: u8,
    /// Value used by SET_CONFIGURATION to select this configuration. Must be nonzero.
    pub b_configuration_value: NonZeroU8,
    /// Index of string descriptor for this configuration, or 0.
    pub i_configuration: u8,
    /// Configuration attributes. Bit 7 must be 1; bit 6 = self-powered; bit 5 = remote wakeup.
    pub bm_attributes: BmAttributes,
    /// Maximum power consumption in 2 mA units.
    pub b_max_power: MaxPower2mA,
}

impl ConfigurationDescriptor {
    /// Construct a Configuration Descriptor with OCP Recovery defaults.
    ///
    /// Fixed: bConfigurationValue = 1, iConfiguration = 0.
    pub const fn ocp(
        w_total_length: u16,
        b_num_interfaces: u8,
        bm_attributes: BmAttributes,
        b_max_power: MaxPower2mA,
    ) -> Self {
        Self {
            b_length: CONFIGURATION_DESCRIPTOR_LEN as u8,
            b_descriptor_type: DescriptorType::Configuration,
            w_total_length: w_total_length.to_le(),
            b_num_interfaces,
            // SAFETY: By construction this is non-zero and thus always returns a value.
            b_configuration_value: NonZeroU8::new(1).unwrap(),
            i_configuration: 0,
            bm_attributes,
            b_max_power,
        }
    }
}

/// USB Interface Descriptor (9 bytes, USB 2.0 Table 9-12).
///
/// For OCP Recovery (Section 8.5.2):
///   - `b_interface_class = 0xEF` (Miscellaneous)
///   - `b_interface_sub_class = 0x08` (OCP Secure Firmware Recovery)
///   - `b_interface_protocol = 0x01` (OCP Recovery USB transport v1.x)
///   - `b_num_endpoints = 0` (only EP0 control pipe)
pub const INTERFACE_DESCRIPTOR_LEN: usize = 9;

const _: () = assert!(INTERFACE_DESCRIPTOR_LEN == size_of::<InterfaceDescriptor>());

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct InterfaceDescriptor {
    /// Size of this descriptor in bytes (9).
    pub b_length: u8,
    /// Descriptor type (INTERFACE).
    pub b_descriptor_type: DescriptorType,
    /// Zero-based interface number.
    pub b_interface_number: u8,
    /// Alternate setting (must be 0 for OCP Recovery).
    pub b_alternate_setting: u8,
    /// Number of endpoints excluding EP0.
    pub b_num_endpoints: u8,
    /// Interface class code.
    pub b_interface_class: u8,
    /// Interface subclass code.
    pub b_interface_sub_class: u8,
    /// Interface protocol code.
    pub b_interface_protocol: u8,
    /// Index of string descriptor for this interface, or 0.
    pub i_interface: u8,
}

impl InterfaceDescriptor {
    /// Construct an Interface Descriptor with OCP Recovery defaults.
    ///
    /// Fixed by OCP spec Section 8.5.2:
    ///   bAlternateSetting = 0, bNumEndpoints = 0,
    ///   class/subclass/protocol = 0xEF/0x08/0x01.
    pub const fn ocp(b_interface_number: u8, i_interface: u8) -> Self {
        Self {
            b_length: INTERFACE_DESCRIPTOR_LEN as u8,
            b_descriptor_type: DescriptorType::Interface,
            b_interface_number,
            b_alternate_setting: 0,
            b_num_endpoints: 0,
            b_interface_class: OCP_INTERFACE_CLASS,
            b_interface_sub_class: OCP_INTERFACE_SUBCLASS,
            b_interface_protocol: OCP_INTERFACE_PROTOCOL,
            i_interface,
        }
    }
}

/// OCP Recovery Functional Descriptor (10 bytes, OCP spec Section 8.5.3).
///
/// A class-specific interface descriptor (`bDescriptorType = 0x24`)
/// that declares the OCP Recovery transfer size limits and protocol version.
pub const OCP_FUNCTIONAL_DESCRIPTOR_LEN: usize = 10;

const _: () = assert!(OCP_FUNCTIONAL_DESCRIPTOR_LEN == size_of::<OcpFunctionalDescriptor>());

/// OCP Recovery interface class identifiers (USB-IF assigned).
pub const OCP_INTERFACE_CLASS: u8 = 0xEF;
pub const OCP_INTERFACE_SUBCLASS: u8 = 0x08;
pub const OCP_INTERFACE_PROTOCOL: u8 = 0x01;

/// `bDescriptorSubtype` value for the OCP Recovery functional descriptor.
pub const OCP_RECOVERY_FUNCTIONAL_SUBTYPE: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct OcpFunctionalDescriptor {
    /// Size of this descriptor in bytes (10).
    pub b_length: u8,
    /// Descriptor type (CS_INTERFACE).
    pub b_descriptor_type: DescriptorType,
    /// Descriptor subtype (0x01 = OCP Recovery Functional).
    pub b_descriptor_subtype: u8,
    /// Reserved, must be 0.
    pub b_reserved: u8,
    /// Maximum write (Host-to-Device) transfer size in bytes. Must be >= 64.
    pub w_max_wr_transfer_size: u16,
    /// Maximum read (Device-to-Host) transfer size in bytes. Must be >= 64.
    pub w_max_rd_transfer_size: u16,
    /// OCP Secure Firmware Recovery specification version in BCD (e.g. 0x0101 for v1.1).
    pub bcd_ocp_rec_version: u16,
}

impl OcpFunctionalDescriptor {
    /// Construct an OCP Recovery Functional Descriptor.
    ///
    /// Fixed: bDescriptorType = CS_INTERFACE (0x24),
    ///   bDescriptorSubtype = 0x01, bReserved = 0,
    ///   bcdOCPRecVersion = 0x0101 (v1.1).
    pub const fn ocp(w_max_wr_transfer_size: u16, w_max_rd_transfer_size: u16) -> Self {
        Self {
            b_length: OCP_FUNCTIONAL_DESCRIPTOR_LEN as u8,
            b_descriptor_type: DescriptorType::CsInterface,
            b_descriptor_subtype: OCP_RECOVERY_FUNCTIONAL_SUBTYPE,
            b_reserved: 0,
            w_max_wr_transfer_size: w_max_wr_transfer_size.to_le(),
            w_max_rd_transfer_size: w_max_rd_transfer_size.to_le(),
            bcd_ocp_rec_version: 0x0101u16.to_le(),
        }
    }
}

/// USB String Descriptor Zero (4 bytes, USB 2.0 Section 9.6.7).
///
/// Reports supported languages. For OCP Recovery: English (US) only.
pub const STRING_DESCRIPTOR_ZERO_LEN: usize = 4;

const _: () = assert!(STRING_DESCRIPTOR_ZERO_LEN == size_of::<StringDescriptorZero>());

pub const LANG_ID_ENGLISH_US: u16 = 0x0409;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct StringDescriptorZero {
    pub b_length: u8,
    pub b_descriptor_type: DescriptorType,
    pub w_lang_id: u16,
}

impl StringDescriptorZero {
    pub const fn ocp() -> Self {
        Self {
            b_length: STRING_DESCRIPTOR_ZERO_LEN as u8,
            b_descriptor_type: DescriptorType::String,
            w_lang_id: LANG_ID_ENGLISH_US.to_le(),
        }
    }
}

/// OCP Recovery interface string descriptor (58 bytes, USB 2.0 Section 9.6.7).
///
/// Contains "OCP Secure Firmware Recovery" encoded as UTF-16LE, as required
/// by OCP spec Section 8.5.2 for the iInterface string.
const OCP_INTERFACE_STRING: &[u8; 28] = b"OCP Secure Firmware Recovery";
const OCP_INTERFACE_STRING_UTF16_LEN: usize = OCP_INTERFACE_STRING.len();
pub const OCP_INTERFACE_STRING_DESCRIPTOR_LEN: usize = 2 + OCP_INTERFACE_STRING_UTF16_LEN * 2;

const _: () =
    assert!(OCP_INTERFACE_STRING_DESCRIPTOR_LEN == size_of::<OcpInterfaceStringDescriptor>());

/// String descriptor index for the OCP Recovery interface string.
pub const OCP_INTERFACE_STRING_INDEX: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct OcpInterfaceStringDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: DescriptorType,
    pub b_string: [u8; OCP_INTERFACE_STRING_UTF16_LEN * 2],
}

impl OcpInterfaceStringDescriptor {
    pub const fn ocp() -> Self {
        let mut b_string = [0u8; OCP_INTERFACE_STRING_UTF16_LEN * 2];
        let mut i = 0;
        while i < OCP_INTERFACE_STRING.len() {
            b_string[i * 2] = OCP_INTERFACE_STRING[i];
            i += 1;
        }
        Self {
            b_length: OCP_INTERFACE_STRING_DESCRIPTOR_LEN as u8,
            b_descriptor_type: DescriptorType::String,
            b_string,
        }
    }
}

/// Complete set of OCP Recovery descriptors for enumeration.
///
/// Contains the configuration descriptor blob (returned to the host in
/// response to `GET_DESCRIPTOR(Configuration)`) plus the string descriptors
/// (returned separately via `GET_DESCRIPTOR(String, index)`).
///
/// `wTotalLength` in the configuration header covers only the config,
/// interface, and functional descriptors — not the string descriptors.
pub const CONFIGURATION_TREE_LEN: usize = CONFIGURATION_DESCRIPTOR_LEN
    + INTERFACE_DESCRIPTOR_LEN
    + OCP_FUNCTIONAL_DESCRIPTOR_LEN
    + STRING_DESCRIPTOR_ZERO_LEN
    + OCP_INTERFACE_STRING_DESCRIPTOR_LEN;

/// The USB `wTotalLength` value: config + interface + functional only.
const W_TOTAL_LENGTH: u16 = (CONFIGURATION_DESCRIPTOR_LEN
    + INTERFACE_DESCRIPTOR_LEN
    + OCP_FUNCTIONAL_DESCRIPTOR_LEN) as u16;

const _: () = assert!(CONFIGURATION_TREE_LEN == size_of::<ConfigurationTree>());

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
#[repr(C, packed)]
pub struct ConfigurationTree {
    pub configuration: ConfigurationDescriptor,
    pub interface: InterfaceDescriptor,
    pub ocp_functional: OcpFunctionalDescriptor,
    pub string_descriptor_zero: StringDescriptorZero,
    pub ocp_interface_string: OcpInterfaceStringDescriptor,
}

impl ConfigurationTree {
    /// Construct a complete OCP Recovery configuration descriptor tree.
    ///
    /// Fixed: wTotalLength = 28 (config + interface + functional),
    ///   bNumInterfaces = 1, iInterface = `OCP_INTERFACE_STRING_INDEX`,
    ///   bcdOCPRecVersion = 0x0101 (v1.1),
    ///   string descriptors for language table and interface name.
    ///
    /// If the interface number is not specified, it defaults to 0 as
    /// recommended by OCP spec Section 8.5.2.
    pub fn ocp(
        bm_attributes: BmAttributes,
        b_max_power: MaxPower2mA,
        b_interface_number: Option<u8>,
        w_max_wr_transfer_size: u16,
        w_max_rd_transfer_size: u16,
    ) -> Self {
        Self {
            configuration: ConfigurationDescriptor::ocp(
                W_TOTAL_LENGTH,
                1,
                bm_attributes,
                b_max_power,
            ),
            interface: InterfaceDescriptor::ocp(
                b_interface_number.unwrap_or_default(),
                OCP_INTERFACE_STRING_INDEX,
            ),
            ocp_functional: OcpFunctionalDescriptor::ocp(
                w_max_wr_transfer_size,
                w_max_rd_transfer_size,
            ),
            string_descriptor_zero: StringDescriptorZero::ocp(),
            ocp_interface_string: OcpInterfaceStringDescriptor::ocp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;

    #[test]
    fn serialize_device_descriptor() {
        let desc = DeviceDescriptor::ocp(0x0200, 0x1234, 0x5678, 0x0100, 1, 2, 0);

        let bytes = desc.as_bytes();
        assert_eq!(bytes.len(), DEVICE_DESCRIPTOR_LEN);
        assert_eq!(bytes[0], 18);
        assert_eq!(bytes[1], DescriptorType::Device as u8);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x0200);
        assert_eq!(bytes[4], 0x00); // bDeviceClass
        assert_eq!(bytes[7], 64); // bMaxPacketSize0
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 0x1234);
        assert_eq!(u16::from_le_bytes([bytes[10], bytes[11]]), 0x5678);
        assert_eq!(bytes[17], 1); // bNumConfigurations
    }

    #[test]
    fn serialize_configuration_tree() {
        let tree = ConfigurationTree::ocp(
            BmAttributes::new(true, false),
            MaxPower2mA(50),
            None,
            4096,
            4096,
        );
        let bytes = tree.as_bytes();
        assert_eq!(bytes.len(), CONFIGURATION_TREE_LEN);

        // -- Configuration Descriptor (bytes 0..9) --
        assert_eq!(bytes[0], 9); // bLength
        assert_eq!(bytes[1], DescriptorType::Configuration as u8);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 28); // wTotalLength (config blob only)
        assert_eq!(bytes[4], 1); // bNumInterfaces (fixed)
        assert_eq!(bytes[5], 1); // bConfigurationValue (fixed)
        assert_eq!(bytes[6], 0); // iConfiguration (fixed)
        assert_eq!(bytes[7], 0xC0); // bmAttributes
        assert_eq!(bytes[8], 50); // bMaxPower

        // -- Interface Descriptor (bytes 9..18) --
        assert_eq!(bytes[9], 9); // bLength
        assert_eq!(bytes[10], DescriptorType::Interface as u8);
        assert_eq!(bytes[11], 0); // bInterfaceNumber (default)
        assert_eq!(bytes[12], 0); // bAlternateSetting (fixed)
        assert_eq!(bytes[13], 0); // bNumEndpoints (fixed)
        assert_eq!(bytes[14], OCP_INTERFACE_CLASS);
        assert_eq!(bytes[15], OCP_INTERFACE_SUBCLASS);
        assert_eq!(bytes[16], OCP_INTERFACE_PROTOCOL);
        assert_eq!(bytes[17], OCP_INTERFACE_STRING_INDEX); // iInterface -> OCP string

        // -- OCP Functional Descriptor (bytes 18..28) --
        assert_eq!(bytes[18], 10); // bLength
        assert_eq!(bytes[19], DescriptorType::CsInterface as u8);
        assert_eq!(bytes[20], OCP_RECOVERY_FUNCTIONAL_SUBTYPE);
        assert_eq!(bytes[21], 0x00); // bReserved (fixed)
        assert_eq!(u16::from_le_bytes([bytes[22], bytes[23]]), 4096);
        assert_eq!(u16::from_le_bytes([bytes[24], bytes[25]]), 4096);
        assert_eq!(u16::from_le_bytes([bytes[26], bytes[27]]), 0x0101);

        // -- String Descriptor Zero (bytes 28..32) --
        assert_eq!(bytes[28], 4); // bLength
        assert_eq!(bytes[29], DescriptorType::String as u8);
        assert_eq!(u16::from_le_bytes([bytes[30], bytes[31]]), 0x0409);

        // -- OCP Interface String Descriptor (bytes 32..90) --
        assert_eq!(bytes[32], 58); // bLength = 2 + 28*2
        assert_eq!(bytes[33], DescriptorType::String as u8);
        let expected = "OCP Secure Firmware Recovery";
        for (i, ch) in expected.bytes().enumerate() {
            assert_eq!(bytes[34 + i * 2], ch);
            assert_eq!(bytes[34 + i * 2 + 1], 0x00);
        }
    }

    #[test]
    fn descriptor_type_try_from() {
        assert_eq!(DescriptorType::try_from(1), Ok(DescriptorType::Device));
        assert_eq!(
            DescriptorType::try_from(2),
            Ok(DescriptorType::Configuration)
        );
        assert_eq!(DescriptorType::try_from(3), Ok(DescriptorType::String));
        assert_eq!(DescriptorType::try_from(4), Ok(DescriptorType::Interface));
        assert_eq!(
            DescriptorType::try_from(0x24),
            Ok(DescriptorType::CsInterface)
        );
        assert_eq!(
            DescriptorType::try_from(0xFF),
            Err(OcpError::InvalidDescriptorType)
        );
    }
}
