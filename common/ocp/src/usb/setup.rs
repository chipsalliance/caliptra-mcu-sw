// Licensed under the Apache-2.0 license

//! OCP Recovery over USB EP0 SETUP packet structure.
//!
//! Spec reference: Section 8.5.1, "USB EP0 Command Encapsulation".
//! Each OCP Recovery command maps to exactly one EP0 control transfer.
//! The 8-byte SETUP packet carries the OCP command ID in `wValue[0]`
//! and the USB interface number in `wIndex[0]`.

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::error::OcpError;
use crate::protocol::RecoveryCommand;
use crate::usb::descriptors::DescriptorType;

/// Wire size of a USB SETUP packet in bytes (USB 2.0 Table 9-2).
pub const SETUP_PACKET_LEN: usize = 8;

const _: () = assert!(SETUP_PACKET_LEN == size_of::<SetupPacket>());

/// `bRequest` value for OCP Recovery transfers (spec Section 8.5.1).
pub const OCP_RECOVERY_REQUEST: u8 = 0x00;

/// `bmRequestType` direction bit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Host-to-Device (OUT / Write).
    HostToDevice = 0,
    /// Device-to-Host (IN / Read).
    DeviceToHost = 1,
}

/// `bmRequestType` type field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
    Reserved = 3,
}

/// `bmRequestType` recipient field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Recipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
}

/// USB Standard Device Request codes (USB 2.0 Table 9-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StandardRequest {
    GetStatus = 0,
    ClearFeature = 1,
    SetFeature = 3,
    SetAddress = 5,
    GetDescriptor = 6,
    SetDescriptor = 7,
    GetConfiguration = 8,
    SetConfiguration = 9,
    GetInterface = 10,
    SetInterface = 11,
    SynchFrame = 12,
}

impl TryFrom<u8> for StandardRequest {
    type Error = OcpError;

    fn try_from(val: u8) -> Result<Self, OcpError> {
        match val {
            0 => Ok(Self::GetStatus),
            1 => Ok(Self::ClearFeature),
            3 => Ok(Self::SetFeature),
            5 => Ok(Self::SetAddress),
            6 => Ok(Self::GetDescriptor),
            7 => Ok(Self::SetDescriptor),
            8 => Ok(Self::GetConfiguration),
            9 => Ok(Self::SetConfiguration),
            10 => Ok(Self::GetInterface),
            11 => Ok(Self::SetInterface),
            12 => Ok(Self::SynchFrame),
            _ => Err(OcpError::InvalidStandardRequest),
        }
    }
}

bitfield! {
    /// USB SETUP `bmRequestType` byte (USB 2.0 Table 9-2).
    ///
    /// For OCP Recovery over USB:
    ///   - Direction: 0 (H2D) for writes, 1 (D2H) for reads
    ///   - Type: 1 (Class)
    ///   - Recipient: 1 (Interface)
    ///
    /// Write = `0b0_01_00001` = `0x21`
    /// Read  = `0b1_01_00001` = `0xA1`
    #[derive(Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
    pub struct BmRequestType(u8);
    impl Debug;

    /// Bits 4:0 — Recipient (0=Device, 1=Interface, 2=Endpoint, 3=Other).
    pub u8, recipient_raw, set_recipient_raw: 4, 0;
    /// Bits 6:5 — Request type (0=Standard, 1=Class, 2=Vendor).
    pub u8, request_type_raw, set_request_type_raw: 6, 5;
    /// Bit 7 — Data transfer direction (0=Host-to-Device, 1=Device-to-Host).
    pub u8, direction_raw, set_direction_raw: 7, 7;
}

impl BmRequestType {
    pub fn direction(&self) -> Direction {
        match self.direction_raw() {
            0 => Direction::HostToDevice,
            _ => Direction::DeviceToHost,
        }
    }

    pub fn request_type(&self) -> RequestType {
        match self.request_type_raw() {
            0 => RequestType::Standard,
            1 => RequestType::Class,
            2 => RequestType::Vendor,
            _ => RequestType::Reserved,
        }
    }

    pub fn recipient(&self) -> Recipient {
        match self.recipient_raw() {
            0 => Recipient::Device,
            1 => Recipient::Interface,
            2 => Recipient::Endpoint,
            _ => Recipient::Other,
        }
    }
}

/// USB SETUP packet (8 bytes on the wire) as defined for OCP Recovery
/// over USB EP0 (spec Section 8.5.1).
///
/// Field mapping for OCP Recovery:
///   - `bm_request_type`: Class request to Interface
///   - `b_request`: `0x00` (OCP Recovery Transfer)
///   - `w_value`: `[command_id, 0x00]`
///   - `w_index`: `[interface_id, 0x00]`
///   - `w_length`: Data phase length in bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct SetupPacket {
    /// Byte 0: Characteristics of request.
    pub bm_request_type: BmRequestType,
    /// Byte 1: Specific request (`0x00` for OCP Recovery).
    pub b_request: u8,
    /// Bytes 2-3: `wValue` (little-endian). Low byte = OCP command ID.
    pub w_value: [u8; 2],
    /// Bytes 4-5: `wIndex` (little-endian). Low byte = USB Interface ID.
    pub w_index: [u8; 2],
    /// Bytes 6-7: `wLength` (little-endian). Number of bytes in the data phase.
    pub w_length: u16,
}

impl SetupPacket {
    /// Return the USB interface number from `wIndex[0]`.
    pub fn interface_id(&self) -> u8 {
        self.w_index[0]
    }

    /// Return the data phase length from `wLength`.
    pub fn data_length(&self) -> u16 {
        self.w_length
    }

    /// Return `true` if this is a Device-to-Host (IN / read) transfer.
    pub fn is_read(&self) -> bool {
        self.bm_request_type.direction() == Direction::DeviceToHost
    }

    /// Return `true` if this is a Host-to-Device (OUT / write) transfer.
    pub fn is_write(&self) -> bool {
        self.bm_request_type.direction() == Direction::HostToDevice
    }

    /// Returns the [`StandardRequest`] if this is a Standard request with a known `bRequest` code.
    pub fn standard_request(&self) -> Option<StandardRequest> {
        if self.bm_request_type.request_type() == RequestType::Standard {
            StandardRequest::try_from(self.b_request).ok()
        } else {
            None
        }
    }

    /// For GET_DESCRIPTOR requests, return the descriptor type from `wValue[1]`.
    pub fn descriptor_type(&self) -> Option<DescriptorType> {
        DescriptorType::try_from(self.w_value[1]).ok()
    }

    /// For GET_DESCRIPTOR requests, return the descriptor index from `wValue[0]`.
    pub fn descriptor_index(&self) -> u8 {
        self.w_value[0]
    }

    /// Returns the RecoveryCommand if this is an OCP Recovery Command, and it contains a valid
    /// OCP Recover command.
    pub fn ocp_recovery_command(&self) -> Option<RecoveryCommand> {
        if self.bm_request_type.request_type() == RequestType::Class
            && self.bm_request_type.recipient() == Recipient::Interface
            && self.b_request == OCP_RECOVERY_REQUEST
        {
            RecoveryCommand::try_from(self.w_value[0]).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromBytes;

    #[test]
    fn deserialize_ocp_read_setup() {
        // PROT_CAP read: bmRequestType=0xA1, bRequest=0x00,
        // wValue=0x0022 (cmd 0x22), wIndex=0x0000, wLength=15
        let raw: [u8; 8] = [0xA1, 0x00, 0x22, 0x00, 0x00, 0x00, 0x0F, 0x00];
        let pkt = SetupPacket::read_from_bytes(&raw).expect("valid 8-byte SETUP");

        assert_eq!(pkt.bm_request_type.direction(), Direction::DeviceToHost);
        assert_eq!(pkt.bm_request_type.request_type(), RequestType::Class);
        assert_eq!(pkt.bm_request_type.recipient(), Recipient::Interface);
        assert!(pkt.is_read());
        assert_eq!(pkt.ocp_recovery_command(), Some(RecoveryCommand::ProtCap));
        assert_eq!(pkt.interface_id(), 0);
        assert_eq!(pkt.data_length(), 15);
    }

    #[test]
    fn deserialize_get_configuration_setup() {
        // GET_CONFIGURATION: bmRequestType=0x80 (D2H, Standard, Device),
        // bRequest=0x08, wValue=0x0000, wIndex=0x0000, wLength=1
        let raw: [u8; 8] = [0x80, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let pkt = SetupPacket::read_from_bytes(&raw).expect("valid 8-byte SETUP");

        assert_eq!(pkt.bm_request_type.direction(), Direction::DeviceToHost);
        assert_eq!(pkt.bm_request_type.request_type(), RequestType::Standard);
        assert_eq!(pkt.bm_request_type.recipient(), Recipient::Device);
        assert!(pkt.is_read());
        assert_eq!(
            pkt.standard_request(),
            Some(StandardRequest::GetConfiguration)
        );
        assert_eq!(pkt.w_value, [0x00, 0x00]);
        assert_eq!(pkt.w_index, [0x00, 0x00]);
        assert_eq!(pkt.data_length(), 1);
        assert_eq!(pkt.ocp_recovery_command(), None);
    }
}
