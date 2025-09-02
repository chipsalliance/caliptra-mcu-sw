// Licensed under the Apache-2.0 license

// DOE Transport Implementation

extern crate alloc;
use crate::codec::{Codec, CommonCodec, DataKind, MessageBuf};
use crate::transport::common::{SpdmTransport, TransportError, TransportResult};
use alloc::boxed::Box;
use async_trait::async_trait;
use bitfield::bitfield;
use libsyscall_caliptra::doe::{driver_num, Doe};
use zerocopy::{FromBytes, Immutable, IntoBytes};

const DOE_HEADER_SIZE: usize = 8;
const DOE_PCI_SIG_VENDOR_ID: u16 = 0x0001; // PCI-SIG Vendor ID
#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum DataObjectType {
    DoeSpdm = 1,
    DoeSecureSpdm = 2,
}

impl TryFrom<u8> for DataObjectType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DataObjectType::DoeSpdm),
            2 => Ok(DataObjectType::DoeSecureSpdm),
            _ => Err(()),
        }
    }
}

bitfield! {
    #[repr(C)]
    #[derive(Clone, FromBytes, IntoBytes, Immutable)]
    pub struct DoeHeader([u8]);
    impl Debug;
    pub u16, vendor_id, set_vendor_id: 15, 0;
    pub u8, data_object_type, set_data_object_type: 23, 16;
    u8, reserved_1, _: 31, 24;
    u32, length, set_length: 49, 32;
    u16, reserved2, _ : 63, 50;
}

impl DoeHeader<[u8; DOE_HEADER_SIZE]> {
    pub fn new(data_object_type: DataObjectType, length: u32) -> Self {
        let len_dw = length >> 2;
        let mut header = DoeHeader([0u8; DOE_HEADER_SIZE]);
        header.set_vendor_id(DOE_PCI_SIG_VENDOR_ID);
        header.set_data_object_type(data_object_type as u8);
        header.set_length(len_dw);
        header
    }
}

impl CommonCodec for DoeHeader<[u8; DOE_HEADER_SIZE]> {
    const DATA_KIND: DataKind = DataKind::Header;
}

pub struct DoeTransport {
    doe: Doe,
}

impl DoeTransport {
    pub fn new(driver_num: u32) -> Self {
        DoeTransport {
            doe: Doe::new(driver_num),
        }
    }
}

impl Default for DoeTransport {
    fn default() -> Self {
        Self::new(driver_num::DOE_SPDM)
    }
}

#[async_trait]
impl SpdmTransport for DoeTransport {
    async fn send_request<'a>(
        &mut self,
        _dest_eid: u8,
        _req: &mut MessageBuf<'a>,
        _secure: Option<bool>,
    ) -> TransportResult<()> {
        // As a responder, we never send requests over DOE.
        Err(TransportError::OperationNotSupported)
    }
    async fn receive_response<'a>(&mut self, _rsp: &mut MessageBuf<'a>) -> TransportResult<bool> {
        // Not applicable for DOE as a responder.
        Err(TransportError::OperationNotSupported)
    }

    async fn receive_request<'a>(&mut self, req: &mut MessageBuf<'a>) -> TransportResult<bool> {
        req.reset();
        let max_len = req.capacity();
        req.put_data(max_len).map_err(TransportError::Codec)?;

        let data_buf = req.data_mut(max_len).map_err(TransportError::Codec)?;

        let msg_len = self
            .doe
            .receive_message(data_buf)
            .await
            .map_err(TransportError::DriverError)?;

        if msg_len < DOE_HEADER_SIZE as u32 {
            Err(TransportError::InvalidMessage)?;
        }

        req.trim(msg_len as usize).map_err(TransportError::Codec)?;

        let header = DoeHeader::decode(req).map_err(TransportError::Codec)?;

        if header.vendor_id() != DOE_PCI_SIG_VENDOR_ID {
            Err(TransportError::InvalidMessage)?;
        }

        let data_object_type: DataObjectType = header
            .data_object_type()
            .try_into()
            .map_err(|_| TransportError::UnsupportedMessageType)?;
        match data_object_type {
            DataObjectType::DoeSpdm => Ok(false),
            DataObjectType::DoeSecureSpdm => Ok(true),
        }
    }

    async fn send_response<'a>(
        &mut self,
        resp: &mut MessageBuf<'a>,
        secure: bool,
    ) -> TransportResult<()> {
        let data_object_type = if secure {
            DataObjectType::DoeSecureSpdm
        } else {
            DataObjectType::DoeSpdm
        };

        let msg_len = resp.msg_len();
        // Calculate padding size to align the message length to 4 bytes
        let pad_size = (4 - msg_len % 4) % 4;
        let total_len = msg_len + pad_size;
        // Expand the buffer to accommodate the padding bytes
        resp.expand(pad_size).map_err(TransportError::Codec)?;

        let header = DoeHeader::new(data_object_type, total_len as u32);
        header.encode(resp).map_err(TransportError::Codec)?;

        let msg_len = resp.msg_len();
        let rsp_buf = resp.data(msg_len).map_err(TransportError::Codec)?;

        self.doe
            .send_message(rsp_buf)
            .await
            .map_err(TransportError::DriverError)?;

        Ok(())
    }

    fn max_message_size(&self) -> TransportResult<usize> {
        let max_size = self
            .doe
            .max_message_size()
            .map_err(TransportError::DriverError)?;
        Ok(max_size as usize - self.header_size())
    }

    fn header_size(&self) -> usize {
        DOE_HEADER_SIZE
    }
}
