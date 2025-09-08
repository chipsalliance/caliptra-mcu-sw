// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver;
use crate::vdm_handler::pci_sig::ide_km::protocol::{IdeKmCommand, IdeKmHdr};
use crate::vdm_handler::{VdmError, VdmProtocolMatcher, VdmResponder, VdmResult};
use alloc::boxed::Box;
use async_trait::async_trait;

pub(crate) mod commands;
pub mod driver;
pub mod protocol;

const IDE_KM_PROTOCOL_ID: u8 = 0x00;

pub struct IdeKmResponder<'a> {
    ide_km_driver: &'a dyn IdeDriver,
}

impl<'a> IdeKmResponder<'a> {
    pub fn new(ide_km_driver: &'a dyn IdeDriver) -> Self {
        IdeKmResponder { ide_km_driver }
    }
}

impl VdmProtocolMatcher for IdeKmResponder<'_> {
    fn match_protocol(&self, protocol_id: u8) -> bool {
        protocol_id == IDE_KM_PROTOCOL_ID
    }
}

#[async_trait]
impl VdmResponder for IdeKmResponder<'_> {
    async fn handle_request(
        &mut self,
        req_buf: &mut MessageBuf<'_>,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<usize> {
        let hdr = IdeKmHdr::decode(req_buf).map_err(VdmError::Codec)?;

        let ide_km_req = IdeKmCommand::try_from(hdr.object_id)?;

        if req_buf.data_len() != ide_km_req.payload_len() {
            Err(VdmError::InvalidRequestPayload)?;
        }

        match ide_km_req {
            IdeKmCommand::Query => {
                commands::handle_query(req_buf, rsp_buf, self.ide_km_driver).await
            }
            IdeKmCommand::KeyProg => {
                commands::handle_key_prog(req_buf, rsp_buf, self.ide_km_driver).await
            }
            IdeKmCommand::KeySetGo => {
                commands::handle_key_set_go_stop(true, req_buf, rsp_buf, self.ide_km_driver).await
            }
            IdeKmCommand::KeySetStop => {
                commands::handle_key_set_go_stop(false, req_buf, rsp_buf, self.ide_km_driver).await
            }
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }
}
