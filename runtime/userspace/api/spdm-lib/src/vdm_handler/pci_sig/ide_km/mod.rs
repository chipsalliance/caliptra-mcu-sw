// Licensed under the Apache-2.0 license

extern crate alloc;

use crate::codec::{Codec, MessageBuf};
use crate::vdm_handler::pci_sig::ide_km::driver::IdeDriver;
use crate::vdm_handler::pci_sig::ide_km::protocol::IdeKmCommand;
use crate::vdm_handler::{
    VdmError, VdmHandler, VdmProtocolHandler, VdmProtocolMatcher, VdmRegistryMatcher, VdmResponder,
    VdmResult,
};
use alloc::boxed::Box;
use async_trait::async_trait;

pub(crate) mod command;
pub mod driver;
pub(crate) mod protocol;

const IDE_KM_PROTOCOL_ID: u8 = 0x00;

pub struct IdeKmResponder<'a> {
    ide_km_driver: &'a dyn IdeDriver,
}

impl<'a> IdeKmResponder<'a> {
    pub fn new(ide_km_driver: &'a dyn IdeDriver) -> Self {
        IdeKmResponder { ide_km_driver }
    }
}

impl<'a> VdmProtocolMatcher for IdeKmResponder<'a> {
    fn match_protocol(&self, protocol_id: u8) -> bool {
        protocol_id == IDE_KM_PROTOCOL_ID
    }
}

#[async_trait]
impl<'a> VdmResponder for IdeKmResponder<'a> {
    async fn response_size(&self, req_buf: &mut MessageBuf<'_>) -> VdmResult<usize> {
        unimplemented!()
    }

    async fn handle_request(
        &self,
        req_buf: &mut MessageBuf<'_>,
        offset: usize,
        rsp_buf: &mut MessageBuf<'_>,
    ) -> VdmResult<()> {
        let object_id = u8::decode(req_buf).map_err(VdmError::Codec)?;

        let ide_km_cmd = IdeKmCommand::try_from(object_id)?;

        match ide_km_cmd {
            IdeKmCommand::Query => {
                command::handle_query(req_buf, rsp_buf, self.ide_km_driver).await
            }
            // IdeKmCommand::QueryResp => Err(VdmError::InvalidVdmCommand),
            // IdeKmCommand::KeyProg => {
            //     command::handle_key_prog(req_buf, rsp_buf, self.ide_km_driver).await
            // }
            // IdeKmCommand::KeyProgAck => Err(VdmError::InvalidVdmCommand),
            // IdeKmCommand::KeySetGo => {
            //     command::handle_key_set_go(req_buf, rsp_buf, self.ide_km_driver).await
            // }
            // IdeKmCommand::KeySetStop => {
            //     command::handle_key_set_stop(req_buf, offset, rsp_buf, self.ide_km_driver).await
            // }
            _ => Err(VdmError::InvalidVdmCommand),
        }
    }
}
