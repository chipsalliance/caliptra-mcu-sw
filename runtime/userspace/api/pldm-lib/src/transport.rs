// Licensed under the Apache-2.0 license

use crate::errors;
use caliptra_mcu_libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use caliptra_mcu_pldm_common::util::mctp_transport::{
    MctpCommonHeader, MCTP_COMMON_HEADER_OFFSET, MCTP_PLDM_MSG_TYPE,
};
use core::sync::atomic::{AtomicU8, Ordering};
use mcu_error::McuResult;

static DISCOVERED_UA_EID: AtomicU8 = AtomicU8::new(0);

pub enum PldmTransportType {
    Mctp,
}

pub struct MctpTransport {
    mctp: Mctp,
    cur_resp_ctx: Option<MessageInfo>,
    cur_req_ctx: Option<MessageInfo>,
}

impl MctpTransport {
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::new(drv_num),
            cur_resp_ctx: None,
            cur_req_ctx: None,
        }
    }

    pub fn ua_eid(&self) -> u8 {
        match DISCOVERED_UA_EID.load(Ordering::Relaxed) {
            0 => crate::config::UA_EID,
            eid => eid,
        }
    }

    pub fn bind_ua_eid(&self, eid: u8) {
        if eid != 0 {
            DISCOVERED_UA_EID.store(eid, Ordering::Relaxed);
        }
    }

    pub async fn send_request(&mut self, dest_eid: u8, req: &[u8]) -> McuResult<()> {
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(errors::UNEXPECTED_MESSAGE_TYPE)?;
        }

        let tag = self
            .mctp
            .send_request(dest_eid, req)
            .await
            .map_err(|_| errors::SEND_ERROR)?;

        self.cur_req_ctx = Some(MessageInfo { eid: dest_eid, tag });

        Ok(())
    }

    pub async fn receive_response(&mut self, rsp: &mut [u8]) -> McuResult<()> {
        // Reset msg buffer
        rsp.fill(0);
        let (rsp_len, _msg_info) = if let Some(msg_info) = &self.cur_req_ctx {
            self.mctp
                .receive_response(rsp, msg_info.tag, msg_info.eid)
                .await
                .map_err(|_| errors::RECEIVE_ERROR)
        } else {
            Err(errors::RESPONSE_NOT_EXPECTED)
        }?;

        if rsp_len == 0 {
            Err(errors::BUFFER_TOO_SMALL)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(rsp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(errors::UNEXPECTED_MESSAGE_TYPE)?;
        }

        self.cur_req_ctx = None;
        Ok(())
    }

    pub async fn receive_request(&mut self, req: &mut [u8]) -> McuResult<u8> {
        // Reset msg buffer
        req.fill(0);
        let (req_len, msg_info) = self
            .mctp
            .receive_request(req)
            .await
            .map_err(|_| errors::RECEIVE_ERROR)?;

        if req_len == 0 {
            Err(errors::BUFFER_TOO_SMALL)?;
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(errors::UNEXPECTED_MESSAGE_TYPE)?;
        }

        let requester_eid = msg_info.eid;
        self.cur_resp_ctx = Some(msg_info);

        Ok(requester_eid)
    }

    pub async fn send_response(&mut self, resp: &[u8]) -> McuResult<()> {
        let mctp_hdr = MctpCommonHeader(resp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_PLDM_MSG_TYPE {
            Err(errors::UNEXPECTED_MESSAGE_TYPE)?;
        }

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(resp, msg_info)
                .await
                .map_err(|_| errors::SEND_ERROR)?
        } else {
            Err(errors::NO_REQUEST_IN_FLIGHT)?;
        }

        self.cur_resp_ctx = None;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_eid_is_shared_across_transport_instances() {
        DISCOVERED_UA_EID.store(0, Ordering::Relaxed);
        let responder = MctpTransport::new(1);
        let initiator = MctpTransport::new(1);

        assert_eq!(initiator.ua_eid(), crate::config::UA_EID);

        responder.bind_ua_eid(11);
        assert_eq!(responder.ua_eid(), 11);
        assert_eq!(initiator.ua_eid(), 11);

        DISCOVERED_UA_EID.store(0, Ordering::Relaxed);
    }
}
