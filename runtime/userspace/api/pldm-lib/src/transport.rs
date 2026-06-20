// Licensed under the Apache-2.0 license

use crate::errors;
use caliptra_mcu_libsyscall_caliptra::mctp::{Mctp, MessageInfo};
use caliptra_mcu_pldm_common::util::mctp_transport::{
    MctpCommonHeader, MCTP_COMMON_HEADER_OFFSET, MCTP_PLDM_MSG_TYPE,
};
use mcu_error::McuResult;

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

    pub async fn receive_request(&mut self, req: &mut [u8]) -> McuResult<()> {
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

        self.cur_resp_ctx = Some(msg_info);

        Ok(())
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
