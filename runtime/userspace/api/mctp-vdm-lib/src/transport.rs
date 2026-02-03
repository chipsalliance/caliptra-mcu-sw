// Licensed under the Apache-2.0 license

use crate::error::VdmLibError;
use libsyscall_caliptra::mctp::{driver_num, Mctp, MessageInfo};
use mctp_vdm_common::util::mctp_transport::{
    MctpCommonHeader, MCTP_COMMON_HEADER_OFFSET, MCTP_VDM_MSG_TYPE,
};

/// Transport error types.
#[derive(Debug)]
pub enum TransportError {
    DriverError,
    BufferTooSmall,
    UnexpectedMessageType,
    ReceiveError,
    SendError,
    NoRequestInFlight,
}

impl From<TransportError> for VdmLibError {
    fn from(_: TransportError) -> Self {
        VdmLibError::TransportError
    }
}

/// MCTP transport for VDM messages.
pub struct MctpVdmTransport {
    mctp: Mctp,
    cur_resp_ctx: Option<MessageInfo>,
}

impl MctpVdmTransport {
    /// Create a new MCTP VDM transport with a specific driver number.
    pub fn new(drv_num: u32) -> Self {
        Self {
            mctp: Mctp::new(drv_num),
            cur_resp_ctx: None,
        }
    }

    /// Check if the MCTP driver exists.
    pub fn exists(&self) -> bool {
        self.mctp.exists()
    }

    /// Receive a VDM request.
    /// Returns the length of the received request.
    pub async fn receive_request(&mut self, req: &mut [u8]) -> Result<usize, TransportError> {
        // Reset msg buffer
        req.fill(0);
        let (req_len, msg_info) = self
            .mctp
            .receive_request(req)
            .await
            .map_err(|_| TransportError::ReceiveError)?;

        if req_len == 0 {
            return Err(TransportError::BufferTooSmall);
        }

        // Check common header
        let mctp_hdr = MctpCommonHeader(req[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_VDM_MSG_TYPE {
            return Err(TransportError::UnexpectedMessageType);
        }

        self.cur_resp_ctx = Some(msg_info);

        Ok(req_len as usize)
    }

    /// Send a VDM response.
    pub async fn send_response(&mut self, resp: &[u8]) -> Result<(), TransportError> {
        // Ensure the response buffer is large enough to contain the MCTP common header.
        if resp.is_empty() {
            return Err(TransportError::BufferTooSmall);
        }

        let mctp_hdr = MctpCommonHeader(resp[MCTP_COMMON_HEADER_OFFSET]);
        if mctp_hdr.ic() != 0 || mctp_hdr.msg_type() != MCTP_VDM_MSG_TYPE {
            return Err(TransportError::UnexpectedMessageType);
        }

        if let Some(msg_info) = self.cur_resp_ctx.clone() {
            self.mctp
                .send_response(resp, msg_info)
                .await
                .map_err(|_| TransportError::SendError)?;
        } else {
            return Err(TransportError::NoRequestInFlight);
        }

        self.cur_resp_ctx = None;

        Ok(())
    }

    /// Get the maximum message size supported by the transport.
    pub fn max_message_size(&self) -> Result<u32, TransportError> {
        self.mctp
            .max_message_size()
            .map_err(|_| TransportError::DriverError)
    }
}

impl Default for MctpVdmTransport {
    fn default() -> Self {
        Self::new(driver_num::MCTP_CALIPTRA)
    }
}
