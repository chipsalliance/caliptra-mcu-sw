// Licensed under the Apache-2.0 license

//! SPDM transport adapter implementing `SpdmVdmDriver` from the transport crate.
//!
//! Wraps `SpdmRequester` to provide raw Caliptra VDM payload send/receive
//! over SPDM VENDOR_DEFINED_REQUEST/RESPONSE with the OCP vendor ID
//! and IANA registry ID.

use caliptra_mcu_core_util_host_transport::transports::spdm_vdm::protocol::{
    OCP_VENDOR_ID, REGISTRY_ID_IANA,
};
use caliptra_mcu_core_util_host_transport::transports::spdm_vdm::transport::{
    SpdmVdmDriver, SpdmVdmError,
};

use crate::requester::SpdmRequester;

/// SPDM-based implementation of `SpdmVdmDriver`.
///
/// Wraps an `SpdmRequester` and handles SPDM vendor-defined message framing
/// (vendor ID, registry ID). The VDM payload encoding/decoding is handled
/// by the transport crate's encode module.
pub struct SpdmVdmDriverImpl<'a> {
    requester: &'a mut SpdmRequester,
    session_id: Option<u32>,
}

impl<'a> SpdmVdmDriverImpl<'a> {
    /// Create a new SPDM VDM driver.
    ///
    /// # Arguments
    /// * `requester` — Connected SPDM requester
    /// * `session_id` — Optional SPDM session ID (None for unsecured messages)
    pub fn new(requester: &'a mut SpdmRequester, session_id: Option<u32>) -> Self {
        Self {
            requester,
            session_id,
        }
    }
}

impl SpdmVdmDriver for SpdmVdmDriverImpl<'_> {
    fn send_receive_vdm(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, SpdmVdmError> {
        let vendor_id = OCP_VENDOR_ID.to_le_bytes();

        self.requester
            .vendor_command(
                self.session_id,
                REGISTRY_ID_IANA,
                &vendor_id,
                request,
                response,
            )
            .map_err(|_| SpdmVdmError::CommunicationError)
    }

    fn is_ready(&self) -> bool {
        self.requester.is_connected()
    }

    fn connect(&mut self) -> Result<(), SpdmVdmError> {
        if self.requester.is_connected() {
            Ok(())
        } else {
            self.requester
                .connect()
                .map_err(|_| SpdmVdmError::SessionError)
        }
    }

    fn disconnect(&mut self) -> Result<(), SpdmVdmError> {
        // SPDM session teardown is handled by SpdmRequester::drop
        Ok(())
    }
}
