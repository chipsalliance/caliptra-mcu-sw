// Licensed under the Apache-2.0 license

//! SPDM requester — manages libspdm context and session lifecycle.

use core::ffi::c_void;

use libspdm::libspdm_rs;
use libspdm::spdm::{self, LibspdmReturnStatus, TransportLayer};

use crate::transport::{self, SpdmDeviceIo};
use crate::SpdmConfig;

/// SPDM requester wrapping a libspdm context.
///
/// Only one `SpdmRequester` should be active per process (libspdm uses
/// process-global state in some paths via spdm-utils).
pub struct SpdmRequester {
    context: *mut c_void,
    config: SpdmConfig,
    connected: bool,
}

// Safety: the context pointer is only accessed through &mut self methods.
unsafe impl Send for SpdmRequester {}

impl SpdmRequester {
    /// Create a new SPDM requester with the given configuration and device I/O.
    ///
    /// This initializes the libspdm context, registers the MCTP transport layer,
    /// and registers device I/O callbacks.
    pub fn new(config: SpdmConfig, device_io: Box<dyn SpdmDeviceIo>) -> anyhow::Result<Self> {
        let context = spdm::initialise_spdm_context();
        if context.is_null() {
            return Err(anyhow::anyhow!("Failed to initialize SPDM context"));
        }

        // Register MCTP transport layer
        unsafe {
            spdm::setup_transport_layer(context, TransportLayer::Mctp, config.max_spdm_msg_size)
                .map_err(|_| anyhow::anyhow!("Failed to setup transport layer"))?;
        }

        // Register device I/O callbacks
        transport::register_device_io(context, device_io);
        unsafe {
            transport::register_device_io_callbacks(context)?;
        }

        Ok(Self {
            context,
            config,
            connected: false,
        })
    }

    /// Establish SPDM connection (VERSION → CAPABILITIES → ALGORITHMS only).
    ///
    /// This performs VCA negotiation which is sufficient for sending
    /// vendor-defined messages. Does NOT do GET_DIGEST/GET_CERTIFICATE/CHALLENGE.
    pub fn connect(&mut self) -> anyhow::Result<()> {
        // Setup requester capabilities and algorithm preferences before VCA
        unsafe {
            self.setup_capabilities()?;
        }

        // Only do VCA (not full authentication flow)
        let ret = unsafe { libspdm_rs::libspdm_init_connection(self.context, false) };
        if spdm::LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!("SPDM init_connection failed: {:#x}", ret));
        }

        self.connected = true;
        log::info!("SPDM connection established (slot {})", self.config.slot_id);
        Ok(())
    }

    /// Configure requester capabilities and algorithm preferences.
    ///
    /// Must be called before `initialise_connection`. Sets capability flags,
    /// asymmetric/hash algorithms, DHE groups, and AEAD cipher suites.
    unsafe fn setup_capabilities(&self) -> anyhow::Result<()> {
        use libspdm::libspdm_rs::*;

        let parameter = libspdm_data_parameter_t::new_local(self.config.slot_id);

        // Capability flags
        let mut data: u32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_FLAGS,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u32>(),
        );

        // CT exponent
        let mut data: u8 = 0;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u8>(),
        );

        // Measurement spec
        let mut data: u8 = 0;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_SPEC,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u8>(),
        );

        // Base asymmetric algorithm: ECC P-384
        let mut data: u32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_BASE_ASYM_ALGO,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u32>(),
        );

        // Base hash algorithm: SHA-384
        let mut data: u32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_BASE_HASH_ALGO,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u32>(),
        );

        // DHE named group: SECP-384-R1
        let mut data: u16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 as u16;
        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_DHE_NAME_GROUP,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u16>(),
        )) {
            return Err(anyhow::anyhow!("Failed to set DHE named group"));
        }

        // AEAD cipher suite: AES-256-GCM
        let mut data: u16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM as u16;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_AEAD_CIPHER_SUITE,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u16>(),
        );

        Ok(())
    }

    /// Send a vendor-defined request and receive the response.
    ///
    /// Uses `libspdm_vendor_send_request_receive_response()` which handles
    /// proper SPDM VENDOR_DEFINED_REQUEST/RESPONSE framing.
    ///
    /// `session_id`: Pass `None` for unsecured messages, `Some(id)` for session.
    pub fn vendor_command(
        &mut self,
        session_id: Option<u32>,
        req_standard_id: u16,
        req_vendor_id: &[u8],
        request: &[u8],
        response: &mut [u8],
    ) -> anyhow::Result<usize> {
        if !self.connected {
            return Err(anyhow::anyhow!("Not connected — call connect() first"));
        }

        let session_id_ptr = match &session_id {
            Some(id) => id as *const u32,
            None => core::ptr::null(),
        };

        let mut resp_standard_id: u16 = 0;
        let mut resp_vendor_id = [0u8; 4];
        let mut resp_vendor_id_len: u8 = resp_vendor_id.len() as u8;
        let mut resp_size: u16 = response.len() as u16;

        let ret = unsafe {
            libspdm_rs::libspdm_vendor_send_request_receive_response(
                self.context,
                session_id_ptr,
                req_standard_id,
                req_vendor_id.len() as u8,
                req_vendor_id.as_ptr() as *const c_void,
                request.len() as u16,
                request.as_ptr() as *const c_void,
                &mut resp_standard_id,
                &mut resp_vendor_id_len,
                resp_vendor_id.as_mut_ptr() as *mut c_void,
                &mut resp_size,
                response.as_mut_ptr() as *mut c_void,
            )
        };

        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!("Vendor command failed: {:#x}", ret));
        }

        log::debug!(
            "Vendor response: standard_id={:#x}, vendor_id_len={}, resp_size={}",
            resp_standard_id,
            resp_vendor_id_len,
            resp_size
        );

        Ok(resp_size as usize)
    }

    /// Get the raw libspdm context pointer (for advanced usage).
    pub fn context(&self) -> *mut c_void {
        self.context
    }

    /// Check if the connection has been established.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

impl Drop for SpdmRequester {
    fn drop(&mut self) {
        transport::unregister_device_io(self.context);
        // Note: libspdm context cleanup is handled by spdm-utils internals.
        // The context was allocated by initialise_spdm_context() and libspdm
        // manages its lifetime.
    }
}
