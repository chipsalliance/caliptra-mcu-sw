// Licensed under the Apache-2.0 license

//! SPDM requester — manages libspdm context and session lifecycle.

use core::ffi::c_void;
use core::ptr;
use std::alloc::{dealloc, Layout};
use std::sync::Mutex;

use libspdm::libspdm_rs;
use libspdm::spdm::{self, LibspdmReturnStatus, TransportLayer};
use sha2::{Digest, Sha384};
use x509_cert::der::{Reader, SliceReader};
use x509_cert::Certificate;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::transport::{self, SpdmDeviceIo};
use crate::{PeerRootCert, SpdmConfig};

const SHA384_DIGEST_LEN: usize = 48;
const SPDM_MAX_CERTIFICATE_CHAIN_SIZE: usize = 65_535;

// libspdm's verifier registration is a C callback with no user-data pointer.
// spdm-utils also assumes only one requester context is active per process, so
// keep the configured peer roots in a process-global table for the callback.
static TRUSTED_PEER_ROOTS: Mutex<Vec<PeerRootCert>> = Mutex::new(Vec::new());

unsafe extern "C" {
    fn libspdm_register_verify_spdm_cert_chain_func(
        spdm_context: *mut c_void,
        verify_spdm_cert_chain: Option<
            unsafe extern "C" fn(
                spdm_context: *mut c_void,
                slot_id: u8,
                cert_chain_size: usize,
                cert_chain: *const c_void,
                trust_anchor: *mut *const c_void,
                trust_anchor_size: *mut usize,
            ) -> bool,
        >,
    );
    fn libspdm_challenge(
        spdm_context: *mut c_void,
        reserved: *mut c_void,
        slot_id: u8,
        measurement_hash_type: u8,
        measurement_hash: *mut c_void,
        slot_mask: *mut u8,
    ) -> usize;
}

unsafe extern "C" fn accept_peer_cert_chain(
    _spdm_context: *mut c_void,
    _slot_id: u8,
    _cert_chain_size: usize,
    _cert_chain: *const c_void,
    _trust_anchor: *mut *const c_void,
    _trust_anchor_size: *mut usize,
) -> bool {
    true
}

unsafe extern "C" fn verify_peer_cert_chain_trust_anchor(
    _spdm_context: *mut c_void,
    slot_id: u8,
    cert_chain_size: usize,
    cert_chain: *const c_void,
    _trust_anchor: *mut *const c_void,
    _trust_anchor_size: *mut usize,
) -> bool {
    let Some(chain) = (unsafe { cert_chain.as_ref() }).map(|_| unsafe {
        core::slice::from_raw_parts(cert_chain as *const u8, cert_chain_size)
    }) else {
        log::error!("SPDM cert-chain verifier received null chain for slot {slot_id}");
        return false;
    };

    match verify_spdm_cert_chain_root(slot_id, chain) {
        Ok(()) => true,
        Err(err) => {
            log::error!("SPDM cert-chain verification failed for slot {slot_id}: {err}");
            false
        }
    }
}

fn verify_spdm_cert_chain_root(slot_id: u8, chain: &[u8]) -> anyhow::Result<()> {
    let trusted_roots = TRUSTED_PEER_ROOTS
        .lock()
        .map_err(|_| anyhow::anyhow!("trusted root table lock poisoned"))?;
    verify_spdm_cert_chain_root_against_roots(slot_id, chain, &trusted_roots)
}

fn verify_spdm_cert_chain_root_against_roots(
    slot_id: u8,
    chain: &[u8],
    trusted_roots: &[PeerRootCert],
) -> anyhow::Result<()> {
    verify_spdm_cert_chain_payload_root(slot_id, chain, trusted_roots)
}

fn verify_spdm_cert_chain_payload_root(
    slot_id: u8,
    payload: &[u8],
    trusted_roots: &[PeerRootCert],
) -> anyhow::Result<()> {
    if payload.len() < SHA384_DIGEST_LEN {
        return Err(anyhow::anyhow!(
            "certificate payload too short: {} bytes",
            payload.len()
        ));
    }
    let root_hash = &payload[..SHA384_DIGEST_LEN];
    let der = &payload[SHA384_DIGEST_LEN..];
    let certs = split_der_certificates(der)?;
    let root_cert = certs
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("missing root certificate DER"))?;
    let digest = Sha384::digest(root_cert);
    if root_hash != &digest[..] {
        return Err(anyhow::anyhow!("root hash does not match root certificate"));
    }

    if !trusted_roots
        .iter()
        .any(|trusted| trusted.slot_id == slot_id && trusted.cert_der == root_cert)
    {
        return Err(anyhow::anyhow!(
            "root certificate does not match any configured trust anchor for slot {slot_id}"
        ));
    }
    verify_x509_certificate_chain(&certs)?;
    Ok(())
}

pub fn split_der_certificates(der: &[u8]) -> anyhow::Result<Vec<&[u8]>> {
    let mut certs = Vec::new();
    let mut reader = SliceReader::new(der)?;
    while usize::try_from(reader.position())? < der.len() {
        let start = usize::try_from(reader.position())?;
        let _: Certificate = reader.decode()?;
        let end = usize::try_from(reader.position())?;
        certs.push(&der[start..end]);
    }
    Ok(certs)
}

pub fn verify_x509_certificate_chain(certs: &[&[u8]]) -> anyhow::Result<()> {
    if certs.is_empty() {
        return Err(anyhow::anyhow!("X.509 certificate chain is empty"));
    }

    let parsed = certs
        .iter()
        .enumerate()
        .map(|(idx, cert)| {
            let (remaining, parsed) = X509Certificate::from_der(cert)
                .map_err(|e| anyhow::anyhow!("failed to parse X.509 cert {idx}: {e:?}"))?;
            if !remaining.is_empty() {
                return Err(anyhow::anyhow!(
                    "X.509 cert {idx} has {} trailing byte(s)",
                    remaining.len()
                ));
            }
            Ok(parsed)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    parsed[0]
        .verify_signature(None)
        .map_err(|e| anyhow::anyhow!("root self-signature verification failed: {e:?}"))?;

    for (idx, pair) in parsed.windows(2).enumerate() {
        let parent = &pair[0];
        let child = &pair[1];
        if child.issuer() != parent.subject() {
            return Err(anyhow::anyhow!(
                "issuer/subject mismatch between X.509 cert {} and {}",
                idx,
                idx + 1
            ));
        }
        child.verify_signature(Some(parent.public_key())).map_err(|e| {
            anyhow::anyhow!("X.509 cert {} signature verification failed: {e:?}", idx + 1)
        })?;
    }
    Ok(())
}


/// SPDM requester wrapping a libspdm context.
///
/// Only one `SpdmRequester` should be active per process (libspdm uses
/// process-global state in some paths via spdm-utils).
pub struct SpdmRequester {
    context: *mut c_void,
    config: SpdmConfig,
    connected: bool,
}

/// Information returned by SPDM GET_KEY_PAIR_INFO.
#[derive(Debug, Clone)]
pub struct KeyPairInfo {
    /// Total key pairs reported by the responder.
    pub total_key_pairs: u8,
    /// Key-pair capabilities bit mask.
    pub capabilities: u16,
    /// Supported key usages for this key pair.
    pub key_usage_capabilities: u16,
    /// Current key usage mask for this key pair.
    pub current_key_usage: u16,
    /// Supported asymmetric algorithms for this key pair.
    pub asym_algo_capabilities: u32,
    /// Current asymmetric algorithm for this key pair.
    pub current_asym_algo: u32,
    /// Associated certificate slot mask.
    pub assoc_cert_slot_mask: u8,
    /// Public-key info returned by the responder.
    pub public_key_info: Vec<u8>,
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

        if config.accept_unverified_peer_cert_chain {
            // OCP owner provisioning verifies that GET_CERTIFICATE returns the
            // just-installed bytes. The provisioned owner cert is not a normal
            // responder identity cert, so libspdm's default leaf-cert checks are
            // intentionally bypassed for that opt-in flow only.
            unsafe {
                libspdm_register_verify_spdm_cert_chain_func(context, Some(accept_peer_cert_chain));
            }
        } else if !config.peer_root_certs.is_empty() {
            let mut trusted_roots = TRUSTED_PEER_ROOTS
                .lock()
                .map_err(|_| anyhow::anyhow!("trusted root table lock poisoned"))?;
            trusted_roots.clear();
            trusted_roots.extend(config.peer_root_certs.iter().cloned());
            drop(trusted_roots);
            unsafe {
                libspdm_register_verify_spdm_cert_chain_func(
                    context,
                    Some(verify_peer_cert_chain_trust_anchor),
                );
            }
        }

        for peer_root in &config.peer_root_certs {
            let parameter = libspdm_rs::libspdm_data_parameter_t::new_local(peer_root.slot_id);
            let ret = unsafe {
                libspdm_rs::libspdm_set_data(
                    context,
                    libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT,
                    &parameter,
                    peer_root.cert_der.as_ptr() as *mut c_void,
                    peer_root.cert_der.len(),
                )
            };
            if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                return Err(anyhow::anyhow!(
                    "failed to provision SPDM peer root certificate for slot {}: {:#x}",
                    peer_root.slot_id,
                    ret
                ));
            }
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
        self.connect_inner(false)
    }

    /// Establish SPDM connection and authenticate the configured responder certificate slot.
    pub fn connect_authenticated(&mut self) -> anyhow::Result<()> {
        unsafe {
            self.setup_capabilities()?;
            self.init_connection_authenticated(self.config.slot_id)?;
        }
        self.connected = true;
        log::info!(
            "SPDM authenticated connection established (slot {})",
            self.config.slot_id
        );
        Ok(())
    }

    unsafe fn init_connection_authenticated(&self, slot_id: u8) -> anyhow::Result<()> {
        let ret = unsafe { libspdm_rs::libspdm_init_connection(self.context, false) };
        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!(
                "SPDM init_connection failed during authenticated connect: {:#x}",
                ret
            ));
        }

        let mut slot_mask = 0u8;
        let mut total_digest_buffer =
            [0u8; (libspdm_rs::LIBSPDM_MAX_HASH_SIZE * libspdm_rs::SPDM_MAX_SLOT_COUNT) as usize];
        let ret = unsafe {
            libspdm_rs::libspdm_get_digest(
                self.context,
                ptr::null_mut(),
                &mut slot_mask,
                total_digest_buffer.as_mut_ptr() as *mut c_void,
            )
        };
        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!(
                "SPDM GET_DIGEST failed during authenticated connect: {:#x}",
                ret
            ));
        }

        self.get_certificate_large_buffer(None, slot_id)
            .map_err(|err| anyhow::anyhow!("SPDM authenticated GET_CERTIFICATE failed for slot {slot_id}: {err}"))?;

        let mut measurement_hash = [0u8; libspdm_rs::LIBSPDM_MAX_HASH_SIZE as usize];
        let ret = unsafe {
            libspdm_challenge(
                self.context,
                ptr::null_mut(),
                slot_id,
                libspdm_rs::SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH as u8,
                measurement_hash.as_mut_ptr() as *mut c_void,
                ptr::null_mut(),
            )
        };
        let ret_status = ret as u32;
        if LibspdmReturnStatus::libspdm_status_is_error(ret_status) {
            return Err(anyhow::anyhow!(
                "SPDM CHALLENGE failed during authenticated connect for slot {}: {:#x}",
                slot_id,
                ret_status
            ));
        }
        Ok(())
    }

    fn connect_inner(&mut self, get_version_only: bool) -> anyhow::Result<()> {
        // Setup requester capabilities and algorithm preferences before VCA
        unsafe {
            self.setup_capabilities()?;
        }

        let ret = unsafe { libspdm_rs::libspdm_init_connection(self.context, get_version_only) };
        if spdm::LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!("SPDM init_connection failed: {:#x}", ret));
        }

        self.connected = true;
        log::info!(
            "SPDM connection established (slot {}, authenticated={})",
            self.config.slot_id,
            get_version_only
        );
        Ok(())
    }

    /// Send CHALLENGE for `slot_id` and let libspdm verify the CHALLENGE_AUTH signature.
    pub fn challenge(&mut self, slot_id: u8) -> anyhow::Result<u8> {
        if !self.connected {
            return Err(anyhow::anyhow!("Not connected — call connect() first"));
        }

        let mut slot_mask = 0u8;
        let ret = unsafe {
            libspdm_challenge(
                self.context,
                ptr::null_mut(),
                slot_id,
                0,
                ptr::null_mut(),
                &mut slot_mask,
            )
        };
        let ret_status = ret as u32;
        if spdm::LibspdmReturnStatus::libspdm_status_is_error(ret_status) {
            return Err(anyhow::anyhow!(
                "SPDM CHALLENGE failed for slot {}: {:#x}",
                slot_id,
                ret_status
            ));
        }
        Ok(slot_mask)
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
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG;
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

        // Other parameters: advertise opaque data format 1 and SPDM 1.3
        // MultiKeyConn support so SET_CERTIFICATE can carry KeyPairID and
        // SetCertModel when the responder advertises negotiable multi-key.
        let mut data: u8 =
            (SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 | SPDM_ALGORITHMS_MULTI_KEY_CONN) as u8;
        libspdm_set_data(
            self.context,
            libspdm_data_type_t_LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
            &parameter,
            &mut data as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<u8>(),
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

    /// Send GET_KEY_PAIR_INFO for a responder key pair.
    pub fn get_key_pair_info(
        &mut self,
        session_id: Option<u32>,
        key_pair_id: u8,
    ) -> anyhow::Result<KeyPairInfo> {
        if !self.connected {
            return Err(anyhow::anyhow!("Not connected — call connect() first"));
        }

        let session_id_ptr = match &session_id {
            Some(id) => id as *const u32,
            None => ptr::null(),
        };
        let mut total_key_pairs = 0u8;
        let mut capabilities = 0u16;
        let mut key_usage_capabilities = 0u16;
        let mut current_key_usage = 0u16;
        let mut asym_algo_capabilities = 0u32;
        let mut current_asym_algo = 0u32;
        let mut assoc_cert_slot_mask = 0u8;
        let mut public_key_info_len = libspdm_rs::SPDM_MAX_PUBLIC_KEY_INFO_LEN as u16;
        let mut public_key_info = vec![0u8; public_key_info_len as usize];

        let ret = unsafe {
            libspdm_rs::libspdm_get_key_pair_info(
                self.context,
                session_id_ptr,
                key_pair_id,
                &mut total_key_pairs,
                &mut capabilities,
                &mut key_usage_capabilities,
                &mut current_key_usage,
                &mut asym_algo_capabilities,
                &mut current_asym_algo,
                &mut assoc_cert_slot_mask,
                &mut public_key_info_len,
                public_key_info.as_mut_ptr() as *mut c_void,
            )
        };
        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!(
                "GET_KEY_PAIR_INFO failed for key_pair_id {}: {:#x}",
                key_pair_id,
                ret
            ));
        }
        public_key_info.truncate(public_key_info_len as usize);

        Ok(KeyPairInfo {
            total_key_pairs,
            capabilities,
            key_usage_capabilities,
            current_key_usage,
            asym_algo_capabilities,
            current_asym_algo,
            assoc_cert_slot_mask,
            public_key_info,
        })
    }

    /// Send SET_CERTIFICATE for a DER X.509 certificate chain.
    ///
    /// `cert_chain_der` is the concatenated DER X.509 certificate chain. This
    /// helper wraps it in the SPDM certificate-chain structure required by
    /// libspdm before sending SET_CERTIFICATE.
    pub fn set_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        key_pair_id: u8,
        cert_model: u8,
        cert_chain_der: &[u8],
    ) -> anyhow::Result<()> {
        if !self.connected {
            return Err(anyhow::anyhow!("Not connected — call connect() first"));
        }

        let session_id_ptr = match &session_id {
            Some(id) => id as *const u32,
            None => ptr::null(),
        };

        let asym_algo = unsafe { spdm::get_base_asym_algo(self.context, slot_id) }
            .map_err(|ret| anyhow::anyhow!("failed to get negotiated asym algo: {:#x}", ret))?
            .0;
        let hash_algo = unsafe { spdm::get_base_hash_algo(self.context, slot_id) }
            .map_err(|ret| anyhow::anyhow!("failed to get negotiated hash algo: {:#x}", ret))?
            .0;

        let (cert_chain_buffer, cert_chain_size) =
            unsafe { spdm::get_local_certchain(cert_chain_der, asym_algo, hash_algo, true) };
        let request_attribute = (cert_model << 4) & 0x70;
        let ret = unsafe {
            libspdm_rs::libspdm_set_certificate_ex(
                self.context,
                session_id_ptr,
                slot_id,
                cert_chain_buffer,
                cert_chain_size,
                request_attribute,
                key_pair_id,
            )
        };
        unsafe {
            if let Ok(layout) = Layout::from_size_align(cert_chain_size, 8) {
                dealloc(cert_chain_buffer as *mut u8, layout);
            }
        }

        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!(
                "SET_CERTIFICATE failed for slot {} key_pair_id {}: {:#x}",
                slot_id,
                key_pair_id,
                ret
            ));
        }

        Ok(())
    }

    /// Send GET_CERTIFICATE and return the SPDM certificate-chain bytes.
    pub fn get_certificate(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
    ) -> anyhow::Result<Vec<u8>> {
        if !self.connected {
            return Err(anyhow::anyhow!("Not connected — call connect() first"));
        }

        let session_id_ptr = match &session_id {
            Some(id) => id as *const u32,
            None => ptr::null(),
        };
        let (ret, mut cert_chain, cert_chain_size) =
            self.get_certificate_large_buffer_raw(session_id_ptr, slot_id);
        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!(
                "GET_CERTIFICATE failed for slot {}: {:#x}",
                slot_id,
                ret
            ));
        }
        cert_chain.truncate(cert_chain_size);
        Ok(cert_chain)
    }

    fn get_certificate_large_buffer(
        &self,
        session_id: Option<u32>,
        slot_id: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let session_id_ptr = match &session_id {
            Some(id) => id as *const u32,
            None => ptr::null(),
        };
        let (ret, mut cert_chain, cert_chain_size) =
            self.get_certificate_large_buffer_raw(session_id_ptr, slot_id);
        if LibspdmReturnStatus::libspdm_status_is_error(ret) {
            return Err(anyhow::anyhow!("{:#x}", ret));
        }
        cert_chain.truncate(cert_chain_size);
        Ok(cert_chain)
    }

    fn get_certificate_large_buffer_raw(
        &self,
        session_id_ptr: *const u32,
        slot_id: u8,
    ) -> (u32, Vec<u8>, usize) {
        let mut cert_chain_size = SPDM_MAX_CERTIFICATE_CHAIN_SIZE;
        let mut cert_chain = vec![0u8; cert_chain_size];
        let ret = unsafe {
            libspdm_rs::libspdm_get_certificate_choose_length(
                self.context,
                session_id_ptr,
                slot_id,
                libspdm_rs::LIBSPDM_MAX_CERT_CHAIN_BLOCK_LEN as u16,
                &mut cert_chain_size,
                cert_chain.as_mut_ptr() as *mut c_void,
            )
        };
        (ret, cert_chain, cert_chain_size)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_vendor_root() -> Vec<u8> {
        include_bytes!("../../certs/test_vendor_root.der").to_vec()
    }

    fn peer_root(slot_id: u8, cert_der: Vec<u8>) -> PeerRootCert {
        PeerRootCert { slot_id, cert_der }
    }

    fn owner_leaf_cert() -> Vec<u8> {
        let certs = split_der_certificates(include_bytes!("../../certs/test_owner_certchain.der"))
            .expect("test owner chain should split");
        certs[1].to_vec()
    }

    fn root_hash_plus_der(root: &[u8]) -> Vec<u8> {
        let mut chain = Vec::with_capacity(SHA384_DIGEST_LEN + root.len());
        chain.extend_from_slice(&Sha384::digest(root));
        chain.extend_from_slice(root);
        chain
    }

    fn root_hash_plus_der_chain(root: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut chain = Vec::with_capacity(SHA384_DIGEST_LEN + root.len() + tail.len());
        chain.extend_from_slice(&Sha384::digest(root));
        chain.extend_from_slice(root);
        chain.extend_from_slice(tail);
        chain
    }


    #[test]
    fn verifier_accepts_libspdm_root_hash_der_payload() {
        let root = trusted_vendor_root();
        let chain = root_hash_plus_der(&root);

        verify_spdm_cert_chain_root_against_roots(0, &chain, &[peer_root(0, root)]).unwrap();
    }


    #[test]
    fn verifier_rejects_bad_root_hash() {
        let root = trusted_vendor_root();
        let mut chain = root_hash_plus_der(&root);
        chain[0] ^= 0x01;

        let err = verify_spdm_cert_chain_root_against_roots(0, &chain, &[peer_root(0, root)])
            .unwrap_err();
        assert!(err.to_string().contains("root hash"));
    }

    #[test]
    fn verifier_rejects_untrusted_root() {
        let root = trusted_vendor_root();
        let chain = root_hash_plus_der(&root);

        let err = verify_spdm_cert_chain_root_against_roots(0, &chain, &[]).unwrap_err();
        assert!(err.to_string().contains("trust anchor"));
    }

    #[test]
    fn verifier_rejects_trusted_root_for_different_slot() {
        let root = trusted_vendor_root();
        let chain = root_hash_plus_der(&root);

        let err = verify_spdm_cert_chain_root_against_roots(0, &chain, &[peer_root(2, root)])
            .unwrap_err();
        assert!(err.to_string().contains("slot 0"));
    }

    #[test]
    fn verifier_rejects_unverified_child_under_trusted_root() {
        let root = trusted_vendor_root();
        let attacker_leaf = owner_leaf_cert();
        let chain = root_hash_plus_der_chain(&root, &attacker_leaf);

        let err = verify_spdm_cert_chain_root_against_roots(0, &chain, &[peer_root(0, root)])
            .unwrap_err();
        assert!(
            err.to_string().contains("issuer/subject")
                || err.to_string().contains("signature verification"),
            "unexpected error: {err}"
        );
    }
}
