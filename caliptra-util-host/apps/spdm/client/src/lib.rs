// Licensed under the Apache-2.0 license

//! Caliptra SPDM VDM Client Library
//!
//! Provides a high-level typed API for Caliptra VDM commands over SPDM transport.
//! The `SpdmVdmClient` wraps an `SpdmVdmDriver` and uses `CaliptraSession` and
//! command APIs for typed request/response handling.
//!
//! Also provides validation tooling for integration testing.
//!
//! # Usage
//!
//! ```ignore
//! let mut client = SpdmVdmClient::new(&mut vdm_driver);
//! client.connect()?;
//! let response = client.export_attested_csr(0x0001, 0x0001, &nonce)?;
//! println!("CSR: {} bytes", response.data_len);
//! ```

pub mod config;
pub mod ocp_dev_identity_provision;
pub mod validator;

pub use config::TestConfig;
pub use validator::{all_passed, print_summary, run_all, ValidationResult, ValidationStatus};

// Re-export the command authorizer trait and types from the common crate
pub use caliptra_mcu_command_auth_challenge_signer::{
    AsymmetricCommandAuthorizer, CommandAuthChallengeSigner,
};

// Re-export the debug unlock signer trait and types from the common crate
pub use caliptra_mcu_debug_unlock_signer::{
    DebugUnlockKeys, DebugUnlockSigner, LocalDebugUnlockSigner,
};

use anyhow::Result;
use caliptra_mcu_core_util_host_command_types::certificate::ExportAttestedCsrResponse;
use caliptra_mcu_core_util_host_command_types::debug_unlock::{
    ProdDebugUnlockReqResponse, ProdDebugUnlockTokenRequest, ProdDebugUnlockTokenResponse,
};
use caliptra_mcu_core_util_host_command_types::device_info::GetDeviceCapabilitiesResponse;
use caliptra_mcu_core_util_host_command_types::fuse::{
    FeProgResponse, FuseIncreaseCaliptraMinSvnRequest, FuseIncreaseCaliptraMinSvnResponse,
    FuseRevokeVendorPkHashRequest, FuseRevokeVendorPkHashResponse, FuseRevokeVendorPubKeyRequest,
    FuseRevokeVendorPubKeyResponse, GetAuthCmdChallengeResponse, ProvisionVendorPkHashRequest,
    ProvisionVendorPkHashResponse,
};
use caliptra_mcu_core_util_host_transport::transports::spdm_vdm::transport::{
    SpdmVdmDriver, SpdmVdmError, SpdmVdmTransport,
};
use caliptra_mcu_core_util_host_transport::Transport;
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_util_host_commands::api::certificate::caliptra_cmd_export_attested_csr;
use caliptra_util_host_commands::api::debug_unlock::{
    caliptra_cmd_prod_debug_unlock_req, caliptra_cmd_prod_debug_unlock_token,
};
use caliptra_util_host_commands::api::device_info::caliptra_cmd_get_device_capabilities;
use caliptra_util_host_commands::api::fuse::{
    caliptra_cmd_fe_prog, caliptra_cmd_fuse_increase_caliptra_min_svn,
    caliptra_cmd_fuse_revoke_vendor_pk_hash, caliptra_cmd_fuse_revoke_vendor_pub_key,
    caliptra_cmd_get_auth_challenge, caliptra_cmd_provision_vendor_pk_hash,
};
use caliptra_util_host_commands::api::{CaliptraApiError, CaliptraResult};
use caliptra_util_host_session::CaliptraSession;

/// High-level SPDM VDM Client for communicating with Caliptra devices.
///
/// Wraps an `SpdmVdmDriver` and provides typed command methods using
/// `CaliptraSession` dispatch (same pattern as `MailboxClient`).
pub struct SpdmVdmClient<'a> {
    transport: SpdmVdmTransport<'a>,
}

impl<'a> SpdmVdmClient<'a> {
    /// Create a new SpdmVdmClient with the provided VDM driver.
    pub fn new(driver: &'a mut dyn SpdmVdmDriver) -> Self {
        let transport = SpdmVdmTransport::new(driver);
        Self { transport }
    }

    /// Connect the SPDM VDM transport.
    pub fn connect(&mut self) -> Result<()> {
        self.transport
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect SPDM VDM transport: {:?}", e))
    }

    /// Disconnect the SPDM VDM transport.
    pub fn disconnect(&mut self) -> Result<()> {
        self.transport
            .disconnect()
            .map_err(|e| anyhow::anyhow!("Failed to disconnect SPDM VDM transport: {:?}", e))
    }

    /// Read the responder's Caliptra device capabilities.
    pub fn get_device_capabilities(&mut self) -> CaliptraResult<GetDeviceCapabilitiesResponse> {
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_get_device_capabilities(&mut session)
    }

    /// Execute the ExportAttestedCsr command.
    ///
    /// # Parameters
    /// - `device_key_id`: Device key identifier (0x0001=LDevID, 0x0002=FMC Alias, 0x0003=RT Alias)
    /// - `algorithm`: Asymmetric algorithm (0x0001=ECC384, 0x0002=MLDSA87)
    /// - `nonce`: 32-byte nonce for freshness
    pub fn export_attested_csr(
        &mut self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
    ) -> Result<ExportAttestedCsrResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_export_attested_csr(&mut session, device_key_id, algorithm, nonce)
            .map_err(|e| anyhow::anyhow!("ExportAttestedCsr failed: {:?}", e))
    }

    /// Request a production debug unlock challenge.
    ///
    /// # Parameters
    /// - `unlock_level`: The debug unlock level requested (1-8)
    pub fn prod_debug_unlock_req(
        &mut self,
        unlock_level: u8,
    ) -> Result<ProdDebugUnlockReqResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_prod_debug_unlock_req(&mut session, unlock_level)
            .map_err(|e| anyhow::anyhow!("ProdDebugUnlockReq failed: {:?}", e))
    }

    /// Submit a production debug unlock token.
    ///
    /// # Parameters
    /// - `request`: The fully populated debug unlock token request
    pub fn prod_debug_unlock_token(
        &mut self,
        request: &ProdDebugUnlockTokenRequest,
    ) -> Result<ProdDebugUnlockTokenResponse> {
        let mut session = self.create_session()?;
        caliptra_cmd_prod_debug_unlock_token(&mut session, request)
            .map_err(|e| anyhow::anyhow!("ProdDebugUnlockToken failed: {:?}", e))
    }

    /// Request an authorization challenge for authorized commands (e.g., FE_PROG).
    pub fn get_auth_challenge(&mut self) -> CaliptraResult<GetAuthCmdChallengeResponse> {
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_get_auth_challenge(&mut session)
    }

    /// Program field entropy for an OTP partition (authorized command).
    ///
    /// # Parameters
    /// - `partition`: OTP partition to program (0-3)
    /// - `sig`: hybrid ECC-P384 + ML-DSA-87 signature over the transcript
    /// - `nonce`: the 48-byte challenge received from `get_auth_challenge`,
    ///   echoed back on the wire (device compares it to its stored one-time
    ///   challenge, then rebuilds the transcript from this wire copy)
    /// - `ecc_pub_x`/`ecc_pub_y`/`mldsa_pub`: the public keys that travel on the
    ///   wire; the device holds only their SHA-384 anchor and re-derives it from
    ///   these received bytes before verifying
    pub fn fe_prog(
        &mut self,
        partition: u32,
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
    ) -> CaliptraResult<FeProgResponse> {
        use caliptra_mcu_core_util_host_command_types::fuse::FeProgRequest;
        let request = FeProgRequest {
            partition,
            sig: sig.clone(),
            nonce: *nonce,
            ecc_pub_x: *ecc_pub_x,
            ecc_pub_y: *ecc_pub_y,
            mldsa_pub: *mldsa_pub,
        };
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_fe_prog(&mut session, &request)
    }

    pub fn provision_vendor_pk_hash(
        &mut self,
        slot: u32,
        hash: &[u8; 48],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
    ) -> CaliptraResult<ProvisionVendorPkHashResponse> {
        let request = ProvisionVendorPkHashRequest {
            slot,
            hash: *hash,
            sig: sig.clone(),
            nonce: *nonce,
            ecc_pub_x: *ecc_pub_x,
            ecc_pub_y: *ecc_pub_y,
            mldsa_pub: *mldsa_pub,
        };
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_provision_vendor_pk_hash(&mut session, &request)
    }

    pub fn fuse_increase_caliptra_min_svn(
        &mut self,
        flags: u32,
        svn: u32,
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
    ) -> CaliptraResult<FuseIncreaseCaliptraMinSvnResponse> {
        let request = FuseIncreaseCaliptraMinSvnRequest {
            flags,
            svn,
            sig: sig.clone(),
            nonce: *nonce,
            ecc_pub_x: *ecc_pub_x,
            ecc_pub_y: *ecc_pub_y,
            mldsa_pub: *mldsa_pub,
        };
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_fuse_increase_caliptra_min_svn(&mut session, &request)
    }

    pub fn fuse_revoke_vendor_pub_key(
        &mut self,
        reserved: u32,
        vendor_pk_hash_slot: u32,
        key_type: u32,
        key_index: u32,
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
    ) -> CaliptraResult<FuseRevokeVendorPubKeyResponse> {
        let request = FuseRevokeVendorPubKeyRequest {
            reserved,
            vendor_pk_hash_slot,
            key_type,
            key_index,
            sig: sig.clone(),
            nonce: *nonce,
            ecc_pub_x: *ecc_pub_x,
            ecc_pub_y: *ecc_pub_y,
            mldsa_pub: *mldsa_pub,
        };
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_fuse_revoke_vendor_pub_key(&mut session, &request)
    }

    pub fn fuse_revoke_vendor_pk_hash(
        &mut self,
        reserved: u32,
        vendor_pk_hash_slot: u32,
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
    ) -> CaliptraResult<FuseRevokeVendorPkHashResponse> {
        let request = FuseRevokeVendorPkHashRequest {
            reserved,
            vendor_pk_hash_slot,
            sig: sig.clone(),
            nonce: *nonce,
            ecc_pub_x: *ecc_pub_x,
            ecc_pub_y: *ecc_pub_y,
            mldsa_pub: *mldsa_pub,
        };
        let mut session = self
            .create_session()
            .map_err(|_| CaliptraApiError::SessionError("Failed to create session"))?;
        caliptra_cmd_fuse_revoke_vendor_pk_hash(&mut session, &request)
    }

    /// Send an unencoded Caliptra VDM payload for responder-negative validation.
    pub fn send_raw_vdm(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, SpdmVdmError> {
        self.transport.send_raw_vdm(request, response)
    }

    fn create_session(&mut self) -> Result<CaliptraSession> {
        let mut session = CaliptraSession::new(1, &mut self.transport as &mut dyn Transport)
            .map_err(|e| anyhow::anyhow!("Failed to create session: {:?}", e))?;
        session
            .connect()
            .map_err(|e| anyhow::anyhow!("Failed to connect session: {:?}", e))?;
        Ok(session)
    }
}
