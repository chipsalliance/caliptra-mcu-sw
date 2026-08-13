// Licensed under the Apache-2.0 license

//! Caliptra VENDOR_DEFINED Message (VDM) backend.
//!
//! Implements [`SpdmVdmBackend`] for the Caliptra VDM protocol (IANA standards
//! body, vendor id [`CALIPTRA_VENDOR_ID`]). The backend decodes the
//! Caliptra VDM message header, dispatches the command, and frames the response.
//! Transport-neutral operations use [`caliptra_mcu_common_commands::CaliptraCmdHandler`].
//! SPDM-specific stream state and shared command authorization use separate hooks.

mod commands;

use caliptra_mcu_common_commands::CaliptraCmdHandler;
use caliptra_mcu_mbox_common::messages::{HybridSignature, AUTH_CMD_NONCE_LEN};
use caliptra_mcu_spdm_codec::StandardsBodyId;
use caliptra_mcu_spdm_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};
use mcu_error::codes::INVARIANT;

pub use caliptra_mcu_spdm_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmCommand, CaliptraVdmResult,
    CALIPTRA_VDM_COMMAND_VERSION, CALIPTRA_VENDOR_ID,
};
pub use commands::authorized_command::{
    FE_PROG_CMD_ID, FUSE_LOCK_PARTITION_CMD_ID, GET_AUTH_CHALLENGE_CMD_ID,
    INCREASE_CALIPTRA_MIN_SVN_CMD_ID, PROVISION_VENDOR_PK_HASH_CMD_ID,
    REVOKE_VENDOR_PK_HASH_CMD_ID, REVOKE_VENDOR_PUB_KEY_CMD_ID,
};

/// Caliptra VDM message header length: `[command_version, command_code]`.
const VDM_HEADER_LEN: usize = 2;
/// Maximum CSR/log payload staged in one Caliptra VDM response.
const MAX_LARGE_COMMAND_DATA_LEN: usize = 4 * 1024;
/// Maximum complete Caliptra VDM large payload:
/// `[command_version, command_code, completion, data_len, data...]`.
const MAX_LARGE_VDM_PAYLOAD_LEN: usize = VDM_HEADER_LEN + 1 + 4 + MAX_LARGE_COMMAND_DATA_LEN;

/// Platform hook for SPDM-specific Caliptra VDM stream state.
pub trait CaliptraVdmStreamOps {
    /// Starts streaming a production debug unlock token request.
    async fn start_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        _token_len: usize,
        _first: &[u8],
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Streams additional production debug unlock token bytes.
    async fn continue_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        _chunk: &[u8],
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Finishes a streaming production debug unlock token request.
    async fn finish_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(
        &self,
        _scratch: &A,
    ) -> CaliptraVdmResult<()> {
        Err(CaliptraCompletionCode::UnsupportedOperation)
    }

    /// Aborts a streaming production debug unlock token request.
    async fn abort_authorize_debug_unlock_token_stream<A: SpdmPalAlloc>(&self, _scratch: &A) {}
}

/// Platform hook for the shared command-authorization service.
///
/// Each `payload` is the exact little-endian wire payload preceding `sig`.
/// Implementations must verify `cmd_id(BE) || payload || challenge(48)` without
/// re-encoding parsed fields.
pub trait CaliptraVdmAuthorization {
    async fn get_auth_challenge<A: SpdmPalAlloc>(
        &self,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;

    #[allow(clippy::too_many_arguments)]
    async fn provision_vendor_pk_hash<A: SpdmPalAlloc>(
        &self,
        slot: u32,
        hash: &[u8; 48],
        payload: &[u8],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn increase_caliptra_min_svn<A: SpdmPalAlloc>(
        &self,
        flags: u32,
        svn: u32,
        payload: &[u8],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn program_field_entropy<A: SpdmPalAlloc>(
        &self,
        partition: u32,
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn revoke_vendor_pub_key<A: SpdmPalAlloc>(
        &self,
        reserved: u32,
        slot: u32,
        key_type: u32,
        key_index: u32,
        payload: &[u8],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn revoke_vendor_pk_hash<A: SpdmPalAlloc>(
        &self,
        reserved: u32,
        slot: u32,
        payload: &[u8],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    #[allow(clippy::too_many_arguments)]
    async fn fuse_lock_partition<A: SpdmPalAlloc>(
        &self,
        partition: u32,
        payload: &[u8],
        sig: &HybridSignature,
        nonce: &[u8; AUTH_CMD_NONCE_LEN],
        ecc_pub_x: &[u8; 48],
        ecc_pub_y: &[u8; 48],
        mldsa_pub: &[u8; 2592],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;
}

/// Caliptra VDM backend with separate shared-command, stream, and authorization hooks.
pub struct CaliptraVdm<'a, H, S, A> {
    commands: &'a H,
    stream: &'a S,
    authorization: &'a A,
}

impl<'a, H, S, A> CaliptraVdm<'a, H, S, A> {
    pub fn new(commands: &'a H, stream: &'a S, authorization: &'a A) -> Self {
        Self {
            commands,
            stream,
            authorization,
        }
    }
}

impl<H, S, A> SpdmVdmBackend for CaliptraVdm<'_, H, S, A>
where
    H: CaliptraCmdHandler,
    S: CaliptraVdmStreamOps,
    A: CaliptraVdmAuthorization,
{
    // Caliptra VDM can emit responses (CSRs, logs) larger than one transport
    // frame, so the stack provisions the buffered large-response path.
    const USES_LARGE_RESPONSE: bool = true;
    const LARGE_RESPONSE_CAPACITY: usize = MAX_LARGE_VDM_PAYLOAD_LEN;

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        registry.standard_id == StandardsBodyId::Iana.as_u16()
            && registry.vendor_id == CALIPTRA_VENDOR_ID.to_le_bytes()
    }

    async fn start_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        req_len: usize,
        first: &[u8],
        alloc: &Alloc,
        _io: &Io,
    ) -> McuResult<bool>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        if first.len() < VDM_HEADER_LEN || req_len < VDM_HEADER_LEN {
            return Err(INVARIANT);
        }
        if first[0] != CALIPTRA_VDM_COMMAND_VERSION
            || first[1] != CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8
        {
            return Ok(false);
        }
        match self
            .stream
            .start_authorize_debug_unlock_token_stream(
                req_len - VDM_HEADER_LEN,
                &first[VDM_HEADER_LEN..],
                alloc,
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(CaliptraCompletionCode::UnsupportedOperation) => Ok(false),
            Err(_) => Err(INVARIANT),
        }
    }

    async fn continue_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        chunk: &[u8],
        alloc: &Alloc,
        _io: &Io,
    ) -> McuResult<()>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        self.stream
            .continue_authorize_debug_unlock_token_stream(chunk, alloc)
            .await
            .map_err(|_| INVARIANT)
    }

    async fn finish_authorize_debug_unlock_token_stream<Alloc, Io>(
        &self,
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        let out = rsp.inline;
        if out.len() < VDM_HEADER_LEN + 1 {
            return Err(INVARIANT);
        }
        let completion = match self
            .stream
            .finish_authorize_debug_unlock_token_stream(rsp.alloc)
            .await
        {
            Ok(()) => CaliptraCompletionCode::Success,
            Err(code) => code,
        };
        out[0] = CALIPTRA_VDM_COMMAND_VERSION;
        out[1] = CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8;
        out[2] = completion as u8;
        Ok(VdmResponse::Inline(VDM_HEADER_LEN + 1))
    }

    async fn abort_authorize_debug_unlock_token_stream<Alloc, Io>(&self, alloc: &Alloc, _io: &Io)
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        self.stream
            .abort_authorize_debug_unlock_token_stream(alloc)
            .await;
    }

    async fn handle_request<Alloc, Io>(
        &self,
        req: &[u8],
        rsp: VdmResponseBuffer<'_, Alloc, Io>,
    ) -> McuResult<VdmResponse>
    where
        Alloc: SpdmPalAlloc,
        Io: SpdmPalIo,
    {
        // Decode the Caliptra VDM header `[command_version, command_code]`. A
        // truncated header leaves no command code to echo, so no vendor-defined
        // response can be formed; the handler returns a plain McuError and the
        // stack classifies it into an SPDM ERROR PDU.
        if req.len() < VDM_HEADER_LEN {
            return Err(INVARIANT);
        }
        let command_version = req[0];
        let command_code = req[1];
        let cmd_req = &req[VDM_HEADER_LEN..];

        let VdmResponseBuffer {
            inline: out,
            large,
            alloc,
            io: _,
        } = rsp;
        let scratch = alloc;
        // No room for even the response header + completion code → no
        // vendor-defined response can be formed; surfaced as an SPDM error by
        // the stack.
        if out.len() < VDM_HEADER_LEN + 1 {
            return Err(INVARIANT);
        }
        // Echo the response header (version + command code).
        out[0] = CALIPTRA_VDM_COMMAND_VERSION;
        out[1] = command_code;
        let payload = &mut out[VDM_HEADER_LEN..];

        // A mismatched command version is reported as a VDM completion, not an
        // SPDM error (the envelope itself is well-formed).
        if command_version != CALIPTRA_VDM_COMMAND_VERSION {
            payload[0] = CaliptraCompletionCode::InvalidCommandVersion as u8;
            return Ok(VdmResponse::Inline(VDM_HEADER_LEN + 1));
        }

        let result = match CaliptraVdmCommand::try_from(command_code) {
            Ok(CaliptraVdmCommand::RequestDebugUnlock) => {
                commands::debug_unlock::handle_request_debug_unlock(
                    self.commands,
                    cmd_req,
                    scratch,
                    payload,
                )
                .await
            }
            Ok(CaliptraVdmCommand::AuthorizeDebugUnlockToken) => {
                commands::debug_unlock::handle_authorize_debug_unlock_token(
                    self.commands,
                    cmd_req,
                    scratch,
                    payload,
                )
                .await
            }
            Ok(CaliptraVdmCommand::ExportAttestedCsr) => {
                commands::export_attested_csr::handle(
                    self.commands,
                    cmd_req,
                    command_code,
                    payload,
                    large,
                    scratch,
                )
                .await
            }
            Ok(CaliptraVdmCommand::AuthorizedCommand) => {
                commands::authorized_command::handle(self.authorization, cmd_req, scratch, payload)
                    .await
            }
            // Recognized-but-unimplemented and unknown command codes both map to
            // an UnsupportedOperation completion.
            _ => CaliptraVdmCmdResult::Error(CaliptraCompletionCode::UnsupportedOperation),
        };

        match result {
            CaliptraVdmCmdResult::Response(n) => Ok(VdmResponse::Inline(VDM_HEADER_LEN + n)),
            // The command wrote the complete VDM payload (header + data) into `large`.
            CaliptraVdmCmdResult::Large(n) => Ok(VdmResponse::Large(n)),
            CaliptraVdmCmdResult::Error(code) => {
                payload[0] = code as u8;
                Ok(VdmResponse::Inline(VDM_HEADER_LEN + 1))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::future::Future;
    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use caliptra_mcu_common_commands::{DeviceCapabilities, FirmwareVersion};
    use caliptra_mcu_spdm_traits::{
        SpdmPalAlloc, SpdmPalIo, SpdmPalIoKind, SpdmVdmBackend, VdmResponse, VdmResponseBuffer,
    };
    use mcu_error::McuResult;
    use std::boxed::Box;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;
    use zerocopy::IntoBytes;

    use super::*;

    struct TestIo;

    impl SpdmPalIo for TestIo {
        fn kind(&self) -> SpdmPalIoKind {
            SpdmPalIoKind::Message
        }

        fn request(&self) -> &[u8] {
            &[]
        }
    }

    struct TestBox<'a, T: 'a> {
        value: Box<T>,
        _lifetime: PhantomData<&'a ()>,
    }

    impl<T> Deref for TestBox<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }

    impl<T> DerefMut for TestBox<'_, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.value
        }
    }

    struct TestAlloc;

    impl mcu_caliptra_api_lite::ApiAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            Ok(vec![0u8; len])
        }
    }

    impl SpdmPalAlloc for TestAlloc {
        type Box<'a, T>
            = TestBox<'a, T>
        where
            Self: 'a,
            T: 'a;
        type Bytes<'a>
            = Vec<u8>
        where
            Self: 'a;
        type LargeBuf = Vec<u8>;

        fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>> {
            Ok(TestBox {
                value: Box::new(value),
                _lifetime: PhantomData,
            })
        }

        fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>> {
            Ok(vec![0; len])
        }

        fn large_capacity(&self) -> usize {
            4096
        }

        fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
            Ok(vec![0; len])
        }

        fn large_buf_into_bytes(
            &self,
            mut buf: Self::LargeBuf,
            len: usize,
        ) -> McuResult<Self::Bytes<'_>> {
            buf.truncate(len);
            Ok(buf)
        }

        type PersistentBox<T: Sized + 'static> = Box<T>;

        fn alloc_persistent<T: Sized + 'static>(
            &self,
            value: T,
        ) -> McuResult<Self::PersistentBox<T>> {
            Ok(Box::new(value))
        }
    }

    const DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE: usize = 32;
    const DEBUG_UNLOCK_CHALLENGE_SIZE: usize = 48;
    const TEST_AUTH_CHALLENGE: [u8; 48] = [0xA5; 48];

    #[derive(Debug, PartialEq, Eq)]
    enum AuthorizedOperation {
        ProvisionVendorPkHash {
            slot: u32,
            hash: [u8; 48],
        },
        IncreaseCaliptraMinSvn {
            flags: u32,
            svn: u32,
        },
        RevokeVendorPubKey {
            reserved: u32,
            slot: u32,
            key_type: u32,
            key_index: u32,
        },
        RevokeVendorPkHash {
            reserved: u32,
            slot: u32,
        },
        FuseLockPartition {
            partition: u32,
        },
    }

    struct TestCommands {
        csr_len: usize,
        authorized_token: Mutex<Option<Vec<u8>>>,
        authorized_operation: Mutex<Option<AuthorizedOperation>>,
        authorization_error: Mutex<Option<CaliptraCompletionCode>>,
        enforce_authorization: bool,
        challenge: Mutex<Option<[u8; 48]>>,
    }

    impl TestCommands {
        fn new(csr_len: usize) -> Self {
            Self {
                csr_len,
                authorized_token: Mutex::new(None),
                authorized_operation: Mutex::new(None),
                authorization_error: Mutex::new(None),
                enforce_authorization: false,
                challenge: Mutex::new(None),
            }
        }

        fn with_authorization(mut self) -> Self {
            self.enforce_authorization = true;
            self
        }

        fn verify_test_signature(
            &self,
            cmd_id: u32,
            payload: &[u8],
            sig: &HybridSignature,
        ) -> CaliptraVdmResult<()> {
            if !self.enforce_authorization {
                return Ok(());
            }
            // Taking the challenge before verification matches the production
            // one-use authorization path, including failed signature attempts.
            let challenge = self
                .challenge
                .lock()
                .unwrap()
                .take()
                .ok_or(CaliptraCompletionCode::AccessDenied)?;
            let sig_bytes = sig.as_bytes();
            let payload_end = 4 + payload.len();
            let challenge_end = payload_end + challenge.len();
            if sig_bytes[..4] != cmd_id.to_be_bytes()
                || sig_bytes[4..payload_end] != *payload
                || sig_bytes[payload_end..challenge_end] != challenge
                || sig_bytes[challenge_end..].iter().any(|byte| *byte != 0x3C)
            {
                return Err(CaliptraCompletionCode::AccessDenied);
            }
            Ok(())
        }

        fn complete_authorized(&self, operation: AuthorizedOperation) -> CaliptraVdmResult<()> {
            if let Some(code) = self.authorization_error.lock().unwrap().take() {
                return Err(code);
            }
            self.authorized_operation.lock().unwrap().replace(operation);
            Ok(())
        }

        fn write_csr(
            &self,
            out: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            if out.len() < self.csr_len {
                return Err(
                    caliptra_mcu_common_commands::CaliptraCompletionCode::InsufficientResources,
                );
            }
            for (i, byte) in out[..self.csr_len].iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok(self.csr_len)
        }
    }

    impl CaliptraCmdHandler for TestCommands {
        async fn get_firmware_version(
            &self,
            area_index: u32,
            out: &mut FirmwareVersion,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            if area_index != 1 {
                return Err(caliptra_mcu_common_commands::CaliptraCompletionCode::InvalidParameter);
            }
            out.ver_str[..5].copy_from_slice(b"1.2.3");
            out.len = 5;
            Ok(())
        }

        async fn get_device_capabilities(
            &self,
            out: &mut DeviceCapabilities,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            out.caliptra_rt = [0x11; 8];
            out.mcu_rt = [0x22; 4];
            Ok(())
        }

        async fn export_attested_csr<Alloc: mcu_caliptra_api_lite::ApiAlloc>(
            &self,
            _alloc: &Alloc,
            _device_key_id: u32,
            _algorithm: u32,
            _nonce: &[u8; 32],
            out: &mut [u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<usize> {
            self.write_csr(out)
        }

        async fn request_debug_unlock<Alloc: mcu_caliptra_api_lite::ApiAlloc>(
            &self,
            _alloc: &Alloc,
            unlock_level: u8,
            challenge: &mut caliptra_mcu_common_commands::DebugUnlockChallenge,
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            if unlock_level != 7 {
                return Err(caliptra_mcu_common_commands::CaliptraCompletionCode::InvalidParameter);
            }
            challenge.unique_device_identifier.fill(0x11);
            challenge.challenge.fill(0x22);
            Ok(())
        }

        async fn authorize_debug_unlock_token<Alloc: mcu_caliptra_api_lite::ApiAlloc>(
            &self,
            _alloc: &Alloc,
            token_data: &[u8],
        ) -> caliptra_mcu_common_commands::CaliptraCmdResult<()> {
            self.authorized_token
                .lock()
                .unwrap()
                .replace(token_data.to_vec());
            Ok(())
        }
    }

    impl CaliptraVdmStreamOps for TestCommands {}

    impl CaliptraVdmAuthorization for TestCommands {
        async fn get_auth_challenge<A: SpdmPalAlloc>(
            &self,
            _scratch: &A,
            out: &mut [u8],
        ) -> CaliptraVdmResult<usize> {
            if out.len() < 48 {
                return Err(CaliptraCompletionCode::InsufficientResources);
            }
            out[..48].copy_from_slice(&TEST_AUTH_CHALLENGE);
            *self.challenge.lock().unwrap() = Some(TEST_AUTH_CHALLENGE);
            Ok(48)
        }

        async fn provision_vendor_pk_hash<A: SpdmPalAlloc>(
            &self,
            slot: u32,
            hash: &[u8; 48],
            payload: &[u8],
            sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.verify_test_signature(PROVISION_VENDOR_PK_HASH_CMD_ID, payload, sig)?;
            self.complete_authorized(AuthorizedOperation::ProvisionVendorPkHash {
                slot,
                hash: *hash,
            })
        }

        async fn increase_caliptra_min_svn<A: SpdmPalAlloc>(
            &self,
            flags: u32,
            svn: u32,
            payload: &[u8],
            sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.verify_test_signature(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, payload, sig)?;
            self.complete_authorized(AuthorizedOperation::IncreaseCaliptraMinSvn { flags, svn })
        }

        #[allow(clippy::too_many_arguments)]
        async fn program_field_entropy<A: SpdmPalAlloc>(
            &self,
            _partition: u32,
            _sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            Ok(())
        }

        async fn revoke_vendor_pub_key<A: SpdmPalAlloc>(
            &self,
            reserved: u32,
            slot: u32,
            key_type: u32,
            key_index: u32,
            payload: &[u8],
            sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.verify_test_signature(REVOKE_VENDOR_PUB_KEY_CMD_ID, payload, sig)?;
            self.complete_authorized(AuthorizedOperation::RevokeVendorPubKey {
                reserved,
                slot,
                key_type,
                key_index,
            })
        }

        async fn revoke_vendor_pk_hash<A: SpdmPalAlloc>(
            &self,
            reserved: u32,
            slot: u32,
            payload: &[u8],
            sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.verify_test_signature(REVOKE_VENDOR_PK_HASH_CMD_ID, payload, sig)?;
            self.complete_authorized(AuthorizedOperation::RevokeVendorPkHash { reserved, slot })
        }

        async fn fuse_lock_partition<A: SpdmPalAlloc>(
            &self,
            partition: u32,
            payload: &[u8],
            sig: &HybridSignature,
            _nonce: &[u8; AUTH_CMD_NONCE_LEN],
            _ecc_pub_x: &[u8; 48],
            _ecc_pub_y: &[u8; 48],
            _mldsa_pub: &[u8; 2592],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.verify_test_signature(FUSE_LOCK_PARTITION_CMD_ID, payload, sig)?;
            self.complete_authorized(AuthorizedOperation::FuseLockPartition { partition })
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}
            RawWaker::new(
                core::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
        }

        // SAFETY: The no-op waker never dereferences the data pointer; these
        // tests only poll futures that complete synchronously.
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match Future::poll(Pin::as_mut(&mut future), &mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => core::hint::spin_loop(),
            }
        }
    }

    fn dispatch(
        cmds: &TestCommands,
        req: &[u8],
        inline_len: usize,
        large_len: usize,
    ) -> (VdmResponse, Vec<u8>, Vec<u8>) {
        let alloc = TestAlloc;
        let io = TestIo;
        let backend = CaliptraVdm::new(cmds, cmds, cmds);
        let mut inline = vec![0; inline_len];
        let mut large = vec![0; large_len];
        let response = block_on(backend.handle_request(
            req,
            VdmResponseBuffer {
                inline: &mut inline,
                large: &mut large,
                alloc: &alloc,
                io: &io,
            },
        ))
        .expect("VDM dispatch should complete");
        (response, inline, large)
    }

    fn assert_inline(response: VdmResponse, expected_len: usize) {
        match response {
            VdmResponse::Inline(len) => assert_eq!(len, expected_len),
            VdmResponse::Large(_) => panic!("expected inline response"),
        }
    }

    fn assert_large(response: VdmResponse, expected_len: usize) {
        match response {
            VdmResponse::Large(len) => assert_eq!(len, expected_len),
            VdmResponse::Inline(_) => panic!("expected large response"),
        }
    }

    fn authorized_req_with_sig(sub_cmd: u32, payload: &[u8], sig: &HybridSignature) -> Vec<u8> {
        let mut req = vec![
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::AuthorizedCommand as u8,
        ];
        req.extend_from_slice(&sub_cmd.to_le_bytes());
        req.extend_from_slice(payload);
        req.extend_from_slice(&[0u8; AUTH_CMD_NONCE_LEN]);
        req.extend_from_slice(&[0u8; 48]);
        req.extend_from_slice(&[0u8; 48]);
        req.extend_from_slice(&[0u8; 2592]);
        req.extend_from_slice(sig.as_bytes());
        req
    }

    fn authorized_req(sub_cmd: u32, payload: &[u8]) -> Vec<u8> {
        authorized_req_with_sig(sub_cmd, payload, &HybridSignature::default())
    }

    /// Deterministic test signature containing the complete signed preimage.
    /// The production verifier performs ECC and ML-DSA verification over this
    /// same `cmd_id(BE) || payload || challenge(48)` byte sequence.
    fn test_signature(cmd_id: u32, payload: &[u8], challenge: &[u8; 48]) -> HybridSignature {
        let mut sig = HybridSignature::default();
        sig.as_mut_bytes().fill(0x3C);
        let preimage_len = 4 + payload.len() + challenge.len();
        let preimage = &mut sig.as_mut_bytes()[..preimage_len];
        preimage[..4].copy_from_slice(&cmd_id.to_be_bytes());
        preimage[4..4 + payload.len()].copy_from_slice(payload);
        preimage[4 + payload.len()..].copy_from_slice(challenge);
        sig
    }

    fn issue_test_challenge(cmds: &TestCommands) {
        let mut req = vec![
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::AuthorizedCommand as u8,
        ];
        req.extend_from_slice(&GET_AUTH_CHALLENGE_CMD_ID.to_le_bytes());
        let (response, inline, _) = dispatch(cmds, &req, 64, 0);
        assert_inline(response, 51);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
    }

    fn export_attested_csr_req() -> Vec<u8> {
        let mut req = vec![
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::ExportAttestedCsr as u8,
        ];
        req.extend_from_slice(&7u32.to_le_bytes());
        req.extend_from_slice(&1u32.to_le_bytes());
        req.extend_from_slice(&[0x5A; 32]);
        req
    }

    #[test]
    fn bad_command_version_returns_vdm_completion() {
        let cmds = TestCommands::new(0);
        let (response, inline, _) = dispatch(
            &cmds,
            &[0x7F, CaliptraVdmCommand::RequestDebugUnlock as u8],
            32,
            0,
        );

        assert_inline(response, 3);
        assert_eq!(
            &inline[..3],
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::RequestDebugUnlock as u8,
                CaliptraCompletionCode::InvalidCommandVersion as u8,
            ]
        );
    }

    #[test]
    fn invalid_payload_length_returns_vdm_completion() {
        let cmds = TestCommands::new(0);
        let (response, inline, _) = dispatch(
            &cmds,
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::ExportAttestedCsr as u8,
                0,
            ],
            32,
            64,
        );

        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::InvalidPayloadSize as u8);
    }

    #[test]
    fn unsupported_command_returns_vdm_completion() {
        let cmds = TestCommands::new(0);
        let (response, inline, _) = dispatch(
            &cmds,
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::GetAttestation as u8,
            ],
            32,
            0,
        );

        assert_inline(response, 3);
        assert_eq!(
            &inline[..3],
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::GetAttestation as u8,
                CaliptraCompletionCode::UnsupportedOperation as u8,
            ]
        );
    }

    #[test]
    fn export_attested_csr_uses_inline_response_when_it_fits() {
        let cmds = TestCommands::new(12);
        let req = export_attested_csr_req();
        let (response, inline, _) = dispatch(&cmds, &req, 64, 64);

        assert_inline(response, 2 + 1 + 4 + 12);
        assert_eq!(inline[0], CALIPTRA_VDM_COMMAND_VERSION);
        assert_eq!(inline[1], CaliptraVdmCommand::ExportAttestedCsr as u8);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(u32::from_le_bytes(inline[3..7].try_into().unwrap()), 12);
        assert_eq!(&inline[7..19], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn export_attested_csr_allows_empty_inline_csr() {
        let cmds = TestCommands::new(0);
        let req = export_attested_csr_req();
        let (response, inline, _) = dispatch(&cmds, &req, 2 + 1 + 4, 0);

        assert_inline(response, 2 + 1 + 4);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(u32::from_le_bytes(inline[3..7].try_into().unwrap()), 0);
    }

    #[test]
    fn export_attested_csr_uses_large_response_when_inline_is_too_small() {
        let cmds = TestCommands::new(12);
        let req = export_attested_csr_req();
        let (response, _inline, large) = dispatch(&cmds, &req, 10, 64);

        assert_large(response, 2 + 1 + 4 + 12);
        assert_eq!(large[0], CALIPTRA_VDM_COMMAND_VERSION);
        assert_eq!(large[1], CaliptraVdmCommand::ExportAttestedCsr as u8);
        assert_eq!(large[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(u32::from_le_bytes(large[3..7].try_into().unwrap()), 12);
        assert_eq!(&large[7..19], &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test]
    fn request_debug_unlock_returns_unique_device_id_and_challenge() {
        let cmds = TestCommands::new(0);
        let req = [
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::RequestDebugUnlock as u8,
            7,
        ];
        let (response, inline, _) = dispatch(&cmds, &req, 128, 0);

        assert_inline(
            response,
            2 + 1 + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE,
        );
        assert_eq!(inline[0], CALIPTRA_VDM_COMMAND_VERSION);
        assert_eq!(inline[1], CaliptraVdmCommand::RequestDebugUnlock as u8);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(
            &inline[3..3 + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE],
            &[0x11; DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE]
        );
        assert_eq!(
            &inline[3 + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE
                ..3 + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE],
            &[0x22; DEBUG_UNLOCK_CHALLENGE_SIZE]
        );
    }

    #[test]
    fn request_debug_unlock_rejects_trailing_payload() {
        let cmds = TestCommands::new(0);
        let req = [
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::RequestDebugUnlock as u8,
            7,
            0xaa,
        ];
        let (response, inline, _) = dispatch(&cmds, &req, 128, 0);

        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::InvalidPayloadSize as u8);
    }

    #[test]
    fn authorized_fuse_commands_parse_golden_packets() {
        let cases = [
            (
                PROVISION_VENDOR_PK_HASH_CMD_ID,
                {
                    let mut payload = vec![];
                    payload.extend_from_slice(&2u32.to_le_bytes());
                    payload.extend_from_slice(&[0x5A; 48]);
                    payload
                },
                AuthorizedOperation::ProvisionVendorPkHash {
                    slot: 2,
                    hash: [0x5A; 48],
                },
            ),
            (
                INCREASE_CALIPTRA_MIN_SVN_CMD_ID,
                {
                    let mut payload = vec![];
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&17u32.to_le_bytes());
                    payload
                },
                AuthorizedOperation::IncreaseCaliptraMinSvn { flags: 0, svn: 17 },
            ),
            (
                REVOKE_VENDOR_PUB_KEY_CMD_ID,
                {
                    let mut payload = vec![];
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&3u32.to_le_bytes());
                    payload.extend_from_slice(&2u32.to_le_bytes());
                    payload.extend_from_slice(&7u32.to_le_bytes());
                    payload
                },
                AuthorizedOperation::RevokeVendorPubKey {
                    reserved: 0,
                    slot: 3,
                    key_type: 2,
                    key_index: 7,
                },
            ),
            (
                REVOKE_VENDOR_PK_HASH_CMD_ID,
                {
                    let mut payload = vec![];
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    payload.extend_from_slice(&4u32.to_le_bytes());
                    payload
                },
                AuthorizedOperation::RevokeVendorPkHash {
                    reserved: 0,
                    slot: 4,
                },
            ),
            (
                FUSE_LOCK_PARTITION_CMD_ID,
                0x0Eu32.to_le_bytes().to_vec(),
                AuthorizedOperation::FuseLockPartition { partition: 0x0E },
            ),
        ];

        for (sub_cmd, payload, expected) in cases {
            let cmds = TestCommands::new(0).with_authorization();
            issue_test_challenge(&cmds);
            let sig = test_signature(sub_cmd, &payload, &TEST_AUTH_CHALLENGE);
            let req = authorized_req_with_sig(sub_cmd, &payload, &sig);
            assert_eq!(&req[2..6], &sub_cmd.to_le_bytes());
            assert_eq!(&req[6..6 + payload.len()], payload.as_slice());

            let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
            assert_inline(response, 3);
            assert_eq!(
                &inline[..3],
                &[
                    CALIPTRA_VDM_COMMAND_VERSION,
                    CaliptraVdmCommand::AuthorizedCommand as u8,
                    CaliptraCompletionCode::Success as u8,
                ]
            );
            assert_eq!(
                cmds.authorized_operation.lock().unwrap().take(),
                Some(expected)
            );
        }
    }

    #[test]
    fn authorized_fuse_commands_reject_missing_truncated_and_oversized_signatures() {
        let payloads = [
            (PROVISION_VENDOR_PK_HASH_CMD_ID, vec![0u8; 52]),
            (INCREASE_CALIPTRA_MIN_SVN_CMD_ID, vec![0u8; 8]),
            (REVOKE_VENDOR_PUB_KEY_CMD_ID, vec![0u8; 16]),
            (REVOKE_VENDOR_PK_HASH_CMD_ID, vec![0u8; 8]),
            (FUSE_LOCK_PARTITION_CMD_ID, vec![0u8; 4]),
        ];

        for (sub_cmd, payload) in payloads {
            let cmds = TestCommands::new(0);
            let mut missing = vec![
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::AuthorizedCommand as u8,
            ];
            missing.extend_from_slice(&sub_cmd.to_le_bytes());
            missing.extend_from_slice(&payload);
            for req in [
                missing,
                {
                    let mut req = authorized_req(sub_cmd, &payload);
                    req.pop();
                    req
                },
                {
                    let mut req = authorized_req(sub_cmd, &payload);
                    req.push(0xA5);
                    req
                },
            ] {
                let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
                assert_inline(response, 3);
                assert_eq!(inline[2], CaliptraCompletionCode::InvalidPayloadSize as u8);
            }
        }
    }

    #[test]
    fn authorized_command_rejects_bad_signature_and_consumes_challenge() {
        let cmds = TestCommands::new(0).with_authorization();
        let payload = [0u8; 8];
        issue_test_challenge(&cmds);
        let bad_req = authorized_req(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload);

        let (response, inline, _) = dispatch(&cmds, &bad_req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);

        // This signature is valid for the original challenge, but verification
        // must fail because the bad attempt already consumed that challenge.
        let sig = test_signature(
            INCREASE_CALIPTRA_MIN_SVN_CMD_ID,
            &payload,
            &TEST_AUTH_CHALLENGE,
        );
        let valid_req = authorized_req_with_sig(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &sig);
        let (response, inline, _) = dispatch(&cmds, &valid_req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);

        // The same signed preimage succeeds after obtaining a fresh challenge.
        issue_test_challenge(&cmds);
        let (response, inline, _) = dispatch(&cmds, &valid_req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
    }

    #[test]
    fn authorized_command_rejects_signature_for_wrong_command() {
        let cmds = TestCommands::new(0).with_authorization();
        issue_test_challenge(&cmds);
        let payload = [0u8; 8];
        let sig = test_signature(
            PROVISION_VENDOR_PK_HASH_CMD_ID,
            &payload,
            &TEST_AUTH_CHALLENGE,
        );
        let req = authorized_req_with_sig(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &sig);

        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);
    }

    #[test]
    fn authorized_command_rejects_signature_for_wrong_payload_or_challenge() {
        let cmds = TestCommands::new(0).with_authorization();
        let payload = [0u8; 8];

        issue_test_challenge(&cmds);
        let sig = test_signature(
            INCREASE_CALIPTRA_MIN_SVN_CMD_ID,
            &[1u8; 8],
            &TEST_AUTH_CHALLENGE,
        );
        let req = authorized_req_with_sig(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &sig);
        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);

        issue_test_challenge(&cmds);
        let sig = test_signature(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &[0x5A; 48]);
        let req = authorized_req_with_sig(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &sig);
        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);
    }

    #[test]
    fn authorized_command_rejects_reused_challenge() {
        let cmds = TestCommands::new(0).with_authorization();
        issue_test_challenge(&cmds);
        let payload = [0u8; 8];
        let sig = test_signature(
            INCREASE_CALIPTRA_MIN_SVN_CMD_ID,
            &payload,
            &TEST_AUTH_CHALLENGE,
        );
        let req = authorized_req_with_sig(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &payload, &sig);

        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);

        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);
    }

    #[test]
    fn authorized_command_maps_authorization_failures() {
        let cmds = TestCommands::new(0);
        cmds.authorization_error
            .lock()
            .unwrap()
            .replace(CaliptraCompletionCode::AccessDenied);
        let req = authorized_req(INCREASE_CALIPTRA_MIN_SVN_CMD_ID, &[0u8; 8]);

        let (response, inline, _) = dispatch(&cmds, &req, 16, 0);
        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::AccessDenied as u8);
        assert_eq!(*cmds.authorized_operation.lock().unwrap(), None);
    }

    #[test]
    fn get_auth_challenge_returns_48_bytes() {
        let cmds = TestCommands::new(0);
        let mut req = vec![
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::AuthorizedCommand as u8,
        ];
        req.extend_from_slice(&GET_AUTH_CHALLENGE_CMD_ID.to_le_bytes());

        let (response, inline, _) = dispatch(&cmds, &req, 64, 0);
        assert_inline(response, 3 + 48);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(&inline[3..51], &[0xA5; 48]);
    }

    #[test]
    fn authorize_debug_unlock_token_accepts_large_request_payload() {
        let cmds = TestCommands::new(0);
        let token = vec![0xA5; 1024];
        let mut req = vec![
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::AuthorizeDebugUnlockToken as u8,
        ];
        req.extend_from_slice(&token);
        let (response, inline, _) = dispatch(&cmds, &req, 32, 0);

        assert_inline(response, 3);
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
        assert_eq!(cmds.authorized_token.lock().unwrap().take(), Some(token));
    }
}
