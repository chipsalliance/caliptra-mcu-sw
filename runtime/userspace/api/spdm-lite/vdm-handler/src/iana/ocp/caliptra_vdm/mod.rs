// Licensed under the Apache-2.0 license

//! Caliptra VENDOR_DEFINED Message (VDM) backend.
//!
//! Implements [`SpdmVdmBackend`] for the Caliptra VDM protocol (IANA standards
//! body, vendor id [`CALIPTRA_VENDOR_ID`]). The backend decodes the
//! Caliptra VDM message header, dispatches the command, and frames the response.
//! Per-command device operations are provided by the platform through the
//! [`CaliptraVdmCommands`] PAL hook — the protocol/dispatch stays in this lib,
//! only the device work crosses to the platform.

mod commands;

use mcu_error::codes::INVARIANT;
use mcu_spdm_lite_codec::StandardsBodyId;
use mcu_spdm_lite_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};

pub use mcu_spdm_lite_codec::vendor_defined::iana::ocp::caliptra::{
    CaliptraCompletionCode, CaliptraVdmCmdResult, CaliptraVdmCommand, CaliptraVdmResult,
    CALIPTRA_VDM_COMMAND_VERSION, CALIPTRA_VENDOR_ID,
};

/// Caliptra VDM message header length: `[command_version, command_code]`.
const VDM_HEADER_LEN: usize = 2;
/// Maximum CSR/log payload staged in one Caliptra VDM response.
const MAX_LARGE_COMMAND_DATA_LEN: usize = 4 * 1024;
/// Maximum complete Caliptra VDM large payload:
/// `[command_version, command_code, completion, data_len, data...]`.
const MAX_LARGE_VDM_PAYLOAD_LEN: usize = VDM_HEADER_LEN + 1 + 4 + MAX_LARGE_COMMAND_DATA_LEN;

/// Platform hook for executing Caliptra VDM commands ("device operations").
///
/// The protocol and dispatch layers live in this crate; the platform implements
/// this trait to perform the actual device work (e.g. Caliptra mailbox calls).
/// Each method writes its command-specific response data into `out` and returns
/// the number of bytes written, or a [`CaliptraCompletionCode`] on failure
/// (surfaced as a VDM error completion, not an SPDM error).
///
/// `scratch` gives each device op the request-scoped scratch allocator so it can
/// stage device interactions without owning persistent buffers.
pub trait CaliptraVdmCommands {
    /// Drains log bytes of `log_type` into `out`.
    async fn get_log<A: SpdmPalAlloc>(
        &self,
        log_type: u32,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<CaliptraVdmLogResult>;

    /// Clears the log identified by `log_type`.
    async fn clear_log<A: SpdmPalAlloc>(&self, log_type: u32, scratch: &A)
        -> CaliptraVdmResult<()>;

    /// Requests a production debug unlock challenge for `unlock_level`, writing
    /// `[unique_device_identifier, challenge]` into `out`.
    async fn request_debug_unlock<A: SpdmPalAlloc>(
        &self,
        unlock_level: u8,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;

    /// Submits a production debug unlock token. `token_data` is the remaining
    /// command payload exactly as sent by the requester.
    async fn authorize_debug_unlock_token<A: SpdmPalAlloc>(
        &self,
        token_data: &[u8],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;

    /// Exports an attested CSR for `device_key_id` using `algorithm` and `nonce`,
    /// writing the raw CSR bytes into `out` and returning their length.
    async fn export_attested_csr<A: SpdmPalAlloc>(
        &self,
        device_key_id: u32,
        algorithm: u32,
        nonce: &[u8; 32],
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;

    /// Generates an authorization challenge nonce into `out`.
    async fn get_auth_challenge<A: SpdmPalAlloc>(
        &self,
        scratch: &A,
        out: &mut [u8],
    ) -> CaliptraVdmResult<usize>;

    /// Verifies `mac` for FE_PROG and programs field entropy for `partition`.
    async fn program_field_entropy<A: SpdmPalAlloc>(
        &self,
        partition: u32,
        mac: &[u8; 48],
        scratch: &A,
    ) -> CaliptraVdmResult<()>;
}

/// Result metadata for log-drain commands.
pub struct CaliptraVdmLogResult {
    /// Number of bytes written into the caller-provided log buffer.
    pub bytes_written: usize,
    /// Indicates whether more log data remains to be drained.
    pub more_data: bool,
}

/// Caliptra VDM backend, parameterized over a platform [`CaliptraVdmCommands`] hook.
pub struct CaliptraVdm<'a, H: CaliptraVdmCommands> {
    cmds: &'a H,
}

impl<'a, H: CaliptraVdmCommands> CaliptraVdm<'a, H> {
    /// Creates a backend that dispatches commands to `cmds`.
    pub fn new(cmds: &'a H) -> Self {
        Self { cmds }
    }
}

impl<H: CaliptraVdmCommands> SpdmVdmBackend for CaliptraVdm<'_, H> {
    // Caliptra VDM can emit responses (CSRs, logs) larger than one transport
    // frame, so the stack provisions the buffered large-response path.
    const USES_LARGE_RESPONSE: bool = true;
    const LARGE_RESPONSE_CAPACITY: usize = MAX_LARGE_VDM_PAYLOAD_LEN;

    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        registry.standard_id == StandardsBodyId::Iana.as_u16()
            && registry.vendor_id == CALIPTRA_VENDOR_ID.to_le_bytes()
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
            Ok(CaliptraVdmCommand::GetDebugLog) => {
                commands::get_debug_log::handle(self.cmds, cmd_req, scratch, payload).await
            }
            Ok(CaliptraVdmCommand::ClearDebugLog) => {
                commands::clear_debug_log::handle(self.cmds, cmd_req, scratch, payload).await
            }
            Ok(CaliptraVdmCommand::GetAttestationLog) => {
                commands::get_attestation_log::handle(self.cmds, cmd_req, scratch, payload).await
            }
            Ok(CaliptraVdmCommand::ClearAttestationLog) => {
                commands::clear_attestation_log::handle(self.cmds, cmd_req, scratch, payload).await
            }
            Ok(CaliptraVdmCommand::RequestDebugUnlock) => {
                commands::debug_unlock::handle_request_debug_unlock(
                    self.cmds, cmd_req, scratch, payload,
                )
                .await
            }
            Ok(CaliptraVdmCommand::AuthorizeDebugUnlockToken) => {
                commands::debug_unlock::handle_authorize_debug_unlock_token(
                    self.cmds, cmd_req, scratch, payload,
                )
                .await
            }
            Ok(CaliptraVdmCommand::ExportAttestedCsr) => {
                commands::export_attested_csr::handle(
                    self.cmds,
                    cmd_req,
                    command_code,
                    payload,
                    large,
                    scratch,
                )
                .await
            }
            Ok(CaliptraVdmCommand::AuthorizedCommand) => {
                commands::authorized_command::handle(self.cmds, cmd_req, scratch, payload).await
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

    use core::cell::RefCell;
    use core::future::Future;
    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use mcu_error::McuResult;
    use mcu_spdm_lite_traits::{
        SpdmPalAlloc, SpdmPalIo, SpdmPalIoKind, SpdmVdmBackend, VdmResponse, VdmResponseBuffer,
    };
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

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

    struct TestCommands {
        csr_len: usize,
        authorized_token: RefCell<Option<Vec<u8>>>,
    }

    impl TestCommands {
        fn new(csr_len: usize) -> Self {
            Self {
                csr_len,
                authorized_token: RefCell::new(None),
            }
        }

        fn write_csr(&self, out: &mut [u8]) -> CaliptraVdmResult<usize> {
            if out.len() < self.csr_len {
                return Err(CaliptraCompletionCode::InsufficientResources);
            }
            for (i, byte) in out[..self.csr_len].iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok(self.csr_len)
        }
    }

    impl CaliptraVdmCommands for TestCommands {
        async fn get_log<A: SpdmPalAlloc>(
            &self,
            _log_type: u32,
            _scratch: &A,
            _out: &mut [u8],
        ) -> CaliptraVdmResult<CaliptraVdmLogResult> {
            Err(CaliptraCompletionCode::UnsupportedOperation)
        }

        async fn clear_log<A: SpdmPalAlloc>(
            &self,
            _log_type: u32,
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            Err(CaliptraCompletionCode::UnsupportedOperation)
        }

        async fn request_debug_unlock<A: SpdmPalAlloc>(
            &self,
            unlock_level: u8,
            _scratch: &A,
            out: &mut [u8],
        ) -> CaliptraVdmResult<usize> {
            if unlock_level != 7 {
                return Err(CaliptraCompletionCode::InvalidParameter);
            }
            let needed = DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE;
            if out.len() < needed {
                return Err(CaliptraCompletionCode::InsufficientResources);
            }
            out[..DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE].fill(0x11);
            out[DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE..needed].fill(0x22);
            Ok(needed)
        }

        async fn authorize_debug_unlock_token<A: SpdmPalAlloc>(
            &self,
            token_data: &[u8],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            self.authorized_token.replace(Some(token_data.to_vec()));
            Ok(())
        }

        async fn export_attested_csr<A: SpdmPalAlloc>(
            &self,
            _device_key_id: u32,
            _algorithm: u32,
            _nonce: &[u8; 32],
            _scratch: &A,
            out: &mut [u8],
        ) -> CaliptraVdmResult<usize> {
            self.write_csr(out)
        }

        async fn get_auth_challenge<A: SpdmPalAlloc>(
            &self,
            _scratch: &A,
            out: &mut [u8],
        ) -> CaliptraVdmResult<usize> {
            if out.len() < 32 {
                return Err(CaliptraCompletionCode::InsufficientResources);
            }
            out[..32].copy_from_slice(&[0xA5; 32]);
            Ok(32)
        }

        async fn program_field_entropy<A: SpdmPalAlloc>(
            &self,
            _partition: u32,
            _mac: &[u8; 48],
            _scratch: &A,
        ) -> CaliptraVdmResult<()> {
            Ok(())
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
        let backend = CaliptraVdm::new(cmds);
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
        let (response, inline, _) =
            dispatch(&cmds, &[0x7F, CaliptraVdmCommand::GetDebugLog as u8], 32, 0);

        assert_inline(response, 3);
        assert_eq!(
            &inline[..3],
            &[
                CALIPTRA_VDM_COMMAND_VERSION,
                CaliptraVdmCommand::GetDebugLog as u8,
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
    fn request_debug_unlock_allows_trailing_payload() {
        let cmds = TestCommands::new(0);
        let req = [
            CALIPTRA_VDM_COMMAND_VERSION,
            CaliptraVdmCommand::RequestDebugUnlock as u8,
            7,
            0xaa,
            0xbb,
        ];
        let (response, inline, _) = dispatch(&cmds, &req, 128, 0);

        assert_inline(
            response,
            2 + 1 + DEBUG_UNLOCK_UNIQUE_DEVICE_ID_SIZE + DEBUG_UNLOCK_CHALLENGE_SIZE,
        );
        assert_eq!(inline[2], CaliptraCompletionCode::Success as u8);
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
        assert_eq!(cmds.authorized_token.take(), Some(token));
    }
}
