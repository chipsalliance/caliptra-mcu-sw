// Licensed under the Apache-2.0 license

//! PCI-SIG VENDOR_DEFINED protocols (Standards Body ID `PciSig`, 0x03).
//!
//! PCI-SIG protocols such as IDE-KM and TDISP are carried as SPDM
//! VENDOR_DEFINED messages inside a secured session on DOE. The first byte of
//! the PCI-SIG VDM payload selects the PCI-SIG protocol.

pub mod ide_km;
pub mod tdisp;

use caliptra_mcu_spdm_codec::errors::{
    SPDM_INVALID_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST,
};
use caliptra_mcu_spdm_codec::StandardsBodyId;
use caliptra_mcu_spdm_traits::{
    McuResult, SpdmPalAlloc, SpdmPalIo, SpdmVdmBackend, VdmRegistry, VdmResponse, VdmResponseBuffer,
};

/// PCI-SIG protocol identifier for TDISP.
pub const TDISP_PROTOCOL_ID: u8 = 0x01;

/// PCI-SIG VDM backend that dispatches protocol-id `0x01` to TDISP.
pub struct PciSigTdispVdm<D> {
    vendor_id: u16,
    tdisp: tdisp::TdispResponder<D>,
}

impl<D> PciSigTdispVdm<D> {
    /// Creates a PCI-SIG/TDISP VDM backend for `vendor_id`.
    pub const fn new(vendor_id: u16, tdisp: tdisp::TdispResponder<D>) -> Self {
        Self { vendor_id, tdisp }
    }

    #[inline]
    fn matches_envelope(&self, registry: &VdmRegistry<'_>) -> bool {
        pci_sig_envelope_matches(registry, self.vendor_id)
    }
}

impl<D> SpdmVdmBackend for PciSigTdispVdm<D>
where
    D: tdisp::TdispDriver,
{
    fn match_id(&self, registry: &VdmRegistry<'_>) -> bool {
        self.matches_envelope(registry)
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
        let VdmResponseBuffer { inline, alloc, .. } = rsp;
        let Some((&protocol_id, payload)) = req.split_first() else {
            return Err(SPDM_INVALID_REQUEST);
        };
        if protocol_id != TDISP_PROTOCOL_ID {
            return Err(SPDM_UNSUPPORTED_REQUEST);
        }
        handle_tdisp_protocol_payload(&self.tdisp, protocol_id, payload, inline, alloc).await
    }
}

#[inline]
fn pci_sig_envelope_matches(registry: &VdmRegistry<'_>, vendor_id: u16) -> bool {
    registry.standard_id == StandardsBodyId::PciSig.as_u16()
        && registry.vendor_id == vendor_id.to_le_bytes()
        && registry.secure_session
}

async fn handle_tdisp_protocol_payload<D, Alloc>(
    tdisp: &tdisp::TdispResponder<D>,
    protocol_id: u8,
    payload: &[u8],
    inline: &mut [u8],
    alloc: &Alloc,
) -> McuResult<VdmResponse>
where
    D: tdisp::TdispDriver,
    Alloc: SpdmPalAlloc,
{
    let Some(tdisp_inline) = inline.get_mut(1..) else {
        return Err(SPDM_UNSPECIFIED);
    };
    let response = tdisp
        .handle_tdisp_payload(payload, alloc, tdisp_inline)
        .await?;
    match response {
        VdmResponse::Inline(len) => {
            inline[0] = protocol_id;
            Ok(VdmResponse::Inline(len + 1))
        }
        VdmResponse::Large(_) => Err(SPDM_UNSPECIFIED),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use core::future::Future;
    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use caliptra_mcu_spdm_codec::{errors::SPDM_VERSION_MISMATCH, IDE_KM_PROTOCOL_ID};
    use caliptra_mcu_spdm_traits::{SpdmPalIoKind, VdmResponse};
    use std::boxed::Box;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::pci_sig::tdisp::{
        FunctionId, TdiStatus, TdispCommand, TdispDriver, TdispDriverResult, TdispErrorCode,
        TdispLockInterfaceParam, TdispReqCapabilities, TdispRespCapabilities, TdispResponder,
        TdispVersion, START_INTERFACE_NONCE_SIZE, TDISP_ERROR_INVALID_INTERFACE_STATE,
        TDISP_ERROR_INVALID_REQUEST, TDISP_VERSION_1_0,
    };

    const TEST_VENDOR_ID: u16 = 0x0001;
    const TDISP_HEADER_LEN: usize = 16;
    const TDISP_ERROR_RSP_LEN: usize = TDISP_HEADER_LEN + 8;
    const SUPPORTED_TDISP_VERSIONS: &[TdispVersion] = &[TdispVersion::V10];

    struct TestIo;

    impl SpdmPalIo for TestIo {
        fn kind(&self) -> SpdmPalIoKind {
            SpdmPalIoKind::SecuredMessage
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
            Ok(vec![0; len])
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
        type PersistentBox<T: Sized + 'static> = Box<T>;

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
            0
        }

        fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
            Ok(vec![0; len])
        }

        fn alloc_persistent<T: Sized + 'static>(
            &self,
            value: T,
        ) -> McuResult<Self::PersistentBox<T>> {
            Ok(Box::new(value))
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

    const TEST_REQ_MSGS_SUPPORTED: [u8; 16] = [
        0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    const TEST_ZERO_MMIO_REPORT: [u8; 20] = [0; 20];

    struct TestTdispDriver {
        state: Cell<TdiStatus>,
        nonce_counter: Cell<u8>,
    }

    impl TestTdispDriver {
        const fn new() -> Self {
            Self {
                state: Cell::new(TdiStatus::ConfigUnlocked),
                nonce_counter: Cell::new(0),
            }
        }
    }

    impl TdispDriver for TestTdispDriver {
        async fn generate_start_interface_nonce<Alloc>(
            &self,
            _scratch: &Alloc,
            out: &mut [u8; START_INTERFACE_NONCE_SIZE],
        ) -> TdispDriverResult<()>
        where
            Alloc: SpdmPalAlloc,
        {
            let start = self.nonce_counter.get().wrapping_add(1);
            self.nonce_counter.set(start);
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = start.wrapping_add(i as u8);
            }
            Ok(())
        }

        async fn get_capabilities<Alloc>(
            &self,
            _req_caps: TdispReqCapabilities,
            _scratch: &Alloc,
            resp_caps: &mut TdispRespCapabilities,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            *resp_caps = TdispRespCapabilities::new(0, TEST_REQ_MSGS_SUPPORTED, 0x07, 48, 0, 0);
            Ok(0)
        }

        async fn lock_interface<Alloc>(
            &self,
            _function_id: FunctionId,
            _param: TdispLockInterfaceParam,
            _scratch: &Alloc,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            if self.state.get() != TdiStatus::ConfigUnlocked {
                return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
            }
            self.state.set(TdiStatus::ConfigLocked);
            Ok(0)
        }

        async fn get_device_interface_report_len<Alloc>(
            &self,
            _function_id: FunctionId,
            _scratch: &Alloc,
            intf_report_len: &mut u16,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            *intf_report_len = if self.state.get() == TdiStatus::ConfigUnlocked {
                0
            } else {
                TEST_ZERO_MMIO_REPORT.len() as u16
            };
            Ok(0)
        }

        async fn get_device_interface_report<Alloc>(
            &self,
            _function_id: FunctionId,
            offset: u16,
            _scratch: &Alloc,
            report: &mut [u8],
            copied: &mut usize,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            let offset = offset as usize;
            if self.state.get() == TdiStatus::ConfigUnlocked
                || offset >= TEST_ZERO_MMIO_REPORT.len()
                || offset + report.len() > TEST_ZERO_MMIO_REPORT.len()
            {
                return Ok(TDISP_ERROR_INVALID_REQUEST);
            }
            let end = offset + report.len();
            report.copy_from_slice(&TEST_ZERO_MMIO_REPORT[offset..end]);
            *copied = report.len();
            Ok(0)
        }

        async fn get_device_interface_state<Alloc>(
            &self,
            _function_id: FunctionId,
            _scratch: &Alloc,
            tdi_state: &mut TdiStatus,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            *tdi_state = self.state.get();
            Ok(0)
        }

        async fn start_interface<Alloc>(
            &self,
            _function_id: FunctionId,
            _scratch: &Alloc,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            if self.state.get() != TdiStatus::ConfigLocked {
                return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
            }
            self.state.set(TdiStatus::Run);
            Ok(0)
        }

        async fn stop_interface<Alloc>(
            &self,
            _function_id: FunctionId,
            _scratch: &Alloc,
        ) -> TdispDriverResult<u32>
        where
            Alloc: SpdmPalAlloc,
        {
            if self.state.get() == TdiStatus::ConfigUnlocked {
                return Ok(TDISP_ERROR_INVALID_INTERFACE_STATE);
            }
            self.state.set(TdiStatus::ConfigUnlocked);
            Ok(0)
        }
    }

    fn backend() -> PciSigTdispVdm<TestTdispDriver> {
        PciSigTdispVdm::new(
            TEST_VENDOR_ID,
            TdispResponder::new(SUPPORTED_TDISP_VERSIONS, TestTdispDriver::new())
                .expect("test TDISP versions are non-empty"),
        )
    }

    fn registry(secure_session: bool) -> VdmRegistry<'static> {
        static VENDOR_ID: [u8; 2] = TEST_VENDOR_ID.to_le_bytes();
        VdmRegistry {
            standard_id: StandardsBodyId::PciSig.as_u16(),
            vendor_id: &VENDOR_ID,
            secure_session,
        }
    }

    fn request(message_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut req = Vec::with_capacity(1 + TDISP_HEADER_LEN + payload.len());
        req.push(TDISP_PROTOCOL_ID);
        req.push(TDISP_VERSION_1_0);
        req.push(message_type);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&1u32.to_le_bytes());
        req.extend_from_slice(&0u64.to_le_bytes());
        req.extend_from_slice(payload);
        req
    }

    fn dispatch(
        backend: &PciSigTdispVdm<TestTdispDriver>,
        req: &[u8],
        inline_len: usize,
    ) -> McuResult<(VdmResponse, Vec<u8>)> {
        let alloc = TestAlloc;
        let io = TestIo;
        let mut inline = vec![0; inline_len];
        let mut large = [];
        let response = block_on(backend.handle_request(
            req,
            VdmResponseBuffer {
                inline: &mut inline,
                large: &mut large,
                alloc: &alloc,
                io: &io,
            },
        ))?;
        Ok((response, inline))
    }

    fn assert_inline(response: VdmResponse, expected_len: usize) {
        match response {
            VdmResponse::Inline(len) => assert_eq!(len, expected_len),
            VdmResponse::Large(_) => panic!("expected inline response"),
        }
    }

    fn assert_tdisp_error(out: &[u8], error: TdispErrorCode, error_data: u32) {
        assert_tdisp_error_with_version(out, TDISP_VERSION_1_0, error, error_data);
    }

    fn assert_tdisp_error_with_version(
        out: &[u8],
        version: u8,
        error: TdispErrorCode,
        error_data: u32,
    ) {
        assert_eq!(out[0], TDISP_PROTOCOL_ID);
        assert_eq!(out[1], version);
        assert_eq!(out[2], TdispCommand::ErrorResponse as u8);
        assert_eq!(u32::from_le_bytes(out[17..21].try_into().unwrap()), error);
        assert_eq!(
            u32::from_le_bytes(out[21..25].try_into().unwrap()),
            error_data
        );
    }

    #[test]
    fn secure_session_get_tdisp_version_matches_and_frames_response() {
        let backend = backend();
        assert!(backend.match_id(&registry(true)));

        let req = request(TdispCommand::GetTdispVersion as u8, &[]);
        let (response, out) = dispatch(&backend, &req, 64).expect("GET_TDISP_VERSION succeeds");

        assert_inline(response, 1 + TDISP_HEADER_LEN + 2);
        assert_eq!(out[0], TDISP_PROTOCOL_ID);
        assert_eq!(out[1], TDISP_VERSION_1_0);
        assert_eq!(out[2], TdispCommand::TdispVersion as u8);
        assert_eq!(out[17], 1);
        assert_eq!(out[18], TDISP_VERSION_1_0);
    }

    #[test]
    fn get_capabilities_matches_expected_sample_after_get_version() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let req = request(TdispCommand::GetTdispCapabilities as u8, &[0; 4]);
        let (response, out) =
            dispatch(&backend, &req, 64).expect("GET_TDISP_CAPABILITIES succeeds");

        assert_inline(response, 1 + TDISP_HEADER_LEN + 28);
        assert_eq!(out[0], TDISP_PROTOCOL_ID);
        assert_eq!(out[2], TdispCommand::TdispCapabilities as u8);
        assert_eq!(u32::from_le_bytes(out[17..21].try_into().unwrap()), 0);
        let req_msgs_supported = &out[21..37];
        assert_eq!(req_msgs_supported[0], 0xfe);
        assert_eq!(&req_msgs_supported[1..], &[0u8; 15]);
        assert_eq!(u16::from_le_bytes(out[37..39].try_into().unwrap()), 0x07);
        assert_eq!(out[42], 48);
        assert_eq!(out[43], 0);
        assert_eq!(out[44], 0);
    }

    #[test]
    fn get_version_initializes_interface_unlocked() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let state = request(TdispCommand::GetDeviceInterfaceState as u8, &[]);
        let (response, out) = dispatch(&backend, &state, 64).expect("state succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN + 1);
        assert_eq!(out[2], TdispCommand::DeviceInterfaceState as u8);
        assert_eq!(out[17], 0);
    }

    #[test]
    fn commands_follow_interface_initialization_rules() {
        let backend = backend();
        let caps = request(TdispCommand::GetTdispCapabilities as u8, &[0; 4]);
        let (response, out) = dispatch(&backend, &caps, 64).expect("capabilities succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN + 28);
        assert_eq!(out[2], TdispCommand::TdispCapabilities as u8);

        let state = request(TdispCommand::GetDeviceInterfaceState as u8, &[]);
        let (response, out) = dispatch(&backend, &state, 64).expect("state succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN + 1);
        assert_eq!(out[2], TdispCommand::DeviceInterfaceState as u8);
        assert_eq!(out[17], 0);

        let stop = request(TdispCommand::StopInterfaceRequest as u8, &[]);
        let (response, out) = dispatch(&backend, &stop, 64).expect("TDISP error is framed");
        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_INTERFACE_STATE, 0);
    }

    #[test]
    fn plaintext_tdisp_registry_is_not_matched() {
        let backend = backend();
        assert!(!backend.match_id(&registry(false)));
    }

    #[test]
    fn unsupported_pci_sig_protocol_id_is_rejected() {
        let backend = backend();
        let mut req = request(TdispCommand::GetTdispVersion as u8, &[]);
        req[0] = IDE_KM_PROTOCOL_ID;

        let err = match dispatch(&backend, &req, 64) {
            Ok(_) => panic!("IDE-KM protocol id is unsupported"),
            Err(err) => err,
        };
        assert_eq!(err, SPDM_UNSUPPORTED_REQUEST);
    }

    #[test]
    fn response_opcode_returns_invalid_request_error() {
        let backend = backend();
        let req = request(TdispCommand::TdispVersion as u8, &[]);
        let err = match dispatch(&backend, &req, 64) {
            Ok(_) => panic!("response opcode is invalid"),
            Err(err) => err,
        };
        assert_eq!(err, SPDM_INVALID_REQUEST);
    }

    #[test]
    fn unsupported_request_opcode_checks_payload_length_before_error_classification() {
        let backend = backend();
        let req = request(TdispCommand::BindP2PStreamRequest as u8, &[1, 2, 3]);
        let (response, out) = dispatch(&backend, &req, 64).expect("TDISP error is framed");

        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_REQUEST, 0);
    }

    #[test]
    fn bad_version_unsupported_opcode_returns_spdm_error_without_tdisp_response() {
        const BAD_VERSION: u8 = 0xff;
        let backend = backend();
        let mut req = request(TdispCommand::BindP2PStreamRequest as u8, &[]);
        req[1] = BAD_VERSION;
        let err = match dispatch(&backend, &req, 64) {
            Ok(_) => panic!("bad TDISP version should not frame a TDISP response"),
            Err(err) => err,
        };

        assert_eq!(err, SPDM_VERSION_MISMATCH);
    }

    #[test]
    fn bad_version_malformed_supported_request_returns_spdm_error_without_tdisp_response() {
        const BAD_VERSION: u8 = 0xff;
        let backend = backend();
        let mut req = request(TdispCommand::GetTdispCapabilities as u8, &[0]);
        req[1] = BAD_VERSION;
        let err = match dispatch(&backend, &req, 64) {
            Ok(_) => panic!("bad TDISP version should not frame a TDISP response"),
            Err(err) => err,
        };

        assert_eq!(err, SPDM_VERSION_MISMATCH);
    }

    #[test]
    fn bad_version_well_formed_supported_request_returns_spdm_error_without_tdisp_response() {
        const BAD_VERSION: u8 = 0xff;
        let backend = backend();
        let mut req = request(TdispCommand::GetTdispCapabilities as u8, &[0; 4]);
        req[1] = BAD_VERSION;
        let err = match dispatch(&backend, &req, 64) {
            Ok(_) => panic!("bad TDISP version should not frame a TDISP response"),
            Err(err) => err,
        };

        assert_eq!(err, SPDM_VERSION_MISMATCH);
    }

    #[test]
    fn lock_start_stop_nonce_flow_reports_invalid_interface_state_for_nonce_mismatch() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let lock = request(TdispCommand::LockInterface as u8, &[0; 20]);
        let (response, out) = dispatch(&backend, &lock, 64).expect("LOCK_INTERFACE succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN + 32);
        assert_eq!(out[2], TdispCommand::LockInterfaceResponse as u8);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&out[17..49]);

        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 0xff;
        let start_wrong = request(TdispCommand::StartInterfaceRequest as u8, &wrong_nonce);
        let (response, out) = dispatch(&backend, &start_wrong, 64).expect("TDISP error is framed");
        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_INTERFACE_STATE, 0);

        let start = request(TdispCommand::StartInterfaceRequest as u8, &nonce);
        let (response, out) = dispatch(&backend, &start, 64).expect("START_INTERFACE succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN);
        assert_eq!(out[2], TdispCommand::StartInterfaceResponse as u8);

        let stop = request(TdispCommand::StopInterfaceRequest as u8, &[]);
        let (response, out) = dispatch(&backend, &stop, 64).expect("STOP_INTERFACE succeeds");
        assert_inline(response, 1 + TDISP_HEADER_LEN);
        assert_eq!(out[2], TdispCommand::StopInterfaceResponse as u8);

        let (response, out) = dispatch(&backend, &stop, 64).expect("TDISP error is framed");
        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_INTERFACE_STATE, 0);
    }

    #[test]
    fn repeated_get_version_resets_pending_start_nonce() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let lock = request(TdispCommand::LockInterface as u8, &[0; 20]);
        let (_response, out) = dispatch(&backend, &lock, 64).expect("LOCK_INTERFACE succeeds");
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&out[17..49]);

        dispatch(&backend, &get_version, 64).expect("GET_TDISP_VERSION succeeds again");

        let start = request(TdispCommand::StartInterfaceRequest as u8, &nonce);
        let (response, out) = dispatch(&backend, &start, 64).expect("TDISP error is framed");
        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_INTERFACE_STATE, 0);
    }

    #[test]
    fn stop_rejects_initialized_unlocked_interface() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let stop = request(TdispCommand::StopInterfaceRequest as u8, &[]);
        let (response, out) = dispatch(&backend, &stop, 64).expect("TDISP error is framed");
        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_INTERFACE_STATE, 0);
    }

    #[test]
    fn device_report_response_is_bounded_by_request_and_remaining_report() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");
        let lock = request(TdispCommand::LockInterface as u8, &[0; 20]);
        dispatch(&backend, &lock, 64).expect("LOCK_INTERFACE succeeds");

        let mut report_req = Vec::new();
        report_req.extend_from_slice(&4u16.to_le_bytes());
        report_req.extend_from_slice(&20u16.to_le_bytes());
        let report = request(TdispCommand::GetDeviceInterfaceReport as u8, &report_req);
        let (response, out) = dispatch(&backend, &report, 64).expect("report succeeds");

        assert_inline(response, 1 + TDISP_HEADER_LEN + 4 + 16);
        assert_eq!(out[2], TdispCommand::DeviceInterfaceReport as u8);
        assert_eq!(u16::from_le_bytes(out[17..19].try_into().unwrap()), 16);
        assert_eq!(u16::from_le_bytes(out[19..21].try_into().unwrap()), 0);
    }

    #[test]
    fn device_report_response_is_bounded_by_response_buffer_after_header() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");
        let lock = request(TdispCommand::LockInterface as u8, &[0; 20]);
        dispatch(&backend, &lock, 64).expect("LOCK_INTERFACE succeeds");

        let mut report_req = Vec::new();
        report_req.extend_from_slice(&0u16.to_le_bytes());
        report_req.extend_from_slice(&20u16.to_le_bytes());
        let report = request(TdispCommand::GetDeviceInterfaceReport as u8, &report_req);
        let (response, out) = dispatch(&backend, &report, 29).expect("report succeeds");

        assert_inline(response, 1 + TDISP_HEADER_LEN + 4 + 8);
        assert_eq!(out[2], TdispCommand::DeviceInterfaceReport as u8);
        assert_eq!(u16::from_le_bytes(out[17..19].try_into().unwrap()), 8);
        assert_eq!(u16::from_le_bytes(out[19..21].try_into().unwrap()), 12);
    }

    #[test]
    fn device_report_rejects_zero_length_request() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let mut report_req = Vec::new();
        report_req.extend_from_slice(&0u16.to_le_bytes());
        report_req.extend_from_slice(&0u16.to_le_bytes());
        let report = request(TdispCommand::GetDeviceInterfaceReport as u8, &report_req);
        let (response, out) = dispatch(&backend, &report, 64).expect("TDISP error is framed");

        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_REQUEST, 0);
    }

    #[test]
    fn emulated_device_report_before_lock_returns_invalid_request() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");

        let mut report_req = Vec::new();
        report_req.extend_from_slice(&0u16.to_le_bytes());
        report_req.extend_from_slice(&0x40u16.to_le_bytes());
        let report = request(TdispCommand::GetDeviceInterfaceReport as u8, &report_req);
        let (response, out) = dispatch(&backend, &report, 64).expect("TDISP error is framed");

        assert_inline(response, 1 + TDISP_ERROR_RSP_LEN);
        assert_tdisp_error(&out, TDISP_ERROR_INVALID_REQUEST, 0);
    }

    #[test]
    fn emulated_device_report_after_lock_is_valid_zero_mmio_structure() {
        let backend = backend();
        let get_version = request(TdispCommand::GetTdispVersion as u8, &[]);
        dispatch(&backend, &get_version, 64).expect("interface initialized");
        let lock = request(TdispCommand::LockInterface as u8, &[0; 20]);
        dispatch(&backend, &lock, 64).expect("LOCK_INTERFACE succeeds");

        let mut report_req = Vec::new();
        report_req.extend_from_slice(&0u16.to_le_bytes());
        report_req.extend_from_slice(&0x40u16.to_le_bytes());
        let report = request(TdispCommand::GetDeviceInterfaceReport as u8, &report_req);
        let (response, out) = dispatch(&backend, &report, 64).expect("report succeeds");

        assert_inline(response, 1 + TDISP_HEADER_LEN + 4 + 20);
        assert_eq!(u16::from_le_bytes(out[17..19].try_into().unwrap()), 20);
        assert_eq!(u16::from_le_bytes(out[19..21].try_into().unwrap()), 0);
        let report = &out[21..41];
        assert_eq!(u32::from_le_bytes(report[12..16].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(report[16..20].try_into().unwrap()), 0);
    }
}
