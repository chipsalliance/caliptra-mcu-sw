// Licensed under the Apache-2.0 license

//! SET_CERTIFICATE → SET_CERTIFICATE_RSP handler.
//!
//! The incoming certificate payload already resides in the per-exchange
//! receive buffer. This handler validates the SPDM cert-chain wrapper in
//! place and passes borrowed DER bytes to the PAL, avoiding a second
//! certificate-sized allocation.

use mcu_error::McuErrorCode;
use mcu_spdm_lite_codec::{
    AsymAlgos, CapFlags, HashAlgos, ReqRespCode, SetCertificateReqBody, SetCertificateRsp,
    SpdmMsgHdrPdu, SpdmVersion,
};
use mcu_spdm_lite_errors::as_spdm_wire;
use mcu_spdm_lite_traits::{
    PalBytes, SpdmPal, SpdmPalIo, SpdmPalIoTransport, MAX_SLOTS,
};
use zerocopy::FromBytes;

use crate::build::build_response;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_SESSION_REQUIRED, SPDM_UNEXPECTED_REQUEST,
    SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::stack::{multi_key_conn_rsp, ConnectionState, Phase};

const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_DIGEST_SIZE;
const SHA384_DIGEST_SIZE: usize = 48;
const CERT_MODEL_DEVICE_CERT: u8 = 1;
const CERT_MODEL_ALIAS_CERT: u8 = 2;
const CERT_MODEL_GENERIC_CERT: u8 = 3;

pub(crate) async fn handle_set_certificate<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if (state.phase as u8) < (Phase::AfterAlgorithms as u8) {
        return Err(SPDM_UNEXPECTED_REQUEST);
    }
    if !state.advertised_cap_flags.contains(CapFlags::SET_CERT) {
        return Err(unsupported_set_certificate());
    }

    let req = io.request();
    if req.len() > pal.mtu() {
        return Err(SPDM_INVALID_REQUEST);
    }
    let (hdr, body) = SpdmMsgHdrPdu::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    if hdr.version != state.version.to_u8() {
        return Err(SPDM_VERSION_MISMATCH);
    }
    if state.version < SpdmVersion::V12 {
        return Err(unsupported_set_certificate());
    }

    let req_body = SetCertificateReqBody::ref_from_bytes(
        body.get(..SetCertificateReqBody::SIZE)
            .ok_or(SPDM_INVALID_REQUEST)?,
    )
    .map_err(|_| SPDM_INVALID_REQUEST)?;
    let payload = body
        .get(SetCertificateReqBody::SIZE..)
        .ok_or(SPDM_INVALID_REQUEST)?;

    let slot_id = req_body.slot_id();
    validate_request_slot(slot_id, pal.supported_slots())?;

    let erase = req_body.erase();
    let cert_model = if erase {
        0
    } else {
        effective_cert_model(state, req_body)?
    };
    if !pal.set_certificate_authorized(io, slot_id, req_body.key_pair_id, cert_model, erase) {
        return Err(SPDM_SESSION_REQUIRED);
    }

    validate_request_attributes(state, req_body)?;
    validate_negotiated_set_certificate_algorithms(state)?;

    if erase {
        if !payload.is_empty() || req_body.cert_model() != 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
        pal.erase_cert_chain(io, slot_id, state.asym_algo()).await?;
    } else {
        let (root_hash, der) = validate_spdm_cert_chain(payload)?;
        pal.validate_set_certificate_chain(
            io,
            slot_id,
            req_body.key_pair_id,
            cert_model,
            root_hash,
            der,
        )
        .await
        .map_err(map_set_cert_validation_error)?;
        pal.write_cert_chain(
            io,
            slot_id,
            state.asym_algo(),
            req_body.key_pair_id,
            cert_model,
            root_hash,
            der,
        )
        .await?;
    }

    build_response(pal, io, state.version, &SetCertificateRsp { slot_id })
}

fn unsupported_set_certificate() -> SpdmError {
    SPDM_UNSUPPORTED_REQUEST.with_data(ReqRespCode::SET_CERTIFICATE.0)
}

fn validate_request_slot(slot_id: u8, supported_slots: u8) -> SpdmResult<()> {
    // Caliptra's Vendor certificate lives in slot 0 and is read-only;
    // SET_CERTIFICATE may only provision mutable owner/device slots.
    if slot_id == 0 || slot_id >= MAX_SLOTS {
        return Err(SPDM_INVALID_REQUEST);
    }
    if supported_slots & (1u8 << slot_id) == 0 {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

fn validate_request_attributes<S: Clone>(
    state: &ConnectionState<S>,
    req: &SetCertificateReqBody,
) -> SpdmResult<()> {
    if state.version < SpdmVersion::V13 {
        if req.key_pair_id != 0 || req.cert_model() != 0 || req.erase() {
            return Err(SPDM_INVALID_REQUEST);
        }
        return Ok(());
    }

    if multi_key_conn_rsp(state)? {
        if req.key_pair_id == 0 {
            return Err(SPDM_INVALID_REQUEST);
        }
        if !req.erase()
            && !(CERT_MODEL_DEVICE_CERT..=CERT_MODEL_GENERIC_CERT).contains(&req.cert_model())
        {
            return Err(SPDM_INVALID_REQUEST);
        }
    } else if req.key_pair_id != 0 || req.cert_model() != 0 {
        return Err(SPDM_INVALID_REQUEST);
    }

    Ok(())
}

fn effective_cert_model<S: Clone>(
    state: &ConnectionState<S>,
    req: &SetCertificateReqBody,
) -> SpdmResult<u8> {
    if multi_key_conn_rsp(state)? && req.cert_model() != 0 {
        Ok(req.cert_model())
    } else {
        Ok(cert_model_from_capabilities(state.advertised_cap_flags))
    }
}

fn cert_model_from_capabilities(cap_flags: CapFlags) -> u8 {
    if cap_flags.contains(CapFlags::ALIAS_CERT) {
        CERT_MODEL_ALIAS_CERT
    } else {
        CERT_MODEL_DEVICE_CERT
    }
}

fn validate_negotiated_set_certificate_algorithms<S: Clone>(
    state: &ConnectionState<S>,
) -> SpdmResult<()> {
    if state.negotiated_base_hash_sel != HashAlgos::SHA_384 {
        return Err(SPDM_UNSPECIFIED);
    }
    if state.negotiated_base_asym_sel != AsymAlgos::ECDSA_ECC_NIST_P384 {
        return Err(SPDM_INVALID_REQUEST);
    }
    Ok(())
}

fn validate_spdm_cert_chain(
    payload: &[u8],
) -> SpdmResult<(&[u8; SHA384_DIGEST_SIZE], &[u8])> {
    if payload.len() < SPDM_CERT_CHAIN_HDR_LEN {
        return Err(SPDM_INVALID_REQUEST);
    }

    let length = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    let reserved = u16::from_le_bytes([payload[2], payload[3]]);
    if reserved != 0 || length != payload.len() || length < SPDM_CERT_CHAIN_HDR_LEN {
        return Err(SPDM_INVALID_REQUEST);
    }

    let der = &payload[SPDM_CERT_CHAIN_HDR_LEN..];
    if der.is_empty() {
        return Err(SPDM_INVALID_REQUEST);
    }
    // Validate DER framing of the chain; PAL re-walks and is responsible
    // for verifying SHA-384(root cert) == root_hash.
    let _root_cert_len = validate_der_chain(der)?;

    let root_hash: &[u8; SHA384_DIGEST_SIZE] = payload[4..SPDM_CERT_CHAIN_HDR_LEN]
        .try_into()
        .map_err(|_| SPDM_INVALID_REQUEST)?;
    Ok((root_hash, der))
}

fn validate_der_chain(der: &[u8]) -> SpdmResult<usize> {
    let mut offset = 0usize;
    let mut root_cert_len = None;
    while offset < der.len() {
        let cert_len = der_sequence_len(&der[offset..]).ok_or(SPDM_INVALID_REQUEST)?;
        if root_cert_len.is_none() {
            root_cert_len = Some(cert_len);
        }
        offset = offset.checked_add(cert_len).ok_or(SPDM_INVALID_REQUEST)?;
    }
    root_cert_len.ok_or(SPDM_INVALID_REQUEST)
}

fn der_sequence_len(input: &[u8]) -> Option<usize> {
    if input.len() < 2 || input[0] != 0x30 {
        return None;
    }

    let len_byte = input[1];
    let (header_len, content_len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let len_len = (len_byte & 0x7f) as usize;
        if len_len == 0 || len_len > 4 || input.len() < 2 + len_len {
            return None;
        }
        let mut content_len = 0usize;
        for &byte in &input[2..2 + len_len] {
            content_len = content_len.checked_shl(8)?;
            content_len = content_len.checked_add(byte as usize)?;
        }
        (2 + len_len, content_len)
    };

    if content_len == 0 {
        return None;
    }
    let total_len = header_len.checked_add(content_len)?;
    (total_len <= input.len()).then_some(total_len)
}

fn map_set_cert_validation_error(err: McuErrorCode) -> SpdmError {
    as_spdm_wire(err)
        .map(SpdmError::new)
        .unwrap_or(SPDM_INVALID_REQUEST)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::error::{SPDM_BUSY, SPDM_OPERATION_FAILED, SPDM_RESET_REQUIRED, SPDM_UNSPECIFIED};
    use core::marker::PhantomData;
    use core::ops::{Deref, DerefMut};
    use futures::executor::block_on;
    use mcu_error::McuErrorCode;
    use mcu_spdm_lite_codec::{errors as wire_errors, OtherParamSupport, ReqRespCode};
    use mcu_spdm_lite_traits::{
        McuResult, SpdmPalAlloc, SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHash, SpdmPalHashAlgo,
        SpdmPalIoKind, SpdmPalLargeMessage,
    };
    use std::boxed::Box;
    use std::cell::RefCell;
    use std::vec;
    use std::vec::Vec;

    #[derive(Clone)]
    struct TestHashState {
        digest: [u8; SHA384_DIGEST_SIZE],
    }

    struct TestIo {
        request: Vec<u8>,
    }

    impl SpdmPalIo for TestIo {
        fn kind(&self) -> SpdmPalIoKind {
            SpdmPalIoKind::Message
        }

        fn request(&self) -> &[u8] {
            &self.request
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum StoreOp {
        Write {
            slot: u8,
            key_pair_id: u8,
            cert_model: u8,
            root_hash: [u8; SHA384_DIGEST_SIZE],
            cert_chain: Vec<u8>,
        },
        Erase {
            slot: u8,
        },
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

    struct TestPal {
        mtu: usize,
        supported_slots: u8,
        authorized: bool,
        validate_error: Option<McuErrorCode>,
        write_error: Option<McuErrorCode>,
        erase_error: Option<McuErrorCode>,
        op: RefCell<Option<StoreOp>>,
    }

    impl Default for TestPal {
        fn default() -> Self {
            Self {
                mtu: 1024,
                supported_slots: u8::MAX,
                authorized: true,
                validate_error: None,
                write_error: None,
                erase_error: None,
                op: RefCell::new(None),
            }
        }
    }

    impl SpdmPalAlloc for TestPal {
        type Box<'a, T>
            = TestBox<'a, T>
        where
            Self: 'a,
            T: 'a;
        type Bytes<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>> {
            Ok(TestBox {
                value: Box::new(value),
                _lifetime: PhantomData,
            })
        }

        fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>> {
            Ok(vec![0u8; len])
        }
    }

    impl SpdmPalIoTransport for TestPal {
        type Io<'a>
            = TestIo
        where
            Self: 'a;

        fn secure_message_supported(&self) -> bool {
            false
        }

        fn header_size(&self) -> usize {
            0
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        async fn recv_request(&self) -> McuResult<Self::Io<'_>> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }

        async fn send_response(
            &self,
            _io: &Self::Io<'_>,
            _kind: SpdmPalIoKind,
            _msg: &mut [u8],
        ) -> McuResult<()> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }
    }

    impl SpdmPalLargeMessage for TestPal {
        fn capacity(&self) -> usize {
            self.mtu
        }

        fn write(&self, _offset: usize, _data: &[u8]) -> McuResult<()> {
            Ok(())
        }

        fn read(&self, _offset: usize, out: &mut [u8]) -> McuResult<()> {
            out.fill(0);
            Ok(())
        }
    }

    impl SpdmPalHash for TestPal {
        type State = TestHashState;

        async fn hash_init(
            &self,
            _io: &impl SpdmPalIo,
            _algo: SpdmPalHashAlgo,
            seed: &[u8],
        ) -> McuResult<Self::State> {
            Ok(TestHashState {
                digest: test_digest(seed),
            })
        }

        async fn hash_update(
            &self,
            _io: &impl SpdmPalIo,
            state: &mut Self::State,
            data: &[u8],
        ) -> McuResult<()> {
            state.digest = test_digest(data);
            Ok(())
        }

        async fn hash_finish(
            &self,
            _io: &impl SpdmPalIo,
            state: &mut Self::State,
            out: &mut [u8],
        ) -> McuResult<()> {
            out[..SHA384_DIGEST_SIZE].copy_from_slice(&state.digest);
            Ok(())
        }
    }

    impl SpdmPalCertStore for TestPal {
        fn provisioned_slots(&self) -> u8 {
            0
        }

        fn supported_slots(&self) -> u8 {
            self.supported_slots
        }

        fn set_certificate_authorized(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _key_pair_id: u8,
            _cert_model: u8,
            _erase: bool,
        ) -> bool {
            self.authorized
        }

        async fn validate_set_certificate_chain(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _key_pair_id: u8,
            _cert_model: u8,
            _root_hash: &[u8; SHA384_DIGEST_SIZE],
            _cert_chain: &[u8],
        ) -> McuResult<()> {
            if let Some(err) = self.validate_error {
                Err(err)
            } else {
                Ok(())
            }
        }

        async fn cert_chain_len(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _algo: SpdmPalAsymAlgo,
        ) -> McuResult<usize> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }

        async fn root_cert_hash(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _algo: SpdmPalAsymAlgo,
            _hash_algo: SpdmPalHashAlgo,
            _out: &mut [u8],
        ) -> McuResult<()> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }

        async fn read_cert_chain(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _algo: SpdmPalAsymAlgo,
            _offset: usize,
            _dst: &mut [u8],
        ) -> McuResult<usize> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }

        async fn sign_hash(
            &self,
            _io: &Self::Io<'_>,
            _slot: u8,
            _algo: SpdmPalAsymAlgo,
            _digest: &[u8],
            _signature: &mut [u8],
        ) -> McuResult<usize> {
            Err(mcu_error::codes::NOT_IMPLEMENTED)
        }

        async fn write_cert_chain(
            &self,
            _io: &Self::Io<'_>,
            slot: u8,
            _algo: SpdmPalAsymAlgo,
            key_pair_id: u8,
            cert_model: u8,
            root_hash: &[u8; SHA384_DIGEST_SIZE],
            cert_chain: &[u8],
        ) -> McuResult<()> {
            if let Some(err) = self.write_error {
                return Err(err);
            }
            self.op.replace(Some(StoreOp::Write {
                slot,
                key_pair_id,
                cert_model,
                root_hash: *root_hash,
                cert_chain: cert_chain.to_vec(),
            }));
            Ok(())
        }

        async fn erase_cert_chain(
            &self,
            _io: &Self::Io<'_>,
            slot: u8,
            _algo: SpdmPalAsymAlgo,
        ) -> McuResult<()> {
            if let Some(err) = self.erase_error {
                return Err(err);
            }
            self.op.replace(Some(StoreOp::Erase { slot }));
            Ok(())
        }

        fn key_pair_id(&self, _slot: u8) -> Option<u8> {
            None
        }

        fn cert_info(&self, _slot: u8) -> Option<u8> {
            None
        }

        fn key_usage_mask(&self, _slot: u8) -> Option<u16> {
            None
        }

        async fn generate_nonce(&self, _io: &Self::Io<'_>, out: &mut [u8]) -> McuResult<()> {
            out.fill(0xA5);
            Ok(())
        }
    }

    impl SpdmPal for TestPal {}

    fn test_digest(data: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
        let mut digest = [0u8; SHA384_DIGEST_SIZE];
        digest[0] = data.len() as u8;
        digest[1] = data.first().copied().unwrap_or_default();
        digest[2] = data.last().copied().unwrap_or_default();
        digest
    }

    fn state(version: SpdmVersion) -> ConnectionState<TestHashState> {
        let mut state = ConnectionState::default();
        state.phase = Phase::AfterAlgorithms;
        state.version = version;
        state.advertised_cap_flags = state.cap_flags;
        state.negotiated_base_hash_sel = HashAlgos::SHA_384;
        state.negotiated_base_asym_sel = AsymAlgos::ECDSA_ECC_NIST_P384;
        state
    }

    fn state_v13_multi_key() -> ConnectionState<TestHashState> {
        let mut state = state(SpdmVersion::V13);
        state.other_param_sel = OtherParamSupport::MULTI_KEY_CONN;
        state.peer_cap_flags = CapFlags::MULTI_KEY_CONN_RSP;
        state
    }

    fn der_chain() -> Vec<u8> {
        vec![0x30, 0x03, 1, 2, 3, 0x30, 0x01, 4]
    }

    fn cert_payload(der: &[u8], root_hash: [u8; SHA384_DIGEST_SIZE]) -> Vec<u8> {
        let len = SPDM_CERT_CHAIN_HDR_LEN + der.len();
        let mut payload = Vec::with_capacity(len);
        payload.extend_from_slice(&(len as u16).to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&root_hash);
        payload.extend_from_slice(der);
        payload
    }

    fn request(version: SpdmVersion, attributes: u8, key_pair_id: u8, payload: &[u8]) -> TestIo {
        let mut request = vec![
            version.to_u8(),
            ReqRespCode::SET_CERTIFICATE.0,
            attributes,
            key_pair_id,
        ];
        request.extend_from_slice(payload);
        TestIo { request }
    }

    #[test]
    fn test_handle_set_certificate_v12_writes_cert_chain() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V12.to_u8(),
                ReqRespCode::SET_CERTIFICATE_RSP.0,
                1,
                0
            ]
        );
        assert_eq!(
            pal.op.take(),
            Some(StoreOp::Write {
                slot: 1,
                key_pair_id: 0,
                cert_model: CERT_MODEL_ALIAS_CERT,
                root_hash,
                cert_chain: der,
            })
        );
    }

    #[test]
    fn test_handle_set_certificate_v12_uses_device_cert_without_alias_cap() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        state.advertised_cap_flags = CapFlags::CERT
            | CapFlags::CHAL
            | CapFlags::MEAS_SIG
            | CapFlags::SET_CERT
            | CapFlags::MULTI_KEY_CONN_RSP;
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            pal.op.take(),
            Some(StoreOp::Write {
                slot: 1,
                key_pair_id: 0,
                cert_model: CERT_MODEL_DEVICE_CERT,
                root_hash,
                cert_chain: der,
            })
        );
    }

    #[test]
    fn test_handle_set_certificate_v13_non_multi_key_uses_alias_cert() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V13);
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let io = request(SpdmVersion::V13, 2, 0, &payload);

        block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            pal.op.take(),
            Some(StoreOp::Write {
                slot: 2,
                key_pair_id: 0,
                cert_model: CERT_MODEL_ALIAS_CERT,
                root_hash,
                cert_chain: der,
            })
        );
    }

    #[test]
    fn test_handle_set_certificate_v13_rejects_multikey_when_not_advertised() {
        let pal = TestPal::default();
        let mut state = state_v13_multi_key();
        state.advertised_cap_flags = CapFlags::CERT
            | CapFlags::CHAL
            | CapFlags::MEAS_SIG
            | CapFlags::ALIAS_CERT
            | CapFlags::SET_CERT;
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
        let io = request(SpdmVersion::V13, attributes, 7, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_v13_multi_key_writes_cert_chain() {
        let pal = TestPal::default();
        let mut state = state_v13_multi_key();
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
        let io = request(SpdmVersion::V13, attributes, 7, &payload);

        let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V13.to_u8(),
                ReqRespCode::SET_CERTIFICATE_RSP.0,
                2,
                0,
            ]
        );
        assert_eq!(
            pal.op.take(),
            Some(StoreOp::Write {
                slot: 2,
                key_pair_id: 7,
                cert_model: CERT_MODEL_GENERIC_CERT,
                root_hash,
                cert_chain: der,
            })
        );
    }

    #[test]
    fn test_handle_set_certificate_v13_multi_key_cap_one_writes_cert_chain() {
        let pal = TestPal::default();
        let mut state = state_v13_multi_key();
        state.advertised_cap_flags = CapFlags::from_bits(
            (state.advertised_cap_flags.into_bits() & !(0b11 << 26)) | (0b01 << 26),
        );
        let der = der_chain();
        let root_hash = test_digest(&der[..5]);
        let payload = cert_payload(&der, root_hash);
        let attributes = 2 | (CERT_MODEL_GENERIC_CERT << 4);
        let io = request(SpdmVersion::V13, attributes, 7, &payload);

        block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            pal.op.take(),
            Some(StoreOp::Write {
                slot: 2,
                key_pair_id: 7,
                cert_model: CERT_MODEL_GENERIC_CERT,
                root_hash,
                cert_chain: der,
            })
        );
    }

    #[test]
    fn test_handle_set_certificate_v13_erase_succeeds() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V13);
        let io = request(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

        let rsp = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap();

        assert_eq!(
            &rsp[..],
            &[
                SpdmVersion::V13.to_u8(),
                ReqRespCode::SET_CERTIFICATE_RSP.0,
                3,
                0,
            ]
        );
        assert_eq!(pal.op.take(), Some(StoreOp::Erase { slot: 3 }));
    }

    #[test]
    fn test_handle_set_certificate_rejects_unadvertised_capability() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        state.advertised_cap_flags = CapFlags::from_bits(
            state.advertised_cap_flags.into_bits() & !CapFlags::SET_CERT.into_bits(),
        );
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, unsupported_set_certificate());
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_request_larger_than_mtu() {
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);
        let pal = TestPal {
            mtu: io.request.len() - 1,
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_unsupported_slot() {
        let pal = TestPal {
            supported_slots: u8::MAX ^ (1u8 << 2),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 2, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_erase_for_unsupported_slot() {
        let pal = TestPal {
            supported_slots: u8::MAX ^ (1u8 << 3),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V13);
        let io = request(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_unnegotiated_hash_algo() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        state.negotiated_base_hash_sel = HashAlgos::EMPTY;
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_UNSPECIFIED);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_unnegotiated_base_asym_algo() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        state.negotiated_base_asym_sel = AsymAlgos::EMPTY;
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_checks_authorization_before_algorithms() {
        let pal = TestPal {
            authorized: false,
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        state.negotiated_base_hash_sel = HashAlgos::EMPTY;
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_SESSION_REQUIRED);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_reset_negotiation_clears_selected_algorithms() {
        let mut state = state(SpdmVersion::V13);

        state.reset_negotiation();

        assert_eq!(
            state.negotiated_base_hash_sel.into_bits(),
            HashAlgos::EMPTY.into_bits()
        );
        assert_eq!(
            state.negotiated_base_asym_sel.into_bits(),
            AsymAlgos::EMPTY.into_bits()
        );
        assert_eq!(
            state.advertised_cap_flags.into_bits(),
            CapFlags::EMPTY.into_bits()
        );
    }

    #[test]
    fn test_handle_set_certificate_rejects_unauthorized_request() {
        let pal = TestPal {
            authorized: false,
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_SESSION_REQUIRED);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_rejects_root_hash_mismatch() {
        let pal = TestPal::default();
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, [0xa5; SHA384_DIGEST_SIZE]);
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_validate_der_chain_rejects_trailing_garbage() {
        assert!(validate_der_chain(&[0x30, 0x01, 0x00, 0xff]).is_err());
    }

    #[test]
    fn test_handle_set_certificate_calls_pal_validation_before_write() {
        let pal = TestPal {
            validate_error: Some(mcu_error::codes::INVARIANT),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_INVALID_REQUEST);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_preserves_wire_validation_error() {
        let pal = TestPal {
            validate_error: Some(wire_errors::SPDM_OPERATION_FAILED),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_OPERATION_FAILED);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_preserves_wire_write_error() {
        let pal = TestPal {
            write_error: Some(wire_errors::SPDM_BUSY),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V12);
        let der = der_chain();
        let payload = cert_payload(&der, test_digest(&der[..5]));
        let io = request(SpdmVersion::V12, 1, 0, &payload);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_BUSY);
        assert_eq!(pal.op.take(), None);
    }

    #[test]
    fn test_handle_set_certificate_preserves_wire_erase_error() {
        let pal = TestPal {
            erase_error: Some(wire_errors::SPDM_RESET_REQUIRED),
            ..TestPal::default()
        };
        let mut state = state(SpdmVersion::V13);
        let io = request(SpdmVersion::V13, 3 | (1 << 7), 0, &[]);

        let err = block_on(handle_set_certificate(&mut state, &pal, &io)).unwrap_err();

        assert_eq!(err, SPDM_RESET_REQUIRED);
        assert_eq!(pal.op.take(), None);
    }
}
