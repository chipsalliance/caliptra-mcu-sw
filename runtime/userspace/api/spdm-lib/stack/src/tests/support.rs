// Licensed under the Apache-2.0 license

#![allow(dead_code)]

extern crate std;

use caliptra_mcu_spdm_codec::{
    AsymAlgos, CapFlags, HashAlgos, ReqRespCode, SpdmVersion, AES_256_GCM_TAG_SIZE,
    CHUNK_ATTR_LAST_CHUNK, SECURED_MSG_HDR_SIZE,
};
use caliptra_mcu_spdm_traits::{
    MeasurementInfo, SpdmPalAlloc, SpdmPalAsymAlgo, SpdmPalCertStore, SpdmPalHash, SpdmPalHashAlgo,
    SpdmPalIo, SpdmPalIoKind, SpdmPalIoTransport, SpdmPalMeasurements, SpdmPalSessionCrypto,
    SPDM_NONCE_LEN,
};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use futures::executor::block_on;
use mcu_error::{McuErrorCode, McuResult};
use std::boxed::Box;
use std::cell::RefCell;
use std::vec;
use std::vec::Vec;

use crate::stack::{ConnectionState, Phase, Sessions};

pub const SHA384_DIGEST_SIZE: usize = 48;
pub const SPDM_CERT_CHAIN_HDR_LEN: usize = 4 + SHA384_DIGEST_SIZE;
pub const TEST_CERT_CHAIN: &[u8] = &[0x30, 0x03, 1, 2, 3, 0x30, 0x01, 4];

#[derive(Clone)]
pub struct TestHashState {
    digest: [u8; SHA384_DIGEST_SIZE],
}

pub struct TestIo {
    pub request: Vec<u8>,
    kind: SpdmPalIoKind,
}

impl TestIo {
    pub fn message(request: Vec<u8>) -> Self {
        Self {
            request,
            kind: SpdmPalIoKind::Message,
        }
    }

    pub fn secured(request: Vec<u8>) -> Self {
        Self {
            request,
            kind: SpdmPalIoKind::SecuredMessage,
        }
    }
}

impl SpdmPalIo for TestIo {
    fn kind(&self) -> SpdmPalIoKind {
        self.kind
    }

    fn request(&self) -> &[u8] {
        &self.request
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StoreOp {
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

pub struct TestBox<'a, T: 'a> {
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

pub struct TestPal {
    pub mtu: usize,
    pub supported_slots: u8,
    pub authorized: bool,
    pub validate_error: Option<McuErrorCode>,
    pub write_error: Option<McuErrorCode>,
    pub erase_error: Option<McuErrorCode>,
    pub cert_chain: &'static [u8],
    pub op: RefCell<Option<StoreOp>>,
    pub stream_cert: RefCell<Vec<u8>>,
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
            cert_chain: TEST_CERT_CHAIN,
            op: RefCell::new(None),
            stream_cert: RefCell::new(Vec::new()),
        }
    }
}

impl mcu_caliptra_api_lite::ApiAlloc for TestPal {
    type Buf<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
        Ok(vec![0u8; len])
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
    type LargeBuf = Vec<u8>;

    fn alloc<T: Sized>(&self, _io: &impl SpdmPalIo, value: T) -> McuResult<Self::Box<'_, T>> {
        Ok(TestBox {
            value: Box::new(value),
            _lifetime: PhantomData,
        })
    }

    fn alloc_bytes(&self, _io: &impl SpdmPalIo, len: usize) -> McuResult<Self::Bytes<'_>> {
        Ok(vec![0u8; len])
    }

    fn large_capacity(&self) -> usize {
        self.mtu
    }

    fn alloc_large_buf(&self, len: usize) -> McuResult<Self::LargeBuf> {
        Ok(vec![0u8; len])
    }

    type PersistentBox<T: Sized + 'static> = Box<T>;

    fn alloc_persistent<T: Sized + 'static>(&self, value: T) -> McuResult<Self::PersistentBox<T>> {
        Ok(Box::new(value))
    }
}

impl SpdmPalIoTransport for TestPal {
    type Io<'a>
        = TestIo
    where
        Self: 'a;

    fn secure_message_supported(&self) -> bool {
        true
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

    fn hash_clone(&self, _io: &impl SpdmPalIo, state: &Self::State) -> McuResult<Self::State> {
        Ok(state.clone())
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

    #[cfg(feature = "set-certificate")]
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

    #[cfg(feature = "set-certificate")]
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
        Ok(self.cert_chain.len())
    }

    async fn cert_chain_slot_size(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
    ) -> McuResult<usize> {
        Ok(self.cert_chain.len())
    }

    async fn root_cert_hash(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        _hash_algo: SpdmPalHashAlgo,
        out: &mut [u8],
    ) -> McuResult<()> {
        out.copy_from_slice(&test_digest(&self.cert_chain[..5]));
        Ok(())
    }

    async fn read_cert_chain(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        dst: &mut [u8],
    ) -> McuResult<usize> {
        let end = (offset + dst.len()).min(self.cert_chain.len());
        let src = &self.cert_chain[offset..end];
        dst[..src.len()].copy_from_slice(src);
        Ok(src.len())
    }

    async fn sign_hash(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        _digest: &[u8],
        signature: &mut [u8],
    ) -> McuResult<usize> {
        signature.fill(0x77);
        Ok(signature.len())
    }

    #[cfg(feature = "set-certificate")]
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

    async fn begin_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; SHA384_DIGEST_SIZE],
        data_len: usize,
    ) -> McuResult<()> {
        if let Some(err) = self.write_error {
            return Err(err);
        }
        let mut data = self.stream_cert.borrow_mut();
        data.clear();
        data.resize(data_len, 0);
        let _ = (slot, key_pair_id, cert_model, root_hash);
        Ok(())
    }

    async fn write_cert_chain_stream_chunk(
        &self,
        _io: &Self::Io<'_>,
        _slot: u8,
        _algo: SpdmPalAsymAlgo,
        offset: usize,
        data: &[u8],
    ) -> McuResult<()> {
        let mut cert = self.stream_cert.borrow_mut();
        cert[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    async fn finish_write_cert_chain_stream(
        &self,
        _io: &Self::Io<'_>,
        slot: u8,
        _algo: SpdmPalAsymAlgo,
        key_pair_id: u8,
        cert_model: u8,
        root_hash: &[u8; SHA384_DIGEST_SIZE],
        _data_len: usize,
    ) -> McuResult<()> {
        if let Some(err) = self.validate_error {
            return Err(err);
        }
        let cert_chain = self.stream_cert.borrow().clone();
        let first_len = cert_chain
            .get(1)
            .copied()
            .map(|len| len as usize + 2)
            .unwrap_or(0);
        if first_len == 0
            || first_len > cert_chain.len()
            || test_digest(&cert_chain[..first_len]) != *root_hash
        {
            return Err(mcu_error::codes::INVARIANT);
        }
        self.op.replace(Some(StoreOp::Write {
            slot,
            key_pair_id,
            cert_model,
            root_hash: *root_hash,
            cert_chain,
        }));
        Ok(())
    }
    #[cfg(feature = "set-certificate")]
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

impl SpdmPalMeasurements for TestPal {
    fn measurement_info(&self) -> &[MeasurementInfo] {
        &[]
    }

    async fn get_measurement_value(
        &self,
        _io: &Self::Io<'_>,
        _index: u8,
        _nonce: Option<&[u8; SPDM_NONCE_LEN]>,
        _out: &mut [u8],
    ) -> McuResult<usize> {
        Err(mcu_error::codes::NOT_IMPLEMENTED)
    }
}

impl SpdmPalSessionCrypto for TestPal {
    type Key = u8;

    async fn ecdh_generate(
        &self,
        _io: &impl SpdmPalIo,
        _context: &mut [u8],
        _exchange_data: &mut [u8],
    ) -> McuResult<()> {
        Ok(())
    }

    async fn ecdh_finish(
        &self,
        _io: &impl SpdmPalIo,
        _context: &[u8],
        _peer_exchange_data: &[u8],
    ) -> McuResult<Self::Key> {
        Ok(1)
    }

    async fn hkdf_extract_bytes(
        &self,
        _io: &impl SpdmPalIo,
        _salt: &[u8],
        _ikm: &Self::Key,
    ) -> McuResult<Self::Key> {
        Ok(1)
    }

    async fn hkdf_extract_key(
        &self,
        _io: &impl SpdmPalIo,
        _salt: &Self::Key,
        _ikm: &Self::Key,
    ) -> McuResult<Self::Key> {
        Ok(1)
    }

    async fn hkdf_expand(
        &self,
        _io: &impl SpdmPalIo,
        _prk: &Self::Key,
        _key_size: u32,
        _info: &[u8],
    ) -> McuResult<Self::Key> {
        Ok(1)
    }

    async fn hmac(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        data: &[u8],
        out: &mut [u8],
    ) -> McuResult<usize> {
        let n = out.len().min(data.len());
        out[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }

    async fn import_key(&self, _io: &impl SpdmPalIo, _data: &[u8]) -> McuResult<Self::Key> {
        Ok(1)
    }

    async fn aead_encrypt(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        _spdm_version: u8,
        _seq: u64,
        _aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> McuResult<(usize, [u8; 16])> {
        ciphertext[..plaintext.len()].copy_from_slice(plaintext);
        Ok((plaintext.len(), [0u8; 16]))
    }

    async fn aead_decrypt(
        &self,
        _io: &impl SpdmPalIo,
        _key: &Self::Key,
        _spdm_version: u8,
        _seq: u64,
        _aad: &[u8],
        ciphertext: &[u8],
        _tag: &[u8; 16],
        plaintext: &mut [u8],
    ) -> McuResult<usize> {
        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        Ok(ciphertext.len())
    }
}

impl caliptra_mcu_spdm_traits::SpdmPal for TestPal {}

pub fn test_digest(data: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
    let mut digest = [0u8; SHA384_DIGEST_SIZE];
    digest[0] = data.len() as u8;
    digest[1] = data.first().copied().unwrap_or_default();
    digest[2] = data.last().copied().unwrap_or_default();
    digest
}

pub fn der_chain() -> Vec<u8> {
    TEST_CERT_CHAIN.to_vec()
}

pub fn cert_payload(der: &[u8], root_hash: [u8; SHA384_DIGEST_SIZE]) -> Vec<u8> {
    let len = SPDM_CERT_CHAIN_HDR_LEN + der.len();
    let mut payload = Vec::with_capacity(len);
    payload.extend_from_slice(&(len as u16).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&root_hash);
    payload.extend_from_slice(der);
    payload
}

pub fn set_certificate_io(
    version: SpdmVersion,
    attributes: u8,
    key_pair_id: u8,
    payload: &[u8],
) -> TestIo {
    let mut request = vec![
        version.to_u8(),
        ReqRespCode::SET_CERTIFICATE.0,
        attributes,
        key_pair_id,
    ];
    request.extend_from_slice(payload);
    TestIo::message(request)
}

pub fn set_certificate_request(pal: &TestPal) -> Vec<u8> {
    let der = pal.cert_chain;
    let payload = cert_payload(der, test_digest(&der[..5]));
    let mut req = vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::SET_CERTIFICATE.0,
        1,
        0,
    ];
    req.extend_from_slice(&payload);
    req
}

pub fn split_large_request(req: &[u8]) -> (&[u8], &[u8]) {
    req.split_at(26)
}

pub fn chunk_send_request(
    handle: u8,
    seq: u16,
    last_chunk: bool,
    large_msg_size: Option<usize>,
    chunk: &[u8],
) -> Vec<u8> {
    let mut req = vec![
        SpdmVersion::V12.to_u8(),
        ReqRespCode::CHUNK_SEND.0,
        if last_chunk { CHUNK_ATTR_LAST_CHUNK } else { 0 },
        handle,
    ];
    req.extend_from_slice(&seq.to_le_bytes());
    req.extend_from_slice(&0u16.to_le_bytes());
    req.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    if let Some(size) = large_msg_size {
        req.extend_from_slice(&(size as u32).to_le_bytes());
    }
    req.extend_from_slice(chunk);
    req
}

pub fn secured_io(session_id: u32, spdm_msg: &[u8]) -> TestIo {
    let plaintext_len = 2 + spdm_msg.len();
    let mut req = Vec::with_capacity(SECURED_MSG_HDR_SIZE + plaintext_len + AES_256_GCM_TAG_SIZE);
    req.extend_from_slice(&session_id.to_le_bytes());
    req.extend_from_slice(&((plaintext_len + AES_256_GCM_TAG_SIZE) as u16).to_le_bytes());
    req.extend_from_slice(&(spdm_msg.len() as u16).to_le_bytes());
    req.extend_from_slice(spdm_msg);
    req.extend_from_slice(&[0u8; AES_256_GCM_TAG_SIZE]);
    TestIo::secured(req)
}

pub fn secured_spdm_response(rsp: &[u8]) -> &[u8] {
    let msg_len = u16::from_le_bytes([rsp[6], rsp[7]]) as usize;
    &rsp[8..8 + msg_len]
}

pub fn negotiated_state(version: SpdmVersion) -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = ConnectionState::default();
    state.phase = Phase::AfterAlgorithms;
    state.version = version;
    state.advertised_cap_flags = state.cap_flags;
    state.negotiated_base_hash_sel = HashAlgos::SHA_384;
    state.negotiated_base_asym_sel = AsymAlgos::ECDSA_ECC_NIST_P384;
    state
}

pub fn chunking_state() -> ConnectionState<TestHashState, Vec<u8>> {
    let mut state = negotiated_state(SpdmVersion::V12);
    state.peer_cap_flags = CapFlags::CHUNK;
    state
}

pub fn handshake_session(
    pal: &TestPal,
) -> (
    ConnectionState<TestHashState, Vec<u8>>,
    Sessions<TestPal, 1>,
    u32,
) {
    let empty_io = TestIo::message(Vec::new());
    let state = chunking_state();
    let mut sessions = crate::session::SessionManager::new();
    let session_id = sessions
        .create_session(0x1234, SpdmVersion::V12, |info| pal.alloc_persistent(info))
        .unwrap();
    let session = sessions.find_mut(session_id).unwrap();
    session.key_schedule.set_dhe_secret(1);
    block_on(session.key_schedule.generate_handshake_keys(
        pal,
        &empty_io,
        &[0u8; SHA384_DIGEST_SIZE],
    ))
    .unwrap();
    (state, sessions, session_id)
}

pub fn established_session(
    pal: &TestPal,
) -> (
    ConnectionState<TestHashState, Vec<u8>>,
    Sessions<TestPal, 1>,
    u32,
) {
    let empty_io = TestIo::message(Vec::new());
    let (state, mut sessions, session_id) = handshake_session(pal);
    let session = sessions.find_mut(session_id).unwrap();
    block_on(
        session
            .key_schedule
            .generate_data_keys(pal, &empty_io, &[0u8; SHA384_DIGEST_SIZE]),
    )
    .unwrap();
    session.key_schedule.destroy_handshake_secrets();
    session.state = crate::session::SessionState::Established;
    (state, sessions, session_id)
}
