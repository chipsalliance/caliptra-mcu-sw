// Licensed under the Apache-2.0 license

//! SPDM responder state machine and dispatcher.
//!
//! This module owns the [`SpdmStack`] run loop, the connection-scoped
//! [`ConnectionState`], and the [`Phase`] enum that enforces the
//! strict SPDM ordering
//! `GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS`. Per-command
//! handlers live in `algorithms`, `capabilities`, `certificate`,
//! `chunk`, `digests`, and `version`.
//!
//! `GET_VERSION` is legal in any phase; the dispatcher resets
//! connection-scoped state via [`ConnectionState::reset_negotiation`]
//! before invoking [`version::handle_get_version`] so the handler
//! itself is unaware of the phase.

use mcu_spdm_lite_codec::{
    encode_aad, AeadAlgos, AsymAlgos, CapFlags, DheAlgos, HashAlgos, KeyScheduleAlgos,
    MeasHashAlgos, MeasSpec, OtherParamSupport, ReqRespCode, SecuredMessageHeader, SpdmMsgHdrPdu,
    SpdmVersion, AES_256_GCM_TAG_SIZE, SECURED_MSG_HDR_SIZE,
};
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::build::{alloc_padded, build_error_response};
use crate::error::{
    SpdmError, SpdmResult, SPDM_DECRYPT_ERROR, SPDM_INVALID_REQUEST, SPDM_SESSION_REQUIRED,
    SPDM_UNEXPECTED_REQUEST, SPDM_UNSPECIFIED, SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::key_schedule::SessionKeyType;
use crate::session::{SessionManager, SessionState};
use crate::{
    algorithms, capabilities, certificate, challenge, chunk, digests, end_session, finish,
    key_exchange, measurements, vendor_defined, version,
};

/// Connection phase tracked on the responder so the dispatcher can
/// enforce the SPDM ordering
/// `GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS`.
///
/// `GET_VERSION` is legal in every phase (it resets the connection),
/// so phase checks live in the individual handlers and only reject
/// **out-of-order** messages, not late `GET_VERSION` calls.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Initial phase. Only `GET_VERSION` is accepted.
    Start,
    /// `GET_VERSION` exchanged. `GET_CAPABILITIES` is now legal.
    AfterVersion,
    /// `GET_CAPABILITIES` exchanged. `NEGOTIATE_ALGORITHMS` is now legal.
    AfterCapabilities,
    /// `NEGOTIATE_ALGORITHMS` exchanged. Ready for post-negotiation
    /// authentication and discovery commands.
    AfterAlgorithms,
    /// `GET_DIGESTS` completed.
    AfterDigests,
    /// `GET_CERTIFICATE` completed (may be re-issued multiple times
    /// for pagination).
    AfterCertificate,
}

/// Per-connection responder state.
///
/// Bundles two logically distinct concerns:
///
/// 1. **Local responder policy** (the upper block of fields). Set once
///    at construction and never modified during a connection — this is
///    what the responder advertises for `CAPABILITIES` and
///    `ALGORITHMS`.
/// 2. **Connection-scoped negotiation results** (the lower block).
///    Captured from the peer during the
///    `GET_VERSION` → `GET_CAPABILITIES` → `NEGOTIATE_ALGORITHMS`
///    handshake and reset on every `GET_VERSION` via
///    [`Self::reset_negotiation`].
pub struct ConnectionState<S> {
    // ---- Local responder policy (fixed at startup) -----------------------
    /// Responder `CT` time exponent.
    /// Maximum response time is `2^ct_exponent` µs.
    pub ct_exponent: u8,
    /// Responder capability bitmap advertised in `CAPABILITIES`.
    pub cap_flags: CapFlags,

    /// Measurement specification (always `DMTF` for this responder).
    pub measurement_spec: MeasSpec,
    /// `OtherParamSupport` bitmap advertised in `ALGORITHMS`.
    pub other_param_support: OtherParamSupport,
    /// Hash algorithm used for `MEASUREMENTS` digests.
    pub meas_hash_algo: MeasHashAlgos,
    /// Base asymmetric algorithm advertised for `CHALLENGE_AUTH`.
    pub base_asym_sel: AsymAlgos,
    /// Base hash algorithm (transcript hash + everything else).
    pub base_hash_sel: HashAlgos,
    /// Diffie-Hellman group bitmap for `KEY_EXCHANGE`.
    pub dhe: DheAlgos,
    /// AEAD suite bitmap for secured-message protection.
    pub aead: AeadAlgos,
    /// Key-schedule bitmap (always `SPDM` for this responder).
    pub key_schedule: KeyScheduleAlgos,

    // ---- Connection-scoped negotiation -----------------------------------
    /// Current connection phase.
    pub phase: Phase,
    /// Negotiated SPDM version. Defaults to the minimum supported
    /// version (V1.2) and is overwritten on a successful
    /// `GET_CAPABILITIES`.
    pub version: SpdmVersion,
    /// Peer-advertised `DataTransferSize` (V1.2+ `GET_CAPABILITIES`).
    pub peer_data_transfer_size: u32,
    /// Peer-advertised `MaxSPDMmsgSize` (V1.2+ `GET_CAPABILITIES`).
    pub peer_max_spdm_msg_size: u32,
    /// Effective local capability flags advertised in CAPABILITIES for this
    /// connection after version gating.
    pub advertised_cap_flags: CapFlags,
    /// Peer-advertised capability flags.
    pub peer_cap_flags: CapFlags,
    /// Negotiated OtherParamsSel from NEGOTIATE_ALGORITHMS.
    pub other_param_sel: OtherParamSupport,
    /// Negotiated BaseAsymSel from NEGOTIATE_ALGORITHMS.
    pub negotiated_base_asym_sel: AsymAlgos,
    /// Negotiated BaseHashSel from NEGOTIATE_ALGORITHMS.
    pub negotiated_base_hash_sel: HashAlgos,
    /// Transcript state (running VCA/M1/L1 hashes per SPDM).
    pub transcript: crate::transcript::Transcript<S>,
    /// In-progress CHUNK_SEND large-request reassembly state.
    pub(crate) chunk: chunk::ChunkState,
    /// Pending large response served by CHUNK_GET.
    pub(crate) large_response: chunk::LargeResponseState,
}

impl<S> ConnectionState<S> {
    /// Builds the Caliptra responder's fixed local-policy advertisement.
    ///
    /// # Returns
    ///
    /// A new `ConnectionState` with:
    ///
    /// * `ct_exponent = 20` (≈ 1 s — `2^20` µs).
    /// * `cap_flags = CERT | CHAL | MEAS_SIG | ALIAS_CERT | KEY_EX |
    ///   ENCRYPT | MAC | CHUNK`, plus SET_CERTIFICATE capabilities when
    ///   that test feature is enabled. `HANDSHAKE_IN_THE_CLEAR` is
    ///   intentionally omitted — FINISH is encrypted with handshake keys.
    /// * `measurement_spec = DMTF`, `meas_hash_algo = SHA_384`,
    ///   `base_asym_sel = ECDSA_ECC_NIST_P384`,
    ///   `base_hash_sel = SHA_384`.
    /// * `dhe = SECP_384_R1`, `aead = AES_256_GCM`,
    ///   `key_schedule = SPDM`, `other_param_support = OPAQUE_DATA_FMT1`.
    /// * `phase = Start`, `version = V12`, peer fields cleared.
    pub fn caliptra() -> Self {
        let cap_flags = CapFlags::CERT
            | CapFlags::CHAL
            | CapFlags::MEAS_SIG
            | CapFlags::ALIAS_CERT
            | CapFlags::KEY_EX
            | CapFlags::ENCRYPT
            | CapFlags::MAC
            | CapFlags::CHUNK
            | set_certificate_cap_flags();
        let other_param_support =
            OtherParamSupport::OPAQUE_DATA_FMT1 | set_certificate_other_params();

        Self {
            ct_exponent: 20, // 2^20 µs
            cap_flags,

            measurement_spec: MeasSpec::DMTF,
            other_param_support,
            meas_hash_algo: MeasHashAlgos::SHA_384,
            base_asym_sel: AsymAlgos::ECDSA_ECC_NIST_P384,
            base_hash_sel: HashAlgos::SHA_384,
            dhe: DheAlgos::SECP_384_R1,
            aead: AeadAlgos::AES_256_GCM,
            key_schedule: KeyScheduleAlgos::SPDM,

            phase: Phase::Start,
            version: SpdmVersion::V12,
            peer_data_transfer_size: 0,
            peer_max_spdm_msg_size: 0,
            advertised_cap_flags: CapFlags::EMPTY,
            peer_cap_flags: CapFlags::EMPTY,
            other_param_sel: OtherParamSupport::EMPTY,
            negotiated_base_asym_sel: AsymAlgos::EMPTY,
            negotiated_base_hash_sel: HashAlgos::EMPTY,
            transcript: crate::transcript::Transcript::new(),
            chunk: chunk::ChunkState::default(),
            large_response: chunk::LargeResponseState::default(),
        }
    }

    /// Drops every connection-scoped negotiation result.
    ///
    /// Called by the dispatcher on every `GET_VERSION` per SPDM
    /// Local-policy fields (the upper block) are not modified.
    pub(crate) fn reset_negotiation(&mut self) {
        self.phase = Phase::Start;
        self.version = SpdmVersion::V12;
        self.peer_data_transfer_size = 0;
        self.peer_max_spdm_msg_size = 0;
        self.advertised_cap_flags = CapFlags::EMPTY;
        self.peer_cap_flags = CapFlags::EMPTY;
        self.other_param_sel = OtherParamSupport::EMPTY;
        self.negotiated_base_asym_sel = AsymAlgos::EMPTY;
        self.negotiated_base_hash_sel = HashAlgos::EMPTY;
        self.transcript.reset();
        self.chunk.reset();
        self.large_response.reset();
    }

    /// Returns true when both peers negotiated CHUNK support.
    pub(crate) fn chunking_enabled(&self) -> bool {
        self.cap_flags.contains(CapFlags::CHUNK) && self.peer_cap_flags.contains(CapFlags::CHUNK)
    }

    pub(crate) fn effective_data_transfer_size<Pal: SpdmPal>(&self, pal: &Pal) -> usize {
        let peer = if self.peer_data_transfer_size == 0 {
            pal.mtu()
        } else {
            self.peer_data_transfer_size as usize
        };
        pal.mtu().min(peer)
    }

    pub(crate) fn effective_max_spdm_msg_size<Pal: SpdmPal>(&self, pal: &Pal) -> usize {
        let local = pal.large_capacity().max(pal.mtu());
        let peer = if self.peer_max_spdm_msg_size == 0 {
            local
        } else {
            self.peer_max_spdm_msg_size as usize
        };
        local.min(peer)
    }

    /// Convert the negotiated `base_asym_sel` bitfield to
    /// [`SpdmPalAsymAlgo`] for cert-store calls.
    pub(crate) fn asym_algo(&self) -> SpdmPalAsymAlgo {
        // TODO: add MLDSA-87 mapping once codec and DPE support it.
        SpdmPalAsymAlgo::EccP384
    }
}

impl<S> Default for ConnectionState<S> {
    fn default() -> Self {
        Self::caliptra()
    }
}

pub(crate) fn multi_key_conn_rsp<S>(state: &ConnectionState<S>) -> SpdmResult<bool> {
    let selected = state
        .other_param_sel
        .contains(OtherParamSupport::MULTI_KEY_CONN);
    if state.version < SpdmVersion::V13 {
        return if selected {
            Err(SPDM_INVALID_REQUEST)
        } else {
            Ok(false)
        };
    }

    match (state.advertised_cap_flags.multi_key_field(), selected) {
        (0b00, false) => Ok(false),
        (0b00, true) => Err(SPDM_INVALID_REQUEST),
        (0b01, false) => Err(SPDM_INVALID_REQUEST),
        (0b01, true) => Ok(true),
        (0b10, false) => Ok(false),
        (0b10, true) => Ok(true),
        _ => Err(SPDM_INVALID_REQUEST),
    }
}

#[cfg(feature = "set-certificate")]
fn set_certificate_cap_flags() -> CapFlags {
    CapFlags::SET_CERT | CapFlags::MULTI_KEY_CONN_RSP
}

#[cfg(not(feature = "set-certificate"))]
fn set_certificate_cap_flags() -> CapFlags {
    CapFlags::EMPTY
}

#[cfg(feature = "set-certificate")]
fn set_certificate_other_params() -> OtherParamSupport {
    OtherParamSupport::MULTI_KEY_CONN
}

#[cfg(not(feature = "set-certificate"))]
fn set_certificate_other_params() -> OtherParamSupport {
    OtherParamSupport::EMPTY
}

/// SPDM responder state machine + dispatcher.
///
/// Owns a `Pal` (transport + allocator), the [`ConnectionState`],
/// and a fixed-size session table.
/// Drive it with [`Self::run`], which loops forever until the
/// transport returns a fatal error.
pub struct SpdmStack<
    Pal: SpdmPal,
    const MAX_SESSIONS: usize = 1,
    Vdm: SpdmVdmBackend = NoVdmBackend,
> {
    pub(crate) pal: Pal,
    pub(crate) state: ConnectionState<Pal::State>,
    pub(crate) sessions:
        SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, MAX_SESSIONS>,
    vdm_backend: Vdm,
}

impl<Pal: SpdmPal, const MAX_SESSIONS: usize> SpdmStack<Pal, MAX_SESSIONS, NoVdmBackend> {
    /// Constructs a new responder over `pal` with the default
    /// (Caliptra) local-policy advertisement and no VENDOR_DEFINED support
    /// (`VENDOR_DEFINED_REQUEST` -> `SPDM_UNSUPPORTED_REQUEST`). Use
    /// [`Self::with_vdm_backend`] to register a VDM backend.
    ///
    /// # Parameters
    ///
    /// * `pal` — The platform abstraction implementing both transport
    ///   and allocator.
    ///
    /// # Returns
    ///
    /// A new `SpdmStack` in [`Phase::Start`].
    pub fn new(pal: Pal) -> Self {
        Self::with_vdm_backend(pal, NoVdmBackend)
    }
}

impl<Pal: SpdmPal, const MAX_SESSIONS: usize, Vdm: SpdmVdmBackend>
    SpdmStack<Pal, MAX_SESSIONS, Vdm>
{
    /// Constructs a responder over `pal` with a static-dispatch VDM backend.
    ///
    /// If the PAL cannot hold at least one transport-sized large message,
    /// `CHUNK` is removed from the advertised capabilities.
    pub fn with_vdm_backend(pal: Pal, vdm_backend: Vdm) -> Self {
        let mut state = ConnectionState::<Pal::State>::default();
        if pal.large_capacity() < pal.mtu() {
            state.cap_flags =
                CapFlags::from_bits(state.cap_flags.into_bits() & !CapFlags::CHUNK.into_bits());
        }
        Self {
            pal,
            state,
            sessions: SessionManager::new(),
            vdm_backend,
        }
    }

    /// Main responder run loop. On each iteration: receive one request, dispatch
    /// it to the matching handler (routing `VENDOR_DEFINED_REQUEST` to the
    /// registered VDM backend), and send back either the handler's response or a
    /// SPDM `ERROR` PDU. Returns only on a fatal transport error (`recv_request`
    /// / `send_response` failure).
    ///
    /// # Returns
    ///
    /// * `Err(McuErrorCode)` — A fatal transport error. Successful
    ///   loops never return.
    pub async fn run(&mut self) -> McuResult<()> {
        #[cfg(feature = "debug-trace")]
        use core::fmt::Write;
        #[cfg(feature = "debug-trace")]
        let mut console = caliptra_mcu_libtock_console::Console::<
            caliptra_mcu_libsyscall_caliptra::DefaultSyscalls,
        >::writer();
        loop {
            let io = self.pal.recv_request().await?;
            #[cfg(feature = "debug-trace")]
            {
                let r = io.request();
                let n = r.len().min(8);
                let _ = write!(&mut console, "[spdm] req len={}", r.len());
                for x in &r[..n] {
                    let _ = write!(&mut console, " {:02x}", x);
                }
                let _ = writeln!(&mut console);
            }

            match io.kind() {
                SpdmPalIoKind::Message => {
                    let (code, req_version) = decode_header(io.request());
                    match dispatch(
                        &mut self.state,
                        &mut self.sessions,
                        &self.pal,
                        &io,
                        code,
                        &self.vdm_backend,
                    )
                    .await
                    {
                        Ok(mut rsp) => {
                            #[cfg(feature = "debug-trace")]
                            {
                                let head = self.pal.header_size();
                                let body = &rsp[head..];
                                let n = body.len().min(8);
                                let _ = write!(&mut console, "[spdm] rsp len={}", body.len());
                                for x in &body[..n] {
                                    let _ = write!(&mut console, " {:02x}", x);
                                }
                                let _ = writeln!(&mut console);
                            }
                            self.pal
                                .send_response(&io, SpdmPalIoKind::Message, &mut rsp)
                                .await?
                        }
                        Err(e) => {
                            #[cfg(feature = "debug-trace")]
                            {
                                let _ = writeln!(
                                    &mut console,
                                    "[spdm] err spec=0x{:02x} req_ver=0x{:02x}",
                                    e.spec_byte(),
                                    req_version.to_u8()
                                );
                            }
                            self.send_error_pdu(&io, e, req_version).await?
                        }
                    }
                }
                SpdmPalIoKind::SecuredMessage => {
                    match handle_secured_request(
                        &mut self.state,
                        &mut self.sessions,
                        &self.pal,
                        &io,
                        &self.vdm_backend,
                    )
                    .await
                    {
                        Ok(Some(mut rsp)) => {
                            #[cfg(feature = "debug-trace")]
                            {
                                let _ = writeln!(&mut console, "[spdm] sec rsp len={}", rsp.len());
                            }
                            self.pal
                                .send_response(&io, SpdmPalIoKind::SecuredMessage, &mut rsp)
                                .await?
                        }
                        Ok(None) => {}
                        Err(e) => {
                            #[cfg(feature = "debug-trace")]
                            {
                                let _ = writeln!(
                                    &mut console,
                                    "[spdm] sec err spec=0x{:02x}",
                                    e.spec_byte()
                                );
                            }
                            self.send_error_pdu(&io, e, self.state.version).await?
                        }
                    }
                }
            }
        }
    }

    /// Builds and sends a SPDM `ERROR` PDU.
    ///
    /// If the `ERROR` PDU itself cannot be built (e.g. allocator
    /// exhausted) the request is silently dropped — there is nothing
    /// meaningful to send back. Transport-level failures on the send
    /// path are still propagated.
    ///
    /// # Parameters
    ///
    /// * `io` — The I/O handle of the current request (used for
    ///   `send_response` and as the allocator's scoping handle).
    /// * `err` — The handler-returned [`SpdmError`]; its spec byte
    ///   becomes the `ERROR` PDU's `param1`.
    /// * `req_version` — The SPDM version decoded from the request
    ///   header. Used as the `ERROR` response version, except for
    ///   `VersionMismatch` which always uses V1.0 (the requester and
    ///   responder don't agree on the version, so reply at the
    ///   protocol floor).
    ///
    /// # Returns
    ///
    /// * `Ok(())` — `ERROR` PDU sent, or build failed and was dropped.
    ///
    /// # Errors
    ///
    /// * `Err(McuErrorCode)` — Transport-level failure during send.
    async fn send_error_pdu(
        &self,
        io: &<Pal as SpdmPalIoTransport>::Io<'_>,
        err: SpdmError,
        req_version: SpdmVersion,
    ) -> McuResult<()> {
        // ERROR response uses the same version as
        // the requester's message. For `VersionMismatch`, the
        // responder shall instead use the highest supported version
        // (libspdm matches: post-negotiation = negotiated, else V1.0;
        // the conformance validator expects the request version
        // verbatim for the non-VersionMismatch path).
        let rsp_version = if err.spec_byte() == SPDM_VERSION_MISMATCH.spec_byte() {
            if (self.state.phase as u8) >= (Phase::AfterCapabilities as u8) {
                self.state.version
            } else {
                SpdmVersion::V10
            }
        } else {
            req_version
        };

        let Ok(mut err_rsp) = build_error_response(
            &self.pal,
            io,
            rsp_version,
            err.spec_byte(),
            err.error_data(),
            &[],
        ) else {
            // Allocator exhausted or codec failure — nothing more we
            // can do for this exchange.
            return Ok(());
        };

        self.pal
            .send_response(io, SpdmPalIoKind::Message, &mut err_rsp)
            .await
    }
}

/// Routes a decoded request code to the matching handler.
///
/// Free-standing (rather than a method on [`SpdmStack`]) so the
/// caller can keep an independent borrow on `self.pal` via `io`
/// alongside the `&mut self.state` borrow needed by handlers.
///
/// # Parameters
///
/// * `state` — Mutable connection state (forwarded to handlers).
/// * `pal` — Borrowed PAL (forwarded to handlers).
/// * `io` — I/O handle for the current request.
/// * `code` — The decoded SPDM request code.
///
/// # Returns
///
/// * `Ok(PalBytes)` — Handler's encoded response.
///
/// # Errors
///
/// * [`SPDM_INVALID_REQUEST`] — header decode failed
///   (`code == ReqRespCode(0)`).
/// * [`SPDM_UNSUPPORTED_REQUEST`] — code is recognised by SPDM but
///   not handled by this responder.
/// * Whatever the specific handler returns.
#[inline(never)]
async fn dispatch<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend, const MAX_SESSIONS: usize>(
    state: &mut ConnectionState<Pal::State>,
    sessions: &mut SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    code: ReqRespCode,
    vdm: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>> {
    if code != ReqRespCode::CHUNK_SEND && state.chunk.in_progress() {
        state.chunk.reset();
    }
    if code != ReqRespCode::CHUNK_GET
        && code != ReqRespCode::CHUNK_SEND
        && state.large_response.in_progress()
    {
        state.large_response.reset();
    }
    match code {
        ReqRespCode::GET_VERSION => {
            state.reset_negotiation();
            sessions.remove_all_and_destroy();
            version::handle_get_version(state, pal, io).await
        }
        ReqRespCode::GET_CAPABILITIES => {
            capabilities::handle_get_capabilities(state, pal, io).await
        }
        ReqRespCode::NEGOTIATE_ALGORITHMS => {
            algorithms::handle_negotiate_algorithms(state, pal, io).await
        }
        ReqRespCode::GET_DIGESTS => digests::handle_get_digests(state, pal, io).await,
        ReqRespCode::GET_CERTIFICATE => certificate::handle_get_certificate(state, pal, io).await,
        ReqRespCode::CHALLENGE => challenge::handle_challenge(state, pal, io).await,
        ReqRespCode::CHUNK_SEND => chunk::handle_chunk_send(state, pal, io).await,
        ReqRespCode::CHUNK_GET => chunk::handle_chunk_get(state, pal, io).await,
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            crate::set_certificate::handle_set_certificate(state, pal, io).await
        }
        #[cfg(not(feature = "set-certificate"))]
        ReqRespCode::SET_CERTIFICATE => Err(SPDM_UNSUPPORTED_REQUEST.with_data(code.0)),
        ReqRespCode::GET_MEASUREMENTS => {
            let (resp, _) =
                measurements::handle_get_measurements_req(state, pal, io, io.request()).await?;
            Ok(resp)
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            let (resp, _) = vendor_defined::handle_vendor_defined_request(
                vdm,
                state,
                pal,
                io,
                io.request(),
                false,
            )
            .await?;
            Ok(resp)
        }
        ReqRespCode::KEY_EXCHANGE => {
            key_exchange::handle_key_exchange(state, sessions, pal, io).await
        }
        ReqRespCode::FINISH | ReqRespCode::END_SESSION => Err(SPDM_SESSION_REQUIRED),
        ReqRespCode(0) => Err(SPDM_INVALID_REQUEST),
        _ => Err(SPDM_UNSUPPORTED_REQUEST.with_data(code.0)),
    }
}

// ── Secured message handling ────────────────────────────────────────

/// Handle an incoming secured message.
///
/// Parses the session ID, dispatches to the inner handler, and
/// destroys the session on any error (conservative cleanup).
#[inline(never)]
async fn handle_secured_request<
    'a,
    Pal: SpdmPal,
    Vdm: SpdmVdmBackend,
    const MAX_SESSIONS: usize,
>(
    state: &mut ConnectionState<Pal::State>,
    sessions: &mut SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    vdm: &Vdm,
) -> SpdmResult<Option<PalBytes<'a, Pal>>> {
    let req = io.request();

    // Parse session_id from the secured message header.
    let (hdr, _) = SecuredMessageHeader::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    let session_id = hdr.session_id_u32();
    if sessions.find(session_id).is_none() {
        return Ok(None);
    }

    match handle_secured_inner(state, sessions, pal, io, session_id, vdm).await {
        Ok(rsp) => Ok(Some(rsp)),
        Err(e) => {
            let Some(session) = sessions.find_mut(session_id) else {
                return Ok(None);
            };
            let key_type = match session.state {
                SessionState::HandshakeInProgress => SessionKeyType::ResponseHandshakeKey,
                SessionState::Established => SessionKeyType::ResponseDataKey,
            };
            let error_rsp = [
                state.version.to_u8(),
                ReqRespCode::ERROR.0,
                e.spec_byte(),
                e.error_data(),
            ];
            let rsp = encrypt_secured_spdm_response(
                pal,
                io,
                session,
                session_id,
                state.version,
                key_type,
                &error_rsp,
            )
            .await
            .ok();
            if e.spec_byte() == SPDM_DECRYPT_ERROR.spec_byte() {
                sessions.remove_and_destroy(session_id);
            }
            Ok(rsp)
        }
    }
}

/// Inner secured message handler: decrypt → dispatch → encrypt.
#[inline(never)]
async fn handle_secured_inner<'a, Pal: SpdmPal, Vdm: SpdmVdmBackend, const MAX_SESSIONS: usize>(
    state: &mut ConnectionState<Pal::State>,
    sessions: &mut SessionManager<<Pal as SpdmPalSessionCrypto>::Key, Pal::State, MAX_SESSIONS>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    session_id: u32,
    vdm: &Vdm,
) -> SpdmResult<PalBytes<'a, Pal>> {
    let req = io.request();
    let version = state.version;

    // ── Parse secured message envelope ──────────────────────────────
    let (hdr, payload) =
        SecuredMessageHeader::ref_from_prefix(req).map_err(|_| SPDM_INVALID_REQUEST)?;
    let length = hdr.length_u16() as usize;

    // length = ciphertext_len + tag_len
    if payload.len() < length || length < AES_256_GCM_TAG_SIZE {
        return Err(SPDM_INVALID_REQUEST);
    }
    let ct_len = length - AES_256_GCM_TAG_SIZE;
    let ciphertext = &payload[..ct_len];
    let tag: &[u8; AES_256_GCM_TAG_SIZE] = payload[ct_len..ct_len + AES_256_GCM_TAG_SIZE]
        .try_into()
        .map_err(|_| SPDM_INVALID_REQUEST)?;

    let decrypt_key_type = match sessions.find(session_id).ok_or(SPDM_UNSPECIFIED)?.state {
        SessionState::HandshakeInProgress => SessionKeyType::RequestHandshakeKey,
        SessionState::Established => SessionKeyType::RequestDataKey,
    };

    // ── Build AAD ───────────────────────────────────────────────────
    let mut aad = pal.alloc_bytes(io, SECURED_MSG_HDR_SIZE)?;
    encode_aad(session_id, length as u16, &mut aad).map_err(|_| SPDM_UNSPECIFIED)?;

    // ── Decrypt ─────────────────────────────────────────────────────
    let mut plaintext = pal.alloc_bytes(io, ct_len)?;
    {
        let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
        if session
            .key_schedule
            .decrypt(
                pal,
                io,
                decrypt_key_type,
                version.to_u8(),
                &aad,
                ciphertext,
                tag,
                &mut plaintext[..ct_len],
            )
            .await
            .map_err(|_| SPDM_DECRYPT_ERROR)?
            != ct_len
        {
            return Err(SPDM_DECRYPT_ERROR);
        }
    }

    // ── Parse app_data_length + spdm_msg ────────────────────────────
    if ct_len < 2 {
        return Err(SPDM_INVALID_REQUEST);
    }
    let app_data_len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
    if app_data_len + 2 != ct_len {
        return Err(SPDM_INVALID_REQUEST);
    }
    let spdm_msg = &plaintext[2..2 + app_data_len];

    // ── Dispatch on SPDM code ───────────────────────────────────────
    let (spdm_hdr, _) =
        SpdmMsgHdrPdu::ref_from_prefix(spdm_msg).map_err(|_| SPDM_INVALID_REQUEST)?;
    let session_state = sessions.find(session_id).ok_or(SPDM_UNSPECIFIED)?.state;
    let response_key_type = validate_message_allowed_phase(spdm_hdr.code, session_state)?;

    match spdm_hdr.code {
        ReqRespCode::FINISH => {
            let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
            let finish_rsp =
                finish::handle_finish::<Pal>(version, session, pal, io, spdm_msg).await?;
            let rsp = encrypt_secured_spdm_response(
                pal,
                io,
                session,
                session_id,
                version,
                response_key_type,
                &finish_rsp,
            )
            .await?;
            session.key_schedule.destroy_handshake_secrets();
            session.state = SessionState::Established;
            Ok(rsp)
        }
        ReqRespCode::END_SESSION => {
            let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
            let end_session_ack = end_session::handle_end_session(version, spdm_msg)?;
            let rsp = encrypt_secured_spdm_response(
                pal,
                io,
                session,
                session_id,
                version,
                response_key_type,
                &end_session_ack,
            )
            .await?;
            sessions.remove_and_destroy(session_id);
            Ok(rsp)
        }
        ReqRespCode::GET_MEASUREMENTS => {
            let (measurements_rsp, spdm_len) =
                measurements::handle_get_measurements_req(state, pal, io, spdm_msg).await?;
            let head = pal.header_size();
            let spdm_rsp = &measurements_rsp[head..head + spdm_len];
            let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
            encrypt_secured_spdm_response(
                pal,
                io,
                session,
                session_id,
                version,
                response_key_type,
                spdm_rsp,
            )
            .await
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => {
            let (rsp, spdm_len) =
                vendor_defined::handle_vendor_defined_request(vdm, state, pal, io, spdm_msg, true)
                    .await?;
            let head = pal.header_size();
            let spdm_rsp = &rsp[head..head + spdm_len];
            let session = sessions.find_mut(session_id).ok_or(SPDM_UNSPECIFIED)?;
            encrypt_secured_spdm_response(
                pal,
                io,
                session,
                session_id,
                version,
                response_key_type,
                spdm_rsp,
            )
            .await
        }
        _ => Err(SPDM_UNSUPPORTED_REQUEST.with_data(spdm_hdr.code.0)),
    }
}

fn validate_message_allowed_phase(
    code: ReqRespCode,
    session_state: SessionState,
) -> SpdmResult<SessionKeyType> {
    let application_key = || {
        if session_state == SessionState::Established {
            Ok(SessionKeyType::ResponseDataKey)
        } else {
            Err(SPDM_UNEXPECTED_REQUEST)
        }
    };
    let current_key = || match session_state {
        SessionState::HandshakeInProgress => Ok(SessionKeyType::ResponseHandshakeKey),
        SessionState::Established => Ok(SessionKeyType::ResponseDataKey),
    };

    match code {
        ReqRespCode(0) => Err(SPDM_INVALID_REQUEST),
        ReqRespCode::GET_VERSION
        | ReqRespCode::GET_CAPABILITIES
        | ReqRespCode::NEGOTIATE_ALGORITHMS
        | ReqRespCode::CHALLENGE
        | ReqRespCode::KEY_EXCHANGE => Err(SPDM_UNEXPECTED_REQUEST),
        ReqRespCode::GET_DIGESTS
        | ReqRespCode::GET_CERTIFICATE
        | ReqRespCode::SET_CERTIFICATE
        | ReqRespCode::GET_MEASUREMENTS
        | ReqRespCode::END_SESSION => application_key(),
        ReqRespCode::FINISH => {
            if session_state == SessionState::HandshakeInProgress {
                Ok(SessionKeyType::ResponseHandshakeKey)
            } else {
                Err(SPDM_UNEXPECTED_REQUEST)
            }
        }
        ReqRespCode::VENDOR_DEFINED_REQUEST => current_key(),
        _ => Err(SPDM_UNSUPPORTED_REQUEST.with_data(code.0)),
    }
}

#[inline(never)]
async fn encrypt_secured_spdm_response<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    session: &mut crate::session::SessionInfo<<Pal as SpdmPalSessionCrypto>::Key, Pal::State>,
    session_id: u32,
    version: SpdmVersion,
    key_type: SessionKeyType,
    spdm_response: &[u8],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let rsp_pt_len = 2 + spdm_response.len();
    let rsp_ct_len = rsp_pt_len;
    let rsp_length_len = rsp_ct_len + AES_256_GCM_TAG_SIZE;
    if rsp_length_len > u16::MAX as usize {
        return Err(SPDM_UNSPECIFIED);
    }

    let mut rsp_plaintext = pal.alloc_bytes(io, rsp_pt_len)?;
    rsp_plaintext[0..2].copy_from_slice(&(spdm_response.len() as u16).to_le_bytes());
    rsp_plaintext[2..2 + spdm_response.len()].copy_from_slice(spdm_response);

    let rsp_length = rsp_length_len as u16;
    let mut rsp_aad = pal.alloc_bytes(io, SECURED_MSG_HDR_SIZE)?;
    encode_aad(session_id, rsp_length, &mut rsp_aad).map_err(|_| SPDM_UNSPECIFIED)?;

    let mut rsp_ct = pal.alloc_bytes(io, rsp_ct_len)?;
    let (rsp_written, rsp_tag) = session
        .key_schedule
        .encrypt(
            pal,
            io,
            key_type,
            version.to_u8(),
            &rsp_aad,
            &rsp_plaintext,
            &mut rsp_ct,
        )
        .await
        .map_err(|_| SPDM_UNSPECIFIED)?;
    if rsp_written != rsp_ct_len {
        return Err(SPDM_UNSPECIFIED);
    }

    build_secured_response_wire(pal, io, session_id, rsp_length, &rsp_ct, &rsp_tag)
}

#[inline(never)]
fn build_secured_response_wire<'a, Pal: SpdmPal>(
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    session_id: u32,
    rsp_length: u16,
    ciphertext: &[u8],
    tag: &[u8; AES_256_GCM_TAG_SIZE],
) -> SpdmResult<PalBytes<'a, Pal>> {
    let wire_body_len = SECURED_MSG_HDR_SIZE + ciphertext.len() + AES_256_GCM_TAG_SIZE;
    let raw_len = pal.header_size() + wire_body_len;
    let mut buf = alloc_padded(pal, io, raw_len).map_err(|_| SPDM_UNSPECIFIED)?;
    let hdr_off = pal.header_size();
    buf[hdr_off..hdr_off + 4].copy_from_slice(&session_id.to_le_bytes());
    buf[hdr_off + 4..hdr_off + 6].copy_from_slice(&rsp_length.to_le_bytes());
    buf[hdr_off + 6..hdr_off + 6 + ciphertext.len()].copy_from_slice(ciphertext);
    buf[hdr_off + 6 + ciphertext.len()..hdr_off + 6 + ciphertext.len() + AES_256_GCM_TAG_SIZE]
        .copy_from_slice(tag);

    Ok(buf)
}
/// Decodes the SPDM common header from a raw request buffer.
///
/// # Parameters
///
/// * `req` — Raw request bytes as returned by `SpdmPalIo::request()`.
///
/// # Returns
///
/// A `(code, version)` pair. If decoding fails, returns
/// `(ReqRespCode(0), SpdmVersion::V12)` — the dispatcher will then
/// reject the request with [`SPDM_INVALID_REQUEST`] and reply at the
/// current connection version (V1.2 by default).
fn decode_header(req: &[u8]) -> (ReqRespCode, SpdmVersion) {
    match SpdmMsgHdrPdu::ref_from_prefix(req) {
        Ok((hdr, _)) => (
            hdr.code,
            SpdmVersion::from_u8(hdr.version).unwrap_or(SpdmVersion::V12),
        ),
        Err(_) => (ReqRespCode(0), SpdmVersion::V12),
    }
}
