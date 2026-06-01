// Licensed under the Apache-2.0 license

//! SPDM responder state machine and dispatcher.
//!
//! This module owns the [`SpdmStack`] run loop, the connection-scoped
//! [`ConnectionState`], and the [`Phase`] enum that enforces the
//! strict DSP0274 §10 ordering
//! `GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS`. Per-command
//! handlers live in `algorithms`, `capabilities`, and `version`.
//!
//! `GET_VERSION` is legal in any phase; the dispatcher resets
//! connection-scoped state via [`ConnectionState::reset_negotiation`]
//! before invoking [`version::handle_get_version`] so the handler
//! itself is unaware of the phase.

use mcu_spdm_lite_codec::{
    AeadAlgos, AsymAlgos, CapFlags, DheAlgos, HashAlgos, KeyScheduleAlgos, MeasHashAlgos, MeasSpec,
    OtherParamSupport, ReqRespCode, SpdmMsgHdrPdu, SpdmVersion,
};
use mcu_spdm_lite_traits::*;
use zerocopy::FromBytes;

use crate::build::build_error_response;
use crate::error::{
    SpdmError, SpdmResult, SPDM_INVALID_REQUEST, SPDM_UNSUPPORTED_REQUEST, SPDM_VERSION_MISMATCH,
};
use crate::{algorithms, capabilities, certificate, challenge, digests, version};

/// Connection phase tracked on the responder so the dispatcher can
/// enforce the DSP0274 §10 ordering
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
    /// `NEGOTIATE_ALGORITHMS` exchanged. Ready for authentication /
    /// key-exchange / measurements (not yet implemented).
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
#[derive(Clone)]
pub struct ConnectionState<S: Clone> {
    // ---- Local responder policy (fixed at startup) -----------------------
    /// Responder `CT` time exponent (DSP0274 §10.3, `CAPABILITIES.CTExponent`).
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
    /// connection after version/PAL policy gating.
    pub advertised_cap_flags: CapFlags,
    /// Peer-advertised capability flags.
    pub peer_cap_flags: CapFlags,
    /// Negotiated OtherParamsSel from NEGOTIATE_ALGORITHMS.
    pub other_param_sel: OtherParamSupport,
    /// Negotiated BaseAsymSel from NEGOTIATE_ALGORITHMS.
    pub negotiated_base_asym_sel: AsymAlgos,
    /// Negotiated BaseHashSel from NEGOTIATE_ALGORITHMS.
    pub negotiated_base_hash_sel: HashAlgos,
    /// Transcript state (running VCA/M1/L1 hashes per DSP0274 §8.10).
    pub transcript: crate::transcript::Transcript<S>,
}

impl<S: Clone> ConnectionState<S> {
    /// Builds the Caliptra responder's fixed local-policy advertisement.
    ///
    /// # Returns
    ///
    /// A new `ConnectionState` with:
    ///
    /// * `ct_exponent = 20` (≈ 1 s — `2^20` µs).
    /// * `cap_flags = CERT | CHAL | MEAS_SIG | ALIAS_CERT`. `CHUNK` is
    ///   intentionally omitted until large-message assembly is
    ///   implemented (DSP0274 §10.26).
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
            dhe: DheAlgos::EMPTY,
            aead: AeadAlgos::EMPTY,
            key_schedule: KeyScheduleAlgos::EMPTY,

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
        }
    }

    /// Drops every connection-scoped negotiation result.
    ///
    /// Called by the dispatcher on every `GET_VERSION` per DSP0274
    /// §10.4. Local-policy fields (the upper block) are not modified.
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
    }

    /// Convert the negotiated `base_asym_sel` bitfield to
    /// [`SpdmPalAsymAlgo`] for cert-store calls.
    pub(crate) fn asym_algo(&self) -> SpdmPalAsymAlgo {
        // TODO: add MLDSA-87 mapping once codec and DPE support it.
        SpdmPalAsymAlgo::EccP384
    }
}

impl<S: Clone> Default for ConnectionState<S> {
    fn default() -> Self {
        Self::caliptra()
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
/// Owns a `Pal` (transport + allocator) and the [`ConnectionState`].
/// Drive it with [`Self::run`], which loops forever until the
/// transport returns a fatal error.
pub struct SpdmStack<Pal: SpdmPal> {
    pub(crate) pal: Pal,
    pub(crate) state: ConnectionState<Pal::State>,
}

impl<Pal: SpdmPal> SpdmStack<Pal> {
    /// Constructs a new responder over `pal` with the default
    /// (Caliptra) local-policy advertisement.
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
        Self {
            pal,
            state: ConnectionState::<Pal::State>::default(),
        }
    }

    /// Main responder run loop.
    ///
    /// On each iteration: receive one request, dispatch it to the
    /// matching handler, and send back either the handler's response
    /// or a DSP0274 §10.10 `ERROR` PDU. Returns only on a fatal
    /// transport error (`recv_request` / `send_response` failure).
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
            let (code, req_version) = decode_header(io.request());
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
            match dispatch(&mut self.state, &self.pal, &io, code).await {
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
    }

    /// Builds and sends a DSP0274 §10.10 `ERROR` PDU.
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
        // DSP0274 §10.10.2: ERROR response uses the same version as
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
async fn dispatch<'a, Pal: SpdmPal>(
    state: &mut ConnectionState<Pal::State>,
    pal: &'a Pal,
    io: &<Pal as SpdmPalIoTransport>::Io<'_>,
    code: ReqRespCode,
) -> SpdmResult<PalBytes<'a, Pal>> {
    match code {
        ReqRespCode::GET_VERSION => {
            state.reset_negotiation();
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
        #[cfg(feature = "set-certificate")]
        ReqRespCode::SET_CERTIFICATE => {
            crate::set_certificate::handle_set_certificate(state, pal, io).await
        }
        #[cfg(not(feature = "set-certificate"))]
        ReqRespCode::SET_CERTIFICATE => Err(SPDM_UNSUPPORTED_REQUEST.with_data(code.0)),
        ReqRespCode(0) => Err(SPDM_INVALID_REQUEST),
        _ => Err(SPDM_UNSUPPORTED_REQUEST.with_data(code.0)),
    }
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
