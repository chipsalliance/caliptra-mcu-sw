// Licensed under the Apache-2.0 license

//! Running SHA hashes via Caliptra `CM_SHA_*` mailbox commands.
//!
//! All request/response buffers come from the caller's [`ApiAlloc`]
//! — never the stack — so calling these from inside an async loop
//! never inflates the task future with multi-kilobyte mailbox-request
//! structs.
//!
//! The 200-byte SHA running-context is held behind a heap-allocated
//! [`Box`](alloc::boxed::Box) so [`HashState`] is only a single
//! 8-byte pointer in async futures and other holders. That keeps the
//! per-handler future state slim while the actual SHA context lives
//! on the system heap and is freed automatically on drop.

extern crate alloc;

use alloc::boxed::Box;
use caliptra_mcu_libsyscall_caliptra::mailbox::Mailbox;
use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{
    calc_checksum, CMB_SHA_CONTEXT_SIZE, CMD_CM_SHA_FINAL, CMD_CM_SHA_INIT, CMD_CM_SHA_UPDATE,
    CM_HASH_ALGO_SHA384, MAX_CMB_DATA_SIZE,
};
use crate::ApiAlloc;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Maximum input bytes per single `CM_SHA_*` mailbox call. Smaller
/// than Caliptra's `MAX_CMB_DATA_SIZE = 4096` so each request fits
/// in a small number of bitmap slots.
pub const SHA_CHUNK_SIZE: usize = 512;
const _: () = assert!(SHA_CHUNK_SIZE <= MAX_CMB_DATA_SIZE);

/// Caliptra-mailbox SHA running-context.
///
/// The 200-byte opaque context blob is stored on the heap behind a
/// [`Box`], so `HashState` itself is only a pointer's worth of
/// inline storage. This is critical for SPDM transcript-tracking
/// where multiple [`HashState`]s live across many async `.await`
/// points — keeping each holder slim avoids ballooning the task
/// future.
///
/// Implements [`Clone`] (deep-copies the underlying context) so
/// callers can fork a running hash — e.g. the SPDM transcript's
/// `M1 = VCA.clone(); ...` pattern.
pub struct HashState {
    inner: Box<[u8; CMB_SHA_CONTEXT_SIZE]>,
}

impl HashState {
    /// Allocate a fresh, all-zero `HashState`. Not a valid running
    /// hash — must be initialized via [`sha_init`] before use.
    ///
    /// Panics on allocation failure — the underlying allocator
    /// (Caliptra-MCU runtime heap) is statically sized, so an OOM
    /// at this 200-byte allocation indicates a heap-budget
    /// configuration bug rather than a recoverable condition.
    pub fn new() -> Self {
        Self {
            inner: Box::new([0u8; CMB_SHA_CONTEXT_SIZE]),
        }
    }

    #[inline]
    fn ctx(&self) -> &[u8; CMB_SHA_CONTEXT_SIZE] {
        &self.inner
    }

    #[inline]
    fn ctx_mut(&mut self) -> &mut [u8; CMB_SHA_CONTEXT_SIZE] {
        &mut self.inner
    }
}

impl Default for HashState {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HashState {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        new.inner.copy_from_slice(self.inner.as_ref());
        new
    }
}

/// Hash algorithms supported by Caliptra's `CM_SHA_*` commands.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    /// SHA-384 (48-byte digest).
    Sha384,
}

impl HashAlgo {
    /// Digest size in bytes produced by [`sha_finish`] for this
    /// algorithm.
    #[inline]
    pub const fn hash_size(self) -> usize {
        match self {
            HashAlgo::Sha384 => 48,
        }
    }
}

// ---------------------------------------------------------------------------
// Slim wire types (Caliptra `Cm*` request/response prefixes minus
// the inline 4 KB payload).
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaInitPrefix {
    chksum: U32,
    hash_algorithm: U32,
    input_size: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaUpdatePrefix {
    chksum: U32,
    context: [u8; CMB_SHA_CONTEXT_SIZE],
    input_size: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaCtxResp {
    _chksum: U32,
    _fips_status: U32,
    context: [u8; CMB_SHA_CONTEXT_SIZE],
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct ShaFinalRespPrefix {
    _chksum: U32,
    _fips_status: U32,
    data_len: U32,
}

const _: () = assert!(size_of::<ShaInitPrefix>() == 12);
const _: () = assert!(size_of::<ShaUpdatePrefix>() == 4 + CMB_SHA_CONTEXT_SIZE + 4);
const _: () = assert!(size_of::<ShaCtxResp>() == 4 + 4 + CMB_SHA_CONTEXT_SIZE);
const _: () = assert!(size_of::<ShaFinalRespPrefix>() == 12);

const FINAL_RSP_MAX_LEN: usize = size_of::<ShaFinalRespPrefix>() + 64;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Begin a new running hash and return the resulting state.
#[inline(never)]
pub async fn sha_init<A: ApiAlloc>(alloc: &A, algo: HashAlgo, seed: &[u8]) -> McuResult<HashState> {
    let mut state = HashState::new();
    if seed.len() > SHA_CHUNK_SIZE {
        return Err(INVARIANT);
    }
    sha_call(
        alloc,
        CMD_CM_SHA_INIT,
        Some(algo_code(algo)),
        seed,
        &mut state,
        None,
    )
    .await?;
    Ok(state)
}

/// Append `data` to a running hash. `data` may be any length; this
/// function chunks internally as needed.
#[inline(never)]
pub async fn sha_update<A: ApiAlloc>(
    alloc: &A,
    state: &mut HashState,
    data: &[u8],
) -> McuResult<()> {
    if data.is_empty() {
        return Ok(());
    }
    for chunk in data.chunks(SHA_CHUNK_SIZE) {
        sha_call(alloc, CMD_CM_SHA_UPDATE, None, chunk, state, None).await?;
    }
    Ok(())
}

/// Finalise the running hash, writing the digest into the prefix of
/// `out`. After this call, `state` is no longer a valid running
/// hash.
#[inline(never)]
pub async fn sha_finish<A: ApiAlloc>(
    alloc: &A,
    state: &mut HashState,
    out: &mut [u8],
) -> McuResult<()> {
    sha_call(alloc, CMD_CM_SHA_FINAL, None, &[], state, Some(out)).await
}

// ---------------------------------------------------------------------------
// Shared private workhorse — one async state machine for all 3 ops.
// ---------------------------------------------------------------------------

async fn sha_call<A: ApiAlloc>(
    alloc: &A,
    cmd: u32,
    algo: Option<u32>,
    data: &[u8],
    state: &mut HashState,
    out: Option<&mut [u8]>,
) -> McuResult<()> {
    let chunk_len = data.len();
    let is_init = algo.is_some();
    let is_final = out.is_some();

    let prefix_len = if is_init {
        size_of::<ShaInitPrefix>()
    } else {
        size_of::<ShaUpdatePrefix>()
    };
    let wire_len = pad4(prefix_len + chunk_len);

    let mut req = alloc.alloc(wire_len)?;
    req.fill(0);
    if is_init {
        let prefix =
            ShaInitPrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
        prefix.hash_algorithm = U32::new(algo.unwrap());
        prefix.input_size = U32::new(chunk_len as u32);
    } else {
        let prefix =
            ShaUpdatePrefix::mut_from_bytes(&mut req[..prefix_len]).map_err(|_| INVARIANT)?;
        prefix.context = *state.ctx();
        prefix.input_size = U32::new(chunk_len as u32);
    }
    req[prefix_len..prefix_len + chunk_len].copy_from_slice(data);
    populate_checksum(cmd, &mut req)?;

    let rsp_alloc_len = if is_final {
        FINAL_RSP_MAX_LEN
    } else {
        size_of::<ShaCtxResp>()
    };
    let mut rsp = alloc.alloc(rsp_alloc_len)?;
    let rsp_len = execute(cmd, &req, &mut rsp).await?;

    if let Some(out) = out {
        let prefix_len = size_of::<ShaFinalRespPrefix>();
        if rsp_len < prefix_len {
            return Err(INTERNAL_BUG);
        }
        let prefix =
            ShaFinalRespPrefix::ref_from_bytes(&rsp[..prefix_len]).map_err(|_| INTERNAL_BUG)?;
        let data_len = prefix.data_len.get() as usize;
        let hash_end = prefix_len + data_len;
        if hash_end > rsp_len || data_len > out.len() {
            return Err(INVARIANT);
        }
        out[..data_len].copy_from_slice(&rsp[prefix_len..hash_end]);
    } else {
        let parsed = ShaCtxResp::ref_from_bytes(&rsp[..size_of::<ShaCtxResp>()])
            .map_err(|_| INTERNAL_BUG)?;
        *state.ctx_mut() = parsed.context;
    }
    Ok(())
}

#[inline(never)]
async fn execute(cmd: u32, req: &[u8], rsp: &mut [u8]) -> McuResult<usize> {
    let mbox: Mailbox = Mailbox::new();
    mbox.execute(cmd, req, rsp).await.map_err(|_| INTERNAL_BUG)
}

#[inline]
fn algo_code(algo: HashAlgo) -> u32 {
    match algo {
        HashAlgo::Sha384 => CM_HASH_ALGO_SHA384,
    }
}

#[inline]
fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

fn populate_checksum(cmd: u32, data: &mut [u8]) -> McuResult<()> {
    if data.len() < 4 {
        return Err(INVARIANT);
    }
    let checksum = calc_checksum(cmd, data);
    data[..4].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}
