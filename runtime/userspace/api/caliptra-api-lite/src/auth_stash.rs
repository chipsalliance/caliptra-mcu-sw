// Licensed under the Apache-2.0 license

//! Caliptra `AUTHORIZE_AND_STASH` mailbox helper.
//!
//! This module only encodes and executes the mailbox command. It does not read
//! or write Measurement API stores, derive DPE contexts, or extend PCRs.

use core::mem::size_of;
use mcu_error::codes::{INTERNAL_BUG, INVARIANT};
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::slice::{checked_slice_mut, internal_slice};
use crate::wire::{mbox_execute, populate_checksum, CMD_AUTHORIZE_AND_STASH};
use crate::ApiAlloc;

/// Width in bytes of an image measurement digest carried by `AUTHORIZE_AND_STASH`.
pub const AUTHORIZE_AND_STASH_MEASUREMENT_SIZE: usize = 48;
/// Width in bytes of the `context` field carried by `AUTHORIZE_AND_STASH`.
pub const AUTHORIZE_AND_STASH_CONTEXT_SIZE: usize = 48;

const IMAGE_AUTHORIZED: u32 = 0xDEAD_C0DE;

/// Source used by Caliptra authorization to obtain the image hash.
///
/// Values match Caliptra mailbox `ImageHashSource` wire values.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ImageHashSource {
    /// Hash is carried in the authorize request.
    InRequest = 1,
    /// Hash image bytes from the load address.
    LoadAddress = 2,
    /// Hash image bytes from the staging address.
    StagingAddress = 3,
}

/// `AUTHORIZE_AND_STASH` request flags.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeAndStashFlags(u32);

impl AuthorizeAndStashFlags {
    /// No request flags.
    pub const EMPTY: Self = Self(0);
    /// Ask Caliptra to authorize only and skip Caliptra-managed stashing.
    pub const SKIP_STASH: Self = Self(0x1);

    /// Return the raw request flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Parameters for a single `AUTHORIZE_AND_STASH` mailbox command.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeAndStashParams {
    /// Stable component firmware identifier.
    pub fw_id: u32,
    /// Image measurement digest. Used by Caliptra when `source` is `InRequest`.
    pub measurement: [u8; AUTHORIZE_AND_STASH_MEASUREMENT_SIZE],
    /// Authorization context bytes.
    pub context: [u8; AUTHORIZE_AND_STASH_CONTEXT_SIZE],
    /// Security version number associated with the image.
    pub svn: u32,
    /// Request flags, including `SKIP_STASH` when the caller wants authorization only.
    pub flags: AuthorizeAndStashFlags,
    /// Source Caliptra uses to obtain the image hash.
    pub source: ImageHashSource,
    /// Image size in bytes for load-address or staging-address hashing.
    pub image_size: u32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct AuthorizeAndStashReq {
    chksum: U32,
    fw_id: [u8; 4],
    measurement: [u8; AUTHORIZE_AND_STASH_MEASUREMENT_SIZE],
    context: [u8; AUTHORIZE_AND_STASH_CONTEXT_SIZE],
    svn: U32,
    flags: U32,
    source: U32,
    image_size: U32,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct AuthorizeAndStashResp {
    _chksum: U32,
    _fips_status: U32,
    auth_req_result: U32,
}

const AUTHORIZE_AND_STASH_REQ_LEN: usize = size_of::<AuthorizeAndStashReq>();
const AUTHORIZE_AND_STASH_RESP_LEN: usize = size_of::<AuthorizeAndStashResp>();
const _: () = assert!(AUTHORIZE_AND_STASH_REQ_LEN == 120);
const _: () = assert!(AUTHORIZE_AND_STASH_RESP_LEN == 12);

/// Execute Caliptra `AUTHORIZE_AND_STASH` once.
///
/// The helper preserves Caliptra's public `SKIP_STASH` behavior through
/// [`AuthorizeAndStashFlags`]. Measurement API callers that manage DPE/PCR
/// state themselves should pass [`AuthorizeAndStashFlags::SKIP_STASH`].
#[inline(never)]
pub async fn authorize_and_stash<A: ApiAlloc>(
    alloc: &A,
    params: &AuthorizeAndStashParams,
) -> McuResult<()> {
    // The 120-byte request is borrowed across the mailbox await; keep it in
    // caller scratch. The 12-byte response is small enough to keep inline.
    let req = build_authorize_and_stash_req(alloc, params)?;
    let mut rsp = [0u8; AUTHORIZE_AND_STASH_RESP_LEN];
    let rsp_len = mbox_execute(CMD_AUTHORIZE_AND_STASH, &req, &mut rsp).await?;
    validate_authorize_and_stash_response(&rsp, rsp_len)
}

fn build_authorize_and_stash_req<'a, A: ApiAlloc>(
    alloc: &'a A,
    params: &AuthorizeAndStashParams,
) -> McuResult<A::Buf<'a>> {
    let mut req = alloc.alloc(AUTHORIZE_AND_STASH_REQ_LEN)?;
    req.fill(0);
    {
        let cmd = AuthorizeAndStashReq::mut_from_bytes(checked_slice_mut(
            &mut req,
            0,
            AUTHORIZE_AND_STASH_REQ_LEN,
        )?)
        .map_err(|_| INVARIANT)?;
        cmd.fw_id = params.fw_id.to_le_bytes();
        cmd.measurement = params.measurement;
        cmd.context = params.context;
        cmd.svn = U32::new(params.svn);
        cmd.flags = U32::new(params.flags.bits());
        cmd.source = U32::new(params.source as u32);
        cmd.image_size = U32::new(params.image_size);
    }
    populate_checksum(CMD_AUTHORIZE_AND_STASH, &mut req)?;
    Ok(req)
}

fn validate_authorize_and_stash_response(rsp: &[u8], rsp_len: usize) -> McuResult<()> {
    if rsp_len < AUTHORIZE_AND_STASH_RESP_LEN {
        return Err(INTERNAL_BUG);
    }
    let resp = AuthorizeAndStashResp::ref_from_bytes(internal_slice(
        rsp,
        0,
        AUTHORIZE_AND_STASH_RESP_LEN,
    )?)
    .map_err(|_| INTERNAL_BUG)?;
    if resp.auth_req_result.get() != IMAGE_AUTHORIZED {
        return Err(INTERNAL_BUG);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct TestAlloc;

    impl ApiAlloc for TestAlloc {
        type Buf<'a>
            = Vec<u8>
        where
            Self: 'a;

        fn alloc(&self, len: usize) -> McuResult<Self::Buf<'_>> {
            let mut buf = Vec::new();
            buf.resize(len, 0);
            Ok(buf)
        }
    }

    #[test]
    fn authorize_and_stash_wire_layout() {
        assert_eq!(CMD_AUTHORIZE_AND_STASH, 0x4154_5348);
        assert_eq!(AUTHORIZE_AND_STASH_REQ_LEN, 120);
        assert_eq!(AUTHORIZE_AND_STASH_RESP_LEN, 12);
        assert_eq!(ImageHashSource::InRequest as u32, 1);
        assert_eq!(ImageHashSource::LoadAddress as u32, 2);
        assert_eq!(ImageHashSource::StagingAddress as u32, 3);
        assert_eq!(AuthorizeAndStashFlags::SKIP_STASH.bits(), 1);
    }

    #[test]
    fn request_builder_preserves_skip_stash_and_load_address_source() {
        let params = AuthorizeAndStashParams {
            fw_id: 0x1122_3344,
            measurement: [0xa5; AUTHORIZE_AND_STASH_MEASUREMENT_SIZE],
            context: [0x5a; AUTHORIZE_AND_STASH_CONTEXT_SIZE],
            svn: 7,
            flags: AuthorizeAndStashFlags::SKIP_STASH,
            source: ImageHashSource::LoadAddress,
            image_size: 0x1000,
        };
        let alloc = TestAlloc;

        let req = build_authorize_and_stash_req(&alloc, &params).unwrap();
        let cmd = AuthorizeAndStashReq::ref_from_bytes(&req).unwrap();

        assert_eq!(cmd.fw_id, params.fw_id.to_le_bytes());
        assert_eq!(cmd.measurement, params.measurement);
        assert_eq!(cmd.context, params.context);
        assert_eq!(cmd.svn.get(), params.svn);
        assert_eq!(cmd.flags.get(), AuthorizeAndStashFlags::SKIP_STASH.bits());
        assert_eq!(cmd.source.get(), ImageHashSource::LoadAddress as u32);
        assert_eq!(cmd.image_size.get(), params.image_size);
    }

    #[test]
    fn response_validation_requires_authorized_result() {
        let mut rsp = [0u8; AUTHORIZE_AND_STASH_RESP_LEN];
        rsp[8..12].copy_from_slice(&IMAGE_AUTHORIZED.to_le_bytes());

        assert_eq!(
            validate_authorize_and_stash_response(&rsp, rsp.len()),
            Ok(())
        );

        rsp[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            validate_authorize_and_stash_response(&rsp, rsp.len()),
            Err(INTERNAL_BUG)
        );
    }
}
