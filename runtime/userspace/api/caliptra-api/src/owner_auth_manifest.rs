// Licensed under the Apache-2.0 license

//! Caliptra `SET_OWNER_AUTH_MANIFEST` mailbox helper.
//!
//! This module only encodes and executes the mailbox command. It does not parse
//! owner policy, validate the owner component set, create DPE contexts, extend
//! PCRs, or load owner firmware.

use caliptra_api::mailbox::{CommandId, SetOwnerAuthManifestReq};
use core::mem::{offset_of, size_of};
use mcu_error::codes::INVARIANT;
use mcu_error::McuResult;
use zerocopy::{little_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::wire::{calc_checksum, CMD_SET_OWNER_AUTH_MANIFEST, MBOX_RESP_HEADER_SIZE};
use crate::ApiAlloc;

/// Maximum Owner Authorization Manifest payload accepted by Caliptra.
///
/// Sized upstream to hold the owner preamble plus the owner-only image-metadata
/// collection.
pub const OWNER_AUTH_MANIFEST_MAX_SIZE: usize = 24 * 1024;

/// Fixed-size head of a `SET_OWNER_AUTH_MANIFEST` request:
/// `MailboxReqHeader.chksum(4) | manifest_size(4)`, followed on the wire by
/// exactly `manifest_size` manifest bytes.
///
/// `Unaligned` with `little_endian::U32` fields on purpose: this is written
/// directly into an allocator-provided byte buffer, so no field may assume host
/// alignment or host endianness.
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
struct SetOwnerAuthManifestReqHeader {
    chksum: U32,
    manifest_size: U32,
}

#[allow(dead_code)] // only referenced from `const _: () = assert!(...)` below
const PREFIX_LEN: usize = size_of::<SetOwnerAuthManifestReqHeader>();
const _: () = assert!(PREFIX_LEN == 8);

// The wire layout is anchored to Caliptra's own request struct rather than to
// hand-counted offsets, so a change on the Caliptra side breaks the build here
// instead of producing a request Caliptra silently rejects.
//
// `size_of` / `offset_of` / associated consts are const-evaluated, so naming the
// 24 KiB `SetOwnerAuthManifestReq` costs no code, no `.bss` and no stack.
const _: () = assert!(CMD_SET_OWNER_AUTH_MANIFEST == CommandId::SET_OWNER_AUTH_MANIFEST.0);
const _: () = assert!(
    offset_of!(SetOwnerAuthManifestReq, manifest_size)
        == offset_of!(SetOwnerAuthManifestReqHeader, manifest_size)
);
const _: () = assert!(offset_of!(SetOwnerAuthManifestReq, manifest) == PREFIX_LEN);
const _: () = assert!(OWNER_AUTH_MANIFEST_MAX_SIZE == SetOwnerAuthManifestReq::MAX_MAN_SIZE);
const _: () =
    assert!(PREFIX_LEN + OWNER_AUTH_MANIFEST_MAX_SIZE == size_of::<SetOwnerAuthManifestReq>());

/// Install the Owner Authorization Manifest into Caliptra's owner-only
/// image-metadata collection via `SET_OWNER_AUTH_MANIFEST`.
///
/// `manifest` is the exact serialized Owner Authorization Manifest (preamble
/// followed by the owner image-metadata collection) to install. Caliptra
/// authenticates it and, on success, activates the owner-only collection.
///
/// The manifest is sent as one contiguous payload rather than streamed: the
/// mailbox lock is taken before a stream is pulled from, so streaming out of a
/// slow backing store would hold the Caliptra mailbox with EXECUTE asserted long
/// enough to starve other mailbox users. The caller stages the manifest first
/// and passes that same immutable buffer here, so the bytes Caliptra
/// authenticates are the bytes the caller already committed to.
///
/// Only `manifest_size` bytes are placed on the wire; the caller never
/// materializes the 24 KiB fixed-size upstream request value.
#[inline(never)]
pub async fn set_owner_auth_manifest<A: ApiAlloc>(alloc: &A, manifest: &[u8]) -> McuResult<()> {
    check_manifest_len(manifest.len())?;

    let mut bytesum = 0u32;
    for b in manifest {
        bytesum = bytesum.wrapping_add(u32::from(*b));
    }
    let header = set_owner_auth_manifest_header(manifest.len() as u32, bytesum);

    let mut rsp = alloc.alloc(MBOX_RESP_HEADER_SIZE)?;
    let _rsp_len = crate::wire::mbox_execute_slice(
        CMD_SET_OWNER_AUTH_MANIFEST,
        Some(header.as_bytes()),
        manifest,
        &mut rsp,
    )
    .await?;

    Ok(())
}

/// Reject manifests Caliptra cannot accept before the mailbox is touched.
///
/// An empty manifest carries no preamble, and anything past
/// [`OWNER_AUTH_MANIFEST_MAX_SIZE`] overruns the upstream request's fixed
/// `manifest` array.
fn check_manifest_len(len: usize) -> McuResult<()> {
    if len == 0 || len > OWNER_AUTH_MANIFEST_MAX_SIZE {
        return Err(INVARIANT);
    }
    Ok(())
}

/// Build the `chksum(4) | manifest_size(4)` request header for
/// `SET_OWNER_AUTH_MANIFEST`.
///
/// The mailbox checksum covers the manifest bytes as well as the header.
/// Because [`calc_checksum`] already returns the *negated* running sum, folding
/// in the payload's byte-sum is a single subtraction:
/// `0 - (S_hdr + S_manifest) == calc_checksum(cmd, hdr) - S_manifest`.
fn set_owner_auth_manifest_header(
    manifest_size: u32,
    manifest_bytesum: u32,
) -> SetOwnerAuthManifestReqHeader {
    let mut header = SetOwnerAuthManifestReqHeader {
        // chksum stays 0 while it is summed over, matching Caliptra, which
        // verifies over the payload following that field.
        chksum: U32::new(0),
        manifest_size: U32::new(manifest_size),
    };
    let chksum = calc_checksum(CMD_SET_OWNER_AUTH_MANIFEST, header.as_bytes())
        .wrapping_sub(manifest_bytesum);
    header.chksum = U32::new(chksum);
    header
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// Recompute the checksum the way Caliptra's runtime verifies it: over the
    /// full on-wire request following the `chksum` field.
    fn caliptra_expected_chksum(manifest: &[u8], header: &SetOwnerAuthManifestReqHeader) -> u32 {
        let mut wire = Vec::new();
        wire.extend_from_slice(&header.as_bytes()[4..]);
        wire.extend_from_slice(manifest);
        calc_checksum(CMD_SET_OWNER_AUTH_MANIFEST, &wire)
    }

    #[test]
    fn command_id_and_prefix_match_caliptra() {
        assert_eq!(CMD_SET_OWNER_AUTH_MANIFEST, 0x4F41_4D4E);
        assert_eq!(PREFIX_LEN, 8);
        assert_eq!(OWNER_AUTH_MANIFEST_MAX_SIZE, 24 * 1024);
    }

    #[test]
    fn header_records_manifest_size() {
        let manifest = [0xa5u8; 64];
        let bytesum = manifest
            .iter()
            .fold(0u32, |a, b| a.wrapping_add(u32::from(*b)));
        let header = set_owner_auth_manifest_header(manifest.len() as u32, bytesum);

        assert_eq!(header.manifest_size.get(), manifest.len() as u32);
    }

    #[test]
    fn checksum_covers_header_and_manifest() {
        let manifest: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let bytesum = manifest
            .iter()
            .fold(0u32, |a, b| a.wrapping_add(u32::from(*b)));
        let header = set_owner_auth_manifest_header(manifest.len() as u32, bytesum);

        assert_eq!(
            header.chksum.get(),
            caliptra_expected_chksum(&manifest, &header)
        );
    }

    #[test]
    fn checksum_is_sensitive_to_manifest_bytes() {
        let mut manifest = std::vec![0u8; 32];
        let bytesum = 0u32;
        let header = set_owner_auth_manifest_header(manifest.len() as u32, bytesum);

        manifest[0] = 1;
        assert_ne!(
            header.chksum.get(),
            caliptra_expected_chksum(&manifest, &header)
        );
    }

    #[test]
    fn empty_and_oversized_manifests_are_rejected() {
        assert_eq!(check_manifest_len(0), Err(INVARIANT));
        assert_eq!(
            check_manifest_len(OWNER_AUTH_MANIFEST_MAX_SIZE + 1),
            Err(INVARIANT)
        );

        assert_eq!(check_manifest_len(1), Ok(()));
        assert_eq!(check_manifest_len(OWNER_AUTH_MANIFEST_MAX_SIZE), Ok(()));
    }
}
